#!/usr/bin/env python3
"""Inspect actual A/B OTA bytes before emitting the LineageOS 23.2 v2 feed."""
import argparse
import base64
import hashlib
import json
import re
import struct
import zipfile
from pathlib import Path

PUBLIC_PARTITIONS = {'system', 'system_ext', 'product', 'vbmeta_system'}
PUBLIC_ENTRIES = {'payload.bin', 'payload_properties.txt', 'care_map.pb', 'compatibility.zip',
    'apex_info.pb', 'META-INF/com/android/metadata', 'META-INF/com/android/metadata.pb',
    'META-INF/com/android/otacert', 'META-INF/com/google/android/update-binary',
    'META-INF/com/google/android/updater-script', 'META-INF/CERT.RSA', 'META-INF/CERT.SF',
    'META-INF/MANIFEST.MF'}

def varint(data, pos):
    value = 0
    for shift in range(0, 70, 7):
        if pos >= len(data):
            raise ValueError('truncated protobuf varint')
        byte = data[pos]
        pos += 1
        value |= (byte & 127) << shift
        if not byte & 128:
            return value, pos
    raise ValueError('oversized protobuf varint')

def fields(data):
    pos = 0
    while pos < len(data):
        key, pos = varint(data, pos)
        number, wire = key >> 3, key & 7
        if not number:
            raise ValueError('zero protobuf field')
        if wire == 0:
            value, pos = varint(data, pos)
        elif wire in (1, 5):
            end = pos + (8 if wire == 1 else 4)
            value = data[pos:end]
            if end > len(data):
                raise ValueError('truncated protobuf fixed field')
            pos = end
        elif wire == 2:
            size, pos = varint(data, pos)
            end = pos + size
            if end > len(data):
                raise ValueError('truncated protobuf bytes')
            value, pos = data[pos:end], end
        else:
            raise ValueError('unsupported protobuf wire type')
        yield number, wire, value

def key_values(raw):
    result = {}
    for line in raw.decode('utf-8').splitlines():
        if not line:
            continue
        key, sep, value = line.partition('=')
        if not sep or key in result:
            raise ValueError('malformed or duplicate metadata key')
        result[key] = value
    return result

def inspect(package, url):
    package = Path(package)
    if package.stat().st_size >= 2 * 1024**3:
        raise ValueError('package exceeds GitHub release asset size limit')
    if not re.fullmatch(r'https://github\.com/droiddeck/releases/releases/download/[^/]+/[^/?#]+', url):
        raise ValueError('download URL must point to the public release repository')
    if url.rsplit('/', 1)[1] != package.name or not re.fullmatch(r'[A-Za-z0-9_.-]+\.zip', package.name):
        raise ValueError('release filename mismatch')
    with zipfile.ZipFile(package) as archive:
        infos = archive.infolist()
        if any(not i.is_dir() and i.filename not in PUBLIC_ENTRIES for i in infos):
            raise ValueError('unapproved ZIP entry may contain private or proprietary material')
        if len({i.filename for i in infos}) != len(infos):
            raise ValueError('duplicate ZIP entry')
        for name in ('payload.bin', 'payload_properties.txt', 'META-INF/com/android/metadata'):
            if archive.getinfo(name).file_size > (2 * 1024**3 if name == 'payload.bin' else 1024**2):
                raise ValueError('oversized OTA entry')
        info = archive.getinfo('payload.bin')
        if info.compress_type != zipfile.ZIP_STORED or info.flag_bits & 1:
            raise ValueError('payload must be unencrypted ZIP_STORED')
        metadata = key_values(archive.read('META-INF/com/android/metadata'))
        props = key_values(archive.read('payload_properties.txt'))
        if metadata.get('ota-type') != 'AB' or metadata.get('pre-device') != 'odin2_mini':
            raise ValueError('package is not an Odin2 Mini A/B OTA')
        if metadata.get('pre-build') or metadata.get('pre-build-incremental'):
            raise ValueError('incremental OTA needs a separate baseline compatibility lane')
        if metadata.get('ota-wipe', 'no') != 'no' or metadata.get('ota-downgrade', 'no') != 'no':
            raise ValueError('wipe/downgrade OTA cannot enter automatic feed')
        with archive.open(info) as stream:
            header = stream.read(24)
            if len(header) != 24 or header[:4] != b'CrAU':
                raise ValueError('invalid payload header')
            version, manifest_size, signature_size = struct.unpack('>QQI', header[4:])
            if version != 2 or not 0 < manifest_size <= 16 * 1024**2:
                raise ValueError('unsupported or oversized payload manifest')
            metadata_size = 24 + manifest_size + signature_size
            if metadata_size > info.file_size or signature_size > 1024**2:
                raise ValueError('payload metadata exceeds payload')
            manifest = stream.read(manifest_size)
            signature = stream.read(signature_size)
            if len(manifest) != manifest_size or len(signature) != signature_size:
                raise ValueError('truncated payload metadata')
            manifest_fields = list(fields(manifest))
            minor = [value for number, wire, value in manifest_fields if number == 12 and wire == 0]
            partial = [value for number, wire, value in manifest_fields if number == 16 and wire == 0]
            if (len(minor) > 1 or len(partial) > 1 or
                    any(wire != 0 for number, wire, value in manifest_fields if number in (12, 16))):
                raise ValueError('invalid payload version or partial-update field')
            # AOSP uses minor version 7 for a partial update even when all
            # selected images are full replacements. No old-image dependency
            # may enter this lane; inspect the actual partition operations too.
            if (minor[0] if minor else 0, partial[0] if partial else 0) != (7, 1):
                raise ValueError('source-only OTA requires full partial-update mode')
            partitions = []
            for number, wire, value in manifest_fields:
                if number == 15:
                    if wire != 2:
                        raise ValueError('invalid dynamic partition metadata')
                    for n, w, group in fields(value):
                        if n != 1:
                            continue
                        if w != 2:
                            raise ValueError('invalid dynamic partition group')
                        for n, w, name in fields(group):
                            if n == 3 and (w != 2 or name.decode('ascii') not in PUBLIC_PARTITIONS - {'vbmeta_system'}):
                                raise ValueError('dynamic metadata includes a private partition')
                if number == 13:
                    if wire != 2:
                        raise ValueError('invalid partition message')
                    partition_fields = list(fields(value))
                    if any(n == 6 for n, w, v in partition_fields):
                        raise ValueError('payload depends on an old partition image')
                    for n, w, operation in partition_fields:
                        if n != 8:
                            continue
                        if w != 2:
                            raise ValueError('invalid install operation')
                        op_fields = list(fields(operation))
                        kinds = [v for n, w, v in op_fields if n == 1 and w == 0]
                        if (len(kinds) != 1 or kinds[0] not in (0, 1, 6, 7, 8) or
                                any(n in (4, 5, 9) for n, w, v in op_fields)):
                            raise ValueError('incremental/source-reading install operation')
                    names = [v.decode('ascii') for n, w, v in partition_fields if n == 1 and w == 2]
                    if len(names) != 1:
                        raise ValueError('invalid partition name')
                    partitions.extend(names)
            if not partitions or len(partitions) != len(set(partitions)) or not set(partitions) <= PUBLIC_PARTITIONS:
                raise ValueError('public OTA contains unapproved or proprietary partitions')
            digest = hashlib.sha256(header + manifest + signature)
            md_hash = base64.b64encode(digest.digest()).decode()
            for chunk in iter(lambda: stream.read(1024**2), b''):
                digest.update(chunk)
            expected = {'FILE_SIZE': str(info.file_size), 'FILE_HASH': base64.b64encode(digest.digest()).decode(),
                        'METADATA_SIZE': str(metadata_size), 'METADATA_HASH': md_hash}
            if any(props.get(k) != v for k, v in expected.items()):
                raise ValueError('payload properties do not match package bytes')
        # Check every streaming range against local ZIP headers, not central sizes alone.
        ranges = metadata.get('ota-property-files', '').strip()
        if not ranges:
            raise ValueError('streaming property files missing')
        by_name = {i.filename: i for i in infos}
        seen = set()
        with package.open('rb') as raw:
            raw.seek(info.header_offset)
            local = raw.read(30)
            if len(local) != 30 or local[:4] != b'PK\x03\x04':
                raise ValueError('invalid local ZIP header')
            payload_offset = info.header_offset + 30 + sum(struct.unpack('<HH', local[26:30]))
            for item in ranges.split(','):
                name, offset, size = item.strip().rsplit(':', 2)
                offset, size = int(offset), int(size)
                if name in seen or offset < 0 or size < 0 or offset + size > package.stat().st_size:
                    raise ValueError('invalid streaming range')
                seen.add(name)
                if name == 'payload_metadata.bin':
                    valid = offset == payload_offset and size == metadata_size
                else:
                    matches = [v for k, v in by_name.items() if k.rsplit('/', 1)[-1] == name]
                    if len(matches) != 1:
                        raise ValueError('ambiguous streaming entry')
                    entry = matches[0]
                    raw.seek(entry.header_offset)
                    local = raw.read(30)
                    if len(local) != 30 or local[:4] != b'PK\x03\x04':
                        raise ValueError('invalid local ZIP header')
                    actual = entry.header_offset + 30 + sum(struct.unpack('<HH', local[26:30]))
                    valid = entry.compress_type == zipfile.ZIP_STORED and offset == actual and size == entry.file_size
                if not valid:
                    raise ValueError('streaming range does not match ZIP bytes')
        if not {'payload.bin', 'payload_properties.txt', 'payload_metadata.bin'} <= seen:
            raise ValueError('required streaming ranges missing')
    digest = hashlib.sha256()
    with package.open('rb') as raw:
        for chunk in iter(lambda: raw.read(1024**2), b''):
            digest.update(chunk)
    sdk, timestamp = int(metadata['post-sdk-level']), int(metadata['post-timestamp'])
    patch_level = metadata['post-security-patch-level']
    if sdk != 36 or timestamp <= 0 or not re.fullmatch(r'\d{4}-\d{2}-\d{2}', patch_level):
        raise ValueError('package is not the Android 16 release lane')
    return {'datetime': timestamp, 'type': 'UNOFFICIAL', 'version': '23.2', 'files': [{
        'filename': package.name, 'os_patch_level': patch_level, 'os_sdk_level': sdk,
        'ota_property_files': ranges, 'sha256': digest.hexdigest(), 'size': package.stat().st_size, 'url': url}]}

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('package')
    parser.add_argument('--url', required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    update = inspect(args.package, args.url)
    Path(args.output).write_text(json.dumps([update], indent=2) + '\n')
