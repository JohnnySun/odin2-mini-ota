#!/usr/bin/env python3
"""Publish an audited source-only OTA, then advance the raw Updater feed."""
import argparse
import base64
import hashlib
import http.client
import importlib.util
import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

REPOSITORY = 'droiddeck/releases'
FEED = 'odin2_mini.json'

def source_module():
    spec = importlib.util.spec_from_file_location('ota_source',
        Path(__file__).with_name('lineage-ota-source.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

def api(method, path, body=None):
    token = os.environ.get('ODIN2_RELEASE_TOKEN')
    if not token:
        raise RuntimeError('release repository credential is missing')
    request = urllib.request.Request('https://api.github.com/repos/' + REPOSITORY + '/' + path,
        data=json.dumps(body).encode() if body is not None else None, method=method,
        headers={'Authorization': 'Bearer ' + token, 'Accept': 'application/vnd.github+json',
                 'Content-Type': 'application/json', 'User-Agent': 'odin2-mini-release'})
    with urllib.request.urlopen(request, timeout=90) as response:
        return json.load(response)

def validate_package(package, audit, certificate):
    spec = importlib.util.spec_from_file_location('ota_feed', Path(__file__).with_name('lineage-ota-feed.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    tag = audit['release_tag']
    if not re.fullmatch(r'23\.2-\d{8}-[A-Za-z0-9_.-]+', tag):
        raise ValueError('invalid release tag')
    url = f'https://github.com/{REPOSITORY}/releases/download/{tag}/{package.name}'
    update = module.inspect(package, url)
    digest = update['files'][0]['sha256']
    if audit.get('sha256') != digest:
        raise ValueError('audit does not cover these exact OTA bytes')
    for key in ('redistribution_verified', 'no_proprietary_payload', 'no_gapps', 'signature_verified',
                'ota_migration_verified', 'return_to_fastboot_verified'):
        if audit.get(key) is not True:
            raise ValueError('publication blocked: ' + key)
    if not re.fullmatch('[0-9a-f]{64}', audit.get('signing_certificate_sha256', '')):
        raise ValueError('stable signing certificate audit missing')
    signature_spec = importlib.util.spec_from_file_location('ota_signature',
        Path(__file__).with_name('lineage-ota-signature.py'))
    signature_module = importlib.util.module_from_spec(signature_spec)
    signature_spec.loader.exec_module(signature_module)
    actual_certificate = signature_module.verify(package, certificate, os.environ.get('TMPDIR'))
    if actual_certificate != audit['signing_certificate_sha256']:
        raise ValueError('whole-file OTA signature does not match the audited signing identity')
    if audit.get('source_archive_verified') is not True:
        raise ValueError('reviewed source correspondence is required for publication')
    return update

def upload_asset(release, path, content_type, digest, size):
    if source_module().digest(path) != digest or path.stat().st_size != size:
        raise ValueError('release asset changed after validation')
    assets = api('GET', f'releases/{release["id"]}/assets')
    matches = [asset for asset in assets if asset['name'] == path.name]
    if len(matches) > 1:
        raise ValueError('duplicate release assets; refusing replacement')
    if matches:
        asset = matches[0]
    else:
        connection = http.client.HTTPSConnection('uploads.github.com', timeout=600)
        endpoint = f'/repos/{REPOSITORY}/releases/{release["id"]}/assets?name=' + urllib.parse.quote(path.name)
        connection.putrequest('POST', endpoint)
        connection.putheader('Authorization', 'Bearer ' + os.environ['ODIN2_RELEASE_TOKEN'])
        connection.putheader('Content-Type', content_type)
        connection.putheader('Content-Length', str(size))
        connection.putheader('User-Agent', 'odin2-mini-release')
        connection.endheaders()
        with path.open('rb') as raw:
            for chunk in iter(lambda: raw.read(1024**2), b''):
                connection.send(chunk)
        response = connection.getresponse()
        asset = json.loads(response.read())
        connection.close()
        if response.status != 201:
            raise ValueError('release asset upload failed; feed unchanged')
    if asset.get('digest') != 'sha256:' + digest or asset.get('size') != size:
        raise ValueError('release asset failed GitHub hash/size readback; feed unchanged')
    return digest

def anonymous_digest(url):
    value, size = hashlib.sha256(), 0
    with urllib.request.urlopen(url, timeout=600) as raw:
        for chunk in iter(lambda: raw.read(1024**2), b''):
            value.update(chunk)
            size += len(chunk)
    return value.hexdigest(), size

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('package')
    parser.add_argument('--audit', required=True, help='Private byte-bound provenance/signing/migration audit')
    parser.add_argument('--certificate', default=str(Path(__file__).resolve().parents[1] /
                        'config/release-keys/odin2-mini-ota.x509.pem'),
                        help='Pinned public OTA signing certificate')
    args = parser.parse_args()
    package = Path(args.package).resolve()
    audit = json.loads(Path(args.audit).read_text())
    update = validate_package(package, audit, args.certificate)
    source_record = audit['source_archive']
    source_archive = package.parent / source_record['filename']
    source_module().validate_archive(source_archive, source_record)
    checksums = package.parent / 'SHA256SUMS'
    expected_checksums = (audit['sha256'] + '  ' + package.name + '\n'
                          + source_record['sha256'] + '  ' + source_archive.name + '\n').encode()
    if checksums.read_bytes() != expected_checksums:
        raise ValueError('release checksums differ from the reviewed assets')
    digest = update['files'][0]['sha256']
    tag = audit['release_tag']
    url = update['files'][0]['url']
    previous = api('GET', 'contents/' + FEED + '?ref=main')
    feed = json.loads(base64.b64decode(previous['content']))
    if not isinstance(feed, list):
        raise ValueError('unexpected public feed format')
    if feed and update['datetime'] <= max(entry['datetime'] for entry in feed):
        if any(entry == update for entry in feed):
            print('This exact release is already advertised')
            return
        raise ValueError('feed cannot regress or replace an equal build timestamp')
    try:
        release = api('GET', 'releases/tags/' + tag)
    except urllib.error.HTTPError as error:
        if error.code != 404:
            raise
        release = api('POST', 'releases', {'tag_name': tag, 'name': 'Android / Odin2 Mini / ' + tag,
            'draft': True, 'prerelease': True,
            'body': 'Third-party LineageOS 23.2 / Android 16 for AYN Odin2 Mini. '
                    'This is not an official LineageOS release.\n\n'
                    'Development preview for the supported adapted baseline. '
                    'This release is not a hardened production build.\n\n'
                    'This full source-only OTA updates system, system_ext, product and vbmeta_system. '
                    'It contains no boot/vendor firmware, Google apps or original AYN APKs.\n\n'
                    '**Supported installation:** an already adapted Odin2 Mini baseline with '
                    'same-slot vendor, working Virtual A/B and this distribution\'s OTA signing key. '
                    'Factory Android 13 and earlier cross-slot development layouts are not supported '
                    'directly by this package. It is not for other Odin models.\n\n'
                    'Use the built-in Updater to check for the release, download it and start installation. '
                    'Keep power connected through installation, reboot and snapshot merge. '
                    'No factory reset is part of the supported update path.\n\n'
                    'Original AYN touch-mapping software and Google services require separately supplied '
                    'private components; they are not bundled in this release.\n\n'
                    'Package SHA-256: `' + digest + '`.'})
    uploaded = []
    for path, kind, expected_digest, expected_size in [
            (package, 'application/zip', digest, update['files'][0]['size']),
            (source_archive, 'application/gzip', source_record['sha256'], source_record['size_bytes']),
            (checksums, 'text/plain', hashlib.sha256(expected_checksums).hexdigest(), len(expected_checksums))]:
        upload_asset(release, path, kind, expected_digest, expected_size)
        uploaded.append((path, expected_digest, expected_size))
    if release['draft']:
        api('PATCH', f'releases/{release["id"]}', {'draft': False})
    # Independent anonymous download readback before advertising an installable URL.
    for path, expected_digest, expected_size in uploaded:
        asset_url = url.rsplit('/', 1)[0] + '/' + urllib.parse.quote(path.name)
        if anonymous_digest(asset_url) != (expected_digest, expected_size):
            raise ValueError('anonymous asset download differs; public feed unchanged')
    new_feed = [update] + feed[:4]
    api('PUT', 'contents/' + FEED, {'message': 'Advertise audited unofficial ' + tag,
        'branch': 'main', 'sha': previous['sha'],
        'content': base64.b64encode((json.dumps(new_feed, indent=2) + '\n').encode()).decode()})
    readback = api('GET', 'contents/' + FEED + '?ref=main')
    if json.loads(base64.b64decode(readback['content'])) != new_feed:
        raise RuntimeError('feed readback mismatch')
    print('Release bytes and public feed verified: ' + tag)

if __name__ == '__main__':
    main()
