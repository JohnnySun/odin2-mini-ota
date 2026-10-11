#!/usr/bin/env python3
import base64
import hashlib
import importlib.util
import struct
import tempfile
import unittest
import zipfile
from pathlib import Path

spec = importlib.util.spec_from_file_location('feed', Path(__file__).with_name('lineage-ota-feed.py'))
feed = importlib.util.module_from_spec(spec)
spec.loader.exec_module(feed)

def v(n):
    out = bytearray()
    while n > 127:
        out.append((n & 127) | 128)
        n >>= 7
    return bytes(out + bytes([n]))

def blob(n, value):
    return v(n * 8 + 2) + v(len(value)) + value

class PayloadTest(unittest.TestCase):
    def make(self, root, partition='system', corrupt=False, wrong_offset=False, truncated=False,
             manifest_extra=None, partition_extra=b'', metadata_signature=b'',
             metadata_properties_include_signature=False, truncated_metadata_range=False):
        path = Path(root) / 'ota.zip'
        if manifest_extra is None:
            manifest_extra = v(12 * 8) + v(7) + v(16 * 8) + v(1)
        manifest = manifest_extra + blob(13, blob(1, partition.encode()) + partition_extra)
        header = b'CrAU' + struct.pack('>QQI', 2, len(manifest), len(metadata_signature))
        meta = header + manifest
        payload = meta + metadata_signature + b'actual image bytes'
        property_meta = meta + metadata_signature if metadata_properties_include_signature else meta
        props = '\n'.join([
            'FILE_SIZE=' + str(len(payload)), 'METADATA_SIZE=' + str(len(property_meta)),
            'FILE_HASH=' + base64.b64encode(hashlib.sha256(payload).digest()).decode(),
            'METADATA_HASH=' + base64.b64encode(hashlib.sha256(property_meta).digest()).decode()])
        if corrupt:
            payload += b'corruption'
        if truncated:
            payload = header[:20]
        with zipfile.ZipFile(path, 'w', compression=zipfile.ZIP_STORED) as z:
            z.writestr('payload.bin', payload)
            z.writestr('payload_properties.txt', props)
            def offset(i):
                return i.header_offset + 30 + len(i.filename.encode()) + len(i.extra)
            p, q = z.getinfo('payload.bin'), z.getinfo('payload_properties.txt')
            metadata_extent = len(meta) + (0 if truncated_metadata_range else len(metadata_signature))
            ranges = f'payload_metadata.bin:{offset(p)}:{metadata_extent},payload.bin:{offset(p) + int(wrong_offset)}:{p.file_size},payload_properties.txt:{offset(q)}:{q.file_size}'
            z.writestr('META-INF/com/android/metadata', '\n'.join([
                'ota-type=AB', 'pre-device=odin2_mini', 'post-sdk-level=36',
                'post-timestamp=1791580800', 'post-security-patch-level=2026-10-05',
                'ota-property-files=' + ranges]))
        return path

    def read(self, path):
        return feed.inspect(path, 'https://github.com/droiddeck/releases/releases/download/test/ota.zip')

    def test_real_payload_ranges_and_hashes(self):
        with tempfile.TemporaryDirectory() as d:
            path = self.make(d)
            result = self.read(path)
            self.assertEqual(result['files'][0]['sha256'], hashlib.sha256(path.read_bytes()).hexdigest())
            self.assertEqual(result['files'][0]['size'], path.stat().st_size)

    def test_rejects_private_partition_and_byte_corruption(self):
        for kwargs in ({'partition': 'vendor'}, {'corrupt': True}, {'wrong_offset': True}, {'truncated': True}):
            with self.subTest(kwargs=kwargs), tempfile.TemporaryDirectory() as d:
                with self.assertRaises(ValueError):
                    self.read(self.make(d, **kwargs))

    def test_extra_private_entry_cannot_bypass_partition_gate(self):
        with tempfile.TemporaryDirectory() as d:
            path = self.make(d)
            with zipfile.ZipFile(path, 'a') as z:
                z.writestr('vendor.img', b'private bytes')
            with self.assertRaises(ValueError):
                self.read(path)

    def test_full_partial_payload_and_source_dependencies(self):
        partial = v(12 * 8) + v(7) + v(16 * 8) + v(1)
        full_operation = blob(8, v(1 * 8) + v(0))
        with tempfile.TemporaryDirectory() as d:
            self.read(self.make(d, manifest_extra=partial, partition_extra=full_operation))
        cases = [
            {'manifest_extra': b''},
            {'manifest_extra': v(12 * 8) + v(7)},
            {'manifest_extra': v(12 * 8) + v(2)},
            {'manifest_extra': partial + v(12 * 8) + v(7)},
            {'manifest_extra': partial, 'partition_extra': blob(6, b'old hash')},
            {'manifest_extra': partial, 'partition_extra': blob(8, v(1 * 8) + v(4))},
            {'manifest_extra': partial, 'partition_extra': blob(8, v(1 * 8) + v(0) + blob(4, b'old extent'))},
            {'manifest_extra': partial + blob(15, blob(1, blob(1, b'group') + blob(3, b'vendor')))},
        ]
        for kwargs in cases:
            with self.subTest(kwargs=kwargs), tempfile.TemporaryDirectory() as d:
                with self.assertRaises(ValueError):
                    self.read(self.make(d, **kwargs))

    def test_android16_partial_versions_still_reject_source_dependencies(self):
        full_operation = blob(8, v(1 * 8) + v(0))
        for minor in (7, 8, 9):
            partial = v(12 * 8) + v(minor) + v(16 * 8) + v(1)
            with self.subTest(minor=minor), tempfile.TemporaryDirectory() as d:
                self.read(self.make(d, manifest_extra=partial, partition_extra=full_operation))
            for extra in (blob(6, b'old partition'),
                          blob(8, v(1 * 8) + v(4)),
                          blob(8, v(1 * 8) + v(0) + blob(4, b'old extent'))):
                with self.subTest(minor=minor, extra=extra), tempfile.TemporaryDirectory() as d:
                    with self.assertRaises(ValueError):
                        self.read(self.make(d, manifest_extra=partial, partition_extra=extra))
        for minor, partial in ((6, 1), (10, 1), (9, 0)):
            manifest = v(12 * 8) + v(minor) + v(16 * 8) + v(partial)
            with self.subTest(minor=minor, partial=partial), tempfile.TemporaryDirectory() as d:
                with self.assertRaises(ValueError):
                    self.read(self.make(d, manifest_extra=manifest, partition_extra=full_operation))

    def test_signed_metadata_hash_excludes_signature_but_streaming_range_includes_it(self):
        kwargs = {'manifest_extra': v(12 * 8) + v(9) + v(16 * 8) + v(1),
                  'metadata_signature': b'metadata signature bytes'}
        with tempfile.TemporaryDirectory() as d:
            self.read(self.make(d, **kwargs))
        for bad in ({'metadata_properties_include_signature': True},
                    {'truncated_metadata_range': True}, {'corrupt': True}):
            with self.subTest(bad=bad), tempfile.TemporaryDirectory() as d:
                with self.assertRaises(ValueError):
                    self.read(self.make(d, **kwargs, **bad))

    def test_protobuf_truncation_and_unsupported_wire(self):
        for data in (b'\x80', b'\x0a\x05x', b'\x0b', b'\x09x'):
            with self.assertRaises(ValueError):
                list(feed.fields(data))

if __name__ == '__main__':
    unittest.main()
