import gzip
import hashlib
import importlib.util
import io
import tarfile
import tempfile
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location('source', Path(__file__).with_name('lineage-ota-source.py'))
source = importlib.util.module_from_spec(spec)
spec.loader.exec_module(source)

class ArchiveBytesTest(unittest.TestCase):
    def make(self, directory, *, private=False, corrupt=False, extra=False, link=False, trailing=False):
        files = {'README.md': b'Public adaptation source\n', 'source-projects.json': b'{}\n',
                 'apply-patches.py': b'print("public patch applier")\n',
                 'patches/lineage-23.2/0001-adaptation.patch': b'diff --git a/a b/a\n'}
        if private:
            files['README.md'] += b'-----BEGIN RSA PRIVATE KEY-----\nsecret\n'
        if extra:
            files['vendor.img'] = b'proprietary bytes'
        checksums = ''.join(hashlib.sha256(data).hexdigest() + '  ' + name + '\n'
                            for name, data in sorted(files.items())).encode()
        files['SHA256SUMS'] = checksums
        if corrupt:
            files['README.md'] += b'edited without checksum update'
        raw = io.BytesIO()
        with tarfile.open(fileobj=raw, mode='w') as archive:
            for name, data in files.items():
                info = tarfile.TarInfo('odin2-mini-source/' + name)
                if link and name == 'README.md':
                    info.type, info.linkname = tarfile.SYMTYPE, '/etc/passwd'
                    archive.addfile(info)
                else:
                    info.size = len(data)
                    archive.addfile(info, io.BytesIO(data))
        contents = raw.getvalue() + (b'unaccounted private trailer' if trailing else b'')
        path = Path(directory) / 'source.tar.gz'
        path.write_bytes(gzip.compress(contents))
        return path, self.record(path)

    def record(self, path):
        return {'filename': path.name, 'size_bytes': path.stat().st_size,
                'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}

    def test_valid_bytes_and_changed_inner_content(self):
        with tempfile.TemporaryDirectory() as directory:
            path, record = self.make(directory)
            self.assertEqual(source.validate_archive(path, record), record['sha256'])
            path, record = self.make(directory, corrupt=True)
            with self.assertRaises(ValueError):
                source.validate_archive(path, record)

    def test_rejects_private_binary_link_and_trailing_bytes(self):
        for kwargs in [{'private': True}, {'extra': True}, {'link': True}, {'trailing': True}]:
            with self.subTest(kwargs=kwargs), tempfile.TemporaryDirectory() as directory:
                path, record = self.make(directory, **kwargs)
                with self.assertRaises(ValueError):
                    source.validate_archive(path, record)

    def test_rejects_truncated_gzip_even_when_outer_hash_matches(self):
        with tempfile.TemporaryDirectory() as directory:
            path, _ = self.make(directory)
            path.write_bytes(path.read_bytes()[:-4])
            with self.assertRaises(ValueError):
                source.validate_archive(path, self.record(path))

if __name__ == '__main__':
    unittest.main()
