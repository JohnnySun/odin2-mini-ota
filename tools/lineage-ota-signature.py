#!/usr/bin/env python3
"""Verify an Android whole-file OTA ZIP signature against one pinned certificate."""
import hashlib
import os
import struct
import subprocess
import tempfile
from pathlib import Path


def openssl(*args):
    result = subprocess.run(['openssl', *map(str, args)], capture_output=True)
    if result.returncode:
        raise ValueError('OTA certificate or whole-file signature verification failed')
    return result.stdout


def verify(package, certificate, temp_root=None):
    package, certificate = Path(package), Path(certificate)
    certificate_der = openssl('x509', '-in', certificate, '-outform', 'DER')
    size = package.stat().st_size
    with package.open('rb') as source:
        if size < 28:
            raise ValueError('OTA ZIP signature footer missing')
        source.seek(-6, os.SEEK_END)
        signature_start, marker, comment_size = struct.unpack('<HHH', source.read(6))
        if marker != 0xffff or not 6 < signature_start <= comment_size or comment_size + 22 > size:
            raise ValueError('Invalid OTA ZIP signature footer')
        source.seek(-(comment_size + 22), os.SEEK_END)
        eocd = source.read(comment_size + 22)
        if (eocd[:4] != b'PK\x05\x06' or b'PK\x05\x06' in eocd[4:]
                or struct.unpack('<H', eocd[20:22])[0] != comment_size):
            raise ValueError('Invalid or ambiguous signed ZIP end record')
        signature = eocd[-signature_start:-6]
        signed_size = size - comment_size - 2
        with tempfile.TemporaryDirectory(prefix='ota-signature-', dir=temp_root) as directory:
            root = Path(directory)
            signed = root / 'signed.bin'
            source.seek(0)
            remaining = signed_size
            with signed.open('wb') as output:
                while remaining:
                    chunk = source.read(min(remaining, 1024 ** 2))
                    if not chunk:
                        raise ValueError('Truncated signed OTA content')
                    output.write(chunk)
                    remaining -= len(chunk)
            signature_file = root / 'signature.der'
            signature_file.write_bytes(signature)
            # Ignore embedded signer certificates: only the pinned certificate
            # can supply the signer public key. CMS validates the signed bytes.
            openssl('cms', '-verify', '-binary', '-inform', 'DER', '-in', signature_file,
                    '-content', signed, '-noverify', '-nointern', '-certfile', certificate,
                    '-out', os.devnull)
    return hashlib.sha256(certificate_der).hexdigest()
