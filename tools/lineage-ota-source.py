#!/usr/bin/env python3
"""Validate the actual public source archive bytes before release staging."""
import gzip
import hashlib
import io
import re
import tarfile
from pathlib import Path, PurePosixPath

LIMIT = 64 * 1024**2
PRIVATE = re.compile(rb'-----BEGIN (?:[A-Z ]*PRIVATE KEY|OPENSSH PRIVATE KEY)-----|github_pat_|ghp_|/Users/[^/\x00\s]+/|/usr/home/[^/\x00\s]+/|/mnt/(?:nfs|nas|net)/|docs/handoff/private|(?:192\.168\.[0-9]{1,3}\.[0-9]{1,3}|10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})')
ROOT = 'odin2-mini-source/'
FIXED = {'README.md', 'source-projects.json', 'apply-patches.py', 'SHA256SUMS'}


def digest(path):
    value = hashlib.sha256()
    with Path(path).open('rb') as raw:
        for block in iter(lambda: raw.read(1024**2), b''):
            value.update(block)
    return value.hexdigest()


def validate_archive(path, record):
    path = Path(path)
    if (set(record) != {'filename', 'sha256', 'size_bytes'}
            or path.is_symlink() or not path.is_file() or path.name != record.get('filename')
            or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]*\.tar\.gz', path.name)
            or record.get('size_bytes') != path.stat().st_size
            or not re.fullmatch('[0-9a-f]{64}', record.get('sha256', ''))
            or digest(path) != record['sha256']):
        raise ValueError('source archive identity differs from its reviewed bytes')
    try:
        with gzip.open(path, 'rb') as source:
            raw = source.read(LIMIT + 1)
        if len(raw) > LIMIT or PRIVATE.search(raw):
            raise ValueError('source archive contains oversized or private material')
        files = {}
        with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as archive:
            end = 0
            for member in archive:
                name = member.name
                if (not member.isfile() or not name.startswith(ROOT)
                        or PurePosixPath(name).is_absolute() or '..' in PurePosixPath(name).parts
                        or member.size > 4 * 1024**2):
                    raise ValueError('source archive contains an unsafe member')
                relative = name[len(ROOT):]
                if (relative not in FIXED and not re.fullmatch(
                        r'patches/lineage-23\.2/[0-9]{4}-[A-Za-z0-9._-]+\.patch', relative)):
                    raise ValueError('source archive contains material outside the source allowlist')
                if relative in files:
                    raise ValueError('source archive contains duplicate entries')
                data = archive.extractfile(member).read()
                data.decode('utf-8')
                files[relative] = data
                end = max(end, ((member.offset_data + member.size + 511) // 512) * 512)
        if any(raw[end:]) or not FIXED <= files.keys() or not any(n.endswith('.patch') for n in files):
            raise ValueError('source archive is incomplete or has unaccounted trailing data')
        expected = {}
        for line in files['SHA256SUMS'].decode().splitlines():
            sha, name = line.split('  ', 1)
            if name in expected or not re.fullmatch('[0-9a-f]{64}', sha):
                raise ValueError('invalid source checksum entry')
            expected[name] = sha
        actual = {name: hashlib.sha256(data).hexdigest()
                  for name, data in files.items() if name != 'SHA256SUMS'}
        if expected != actual:
            raise ValueError('source archive contents differ from their checksums')
    except (OSError, EOFError, tarfile.TarError, UnicodeError) as error:
        raise ValueError('source archive is malformed') from error
    return record['sha256']
