#!/usr/bin/env python3
"""Copy only an audited, signed OTA into an isolated publisher's read-only inbox."""
import argparse
import hashlib
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

AUDIT_FIELDS = {'release_tag', 'sha256', 'signing_certificate_sha256',
    'redistribution_verified', 'no_proprietary_payload', 'no_gapps',
    'signature_verified', 'ota_migration_verified', 'return_to_fastboot_verified'}
CERTIFICATE = Path(__file__).resolve().parents[1] / 'config/release-keys/odin2-mini-ota.x509.pem'


def publisher():
    spec = importlib.util.spec_from_file_location('publisher', Path(__file__).with_name('lineage-publish-ota.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def digest(path):
    value = hashlib.sha256()
    with Path(path).open('rb') as source:
        for chunk in iter(lambda: source.read(1024 ** 2), b''):
            value.update(chunk)
    return value.hexdigest()


def stage(package, audit, root, certificate=CERTIFICATE):
    package, root = Path(package), Path(root)
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]*\.zip', package.name):
        raise ValueError('Unsafe OTA asset filename')
    update = publisher().validate_package(package, audit, certificate)
    sha = update['files'][0]['sha256']
    public_audit = {key: audit[key] for key in AUDIT_FIELDS}
    root.mkdir(parents=True, exist_ok=True)
    destination = root / sha
    if destination.exists():
        if (destination.is_symlink() or digest(destination / package.name) != sha
                or json.loads((destination / 'audit.json').read_text()) != public_audit):
            raise ValueError('Existing staged bytes or audit differ; refusing replacement')
    else:
        with tempfile.TemporaryDirectory(prefix='.stage-', dir=root) as directory:
            temporary = Path(directory)
            copied = temporary / package.name
            shutil.copyfile(package, copied)
            if digest(copied) != sha:
                raise ValueError('Staged OTA bytes differ from the validated package')
            # The publication container receives only this reduced audit and
            # verified OTA, never private paths, manifests, logs or signing keys.
            metadata = temporary / 'audit.json'
            metadata.write_text(json.dumps(public_audit, indent=2) + '\n')
            for path in [copied, metadata]:
                with path.open('rb') as raw:
                    os.fsync(raw.fileno())
            os.chmod(copied, 0o640)
            os.chmod(metadata, 0o640)
            os.chmod(temporary, 0o2750)
            temporary.rename(destination)
    pointer = root / '.latest.json.tmp'
    pointer.write_text(json.dumps({'sha256': sha, 'filename': package.name}) + '\n')
    with pointer.open('rb') as raw:
        os.fsync(raw.fileno())
    os.chmod(pointer, 0o640)
    pointer.replace(root / 'latest.json')
    print('Audited OTA staged for the isolated release publisher')


def publish_ready(root):
    root = Path(root).resolve()
    pointer = root / 'latest.json'
    if not pointer.is_file():
        print('No audited OTA is ready; release feed is unchanged')
        return
    data = json.loads(pointer.read_text())
    sha, filename = data.get('sha256', ''), data.get('filename', '')
    if not re.fullmatch('[0-9a-f]{64}', sha) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]*\.zip', filename):
        raise ValueError('Invalid approved OTA pointer')
    package, audit = root / sha / filename, root / sha / 'audit.json'
    if any(p.is_symlink() or not p.resolve().is_relative_to(root) for p in [pointer, package.parent, package, audit]):
        raise ValueError('Approved OTA paths escape the inbox')
    if digest(package) != sha:
        raise ValueError('Approved OTA bytes changed')
    subprocess.run([sys.executable, str(Path(__file__).with_name('lineage-publish-ota.py')),
                    str(package), '--audit', str(audit)], check=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ready-root', required=True)
    parser.add_argument('--package')
    parser.add_argument('--audit')
    args = parser.parse_args()
    try:
        if args.package and args.audit:
            stage(args.package, json.loads(Path(args.audit).read_text()), args.ready_root)
        elif not args.package and not args.audit:
            publish_ready(args.ready_root)
        else:
            raise ValueError('Package and audit must be supplied together')
    except Exception:
        # Public Actions logs must never echo host paths or private audit text.
        print('OTA staging or publication failed validation; see private host evidence', file=sys.stderr)
        raise SystemExit(1)
