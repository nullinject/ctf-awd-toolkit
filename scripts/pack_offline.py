#!/usr/bin/env python3
"""Export allowlisted source files with a checksum manifest, never local state."""
import argparse
import hashlib
import json
from pathlib import Path
import zipfile

ROOT = Path(__file__).resolve().parents[1]
FILES = ['README.md', 'OFFLINE.md', 'TEST_REPORT.md', 'awd.py', 'awd.example.json', '.gitignore',
         'lab/run.py', 'lab/verify.py', 'lab/pwn_echo.c',
         'scripts/triage.sh', 'scripts/pwn-inspect.sh', 'scripts/offline_check.py', 'scripts/pack_offline.py', 'scripts/verify_offline.py',
         'tests/test_awd.py', 'tests/test_lab.py']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', help='New .zip path; existing files are never overwritten')
    args = parser.parse_args()
    contents = {name: (ROOT / name).read_bytes() for name in FILES}
    manifest = {name: hashlib.sha256(data).hexdigest() for name, data in contents.items()}
    with zipfile.ZipFile(args.output, 'x', compression=zipfile.ZIP_DEFLATED) as bundle:
        for name, data in contents.items():
            bundle.writestr('awd-offline/' + name, data)
        bundle.writestr('awd-offline/SHA256.json', json.dumps(manifest, indent=2) + '\n')
    print(json.dumps({'bundle': str(Path(args.output).resolve()), 'files': len(contents), 'sha256': hashlib.sha256(Path(args.output).read_bytes()).hexdigest()}))


if __name__ == '__main__':
    main()
