#!/usr/bin/env python3
"""Run the practice round with a Python audit guard rejecting non-loopback networking.

This is a test guard for our Python processes, not an OS firewall or a sandbox
for arbitrary native code. No system network configuration is changed.
"""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
GUARD = '''
import ipaddress
import os
import sys
def check(event, args):
    if event == 'socket.getaddrinfo':
        host = args[0]
    elif event in ('socket.connect', 'socket.bind'):
        address = args[1]
        if not isinstance(address, tuple):
            return
        host = address[0]
    else:
        return
    try:
        permitted = ipaddress.ip_address(host).is_loopback
    except ValueError:
        permitted = False
    if not permitted:
        with open(os.environ['AWD_NETWORK_AUDIT'], 'a') as log:
            log.write(event + ' denied\\n')
        raise PermissionError('Offline test rejects non-loopback networking')
sys.addaudithook(check)
os.environ['AWD_GUARD_ACTIVE'] = '1'
'''


def main():
    with tempfile.TemporaryDirectory(prefix='awd-network-guard-') as temp:
        directory = Path(temp)
        (directory / 'sitecustomize.py').write_text(GUARD)
        audit = directory / 'audit.txt'
        env = dict(os.environ, PYTHONPATH=str(directory), PYTHONNOUSERSITE='1', AWD_NETWORK_AUDIT=str(audit))
        probe = """
import os, socket
assert os.environ.get('AWD_GUARD_ACTIVE') == '1'
for operation in (lambda: socket.getaddrinfo('example.invalid', 80), lambda: socket.create_connection(('192.0.2.1', 80), timeout=1)):
    try:
        operation()
    except PermissionError:
        continue
    raise AssertionError('Network guard failed')
"""
        subprocess.run([sys.executable, '-c', probe], env=env, check=True, timeout=10)
        if len(audit.read_text().splitlines()) != 2:
            raise RuntimeError('Guard probe did not reject both external operations')
        audit.write_text('')
        subprocess.run([sys.executable, str(ROOT / 'lab/verify.py')], cwd=ROOT, env=env, check=True, timeout=30)
        if audit.read_text():
            raise RuntimeError('Practice attempted a non-loopback network operation')
        print(json.dumps({'offline_guard_passed': True, 'external_network_attempts': 0, 'scope': 'Python socket audit guard, including child CLI processes; not OS disconnection'}))


if __name__ == '__main__':
    main()
