#!/usr/bin/env python3
"""Runs an end-to-end practice round using only loopback and temporary files."""
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import awd
from lab.run import Lab


def verify(directory):
    lab = Lab(directory).start()
    env = dict(os.environ, AWD_TOKEN=lab.token)
    cfg = lab.directory / 'awd.json'
    def cli(*args, expected=0):
        result = subprocess.run([sys.executable, str(ROOT / 'awd.py'), '-c', str(cfg), *map(str, args)], capture_output=True, text=True, env=env, timeout=15)
        if result.returncode != expected:
            raise AssertionError(f'{args}: expected {expected}, got {result.returncode}\n{result.stdout}\n{result.stderr}')
        return result.stdout
    def require(condition, label):
        if not condition:
            raise AssertionError(label)
    try:
        cli('health')
        web = lab.directory / 'web'
        baseline = lab.directory / 'clean.baseline.json'
        archive = lab.directory / 'before.tar.gz'
        cli('baseline', web, '-o', baseline)
        cli('backup', web, '-o', archive)
        url = f'http://127.0.0.1:{lab.servers[0].server_port}'
        status, body = awd.request(url + '/download?name=../flag.txt')
        require(status == 200 and lab.web_flag in body.decode(), 'vulnerable fixture reproduces disclosure')
        (web / 'policy.txt').write_text('fixed\n')
        require(awd.request(url + '/download?name=../flag.txt')[0] == 403, 'repair blocks private file')
        require(awd.request(url + '/download?name=welcome.txt')[0] == 200, 'repair preserves public download')
        require(awd.request(url + '/download?name=../../../../etc/passwd')[0] == 403, 'lab boundary')
        cli('diff', baseline, expected=1)
        cli('health')
        cli('restore', archive, lab.directory / 'restore', '--sha256', awd.digest(archive))
        require((lab.directory / 'restore/data/policy.txt').read_text().strip() == 'vulnerable', 'restore preserves original')
        with socket.create_connection(lab.servers[1].server_address, timeout=3) as sock:
            with sock.makefile('rwb') as stream:
                require(b'protocol simulator' in stream.readline(), 'TCP banner')
                stream.write(b'FLAG\n')
                stream.flush()
                tcp_flag = stream.readline().decode().strip()
        require(tcp_flag == lab.tcp_flag, 'TCP flag')
        output = lab.directory / 'result.txt'
        output.write_text(body.decode() + '\n' + tcp_flag + '\n' + tcp_flag)
        cli('extract', output)
        cli('submit')
        require(not lab.accepted, 'dry run has no network side effect')
        cli('submit', '--send')
        cli('submit', '--send')
        require(lab.accepted == lab.flags, 'both flags scored once')
        judge = lab.cfg['submission']['url']
        require(awd.request(judge, method='POST', body=b'{"flag":"bad"}')[0] == 401, 'judge requires token')
        status, response = awd.request(judge, method='POST', body=b'{"flag":"bad"}', headers={'Authorization': 'Bearer ' + lab.token, 'Content-Type': 'application/json'})
        require(not json.loads(response)['success'], 'judge rejects incorrect flag')
        return {'ok': True, 'accepted': len(lab.accepted), 'checks': ['health', 'backup/restore', 'web reproduce/repair/regression', 'file drift', 'TCP interaction', 'extract/deduplicate', 'dry run', 'submit/score', 'judge authentication']}
    finally:
        lab.close()


if __name__ == '__main__':
    with tempfile.TemporaryDirectory(prefix='awd-offline-') as temp:
        print(json.dumps(verify(Path(temp) / 'round'), ensure_ascii=False, indent=2))
