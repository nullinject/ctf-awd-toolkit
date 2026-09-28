#!/usr/bin/env python3
"""Offline loopback-only AWD practice services, no external dependencies."""
import argparse
import hmac
import http.server
import json
from pathlib import Path
import secrets
import socketserver
import threading
import time
import urllib.parse


class HTTPServer(http.server.ThreadingHTTPServer):
    daemon_threads = True


class TCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class Handler(http.server.BaseHTTPRequestHandler):
    def setup(self):
        super().setup()
        self.connection.settimeout(3)

    def log_message(self, *args):
        pass

    def reply(self, status, data):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        lab = self.server.lab
        url = urllib.parse.urlsplit(self.path)
        if self.server.role == 'judge':
            if url.path != '/score':
                return self.reply(404, {'error': 'not found'})
            if not lab.authorized(self.headers):
                return self.reply(401, {'error': 'unauthorized'})
            with lab.lock:
                return self.reply(200, {'accepted': len(lab.accepted), 'points': len(lab.accepted) * 100})
        if url.path == '/':
            return self.reply(200, {'service': 'AWD practice web', 'healthy': True})
        if url.path != '/download':
            return self.reply(404, {'error': 'not found'})
        name = urllib.parse.parse_qs(url.query).get('name', ['welcome.txt'])[0]
        # Deliberately flawed policy, but both modes remain confined to this lab's web directory.
        web = lab.directory / 'web'
        public = web / 'public'
        try:
            candidate = (public / name).resolve()
            mode = (web / 'policy.txt').read_text().strip()
            allowed = public if mode == 'fixed' else web if mode == 'vulnerable' else None
            if allowed is None or not candidate.is_relative_to(allowed.resolve()):
                return self.reply(403, {'error': 'outside allowed directory'})
            if not candidate.is_file() or candidate.stat().st_size > 65536:
                return self.reply(404, {'error': 'file unavailable'})
            return self.reply(200, {'content': candidate.read_text()})
        except (ValueError, RuntimeError):
            return self.reply(400, {'error': 'invalid path'})
        except (OSError, UnicodeError):
            return self.reply(404, {'error': 'file unavailable'})

    def do_POST(self):
        lab = self.server.lab
        if self.server.role != 'judge' or self.path != '/submit':
            return self.reply(404, {'success': False})
        if not lab.authorized(self.headers):
            return self.reply(401, {'success': False, 'error': 'unauthorized'})
        try:
            size = int(self.headers.get('Content-Length', '0'))
            if not 0 < size <= 4096:
                return self.reply(400, {'success': False, 'error': 'invalid length'})
            body = json.loads(self.rfile.read(size))
            flag = body.get('flag') if isinstance(body, dict) else None
            if not isinstance(flag, str) or flag not in lab.flags:
                return self.reply(200, {'success': False, 'error': 'invalid flag'})
        except (ValueError, OSError):
            return self.reply(400, {'success': False, 'error': 'invalid request'})
        with lab.lock:
            duplicate = flag in lab.accepted
            lab.accepted.add(flag)
        self.reply(200, {'success': True, 'duplicate': duplicate})


class TCPHandler(socketserver.StreamRequestHandler):
    def handle(self):
        self.connection.settimeout(3)
        try:
            self.wfile.write(b'AWD protocol simulator: PING | ECHO text | FLAG\n')
            line = self.rfile.readline(1025)
            if len(line) > 1024:
                self.wfile.write(b'ERR too long\n')
            elif line.strip() == b'PING':
                self.wfile.write(b'PONG\n')
            elif line.strip() == b'FLAG':
                self.wfile.write((self.server.lab.tcp_flag + '\n').encode())
            elif line.startswith(b'ECHO '):
                self.wfile.write(line[5:])
            elif line:
                self.wfile.write(b'ERR command\n')
        except (OSError, TimeoutError):
            pass


class Lab:
    def __init__(self, directory, web_port=0, tcp_port=0, judge_port=0):
        self.directory = Path(directory).resolve()
        self.directory.mkdir(mode=0o700, parents=False, exist_ok=False)
        self.servers = []
        self.threads = []
        self.lock = threading.Lock()
        self.accepted = set()
        self.token = secrets.token_hex(24)
        self.web_flag = 'flag{web_' + secrets.token_hex(12) + '}'
        self.tcp_flag = 'flag{tcp_' + secrets.token_hex(12) + '}'
        self.flags = {self.web_flag, self.tcp_flag}
        public = self.directory / 'web/public'
        public.mkdir(parents=True)
        (public / 'welcome.txt').write_text('Public download works.\n')
        (self.directory / 'web/flag.txt').write_text(self.web_flag + '\n')
        (self.directory / 'web/policy.txt').write_text('vulnerable\n')
        try:
            for port, handler, role, cls in [(web_port, Handler, 'web', HTTPServer), (tcp_port, TCPHandler, 'tcp', TCPServer), (judge_port, Handler, 'judge', HTTPServer)]:
                server = cls(('127.0.0.1', port), handler)
                server.lab, server.role = self, role
                self.servers.append(server)
            web, tcp, judge = [s.server_address[1] for s in self.servers]
            self.cfg = {
                'state_dir': str(self.directory / 'queue'), 'timeout': 3, 'workers': 3,
                'flag_regex': r'flag\{[A-Za-z0-9_:-]{8,200}\}',
                'targets': [
                    dict(name='lab-web', host='127.0.0.1', port=web, protocol='http', path='/', contains='AWD practice web'),
                    dict(name='lab-tcp-simulator', host='127.0.0.1', port=tcp, protocol='tcp')],
                'submission': dict(url=f'http://127.0.0.1:{judge}/submit', token_env='AWD_TOKEN', success_json_field='success', success_json_value=True, interval_seconds=.1)
            }
            (self.directory / 'awd.json').write_text(json.dumps(self.cfg, indent=2))
            (self.directory / 'token.txt').write_text(self.token)
            (self.directory / 'token.txt').chmod(0o600)
        except Exception:
            for server in self.servers:
                server.server_close()
            raise

    def authorized(self, headers):
        supplied = headers.get('Authorization', '')
        return supplied.isascii() and hmac.compare_digest(supplied, 'Bearer ' + self.token)

    def start(self):
        for server in self.servers:
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            self.threads.append(thread)
        return self

    def close(self):
        for server in self.servers[:len(self.threads)]:
            server.shutdown()
        for server in self.servers:
            server.server_close()
        for thread in self.threads:
            thread.join(timeout=3)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', default='.awd-lab')
    parser.add_argument('--web-port', type=int, default=18080)
    parser.add_argument('--tcp-port', type=int, default=19999)
    parser.add_argument('--judge-port', type=int, default=18081)
    args = parser.parse_args()
    lab = None
    try:
        lab = Lab(args.directory, args.web_port, args.tcp_port, args.judge_port).start()
        print(json.dumps({'directory': str(lab.directory), 'targets': lab.cfg['targets'], 'submission': lab.cfg['submission']['url'], 'stop': 'Ctrl+C; restart with a new directory'}, ensure_ascii=False), flush=True)
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        return 0
    except OSError as exc:
        parser.exit(2, str(exc) + '\nUse a new directory or ports; --web-port 0 --tcp-port 0 --judge-port 0 auto-selects free ports.\n')
    finally:
        if lab:
            lab.close()


if __name__ == '__main__':
    raise SystemExit(main())
