from pathlib import Path
import contextlib
import io
import json
import selectors
import signal
import socket
import subprocess
import sys
import tempfile
import unittest
import awd
from lab.run import Lab
from lab.verify import verify


class OfflineLabTest(unittest.TestCase):
    def test_full_round(self):
        with tempfile.TemporaryDirectory() as directory:
            result = verify(Path(directory) / 'round')
            self.assertTrue(result['ok'])
            self.assertEqual(result['accepted'], 2)


class LabBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.lab = Lab(Path(self.temp.name) / 'round').start()
        self.addCleanup(self.lab.close)
        self.web = f'http://127.0.0.1:{self.lab.servers[0].server_port}'
        self.judge = self.lab.cfg['submission']['url']

    def test_bad_download_paths_return_http_errors(self):
        # Malformed paths must not close the socket or print handler tracebacks.
        with contextlib.redirect_stderr(io.StringIO()) as errors:
            for name in ('%00', '../../etc/passwd', '/etc/passwd'):
                with self.subTest(name=name):
                    self.assertIn(awd.request(self.web + '/download?name=' + name)[0], (400, 403, 404))
            self.assertEqual(errors.getvalue(), '')

    def test_non_ascii_auth_is_rejected(self):
        with contextlib.redirect_stderr(io.StringIO()) as errors:
            self.assertEqual(awd.request(self.judge, method='POST', body=b'{}', headers={'Authorization': 'Bearer \xe9'})[0], 401)
            self.assertEqual(errors.getvalue(), '')

    def test_judge_malformed_bodies_and_duplicate_scoring(self):
        headers = {'Authorization': 'Bearer ' + self.lab.token}
        for body in (b'{', b'\xff', b'x' * 4097):
            self.assertEqual(awd.request(self.judge, method='POST', body=body, headers=headers)[0], 400)
        body = json.dumps({'flag': self.lab.web_flag}).encode()
        for duplicate in (False, True):
            status, reply = awd.request(self.judge, method='POST', body=body, headers=headers)
            self.assertEqual(status, 200)
            self.assertEqual(json.loads(reply)['duplicate'], duplicate)
        status, reply = awd.request(self.judge.replace('/submit', '/score'), headers=headers)
        self.assertEqual(json.loads(reply), {'accepted': 1, 'points': 100})

    def test_tcp_commands_and_length_limit(self):
        for command, expected in [(b'PING\n', b'PONG\n'), (b'ECHO hello\n', b'hello\n'), (b'BAD\n', b'ERR command\n'), (b'A' * 1025 + b'\n', b'ERR too long\n')]:
            with socket.create_connection(self.lab.servers[1].server_address, timeout=3) as sock:
                with sock.makefile('rwb') as stream:
                    self.assertIn(b'simulator', stream.readline())
                    stream.write(command)
                    stream.flush()
                    self.assertEqual(stream.readline(), expected)

    def test_fixed_policy_rejects_symlink_escape(self):
        web = self.lab.directory / 'web'
        (web / 'policy.txt').write_text('fixed\n')
        (web / 'public/link').symlink_to(web / 'flag.txt')
        self.assertEqual(awd.request(self.web + '/download?name=link')[0], 403)
        self.assertEqual(awd.request(self.web + '/download?name=welcome.txt')[0], 200)


class LabLifecycleTests(unittest.TestCase):
    def test_cli_start_stop_and_existing_directory(self):
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as temp:
            command = [sys.executable, str(root / 'lab/run.py'), '--directory', str(Path(temp) / 'round'), '--web-port', '0', '--tcp-port', '0', '--judge-port', '0']
            proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                with selectors.DefaultSelector() as selector:
                    selector.register(proc.stdout, selectors.EVENT_READ)
                    self.assertTrue(selector.select(5), 'startup did not complete')
                info = json.loads(proc.stdout.readline())
                for target in info['targets']:
                    self.assertTrue(awd.check_target(target, 2)['ok'])
                proc.send_signal(signal.SIGINT)
                _, errors = proc.communicate(timeout=8)
                self.assertEqual(proc.returncode, 0, errors)
                self.assertEqual(errors, '')
                for target in info['targets']:
                    self.assertFalse(awd.check_target(target, 1)['ok'])
                result = subprocess.run(command, capture_output=True, text=True, timeout=5)
                self.assertEqual(result.returncode, 2)
                self.assertNotIn('Traceback', result.stderr)
            finally:
                if proc.poll() is None:
                    proc.kill()
                    proc.communicate(timeout=5)

    def test_port_conflict_closes_previously_bound_socket(self):
        with tempfile.TemporaryDirectory() as temp, socket.socket() as occupied:
            occupied.bind(('127.0.0.1', 0))
            occupied.listen()
            with socket.socket() as free:
                free.bind(('127.0.0.1', 0))
                web_port = free.getsockname()[1]
            with self.assertRaises(OSError):
                Lab(Path(temp) / 'round', web_port, occupied.getsockname()[1], 0)
            with socket.socket() as reusable:
                reusable.bind(('127.0.0.1', web_port))
