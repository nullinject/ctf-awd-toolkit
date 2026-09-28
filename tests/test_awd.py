import argparse
import contextlib
import http.server
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
import threading
import unittest
from unittest.mock import patch
import awd


class ToolkitTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.root = self.base / 'web'
        self.root.mkdir()
        (self.root / 'index.php').write_text('hello')
        self.cfg = {'state_dir': str(self.base / 'state'), 'flag_regex': r'flag\{[a-z]+\}'}

    def call(self, fn, **kwargs):
        with contextlib.redirect_stdout(io.StringIO()):
            return fn(argparse.Namespace(**kwargs), self.cfg)

    def test_baseline_detects_changes(self):
        target = self.base / 'baseline.json'
        self.call(awd.baseline, root=str(self.root), output=str(target), exclude=[])
        self.assertEqual(self.call(awd.diff, baseline=str(target), root=None), 0)
        (self.root / 'index.php').write_text('modified')
        self.assertEqual(self.call(awd.diff, baseline=str(target), root=None), 1)

    def test_backup_restore_roundtrip_and_no_overwrite(self):
        archive = self.base / 'backup.tar.gz'
        (self.root / 'external').symlink_to('/etc/passwd')
        self.call(awd.backup, root=str(self.root), output=str(archive), exclude=[])
        dest = self.base / 'restored'
        args = dict(archive=str(archive), destination=str(dest), sha256=awd.digest(archive), max_bytes=10000)
        self.call(awd.restore, **args)
        self.assertEqual((dest / 'data/index.php').read_text(), 'hello')
        self.assertFalse((dest / 'data/external').exists())
        with self.assertRaises(ValueError):
            self.call(awd.restore, **args)

    def test_restore_rejects_unsafe_archive(self):
        for name, kind in [('data/../../escape', tarfile.REGTYPE), ('data/link', tarfile.SYMTYPE)]:
            archive = self.base / 'bad.tar.gz'
            with tarfile.open(archive, 'w:gz') as t:
                m = tarfile.TarInfo(name)
                m.type = kind
                m.linkname = '/etc/passwd'
                t.addfile(m)
            with self.assertRaises(ValueError):
                self.call(awd.restore, archive=str(archive), destination=str(self.base / 'out'), sha256=None, max_bytes=10000)
            self.assertFalse((self.base / 'out').exists())

    def test_extract_deduplicates_full_match(self):
        self.cfg['flag_regex'] = r'flag\{([a-z]+)\}'
        f = self.base / 'flags.txt'
        f.write_text('flag{abc} flag{abc}\nflag{def}')
        self.call(awd.extract, files=[str(f)])
        with awd.database(self.cfg) as db:
            self.assertEqual(db.execute('SELECT flag FROM flags ORDER BY flag').fetchall(), [('flag{abc}',), ('flag{def}',)])

    def serve(self, handler):
        srv = http.server.ThreadingHTTPServer(('127.0.0.1', 0), handler)
        thread = threading.Thread(target=srv.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        return srv.server_port

    def test_http_health_and_redirect_not_followed(self):
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200 if self.path == '/' else 302)
                self.send_header('Location', 'http://127.0.0.1:1/')
                self.end_headers()
                self.wfile.write(b'healthy')
            def log_message(self, *args):
                pass
        port = self.serve(Handler)
        t = dict(name='local', host='127.0.0.1', port=port, protocol='http', contains='healthy')
        self.assertTrue(awd.check_target(t, 1)['ok'])
        t['path'] = '/redirect'
        self.assertEqual(awd.check_target(t, 1)['status'], 302)
        self.assertFalse(awd.check_target(t, 1)['ok'])

    def test_submission_success_and_ambiguous_result(self):
        received = []
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
                received.append(body)
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'{"success":true}' if body['flag'] == 'flag{abc}' else b'{"success":false}')
            def log_message(self, *args):
                pass
        port = self.serve(Handler)
        self.cfg['submission'] = {'url': f'http://127.0.0.1:{port}/submit', 'success_json_field': 'success', 'interval_seconds': .1}
        with awd.database(self.cfg) as db:
            db.executemany('INSERT INTO flags(flag) VALUES (?)', [('flag{abc}',), ('flag{def}',)])
        self.call(awd.submit, send=False, limit=20)
        self.assertEqual(received, [])
        with patch.dict(os.environ, {'AWD_TOKEN': 'test-token'}):
            self.assertEqual(self.call(awd.submit, send=True, limit=20), 1)
            self.call(awd.submit, send=True, limit=20)
        self.assertEqual(len(received), 2)
        with awd.database(self.cfg) as db:
            self.assertEqual(db.execute('SELECT state FROM flags ORDER BY flag').fetchall(), [('accepted',), ('review',)])


if __name__ == '__main__':
    unittest.main()
