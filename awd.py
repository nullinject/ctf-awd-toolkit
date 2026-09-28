#!/usr/bin/env python3
"""Local-first tools for explicitly authorized CTF AWD environments."""
import argparse
import concurrent.futures
import datetime as dt
import hashlib
import http.client
import json
import os
from pathlib import Path, PurePosixPath
import re
import socket
import sqlite3
import stat
import sys
import tarfile
import time
import urllib.parse


def emit(value):
    print(json.dumps(value, ensure_ascii=False, sort_keys=True), flush=True)


def config(path):
    cfg = json.loads(Path(path).read_text())
    if not isinstance(cfg, dict):
        raise ValueError('配置必须是 JSON 对象')
    return cfg


def request(url, timeout=3, method='GET', body=None, headers=None):
    # Intentionally no redirect following or environment proxy inheritance.
    u = urllib.parse.urlsplit(url)
    if u.scheme not in ('http', 'https') or not u.hostname or u.username or u.password or u.fragment:
        raise ValueError('URL 必须为 http(s)，且不含凭据或 fragment')
    cls = http.client.HTTPSConnection if u.scheme == 'https' else http.client.HTTPConnection
    conn = cls(u.hostname, u.port, timeout=timeout)
    try:
        conn.request(method, urllib.parse.urlunsplit(('', '', u.path or '/', u.query, '')), body, headers or {})
        res = conn.getresponse()
        data = res.read(1024 * 1024 + 1)
        if len(data) > 1024 * 1024:
            raise ValueError('响应超过 1 MiB 上限')
        return res.status, data
    finally:
        conn.close()


def check_target(target, timeout):
    start = time.monotonic()
    out = {'name': target['name'], 'ok': False}
    try:
        host, port = target['host'], int(target['port'])
        proto = target['protocol']
        if proto == 'tcp':
            with socket.create_connection((host, port), timeout):
                pass
            out['ok'] = True
            out['detail'] = 'TCP connect only; application health unverified'
        elif proto in ('http', 'https'):
            path = target.get('path', '/')
            if not path.startswith('/') or path.startswith('//'):
                raise ValueError('path 必须是以 / 开头的本地路径')
            if any(c in host for c in '/?#@'):
                raise ValueError('非法 host')
            authority = '[' + host + ']' if ':' in host else host
            status, data = request(f'{proto}://{authority}:{port}{path}', timeout)
            out['status'] = status
            out['ok'] = status in target.get('expected_status', [200]) and target.get('contains', '').encode() in data
        else:
            raise ValueError('protocol 仅支持 tcp/http/https')
    except (OSError, ValueError, http.client.HTTPException) as exc:
        out['error'] = str(exc)
    out['latency_ms'] = round((time.monotonic() - start) * 1000, 1)
    out['time'] = dt.datetime.now(dt.timezone.utc).isoformat()
    return out


def health(args, cfg):
    targets = cfg.get('targets', [])
    if not targets:
        raise ValueError('请先配置 targets 白名单')
    for t in targets:
        if not all(k in t for k in ('name', 'host', 'port', 'protocol')):
            raise ValueError('每个目标需要 name/host/port/protocol')
    while True:
        with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, min(int(cfg.get('workers', 8)), 32))) as pool:
            results = list(pool.map(lambda t: check_target(t, float(cfg.get('timeout', 3))), targets))
        for row in results:
            emit(row)
        if not args.watch:
            return 0 if all(r['ok'] for r in results) else 1
        time.sleep(args.watch)


def entries(root, excludes):
    for base, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = sorted(d for d in dirs if d not in excludes)
        for name in sorted(files + [d for d in dirs if (Path(base) / d).is_symlink()]):
            if name not in excludes:
                yield Path(base) / name


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def snapshot(root, excludes):
    root = root.resolve(strict=True)
    if not root.is_dir():
        raise ValueError('root 必须是目录')
    files = {}
    for p in entries(root, excludes):
        st = p.lstat()
        row = {'mode': stat.S_IMODE(st.st_mode), 'uid': st.st_uid, 'gid': st.st_gid}
        if p.is_symlink():
            row.update(type='symlink', target=os.readlink(p))
        elif stat.S_ISREG(st.st_mode):
            row.update(type='file', size=st.st_size, sha256=digest(p))
        else:
            row.update(type='special')
        files[p.relative_to(root).as_posix()] = row
    return {'version': 1, 'root': str(root), 'exclude': sorted(excludes), 'files': files}


def baseline(args, cfg):
    dest = Path(args.output).resolve()
    root = Path(args.root).resolve(strict=True)
    if dest.is_relative_to(root):
        raise ValueError('基线必须存放在被检查目录外')
    data = snapshot(root, set(args.exclude))
    with dest.open('x') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    emit({'baseline': str(dest), 'files': len(data['files'])})
    return 0


def diff(args, cfg):
    old = json.loads(Path(args.baseline).read_text())
    new = snapshot(Path(args.root or old['root']), set(old['exclude']))
    count = 0
    for name in sorted(old['files'].keys() | new['files'].keys()):
        a, b = old['files'].get(name), new['files'].get(name)
        if a != b:
            count += 1
            emit({'path': name, 'change': 'added' if a is None else 'deleted' if b is None else 'modified', 'before': a, 'after': b})
    emit({'changes': count})
    return int(count != 0)


def backup(args, cfg):
    root = Path(args.root).resolve(strict=True)
    dest = Path(args.output).resolve()
    if not root.is_dir() or dest.is_relative_to(root):
        raise ValueError('root 必须是目录，备份必须位于 root 之外')
    excludes = set(args.exclude)
    skipped = []
    def keep(info):
        if any(part in excludes for part in PurePosixPath(info.name).parts):
            return None
        # Store regular files/directories only; no links, devices, FIFOs.
        if not (info.isfile() or info.isdir()):
            skipped.append(info.name)
            return None
        return info
    with dest.open('xb') as f:
        with tarfile.open(fileobj=f, mode='w:gz', dereference=False) as archive:
            archive.add(root, arcname='data', filter=keep)
    emit({'backup': str(dest), 'sha256': digest(dest), 'skipped': skipped})
    return 0


def restore(args, cfg):
    dest = Path(args.destination).absolute()
    if dest.exists() or dest.is_symlink():
        raise ValueError('恢复目录必须不存在；先恢复到新目录，再检查切换')
    source = Path(args.archive)
    if args.sha256 and digest(source) != args.sha256.lower():
        raise ValueError('备份 SHA256 不匹配')
    with tarfile.open(source, 'r:gz') as archive:
        members = archive.getmembers()
        total = 0
        seen = set()
        for m in members:
            p = PurePosixPath(m.name)
            if p.is_absolute() or '..' in p.parts or not p.parts or p.parts[0] != 'data':
                raise ValueError('归档包含不安全路径')
            if not (m.isfile() or m.isdir()) or m.name in seen:
                raise ValueError('归档包含链接、特殊文件或重复路径')
            seen.add(m.name)
            total += m.size
            if total > args.max_bytes:
                raise ValueError('归档超出解压大小限制')
        dest.mkdir(mode=0o700, parents=False)
        # Manual extraction avoids ownership changes and all archive link semantics.
        for m in members:
            output = dest.joinpath(*PurePosixPath(m.name).parts)
            if m.isdir():
                output.mkdir(parents=True, exist_ok=True, mode=0o700)
            else:
                output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                with archive.extractfile(m) as src, output.open('xb') as dst:
                    import shutil
                    shutil.copyfileobj(src, dst)
                output.chmod(m.mode & 0o777)
        for m in reversed(members):
            if m.isdir():
                dest.joinpath(*PurePosixPath(m.name).parts).chmod(m.mode & 0o777)
    emit({'restored_to': str(dest / 'data'), 'bytes': total, 'ownership': 'current user; setuid/setgid removed'})
    return 0


def database(cfg):
    path = Path(cfg.get('state_dir', '.awd'))
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    db = sqlite3.connect(path / 'flags.sqlite3', timeout=5)
    db.execute('CREATE TABLE IF NOT EXISTS flags (flag TEXT PRIMARY KEY, state TEXT NOT NULL DEFAULT \'pending\', attempts INTEGER NOT NULL DEFAULT 0, last_status TEXT, created TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)')
    db.commit()
    return db


def extract(args, cfg):
    regex = re.compile(cfg['flag_regex'])
    db = database(cfg)
    added = 0
    try:
        for name in args.files:
            stream = sys.stdin if name == '-' else open(name, errors='replace')
            try:
                for line in stream:
                    for match in regex.finditer(line):
                        flag = match.group(0)
                        if not flag or len(flag) > 4096:
                            raise ValueError('flag 为空或超过 4096 字符；检查正则')
                        added += db.execute('INSERT OR IGNORE INTO flags(flag) VALUES (?)', (flag,)).rowcount
            finally:
                if stream is not sys.stdin:
                    stream.close()
        db.commit()
    finally:
        db.close()
    emit({'added': added})
    return 0


def queue(args, cfg):
    with database(cfg) as db:
        for state, count in db.execute('SELECT state, COUNT(*) FROM flags GROUP BY state'):
            emit({'state': state, 'count': count})
    return 0


def submit(args, cfg):
    s = cfg.get('submission', {})
    if not args.send:
        with database(cfg) as db:
            count = db.execute("SELECT COUNT(*) FROM flags WHERE state='pending'").fetchone()[0]
        emit({'dry_run': True, 'pending': count, 'url': s.get('url'), 'note': '核对接口及成功判定后，加 --send 才会发送'})
        return 0
    if not s.get('url') or not s.get('success_json_field'):
        raise ValueError('必须配置提交 URL 和 success_json_field')
    token = os.environ.get(s.get('token_env', 'AWD_TOKEN'))
    if not token:
        raise ValueError('未设置 token 环境变量')
    interval = max(float(s.get('interval_seconds', 1)), 0.1)
    headers = {'Content-Type': 'application/json', s.get('auth_header', 'Authorization'): s.get('auth_prefix', 'Bearer ') + token}
    failed = 0
    with database(cfg) as db:
        for _ in range(args.limit):
            # Commit the claim BEFORE network I/O; an interrupted/ambiguous attempt is never blindly retried.
            db.execute('BEGIN IMMEDIATE')
            row = db.execute("SELECT flag FROM flags WHERE state='pending' ORDER BY created, flag LIMIT 1").fetchone()
            if row is None:
                db.commit()
                break
            flag = row[0]
            db.execute("UPDATE flags SET state='inflight', attempts=attempts+1 WHERE flag=?", (flag,))
            db.commit()
            payload = dict(s.get('extra_fields', {}))
            payload[s.get('flag_field', 'flag')] = flag
            state, detail = 'review', 'unknown'
            try:
                status, body = request(s['url'], cfg.get('timeout', 3), 'POST', json.dumps(payload).encode(), headers)
                detail = 'HTTP ' + str(status)
                response = json.loads(body)
                value = response
                for key in s['success_json_field'].split('.'):
                    value = value[key]
                expected = s.get('success_json_value', True)
                if status in s.get('success_status', [200]) and type(value) is type(expected) and value == expected:
                    state = 'accepted'
            except (OSError, ValueError, KeyError, TypeError, http.client.HTTPException) as exc:
                detail = type(exc).__name__
            db.execute('UPDATE flags SET state=?, last_status=? WHERE flag=?', (state, detail, flag))
            db.commit()
            emit({'flag_id': hashlib.sha256(flag.encode()).hexdigest()[:12], 'state': state, 'detail': detail})
            failed += state != 'accepted'
            if state != 'accepted':
                break
            time.sleep(interval)
    return int(failed != 0)


def requeue(args, cfg):
    with database(cfg) as db:
        changed = db.execute("UPDATE flags SET state='pending' WHERE flag=? AND state IN ('review', 'inflight')", (args.flag,)).rowcount
    emit({'requeued': changed})
    return 0


PATTERNS = [
    ('php_dynamic_eval', re.compile(rb'\b(?:eval|assert)\s*\(', re.I)),
    ('php_encoded_payload', re.compile(rb'\b(?:base64_decode|gzinflate|str_rot13)\s*\(', re.I)),
    ('command_execution', re.compile(rb'\b(?:shell_exec|passthru|system|popen|proc_open)\s*\(', re.I)),
]


def audit(args, cfg):
    root = Path(args.root).resolve(strict=True)
    findings = 0
    for p in entries(root, set(args.exclude)):
        st = p.lstat()
        if p.is_symlink() or not stat.S_ISREG(st.st_mode):
            continue
        reasons = []
        if st.st_mode & stat.S_IWOTH:
            reasons.append('world_writable')
        if st.st_mode & (stat.S_ISUID | stat.S_ISGID):
            reasons.append('setuid_or_setgid')
        if p.suffix.lower() in ('.php', '.phtml', '.php5', '.inc') and st.st_size <= 2 * 1024 * 1024:
            data = p.read_bytes()
            reasons.extend(name for name, pattern in PATTERNS if pattern.search(data))
        if reasons:
            findings += 1
            emit({'path': str(p), 'indicators': reasons, 'verdict': 'manual review required'})
    emit({'findings': findings, 'note': '启发式检查，命中不等于恶意，未命中不等于安全'})
    return 0


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('-c', '--config', default='awd.json')
    sub = p.add_subparsers(dest='command', required=True)
    h = sub.add_parser('health', help='配置白名单内的 HTTP/TCP 巡检')
    h.add_argument('--watch', type=float, default=0)
    for name in ('baseline', 'backup', 'audit'):
        q = sub.add_parser(name)
        q.add_argument('root')
        q.add_argument('--exclude', action='append', default=['.git', '__pycache__', '.awd'])
        if name != 'audit':
            q.add_argument('-o', '--output', required=True)
    d = sub.add_parser('diff')
    d.add_argument('baseline')
    d.add_argument('--root')
    r = sub.add_parser('restore')
    r.add_argument('archive')
    r.add_argument('destination')
    r.add_argument('--sha256')
    r.add_argument('--max-bytes', type=int, default=2 * 1024**3)
    e = sub.add_parser('extract')
    e.add_argument('files', nargs='+', help='日志/文件，或 - 表示 stdin')
    sub.add_parser('queue')
    s = sub.add_parser('submit')
    s.add_argument('--send', action='store_true')
    s.add_argument('--limit', type=int, default=20)
    rq = sub.add_parser('requeue')
    rq.add_argument('flag')
    args = p.parse_args()
    try:
        if getattr(args, 'watch', 0) < 0 or getattr(args, 'limit', 1) < 1:
            raise ValueError('watch 不得为负，limit 必须为正')
        cfg = config(args.config) if args.command in ('health', 'extract', 'queue', 'submit', 'requeue') else {}
        return globals()[args.command](args, cfg)
    except KeyboardInterrupt:
        return 130
    except (OSError, ValueError, KeyError, tarfile.TarError, sqlite3.Error) as exc:
        emit({'error': str(exc)})
        return 2


if __name__ == '__main__':
    sys.exit(main())
