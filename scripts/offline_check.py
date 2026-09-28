#!/usr/bin/env python3
"""Read-only prerequisite inventory. Does not install or access the network."""
import importlib.util
import json
import platform
import shutil
import sys

required = sys.version_info >= (3, 10) and importlib.util.find_spec('sqlite3') is not None
print(json.dumps({
    'core_ready': required, 'python': sys.version, 'os': platform.system(), 'architecture': platform.machine(),
    'tools': {name: shutil.which(name) for name in ['cc', 'gcc', 'gdb', 'readelf', 'file', 'tcpdump', 'ssh', 'scp', 'docker']},
    'optional_python': {name: importlib.util.find_spec(name) is not None for name in ['pwn', 'requests']},
    'note': 'Paths only: tool functionality, Linux ELF compatibility, VM images and offline package dependencies need separate verification.'
}, ensure_ascii=False, indent=2))
raise SystemExit(0 if required else 1)
