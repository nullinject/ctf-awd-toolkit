# Publication verification — 2026-09-28

Verified locally on macOS with Python 3.12, using a clean export of the staged
source files (without local configuration, caches or private data).

```sh
python3 -m unittest discover -s tests -v
python3 scripts/verify_offline.py
bash -n scripts/triage.sh scripts/pwn-inspect.sh
```

Result: 14 tests passed. The documented offline demonstration also passed.
GitHub Actions is configured for Python 3.11 and 3.12 on Linux; its live status
is available in the repository Actions tab and is separate from these local results.

Secrets screening used `detect-secrets scan --no-verify` on the tracked file set,
plus a review of paths and credential patterns. No detector findings required remediation.

Dependency audit: not applicable; the toolkit uses the Python standard library.

## Limits

Real competition APIs and Linux host collection were not tested. The network audit guard covers Python socket operations, not arbitrary native processes.
This is a publication-readiness check, not a complete application security audit.
