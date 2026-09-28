#!/usr/bin/env bash
# Read-only host inventory. Output can contain internal addresses and process arguments.
set -u
umask 077
out="${1:-triage-$(date +%Y%m%d-%H%M%S)}"
mkdir -- "$out" || exit 1
collect() {
  local name="$1"; shift
  if command -v "$1" >/dev/null 2>&1; then
    "$@" >"$out/$name.txt" 2>&1
    local result=$?
    printf '%s exit=%s\n' "$name" "$result" >>"$out/status.txt"
  else
    printf '%s unavailable: %s\n' "$name" "$1" >>"$out/status.txt"
  fi
}
collect date date -u
collect kernel uname -a
collect identity id
collect processes ps auxww
collect sockets ss -lntup
collect connections ss -ntup
collect disk df -h
collect mounts mount
collect services systemctl --no-pager --type=service --state=running
collect timers systemctl --no-pager list-timers --all
collect cron crontab -l
collect logins last -n 20
collect firewall nft list ruleset
collect iptables iptables -S
printf 'Evidence saved to %s (see status.txt for failures).\n' "$out"
