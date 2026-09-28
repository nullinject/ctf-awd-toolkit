#!/usr/bin/env bash
# Static inspection only. Never executes the supplied binary.
set -u
if [ "$#" -ne 1 ]; then
  printf 'Usage: bash scripts/pwn-inspect.sh /path/to/binary\n' >&2
  exit 2
fi
case "$1" in
  /*) binary="$1" ;;
  *) binary="$PWD/$1" ;;
esac
if [ ! -f "$binary" ]; then
  printf 'Binary not found\n' >&2
  exit 2
fi
run() {
  printf '\n[%s]\n' "$1"
  if command -v "$1" >/dev/null 2>&1; then
    "$@"
  else
    printf 'Tool unavailable: %s\n' "$1"
  fi
}
run file "$binary"
run sha256sum "$binary"
run readelf -hW "$binary"
run readelf -lW "$binary"
run readelf -dW "$binary"
run readelf -sW "$binary"
printf '\nInspect GNU_STACK (NX), GNU_RELRO + BIND_NOW (RELRO), ELF type (PIE candidate), and stack_chk symbols (canary indicator). Indicators alone are not proof.\n'
