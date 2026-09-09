#!/bin/bash
# Purpose: exclusive EICAR fixture creation; owner [ASTRA]; updated 2026-09-09.
# Status: local syntax reviewed; lab pending. Source: UC-03 / T-15.
set -euo pipefail
export PATH=/usr/bin:/bin
[[ ${1:-} == --lab && $# == 3 ]] || { echo 'Usage: eicar_test.sh --lab EXISTING_MONITORED_DIRECTORY UNIQUE_TRIAL_KEY' >&2; exit 2; }
python3 -I -B - "$2" "$3" <<'PY'
import os, re, sys
path, trial_key = sys.argv[1:]
if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,95}', trial_key, re.ASCII):
    raise SystemExit('Trial key must be 1..96 ASCII letters/digits/underscore/hyphen')
filename = 'eicar_' + trial_key + '.com'
root = '/home/kali/SOCfile'
if path != root and not path.startswith(root + '/'):
    raise SystemExit('Directory must be the approved SOCfile root or a child')
parts = path.split('/')[1:]
if any(p in ('', '.', '..') or any(ord(c) < 32 for c in p) for p in parts):
    raise SystemExit('Non-canonical directory')
fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
try:
    for part in parts:
        nxt = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
        os.close(fd)
        fd = nxt
    out = os.open(filename, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
    try:
        os.write(out, br'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*')
    finally:
        os.close(out)
finally:
    os.close(fd)
print('EICAR fixture created without overwrite: ' + path + '/' + filename)
print('Verify VT/AR evidence independently; never reuse this trial key after deletion.')
PY
