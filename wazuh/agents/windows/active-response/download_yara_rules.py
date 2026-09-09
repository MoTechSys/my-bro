# Purpose: bounded verified VALHALLA demo download; owner [ASTRA]; 2026-09-09.
# Status: no network/native test in this session. Sources: UC-07 and T-15.
# Save to a protected staging directory; compile/review before deployment.
import argparse
import hashlib
import os
from pathlib import Path
import re
import urllib.parse
import urllib.request


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--expected-sha256', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if not re.fullmatch('[0-9a-fA-F]{64}', args.expected_sha256):
        parser.error('expected SHA-256 must come from an independently verified manifest')
    target = args.output.absolute()
    if target.exists() or target.is_symlink():
        parser.error('refusing existing output')
    for parent in target.parents:
        if parent.is_symlink() or getattr(os.lstat(parent), 'st_file_attributes', 0) & 0x400:
            parser.error('symlink/reparse parent refused')
    url = 'https://valhalla.nextron-systems.com/api/v1/get'
    body = urllib.parse.urlencode({'demo': 'demo', 'apikey': '1' * 64, 'format': 'text'}).encode()
    with urllib.request.urlopen(urllib.request.Request(url, data=body), timeout=20) as response:
        if response.geturl() != url:
            raise ValueError('unexpected redirect')
        data = response.read(20 * 1024 * 1024 + 1)
    if not data or len(data) > 20 * 1024 * 1024:
        raise ValueError('empty or oversized feed')
    if hashlib.sha256(data).hexdigest() != args.expected_sha256.lower():
        raise ValueError('feed hash mismatch')
    data.decode('utf-8', errors='strict')
    # Exclusive creation, never overwrite a live ruleset. ACLs protect staging.
    with target.open('xb') as stream:
        stream.write(data)
    print('Verified demo rules saved; compile and review before protected installation.')


if __name__ == '__main__':
    main()
