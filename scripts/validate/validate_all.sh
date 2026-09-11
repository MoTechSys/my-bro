#!/usr/bin/env bash
# Run every repository check. Must print ALL CHECKS PASSED before committing changes under wazuh/.
set -uo pipefail
shopt -s globstar nullglob
cd "$(dirname "$0")/../.." || exit 1
fail=0

echo "== 1. Wazuh rules / decoders / secrets =="
python3 scripts/validate/check_rule_ids.py || fail=1

echo; echo "== 2. ossec.conf snippets well-formed =="
for f in wazuh/manager/ossec.conf.d/*.xml wazuh/agents/*/ossec.conf.d/*.xml; do
  # Placeholders like <USER_NAME> and <YOUR_VIRUS_TOTAL_API_KEY> are intentional; neutralise for xmllint
  if sed -e 's/<USER_NAME>/USER_NAME/g' -e 's/<YOUR_VIRUS_TOTAL_API_KEY>/YOUR_VIRUS_TOTAL_API_KEY/g' "$f" | xmllint --noout -; then
    echo "ok   $f"
  else
    echo "FAIL $f"; fail=1
  fi
done

echo; echo "== 3. Shell scripts syntax =="
for f in wazuh/agents/linux/active-response/*.sh scripts/**/*.sh; do
  [ -f "$f" ] || continue
  if bash -n "$f"; then echo "ok   $f"; else echo "FAIL $f"; fail=1; fi
done

echo; echo "== 4. Python syntax =="
# Parse in memory: no predictable /tmp files, pycache, or splitting filenames.
if ! python3 - <<'PY'
import ast
from pathlib import Path
for directory in ('scripts', 'tests', 'wazuh'):
    for path in sorted(Path(directory).rglob('*.py')):
        ast.parse(path.read_text(encoding='utf-8'), filename=str(path))
        print('ok  ', path)
PY
then fail=1; fi

echo; echo "== 5. CDB lists format (key:value, no dup keys) =="
for f in wazuh/manager/lists/*; do
  dups=$(grep -v '^#' "$f" | grep -v '^\s*$' | cut -d: -f1 | sort | uniq -d)
  bad=$(grep -v '^#' "$f" | grep -v '^\s*$' | grep -vE '^[^:]+:[^:]+$' || true)
  if [ -z "$dups" ] && [ -z "$bad" ]; then echo "ok   $f"; else echo "FAIL $f dups=[$dups] bad=[$bad]"; fail=1; fi
done

echo; echo "== 6. Required handoff docs exist =="
for f in AI_AGENT_START_HERE.md README.md CHANGELOG.md docs/00_PROJECT_STATE.md docs/01_SOURCE_ANALYSIS.md docs/02_ARCHITECTURE.md docs/03_ROADMAP.md docs/04_ISSUES_LOG.md docs/DECISIONS.md; do
  if [ -f "$f" ]; then echo "ok   $f"; else echo "FAIL missing $f"; fail=1; fi
done

echo; echo "== 7. Local regression tests (not native lab acceptance) =="
# Bound execution and disable bytecode writes. Test fixtures stay inside the repo.
if ! timeout --kill-after=5s 180s python3 -B - <<'PY'
import sys
import unittest
suite = unittest.defaultTestLoader.discover('tests', pattern='test_*.py')
if suite.countTestCases() == 0:
    print('FAIL: no regression tests discovered', file=sys.stderr)
    sys.exit(1)
result = unittest.TextTestRunner(verbosity=1).run(suite)
sys.exit(0 if result.wasSuccessful() else 1)
PY
then fail=1; fi

echo
if [ $fail -eq 0 ]; then echo "ALL CHECKS PASSED"; else echo "SOME CHECKS FAILED"; exit 1; fi
