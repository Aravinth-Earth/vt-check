#!/usr/bin/env bash
# Run the same gates catalog admission runs, plus the unit tests.
# Usage: ./scripts/gates.sh
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1

fail=0

echo "== pytest =="
if [ -x .venv/bin/python ]; then
  .venv/bin/python -m pytest -q || fail=1
else
  python3 -m pytest -q || fail=1
fi

if command -v hermes >/dev/null 2>&1; then
  echo
  echo "== hermes plugins doctor =="
  # requires_env gates loading, so give the gates a throwaway value; nothing leaves the machine.
  VT_API_KEY="${VT_API_KEY:-dummy-for-gates}" hermes plugins doctor ./plugin --ci || fail=1

  echo
  echo "== hermes plugins validate (catalog CI parity) =="
  VT_API_KEY="${VT_API_KEY:-dummy-for-gates}" hermes plugins validate ./plugin || fail=1
else
  echo
  echo "note: 'hermes' not on PATH — skipped doctor + validate"
fi

echo
if [ "$fail" -eq 0 ]; then
  echo "GATES: PASS"
else
  echo "GATES: FAIL"
fi
exit "$fail"
