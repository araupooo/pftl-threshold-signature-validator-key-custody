#!/usr/bin/env bash
# run_drill.sh -- one-command rerun of the whole custody drill.
#
# Runs the custody drill 5 times, measures costs, and compares the
# runs for determinism in their invariants. Logs land in logs/,
# simulated chain state in ledger/.
#
# Requirements: python3 with liboqs-python installed (for the ML-DSA
# path) and liboqs 0.16.0 discoverable (see scripts/oqs_ctypes.py).
# Set PY to choose the interpreter, e.g.:
#   PY=/path/to/venv/bin/python bash scripts/run_drill.sh
#
# Exit code is 0 only if all 5 runs pass, costs measure cleanly, and
# the runs agree on every invariant.
set -u
PY="${PY:-python3}"
cd "$(dirname "$0")/.." || exit 2
mkdir -p logs ledger
fail=0
for i in 1 2 3 4 5; do
  echo "--- drill run $i ---"
  "$PY" scripts/custody_drill.py "$i" ledger > "logs/run-$i.log" 2>&1 \
    || fail=1
done
echo "--- cost measurement ---"
"$PY" scripts/measure_costs.py > logs/costs.log 2>&1 || fail=1
echo "--- determinism comparison ---"
"$PY" scripts/compare_runs.py > logs/compare-runs.log 2>&1 || fail=1
cat logs/compare-runs.log
if [ "$fail" -eq 0 ]; then
  echo "RUN_DRILL: ALL GREEN"
else
  echo "RUN_DRILL: FAILURES (see logs/)"
fi
exit "$fail"
