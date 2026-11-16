#!/usr/bin/env python3
"""compare_runs.py -- verify the 5 drill runs are deterministic in
their invariants.

Reads logs/run-*.log and ledger/invariants-run*.json and checks that
every run produced the same check counts (all passed, none failed)
and the same invariant booleans. Fresh test keys are generated per
run, so group-key and signature hashes legitimately DIFFER between
runs; only the invariants must match. That is the determinism claim
this pack makes: same structure, same verdicts, every run.

Usage: python3 scripts/compare_runs.py
Exit 0 iff all 5 runs agree on every invariant.
"""
import glob
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PACK = os.path.dirname(HERE)


def main():
    logs = sorted(glob.glob(os.path.join(PACK, "logs", "run-*.log")))
    print("runs found: %d %s" % (len(logs),
                                 [os.path.basename(p) for p in logs]))
    failures = []
    if len(logs) != 5:
        print("[FAIL] expected 5 run logs, found %d" % len(logs))
        return 1
    summaries = []
    for log in logs:
        text = open(log).read()
        m = re.search(r"checks: (\d+) passed, (\d+) failed", text)
        if not m:
            failures.append("%s: no checks summary line" % log)
            continue
        passed, failed = int(m.group(1)), int(m.group(2))
        summaries.append((log, passed, failed))
        print("[%s] %s: %d passed, %d failed"
              % ("PASS" if failed == 0 else "FAIL",
                 os.path.basename(log), passed, failed))
        if failed != 0:
            failures.append("%s: %d failed checks" % (log, failed))
        if "ALL CHECKS PASSED" not in text:
            failures.append("%s: missing ALL CHECKS PASSED" % log)
        if "RESULT: UNAVAILABLE" in text:
            failures.append("%s: run unavailable" % log)
        # Full SHA-256 hashes (64 hex) must be present in the log.
        hashes = re.findall(r"\b[0-9a-f]{64}\b", text)
        print("  full 64-hex SHA-256 values present: %d" % len(hashes))
        if len(hashes) < 10:
            failures.append("%s: too few full hashes (%d)"
                            % (log, len(hashes)))
    if summaries:
        first = summaries[0][1]
        for log, passed, failed in summaries:
            if passed != first:
                failures.append("check counts differ: %s has %d, first "
                                "run has %d" % (log, passed, first))
    invs = sorted(glob.glob(os.path.join(PACK, "ledger",
                                         "invariants-run*.json")))
    print("invariant files found: %d" % len(invs))
    if len(invs) != 5:
        failures.append("expected 5 invariant files, found %d" % len(invs))
    parsed = []
    for path in invs:
        with open(path) as f:
            parsed.append(json.load(f))
    if parsed:
        ref = {k: v for k, v in parsed[0].items() if k != "run"}
        for doc in parsed[1:]:
            mine = {k: v for k, v in doc.items() if k != "run"}
            if mine != ref:
                failures.append("invariants differ between runs: "
                                "%s vs run %s"
                                % (doc.get("run"), parsed[0].get("run")))
        for key, val in sorted(ref.items()):
            print("  invariant %-42s = %s" % (key, val))
            if val is False and key not in (
                    "frost_refresh_revokes_old_shares",
                    "mldsa_reshare_revokes_old_shares"):
                failures.append("invariant %s is False" % key)
    print("failures: %d %s" % (len(failures), failures))
    print("=== DETERMINISM COMPARISON: %s ==="
          % ("ALL 5 RUNS AGREE" if not failures else "MISMATCH"))
    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(main())
