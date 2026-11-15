"""Outcomes of the lab attempts with a prefix, oldest first.

attempts.py <repo> <prefix> [skip]
"""
import glob
import json
import os
import sys

repo, prefix = sys.argv[1], sys.argv[2]
skip = int(sys.argv[3]) if len(sys.argv) > 3 else 0
rows = []
for d in glob.glob(os.path.join(repo, ".lab", "hyperv", "attempts", prefix + "-*")):
    f = os.path.join(d, "verdict.json")
    name = os.path.basename(d)
    if not os.path.exists(f):
        rows.append((os.path.getctime(d), name, "running", ""))
        continue
    v = json.load(open(f, encoding="utf-8-sig"))
    c = v.get("check") or {}
    extra = ""
    if c:
        extra = f"check exit {c.get('exit')} {c.get('seconds')}s agrees {c.get('agrees')} same {c.get('named_the_same_refusal')}"
    changed = (v.get("source") or {}).get("partition_bytes_changed_by")
    if changed:
        extra += f" | length {int(changed):+d}"
    error = (v.get("converter") or {}).get("error") or ""
    if error and "refus" in str(v.get("outcome")):
        extra += " | " + error[:150]
    if v.get("error"):
        extra += " | harness: " + str(v["error"])[:200]
    rows.append((os.path.getctime(d), name, v.get("outcome"), extra))
for _, name, outcome, extra in sorted(rows)[skip:]:
    print(f"{name:36} {outcome:30} {extra}")
