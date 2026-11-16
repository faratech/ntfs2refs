"""For every step: its wall-clock seconds from stderr.log beside the seconds
the profile has for it, so that time the sampler did not see shows.

stacks_cover.py <repo> <attempt> [minimum seconds]
"""
import collections
import re
import sys

repo, attempt = sys.argv[1], sys.argv[2]
minimum = float(sys.argv[3]) if len(sys.argv) > 3 else 10.0
base = f"{repo}/.lab/hyperv/attempts/{attempt}"
wall = {}
for line in open(f"{base}/stderr.log", encoding="utf-8", errors="replace"):
    if not line.startswith("timing-steps: "):
        continue
    parts = line.strip()[len("timing-steps: "):].split(" | ")
    for part in parts[1:]:
        match = re.match(r"(.*) ([0-9.]+)s$", part)
        if match:
            key = f"{parts[0]};{match.group(1)}"
            wall[key] = wall.get(key, 0.0) + float(match.group(2))
labels, sampled = {}, collections.Counter()
for line in open(f"{base}/stacks.txt", encoding="utf-8", errors="replace"):
    kind, _, rest = line.rstrip("\n").partition(" ")
    if kind == "L":
        number, _, text = rest.partition(" ")
        labels[int(number)] = text
    elif kind == "K":
        fields = rest.split(" ", 2)
        sampled[labels.get(int(fields[0]), "?")] += int(fields[1])
print(f"{'wall':>8} {'worker':>8} {'helpers':>8}  step")
for key, seconds in sorted(wall.items(), key=lambda kv: -kv[1]):
    if seconds < minimum:
        continue
    worker = sampled.get(key, 0) / 100
    helpers = sampled.get(key + " [helper threads]", 0) / 100
    flag = "  <-- unseen %.0f s" % (seconds - worker) if seconds - worker > 0.15 * seconds and seconds - worker > 5 else ""
    print(f"{seconds:8.1f} {worker:8.1f} {helpers:8.1f}  {key}{flag}")
