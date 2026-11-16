"""Step timings of two attempts side by side, largest differences first.

steps_compare.py <repo> <attempt before> <attempt after> [minimum seconds]
"""
import re
import sys

repo, before, after = sys.argv[1], sys.argv[2], sys.argv[3]
minimum = float(sys.argv[4]) if len(sys.argv) > 4 else 1.0


def steps(name):
    out, total = {}, None
    path = f"{repo}/.lab/hyperv/attempts/{name}/stderr.log"
    for line in open(path, encoding="utf-8", errors="replace"):
        if line.startswith("timing: TOTAL"):
            total = float(re.search(r"TOTAL ([0-9.]+)s", line).group(1))
        if not line.startswith("timing-steps: "):
            continue
        parts = line.strip()[len("timing-steps: "):].split(" | ")
        phase = parts[0]
        for part in parts[1:]:
            match = re.match(r"(.*) ([0-9.]+)s$", part)
            if match:
                key = f"{phase}: {match.group(1)}"
                out[key] = out.get(key, 0.0) + float(match.group(2))
    return out, total


a, total_a = steps(before)
b, total_b = steps(after)
print(f"TOTAL {total_a:.1f} s -> {total_b:.1f} s ({total_b - total_a:+.1f} s, {100 * (total_b - total_a) / total_a:+.1f} %)")
rows = sorted(((b.get(k, 0.0) - a.get(k, 0.0), k) for k in set(a) | set(b)), key=lambda r: r[0])
for delta, key in rows:
    if abs(delta) >= minimum:
        print(f"  {a.get(key, 0.0):7.1f} -> {b.get(key, 0.0):7.1f}  {delta:+7.1f}  {key}")
