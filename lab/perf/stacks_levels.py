"""One step's samples by the chain of our functions from a given depth.
stacks_levels.py <stacks.txt> <label> <from depth> <how many> [top]
"""
import collections, sys
path, want, start, span = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
top = int(sys.argv[5]) if len(sys.argv) > 5 else 14
labels, symbols, stacks = {}, {}, []
for line in open(path, encoding="utf-8", errors="replace"):
    kind, _, rest = line.rstrip("\n").partition(" ")
    if kind == "L":
        n, _, t = rest.partition(" "); labels[int(n)] = t
    elif kind == "S":
        n, _, t = rest.partition(" "); symbols[int(n)] = t
    elif kind == "K":
        f = [int(x) for x in rest.split()]; stacks.append((f[0], f[1], f[2:]))
def is_fn(n): return "::" in n and not n.split(":")[-1].isdigit()
def short(n):
    for p in ("n2r_win32::", "ntfs2refs::"):
        if n.startswith(p): n = n[len(p):]
    return n.split("<")[0][-56:]
c = collections.Counter(); total = 0
for label, count, frames in stacks:
    if labels.get(label) != want: continue
    names = [symbols.get(f, "?") for f in frames]
    chain = [short(n) for n in names[1:] if is_fn(n) and (n.startswith("n2r_win32::") or n.startswith("ntfs2refs::"))]
    c[" > ".join(chain[start:start + span])] += count; total += count
print(f"{total/100:.1f} s")
for k, v in c.most_common(top): print(f"{v/100:7.1f}  {k[:240]}")
