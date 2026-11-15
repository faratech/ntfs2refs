"""One step's samples split into the worker's and the helper threads', each by
leaf and by the converter's nearest functions.

stacks_split.py <stacks.txt> <label text, exact> [top] [frames]
"""
import collections
import sys

path, wanted = sys.argv[1], sys.argv[2]
top = int(sys.argv[3]) if len(sys.argv) > 3 else 12
depth = int(sys.argv[4]) if len(sys.argv) > 4 else 3
labels, symbols, stacks = {}, {}, []
for line in open(path, encoding="utf-8", errors="replace"):
    kind, _, rest = line.rstrip("\n").partition(" ")
    if kind == "L":
        number, _, text = rest.partition(" ")
        labels[int(number)] = text
    elif kind == "S":
        number, _, text = rest.partition(" ")
        symbols[int(number)] = text
    elif kind == "K":
        fields = [int(x) for x in rest.split()]
        stacks.append((fields[0], fields[1], fields[2:]))


def ours(name):
    return name.startswith("n2r_win32::") or name.startswith("ntfs2refs::")


def short(name):
    for prefix in ("n2r_win32::", "ntfs2refs::"):
        if name.startswith(prefix):
            name = name[len(prefix):]
    return name.split("<")[0][-70:]


groups = {}
for label, count, frames in stacks:
    if labels.get(label) != wanted:
        continue
    names = [symbols.get(f, "?") for f in frames]
    helper = any("observe_in_parallel" in n and "closure" in n for n in names[1:]) or any("thread::scoped" in n or "spawn_scoped" in n for n in names[1:])
    g = groups.setdefault("helpers" if helper else "worker", [0, collections.Counter(), collections.Counter()])
    g[0] += count
    g[1][names[0] if names else "?"] += count
    mine = [short(n) for n in names[1:] if ours(n)]
    g[2][" < ".join(reversed(mine[-depth:])) if mine else "(none of ours)"] += count
for name, (total, leaves, near) in sorted(groups.items()):
    print(f"== {wanted} / {name}: {total / 100:.1f} s")
    for leaf, count in leaves.most_common(top):
        print(f"   {count / 100:7.1f}  {leaf[:110]}")
    print("   -- nearest of ours")
    for chain, count in near.most_common(top):
        print(f"   {count / 100:7.1f}  {chain[:240]}")
