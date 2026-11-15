"""Everything under one function of ours, over all steps or one: by step, by
leaf, by the callee just under it and by its callers.

stacks_under.py <stacks.txt> <function substring> [top] [label substring]
"""
import collections
import sys

path, wanted = sys.argv[1], sys.argv[2]
top = int(sys.argv[3]) if len(sys.argv) > 3 else 10
only = sys.argv[4] if len(sys.argv) > 4 else None
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


def is_function(name):
    return "::" in name and not name.split(":")[-1].isdigit()


def short(name):
    for prefix in ("n2r_win32::", "ntfs2refs::"):
        if name.startswith(prefix):
            name = name[len(prefix):]
    return name.split("<")[0][-70:]


total = 0
steps, leaves, under, callers = (collections.Counter() for _ in range(4))
for label, count, frames in stacks:
    step = labels.get(label, "?")
    if only and only not in step:
        continue
    names = [symbols.get(f, "?") for f in frames]
    # names[0] is the leaf; names[1:] run from the root to the nearest.
    chain = [n for n in names[1:] if is_function(n)]
    hits = [i for i, n in enumerate(chain) if wanted in n]
    if not hits:
        continue
    at = hits[-1]
    total += count
    steps[step] += count
    leaves[names[0]] += count
    under[short(chain[at + 1]) if at + 1 < len(chain) else "(itself)"] += count
    callers[" < ".join(short(n) for n in reversed(chain[max(0, at - 2):at]))] += count
print(f"== under {wanted}: {total / 100:.1f} s")
for title, counter in (("steps", steps), ("leaves", leaves), ("just under it", under), ("callers", callers)):
    print(f"-- {title}")
    for name, count in counter.most_common(top):
        print(f"   {count / 100:7.1f}  {name[:200]}")
