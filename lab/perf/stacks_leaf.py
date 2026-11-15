"""Samples whose leaf matches a substring: by step and by nearest callers.

stacks_leaf.py <stacks.txt> <leaf substring> [top] [depth]
"""
import collections
import sys

path, wanted = sys.argv[1], sys.argv[2]
top = int(sys.argv[3]) if len(sys.argv) > 3 else 15
depth = int(sys.argv[4]) if len(sys.argv) > 4 else 4
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
    return name.split("<")[0][-60:]


SKIP = ("sha2::", "digest::", "core::", "alloc::", "std::io::", "serde", "block_buffer", "hex::")
total = 0
steps, callers, pairs = (collections.Counter() for _ in range(3))
for label, count, frames in stacks:
    names = [symbols.get(f, "?") for f in frames]
    if wanted not in names[0]:
        continue
    step = labels.get(label, "?")
    chain = [n for n in names[1:] if is_function(n) and not n.startswith(SKIP)]
    total += count
    steps[step] += count
    near = " < ".join(short(n) for n in reversed(chain[-depth:]))
    callers[near] += count
    pairs[step.split(";")[-1][:40] + " | " + (short(chain[-1]) if chain else "?")] += count
print(f"== leaf {wanted}: {total / 100:.1f} s")
for title, counter in (("steps", steps), ("step | nearest of ours", pairs), ("callers", callers)):
    print(f"-- {title}")
    for name, count in counter.most_common(top):
        print(f"   {count / 100:7.1f}  {name[:230]}")
