"""For one step and one leaf: the frames nearest the leaf, heaviest first.
stacks_near.py <stacks.txt> <label> <leaf> [top] [frames]
"""
import collections, sys
path, wanted, leaf = sys.argv[1], sys.argv[2], sys.argv[3]
top = int(sys.argv[4]) if len(sys.argv) > 4 else 4
keep = int(sys.argv[5]) if len(sys.argv) > 5 else 6
labels, symbols, chains, total = {}, {}, collections.Counter(), 0
for line in open(path, encoding="utf-8", errors="replace"):
    kind, _, rest = line.rstrip("\n").partition(" ")
    if kind == "L":
        n, _, text = rest.partition(" "); labels[int(n)] = text
    elif kind == "S":
        n, _, text = rest.partition(" "); symbols[int(n)] = text
    elif kind == "K":
        f = [int(x) for x in rest.split()]
        if labels.get(f[0]) == wanted and symbols.get(f[2]) == leaf:
            near = [symbols.get(x, "?") for x in f[3:]][-keep:]
            chains[" > ".join(n.split("/src/")[-1][-60:] for n in near)] += f[1]
            total += f[1]
print(f"== {leaf} in {wanted}: {total / 100:.1f} s")
for chain, count in chains.most_common(top):
    print(f"  {count / 100:6.1f} s  {chain}")
