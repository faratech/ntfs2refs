"""Every step: seconds a thread waited, seconds it worked, and for the work
the converter's nearest functions. Threads are told apart by their outermost
function of ours.

stacks_busy.py <stacks.txt> [minimum seconds] [top] [frames]
"""
import collections
import sys

path = sys.argv[1]
minimum = float(sys.argv[2]) if len(sys.argv) > 2 else 20.0
top = int(sys.argv[3]) if len(sys.argv) > 3 else 6
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

WAITS = ("ZwWaitForAlertByThreadId", "RtlWaitOnAddress", "ZwWaitForSingleObject", "NtWaitForSingleObject", "ZwWaitForMultipleObjects", "RtlSleepConditionVariableCS", "RtlSleepConditionVariableSRW", "ZwDelayExecution", "ZwWaitForWorkViaWorkerFactory")


def ours(name):
    return name.startswith("n2r_win32::") or name.startswith("ntfs2refs::")


def short(name):
    for prefix in ("n2r_win32::", "ntfs2refs::"):
        if name.startswith(prefix):
            name = name[len(prefix):]
    return name.split("<")[0][-64:]


steps = {}
for label, count, frames in stacks:
    names = [symbols.get(f, "?") for f in frames]
    mine = [short(n) for n in names[1:] if ours(n)]
    step = steps.setdefault(labels.get(label, "?"), {"wait": 0, "work": 0, "threads": collections.Counter(), "near": collections.Counter(), "leaf": collections.Counter()})
    if names and names[0] in WAITS:
        step["wait"] += count
        continue
    step["work"] += count
    step["threads"][mine[0] if mine else "(none of ours)"] += count
    step["near"][" < ".join(reversed(mine[-depth:])) if mine else "(none of ours)"] += count
    step["leaf"][names[0] if names else "?"] += count
for name, step in sorted(steps.items(), key=lambda kv: -kv[1]["work"]):
    if step["work"] / 100 < minimum:
        continue
    print(f"== {name}: worked {step['work'] / 100:.1f} s, waited {step['wait'] / 100:.1f} s")
    print("   threads: " + "; ".join(f"{t} {c / 100:.1f}" for t, c in step["threads"].most_common(4)))
    print("   leaves:  " + "; ".join(f"{t[:40]} {c / 100:.1f}" for t, c in step["leaf"].most_common(6)))
    for chain, count in step["near"].most_common(top):
        print(f"   {count / 100:7.1f}  {chain[:230]}")
