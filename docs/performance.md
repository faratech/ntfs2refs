# Performance: what is measured, and how

Figures for the lab host (Intel i9-9900K, 16 logical processors, no SHA
instructions; 64 GB of memory; one NVMe disk that holds the VMs). They say
how one build compares with another on that host, not what another machine
will do.

## How a conversion is timed

Every run prints, to its error stream, a `timing:` line for each phase and a
`timing-steps:` line with the wall clock of each step, then the totals and
`memory: the run set aside … MiB at its start (…); its reservations peaked at
… MiB, of which … MiB it could not do without …; the process itself peaked at
… MiB of working set and … MiB of private memory`. Two counters in those lines say how much
of the per-object work ran on several threads: `objects at once (thread
time)` and `objects in turn`.

Memory is read from three more lines. `memory-steps:` follows each phase's
`timing-steps:` and gives, for every step that held a sixteenth of the
ledger or more, the most it could not do without and its three largest
reservations by place in the code. `memory-held:` gives the same for the
moment the whole run peaked. `memory-caches:` appears when caches were given
up because a reservation the run needed found no room. A reservation that
is the same share of the ledger on every volume is sized by the machine;
one that grows with the volume is what limits the number of files.

Two builds are compared with runs that have the host to themselves
(`-NoBoot`, one after the other, nothing else building), with the control
OS's scheduled drive optimisation off, which the harness does by itself
(issue 132: with it on, one build took 1,389, 1,451, 1,720 and 2,410 s). A
gate round's fixtures and data-volume cases share the host and are not such
runs. Its full run has the host to itself and usually is, but it starts the
moment the other sets end: one took 1,366 s where the same build, run again
by itself, took 1,306 s. When a total matters, it is taken by a run of its
own.

A step that changes ReFS metadata varies from run to run by a quarter or
more, because ReFS takes metadata changes one at a time: the metadata step
as a whole took 187 s and 156 s in two runs of one build. A difference of
less than about 30 s in that step is not a result until several runs agree.

The stack sampler (`-SampleStacks`) is for processor time. It does not see
inside a file-system call and slows the steps that are mostly such calls, so
steps are ranked by the `timing-steps:` lines. `lab\perf` has the scripts
that read both; `lab/README.md` lists them.

## The full Windows volume

143,552 objects, 22.9 GB, 112,609 short-name links, converted on the
reference VM (8 processors, 24 GB) to a Dev Drive.

| Build | Seconds | |
|---|---|---|
| 0.3.0-beta.1 | 1,815 | with the drive optimisation of issue 132 in it: not comparable with the rows below |
| after #143 | 1,389 | the first undisturbed total |
| after #145 | 1,373 | |
| after #152 | 1,312 | |
| the same converter without the retired lab code | 1,306 | no change to the converter's code; the difference is what two runs of one build differ by |

A volume of 75 objects on 50 GiB takes 19 s.

Where the 1,312 s go:

| Phase | Seconds | Largest steps |
|---|---|---|
| Building the ReFS volume | 396 | metadata 175, place extents 114, supply payloads 66, verify payloads 41 |
| Reading the source | 268 | observe source through Windows 99, compare raw and Windows views 43, scan MFT 28 |
| Capturing the result | 170 | compare shadow with source 88, walk shadow 51, derive source projection 18 |
| Applying | 152 | write changed ranges 72, verify journal and source 40, read back 33 |
| Journal | 79 | |
| Verifying the converted volume | 73 | short-name links 26, walk 24, contents 15 |
| The gate before the first write | 61 | 16 GB of working files hashed |
| Expected tree | 52 | derive source projection 39 |

The run reads 127.5 GB and writes 13.2 GB to convert 22.9 GB. Its memory
ledger peaked at 13,210 MiB of 14,091; 946,996 objects were worked on at
once and 34,519 in turn.

## 0.0.1: memory

Release 0.0.1 changes how a run uses memory, and these runs show what that
does. None of them had the host to itself: the host shares its memory with
other work, the lab VMs were held to 10 or 12 GB for it, and the totals are
not to be compared with the 24 GB rows above.

| Run | Machine | Seconds | Memory |
|---|---|---|---|
| The full Windows volume, converted and started from ReFS (`w12-full-vm4g`) | VM with 4 GB of RAM, no limit | 3,086 | reservations peaked at 1,625 of the 1,725 MiB the run was given; it could not do without 1,195 MiB |
| The same, held to the limit its estimate asks (`v1-win-1620`) | VM with 10 GB, `--memory-limit 1620` | 2,004 | needed 1,272 of 1,614 MiB |
| The same, in the final gate round (`rc3-full-system`) | VM with 12 GB, no limit | 1,506 | needed 3,149 MiB; nothing went beyond what the machine had |
| 100,000 files (`rc3-files-100k-mid`) | VM with 8 GB, `--memory-limit 1240` | 442 | needed 664 MiB; the process peaked at 956 MiB |
| 100,000 files, 3,000 MiB taken by another process in the middle (`rc3-files-100k-memory-taken`) | VM with 8 GB, no limit | 451 | 1.3 GB was the least the machine had free; converted, listing identical |
| 100,000 files, 5,000 MiB taken in the middle (`v2-takemem-100k`) and not (`v2-plain-100k`) | VM with 10 GB, no limit | 425 and 438 | the run gave up 67 caches and went 2,512 MiB beyond its budget on the page file, and was not slower for it |
| 20,000 files (`rc3-files-20k-limit`) | VM with 8 GB, `--memory-limit 480` | 105 | needed 279 MiB; the process peaked at 349 MiB |

The `memory:` line says what the run set aside at its start (its ceiling
under `--memory-limit`; without it, a starting share, since a run that fits
itself to the machine may hold more while memory is free), the peak of its
reservations and how much of that it could not do without (the rest are
caches it gives back when memory is short), and the process's own peak
working set and private memory, which is what to compare with a machine
(#167). Before 0.1.0 it read "peaked at 16,589 MiB of the 6,148 MiB it may
hold" for `rc3-full-system`, which looked like an overrun and was not.

## A partition on the Windows disk, through a restart

A 6 GiB partition of 505 objects beside C: on Windows Server 2025, working
storage on an NTFS disk of its own (`wb3-converts`): 451 s of preparation in
Windows, most of it the minimal Windows made from the installation media,
then 54 s away (two restarts and the conversion) before Windows was back
with the partition as ReFS.

## The cycle: checks and gates

`lab\Invoke-Checks.ps1` is what a commit has to pass as source code, and
`lab\Invoke-GateRound.ps1` what its build has to pass in the lab. On the lab
host, each from nothing:

| | Before the retired lab code was removed | After |
|---|---|---|
| Rust in the tree | 316,500 lines, 114 executables | 277,000 lines, 3 executables |
| Test executables built by a test run | 176, 111 of them without a test | 20 |
| All tests, built and run | 289 s | 116 s |
| of that, running the tests | 91 s | 11 s |
| Clippy | 78 s | 61 s |
| Executables in release mode | 73 s to compile all, 253 s to build the two that ship | 248 s to build all three |
| All checks | 11 min 45 s | 7 min 15 s |
| A gate round | 1 h 32 min, each set started by hand | 1 h 34 min, one command |

Most of what a check run still takes is one optimised build of the two
crates, about four minutes, and one unoptimised build for the tests. The
hashing crates are compiled with optimisation for the tests as well: without
that, one test took 28 of the 29 seconds the library's tests ran.

A gate round is as long as its three parts, which cannot share the host: the
fixtures beside the data-volume cases (41 min), the full Windows run by
itself (27 min), the Windows Server cases (26 min). The command saves the
attention, not the minutes; those come down as conversions get faster.
