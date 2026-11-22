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

## 0.0.2: same checks, less work

Release 0.0.2 makes the same checks as before with less repeated work: rows
decoded once, the observations of the payload supply and of the walk on
helper threads, a capture compare that reads both disks ahead, and a
recovery that makes each identical check once (#140, #215 to #226). Before
is the build the pass started from (`b0-*`); after is the 0.0.2 candidate
(`g2b-*`, `g2g-*`). Each pair is the same volume on the same VM with the same
memory. Neither had the host to itself throughout (the host shares its
memory with other work), so read the differences to about a tenth.

| Run | Before | 0.0.2 | |
|---|---|---|---|
| The full Windows volume, converted and started from ReFS (VM with 12 GB) | 1,262 s | 1,127 s | 97.6 GB read before, 77.2 GB after; 13.2 GB written by both |
| 100,000 files, `--memory-limit 1240` (`files-100k-mid`, VM with 8 GB) | 442 s (0.0.1's final round) | 387 s | |

Where the full volume's time went:

| Phase | Before | 0.0.2 | Largest changes |
|---|---|---|---|
| Reading the source | 273 | 179 | object ids and transactions 19 → 0.2, observe source through Windows 78 → 61, compare raw and Windows views 52 → 35 |
| Capturing the result | 187 | 141 | compare shadow with source 93 → 60 |
| Building the ReFS volume | 283 | 302 | metadata steps, which vary from run to run by a quarter (above) |
| Applying | 197 | 191 | |

C:, converted in the machine's own recovery environment (Windows 11 build
26300, the same 22.9 GB volume, VM with 8 GB):

| Run | Seconds | |
|---|---|---|
| Converted (`g2b-c-convert`) | 1,107 | 19.4 minutes from the restart until Windows was back, on ReFS |
| Power cut halfway through the writes, recovered on the next start (`g2g-c-cut-apply-mid`) | 385 | the recovery alone; Windows was back, on ReFS, 7 min 8 s after the cut. Before the pass the same cut took 1 h 51 min from the cut until Windows was back (`runc-cut-apply-10`) |

The full volume stopped halfway through the writes (`-InterruptAt
apply-mid-ranges`, VM with 12 GB) and then recovered by `--recover`:

| Recovery | Before | 0.0.2 | Largest changes |
|---|---|---|---|
| Forward, to ReFS (`b0-cut-resume`, `g2r-cut-resume`) | 862 s | 329 s | changed ranges read back 4 times in 370 s before, 3 times in 129 s after; journal scans 254 → 82 s |
| Rollback, to NTFS (`b0-cut-rollback`, `g2r-cut-rollback`) | 1,182 s | 393 s | journal scans 501 → 81 s; changed-range checks 348 → 148 s |

Both recovered volumes started Windows (`RESUMED-BOOTED-ON-REFS`,
`ROLLED-BACK-BOOTED-ON-NTFS`).

## After 0.0.2: spare-RAM sizing, verify-once I/O and syscall elimination

A subsequent optimization pass (`perf/drastic-speed`, on Rust 1.100.0) fixed
spare-RAM workspace overcharges that collapsed parallelism under memory limits,
moved source/journal/read-back I/O onto multi-lane read-ahead and 4 MiB
`HashedBehind` pipelines, stored raw binary page chunks in `observation_pages`,
`paged_storage` and `expected.pages`, folded closing residual tail reads into
the closing shadow walk, fused attestation resource validation with comparison,
and eliminated redundant syscalls and bitmap queries under `--verify fast`
(leaving `--verify thorough` and all source-protection gates unchanged):

| Run | 0.0.2 | After | Change |
|---|---|---|---|
| The full Windows volume, converted and started from ReFS (`perf-final-full-system`, VM with 24 GB) | 1,127 s (1,337 s on `r10-base-full`) | 642 s (10.7 min) | −43% vs 0.0.2, −52% (2.08×) vs `r10-base-full`; `BOOTED-ON-REFS`, identical listing |
| 100,000 files, `--memory-limit 1240` (`perf-final-files-100k-mid`, VM with 24 GB) | 387 s (415 s on `g3b-files-100k-mid`) | 189 s (3.1 min) | −51% vs 0.0.2, 2.20× faster than `g3b-files-100k-mid`; 552 MiB required RAM, identical listing |
| Lived-in data volume, 23,137 objects (`perf-final-lived-in`, `-Check -Acceptance`) | — | 53 s | `check and run: agree`, all acceptance checks passed, identical listing |

Where the full volume's 642 s go:

| Phase | 0.0.2 | After | Largest changes |
|---|---|---|---|
| Building the ReFS volume | 302 | 168 | place extents 90 → 27 s (skip per-move bitmap ioctls under verify-once), supply payloads 83 → 35 s (reuse scan plan & skip redundant tail readback), restore times & attributes 24 → 6 s |
| Capturing the result | 141 | 124 | walk shadow (closing) 48 → 41 s (inline residual tail reads), compare shadow with source 54 → 52 s (8-lane prefetch + identical-chunk fast path) |
| Reading the source | 179 | 117 | observe source through Windows 61 → 18 s (skip non-directory `OpenFileById` + single-pass), compare raw and Windows views 35 → 19 s (fused validation + raw page chunks), fingerprint 8 → 4 s (coalesced lanes) |
| Journal preparation | 79 | 49 | multi-lane source prefetch, 4 MiB `HashedBehind`, read-ahead on COPY source lane, drop unused whole-journal hash |
| Applying | 191 | 47 | read back changed ranges 42 → 12 s (4 MiB `HashedBehind`), verify journal and source 39 → 10 s (QD=2 OLD digest), journal scan window 64 KiB → 4 KiB (16.4 GB → 0.23 GB) |
| Verifying the converted volume | 73 | 48 | check recovered alias links 26 s (trim redundant `GetVolumeInformationByHandleW`, `FSCTL_GET_REPARSE_POINT`, and duplicate `File*Info` queries), walk converted metadata 12 s, contents 5 s |
| Expected tree | 52 | 26 | raw binary chunks & single-pass `ExternalSort` |
| Gate before first write | 61 | 19 | |

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
