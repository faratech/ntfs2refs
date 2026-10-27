# Native SHA-256 for streaming source scans

The i9-9900K laboratory host reports no x86 SHA CPU feature. The pinned
sha2 0.10 implementation selects its software compression path on this CPU.
The running streaming candidate 3 retains its original source/binary pins;
it has not been replaced or restarted for this optimization.

The Rust Win32 boundary now wraps Microsoft's CNG SHA-256 Primitive Provider.
It owns each provider/hash with RAII, propagates every hashing error, and reads
every requested byte with exact reads and a fixed 1 MiB buffer. Windows owns
the hash object's storage; the hash is destroyed before its provider closes.
There is no alternate digest format, sampled scan, zero-range shortcut,
permission change, new filesystem writer or native dependency distribution.
The documented API contracts are
[creation](https://learn.microsoft.com/windows/win32/api/bcrypt/nf-bcrypt-bcryptcreatehash),
[update](https://learn.microsoft.com/windows/win32/api/bcrypt/nf-bcrypt-bcrypthashdata)
and [finish](https://learn.microsoft.com/windows/win32/api/bcrypt/nf-bcrypt-bcryptfinishhash).

`lab-hash-backends` measured an existing ordinary 1,073,741,824-byte NTFS raw
corpus image, opened read-only with competing writes/deletion excluded. The
entire file was read independently by both implementations. Both produced its
previously pinned SHA-256:
`fa41633393c0ea6e32e03053fe8a0e5ffb3d3fd2f3e201be3b38eab4437058d1`.

| Backend | Seconds |
| --- | ---: |
| Microsoft Primitive Provider | 2.2667969 |
| Rust sha2 | 3.7650327 |

This is about 1.66 times faster in this single host observation. It is not a
guest or end-to-end timing claim, nor a claim about other CPUs or storage.
Native ran first; caching/order and concurrent VM activity are uncontrolled.
The report is `.lab/performance/sha256-backends-20261027T181612602Z.json`,
SHA-256 `580c313d4744711782f8ec10df1a41f2487f2e727ebcd826f544117078e3ba63`.

Only `experimental_streaming_tree_v2` full-image source and protected-target
bracket hashes select this backend: initial source freeze, admission recheck,
final target-preservation source recheck, and the before/after target hashes
around its protected native semantic observation. Both old profiles retain
their prior Rust path. Source exclusion,
full-image equality, identity checks and recovery barriers are unchanged.
Streaming V2 journal preparation also selects CNG for the full source/shadow
comparison hashes and the constructed full postimage hash. Its existing bounded
shadow worker constructs/destroys CNG handles on that worker; no native handle
crosses threads. Hashing errors propagate through the worker result and abort
preparation. Both complete source/shadow rechecks still use Rust sha2 and must
match, preserving an independent backend check before write authorization.
The scan order, byte counts, patch hashes, retained-range hashes, serialized
format, buffering bounds and all recovery digests remain unchanged. Legacy
comparisons continue to select Rust, including their worker. The host timing
above measures the native hasher, not this comparison or journal workflow.
This source change builds, but has no native conversion qualification yet.
No unit tests were added or run. The native streaming run already in progress
is evidence only for its original 98d02a4 producer.

Later retention planning reuses the two complete bitmap observations across
streaming V2 runs while no move was submitted and no mapping change observed.
Those cached views only select candidates and provide no-submit diagnostics.
Every submitted move still captures both fresh maps in the existing native
move routine. Any submitted/partial move or observed mapping change invalidates
the planning cache before the next source run. Legacy profiles recapture on
every call. Source retention, metadata reservation handling and final native/raw
target proofs are unchanged. This source/build optimization has not run in a VM;
the recovery producer was staged before it.
