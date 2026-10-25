# Existing-tree conversion

**The four-file tree converted on its original partition and passed native ReFS
verification on Windows 11 build 26300.9457.** The source was populated before its extents were queried. No source
extent was moved or prearranged. Conversion runs inside `N2R-WIN11`; Hyper-V
supplies checkpoints and launches the guest executables.

The original 52 GiB partition has completed journaled reconstruction:

- 166 patches, 70,676,480 target bytes written.
- Complete resulting partition SHA-256:
  `da1e6cd1d676ce806e5937d934ab57ebed57fa6bf4c0f6593fb8d34859490e01`.
- Original NTFS partition SHA-256:
  `798926b2783a747f0d046d1010c9a8d2b109a900388117fcef46449c3abddd89`.
- Durable old/new journal: 141,388,738 bytes.
- Apply report SHA-256:
  `46d05b223e96003104456c4d6d9821b7f4a41ee22ff0ddd959e179dd1d280be5`.

These are measured local laboratory results from
`.lab/hyperv/tree-conversion/win11-20261025T013300511Z`. The ignored artifacts
are not distributed in this repository. The applied image matches the complete
frozen native ReFS shadow. Handoff then completed, and Microsoft's driver
opened the converted original on disk 1. The verifier matched all eight objects,
all four logical file hashes, EOF and storage-validity coverage, directory
names and identities, all four stored timestamps, attributes and both native
security descriptor views. It requested no payload writes. Rollback was closed
before this mount.

Native finish report SHA-256:
`3b17fc3f59ad5636784541b060c2f2c9fe09c7c95e6ec712f674de3e20ddc075`.
The guest shut down cleanly and saved checkpoint
`tree-converted-807a5941b83f4678a8c867b2b8374011`, ID
`711f7af4-5070-475e-835d-b357eaa880bd`. The workflow then restored
`installed-clean`, stopped with 4 GiB memory. Completion and cleanup are known.
This tree has not yet been qualified through a subsequent reboot, mutation
workload or interrupted conversion.

The source tree contains four ordinary files, three directories and the root,
with 512 KiB total logical payload. All four original payload locations collide
with the metadata-inclusive ReFS allocation view. They are explicitly relocated;
this case makes no claim of retaining their physical extents. The journal
contains the real replacement bytes.

`lab-tree-convert` now runs capture, durable journal/ticket preparation, offline
activation, apply, handoff and native verification as one owning-machine command.
Its fresh `--artifacts` directory records the independent recovery pins. Before
handoff, `lab-tree-reconstruct resume` or `rollback` can use that ticket and
journal. A controlled interruption exits 86 after the requested number of
durable target writes. Native interruption recovery has not yet been qualified.
The owning-guest `lab-tree-finalize recover` mode now combines a pinned journal
resume with finalization: it attempts handoff only after resume succeeds and
writes both outcomes to one durable report. This mode is for a target already
activated and persistently offline after an interrupted apply; its native
interruption behavior is not yet qualified.

The independent shadow builder also supports `--retain-eligible`. It attempts
placement only on the shadow, only where both allocation views permit it,
records actual mapping after a move, and leaves conflicting files relocated.
The measured placement and actual frozen shadow generate comparison requests
for retained, mixed, or relocation-only trees. This new placement path builds
but has not yet been qualified in a native mixed-placement case.

The executables remain restricted to enrolled laboratory disks and images.
General source admission, arbitrary existing volumes, low-scratch construction,
broader stream semantics and boot conversion remain unfinished.

## Ordinary-tree profile and interrupted host control

The versioned ordinary-file path independently reconstructed the same frozen
eight-object NTFS tree in a Windows-created ReFS 3.14 shadow. The four source
files were each placed at a different target extent; no source extent shaping
or source partition writes occurred. The shadow's complete partition SHA-256
was `893ddaae593f3b25a6e27fe125e6ee292747214e6be5ad2a92d5450c21db8453`.
The frozen shadow report matched the eight objects, source security and logical
content, and left the original NTFS image at SHA-256
`798926b2783a747f0d046d1010c9a8d2b109a900388117fcef46449c3abddd89`.

The in-guest `lab-tree-convert` prepared a 141,008,546-byte durable journal and
completed the patch apply. The host control process then exited without
exporting its terminal result. A separate elevated read-only probe found no
live converter process, the source persistently offline and writable, the
shadow offline and read-only, a successful durable apply report, and a zero
pre-handoff journal marker. The applied target's complete SHA-256 matched the
frozen shadow hash above. A pinned finalizer, dispatched as a task inside the
VM, completed the handoff and native verification. The journal marker became
`N2RHND01`; the original disk 1 mounted as ReFS. Microsoft's driver returned
all eight expected objects and four matching logical file hashes. The native
verifier requested no payload writes. The finish report SHA-256 is
`0b97d4603acd367186e9b630b14c8a22dda1d6cd0e095dbb238f67a4794567cd`.

The recorded artifacts are under
`.lab/hyperv/existing-tree-shadow/win11-20261025T023729434Z`,
`.lab/hyperv/existing-tree-shadow-steps/win11-20261025T025142276Z`, and
`.lab/hyperv/ordinary-tree-conversion/win11-20261025T030515888Z`.
This qualifies recovery from **loss of the host controller after a completed
apply**. It does not yet qualify interruption during a target write or general
NTFS source admission. The ordinary profile also has code paths for empty,
resident, fragmented and partial-cluster streams; this native case exercises
the versioned path on four cluster-aligned files.
