# Disposable larger-volume beta

The separate VM is `ntfs2refs-shadow-large-beta-20261027`, ID
`6c4793d2-cdee-468b-bf3b-1c11cae0b501`, under
`D:\code\ntfs2refs\.lab\hyperv\shadow-large-beta-20261027`.
It has independent copied/archive-derived disks, no NIC, four CPUs and fixed
4 GiB RAM. It does not inherit the frozen alpha's 8 GiB qualification. The
provisioning before/after records preserve all three earlier VMs/checkpoint sets.

Its actual guest is Windows 11 build 26300.9457 with `refs.sys` SHA-256
`3aa5d90958fc582c5f6567d2b970a3a37b3d4d80a4b58b5a8676943b7860d3c4`.
The source partition is 240 GiB NTFS with 64 KiB clusters; the independent
shadow is 240 GiB ReFS with 4 KiB clusters. Six ordinary files total 134,479,889
logical bytes, including empty/resident files and one 128 MiB file. Their creation
used no source extent moves or artificial allocation-aging writes. The large
file's observed source run begins at NTFS LCN `0x19e` for `0x800` clusters.

The clean imported checkpoint is `971ecdc3-8eca-4abb-a77e-e028e7e54f7f`.
The separate clean NTFS baseline checkpoint is recorded in `baseline.json`.
Checkpoint enumeration initially lagged creation; the completed checkpoint was
observed before resuming, with no duplicate checkpoint or provisioning restart.
PowerShell-5 array and native-stderr handling fixes are recorded in the helpers;
existing staged binaries/discovery were reused rather than repeating disk work.

Initial candidate SHA-256 was
`f90974bf65abef903ec3be76b4462120b5d144f5b061ce3efc498bec733640eb`.
`candidate-pins.json` binds its staging to source commit
`f61011795566928b6db5de2734ffe272d31a4c33`, with a dirty runtime source tree and
patch digest `d99591b5f26b887b513260cf01b8e89d114cb173fa86d40869a1053518d313e9`.
That dirty state is not a clean-commit build claim. The still-present change was
the capabilities-rendering edit in `src/main.rs`.

Public conversion run `592d72139d3443dead6f7f947209c494` terminated with task
result 1, no surviving converter process, and `unsupported disk/partition
geometry` during source-freeze qualification. Collected failure output and
actual terminal disk/task state are under
`refusal-592d72139d3443dead6f7f947209c494`. All four guest disks remained online
and writable; journal preparation and raw source reconstruction were not reached.

The refusal exposed a general TxF path calling the old fixed 52 GiB binding's
`volume_path()` on a diagnostic proxy. The corrected helper takes the root path
from the separately validated general binding; the original fixed-fixture
validator remains unchanged. New candidates must use fresh stage/run paths,
preserve earlier binaries/artifacts and confirm prior workers are terminal.
This report records a refusal and a code fix, not a successful conversion.
