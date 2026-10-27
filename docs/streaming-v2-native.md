# Streaming-payload v2 native fixture

The next conversion case is a separate VM,
`ntfs2refs-streaming-v2-20261027`, ID
`2401593c-4b30-472e-9b6d-c9534cbaa599`, under
`.lab/hyperv/streaming-v2-20261027`. It has fixed 4 GiB RAM, four CPUs and no
NIC. Earlier VMs/checkpoints remain unchanged, including the passed beta OFF
at `cb6a32e9-f237-4d3f-a807-d97fc73f73a1`.

The OS disk is a new writable differencing child of the immutable installed
Windows archive, rather than another full archive copy. Data disks are fresh
independent VHDX files with no parents. This shares an OS dependency; it does
not share writable data media or establish independent physical failure domains.
The parent content hash was checked before and after provisioning:
`38483cb91279b90b6a053098d7b62903c18ea3873ab9023f382bb70ff545fe87`.
Hyper-V automatically added two file-generic-read ACL grants, for
`S-1-5-83-0` and the recorded capability SID. Rule comparison found no removed
rules or owner/group change; no manual ACL restoration was attempted. The
before/after descriptors and actual delta are retained with the fixture.

Readiness observed Windows 11 26300.9457 and refs.sys SHA-256
`3aa5d90958fc582c5f6567d2b970a3a37b3d4d80a4b58b5a8676943b7860d3c4`.
The new data roles were enrolled as RAW by actual device ID, size, partition
count, protection flags and SCSI LUN before formatting. Only those three owned
RAW disks were initialized. Source and shadow partitions are 52 GiB at offset
16 MiB, NTFS/64 KiB and ReFS/4 KiB respectively; the journal has independent
8 GiB virtual media. The shadow uses the existing native Dev Drive profile.

The source contains six user files totaling 4,295,229,458 logical bytes. Names
include `資料`, `Grüße.bin`, `café.txt` and `emoji-🦊.bin`; the large ordinary
uncompressed file is 4,294,967,297 bytes of zeros, SHA-256
`fbb82f7b353676bb562eb82157fcf0ea42c36492ca13ee56dbf82c08b6802c5c`.
Its ordinary sequential creation used no source extent moves or allocation
aging. Windows reported two source runs, retained verbatim in `fixture.json`.
All six file hashes and actual partition identities are recorded there.

This is a setup/readiness result, not native conversion or recovery
qualification. It exercises payload size and Unicode, not a large partition
capacity or nonzero 4 GiB payload. Thin-zero behavior and physical I/O are
separate from the logical source manifest. At fixture completion the conservative
lab counter was 213,674,191,598 bytes of its 223,338,299,392-byte budget, with
131,887,734,784 host bytes free; no reserve/budget was raised. Recheck capacity
before construction or new snapshots. Preserve partial worker/intent records;
do not redispatch a setup or conversion based only on an observer timeout.
