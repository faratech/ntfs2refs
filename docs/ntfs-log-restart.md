# NTFS `$LogFile` restart evidence

`src/ntfs_log.rs` independently reads the unnamed `$DATA` stream of MFT record
2 through the existing checked NTFS mapping. Its initial profile accepts two
4 KiB LFS 1.1 `RSTR` restart pages. It validates all eight sector-tail update
sequence replacements per page, version/geometry, restart bounds, one `NTFS`
client, stream length, matching LSN/revision/flags, and the clean-dismount bit.
The researched [NTFS restart-page and restart-area layout](https://flatcap.github.io/linux-ntfs/ntfs/files/logfile.html)
supplies the field meanings; this remains version-specific format evidence.

On the Windows-created 1 GiB control image, both restart copies pass those
checks, have flag `0x0002`, current LSN `5265997`, and refer to a 5,013,504-byte
`$LogFile`. The ignored native-corpus test also corrupts a sector tail and
confirms rejection. The read-only report is
`.lab/development/ntfs-log-control.json`.

The actual-device freeze now attempts the same check after lock/dismount and
records the result or an explicit refusal. The evidence type has private
fields and cannot be reconstructed from a supplied JSON success flag. This
check does **not** replay all LFS records or prove the transaction and dirty
page tables empty. Source admission and conversion authority remain false.
