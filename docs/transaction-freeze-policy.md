# Native default transaction-manager freeze

The general source path can now capture native transaction observations in
the same process that locks, dismounts and persistently excludes the source.
`GeneralFrozenPartition::isolate_observed_ntfs` creates an opaque freeze
witness. Ordinary `isolate`, `reopen` and recovery handles cannot recreate it.

Before isolation, the default resource manager must return either complete
stable empty queries/listing or the explicit inactive result. After isolation,
the physically read-only observation must return inactive state. Other query
failures remain unresolved. Microsoft documents `ERROR_RM_NOT_ACTIVE` for an
unstarted manager in the [RM-query contract](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-fsctl_txfs_query_rm_information).
The [volume lock](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-fsctl_lock_volume)
must succeed before dismount and persistent exclusion.

The initial source policy additionally requires both clean frozen `$LogFile`
restart copies, the recognized root/default `$TXF_DATA` pair, empty `$Txf` and
`$Deleted` namespaces, and complete hashes for the default log streams. User
transaction metadata, secondary resource-manager namespaces and unknown or
deferred objects remain refused. This is a bounded default-manager policy,
not an implementation of TxF or CLFS log replay.

On October 25, 2026, the owning Windows 11 VM passed this path. Both writable
RM queries returned zero transactions, state 2, tail LSN 1 and current LSN
1024; the transaction list was empty. The post-freeze queries returned 6801.
The frozen source remained offline/read-only and its complete hash agreed
before and after native collection:
`1c645f220635e7002d580a0474b322cad7b6763dec1cf6632d7cc45e07b4b728`.
The report is under ignored local path
`.lab/hyperv/general-source-admission/win11-20261025T161000812Z/basis.json`,
SHA-256 `69d5c103bb5d2d349a988f711d19593ab7c467e681fbbbf279c1c20afc3b2b9c`.

The remount generated `System Volume Information\WPSettings.dat` and
`System Volume Information\IndexerVolumeGuid`. Their stored and kernel
security descriptors agree, but `GetSecurityInfo` returns a different view.
That original run refused both objects and did not receive a source certificate.
The new [paired-view implementation](paired-security-and-resident-data.md)
records the API projections separately and has reproduced both views on native
ReFS. Certificate-backed cutover remains a separate qualification step.
The complete protected native snapshots were separately captured in
`.lab/hyperv/general-source-admission/win11-20261025T162319458Z/basis.json`,
SHA-256 `f06c78ec217a19edf3d368eb3b463c0409d90ae9845d85b5f64c350e39da4835`.

The library now also has a target-preservation path that verifies the actual
ReFS tree, freezes that same shadow and binds its full image hash, measured
placement and retained-allocation checks. An admission certificate can be
created only after the original private source context and every remaining
gate pass. This new combined target/certificate path has not yet been
qualified natively. The general conversion CLI remains closed.
