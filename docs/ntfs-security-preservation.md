# Windows security descriptor preservation

This describes the expanded ordinary-tree implementation at `fa6396f`.
Its public conversion `a8b54a6e` and cold-boot readback `d85aca0e` passed on the
independent NTFS security fixture `d813f2f2`. Auditing, mandatory labels,
inherited auditing, null DACLs and empty DACLs survived in-place conversion.
All 25 objects, 18 default and eight named stream hashes, seven EAs and three
sparse layouts matched. The seven security-file payloads also passed independent
SHA-256 readback without permission repair.

The run took 80.59 seconds on this VM. It is not a controlled performance
comparison. After reboot, all file IDs and data mappings matched the converted
state; all 25 kernel/API descriptor buffers also matched byte-for-byte.
See [the native evidence](../evidence/security-native-conversion-20261031.json).
Mutation, interruption/recovery, physical power loss and broader ACE/geometry
combinations remain unqualified for this exact build.

## Source evidence and views

Raw NTFS security reconciliation resolves each object's central or legacy
descriptor and preserves its self-relative bytes. The native collector queries
both `GetSecurityInfo` and `GetKernelObjectSecurity` on the same held handle.
Both requests use `0x1f`: owner, group, DACL, SACL and mandatory label.

The [Microsoft filesystem query contract](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fsa/0a9f223c-b258-4f61-8b59-92f970341400)
copies the stored SACL when SACL and LABEL information are requested together.
SACL-only queries can omit the mandatory-label ACE. These requests already
exist in schema 10; this change does not silently broaden an unrecorded mask.
The [security-information flags](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-information)
also define separate attribute/scope queries and a full-descriptor backup flag.

Stored NTFS and kernel descriptor semantics must match. The access-control API
can expose an inheritance projection that differs from stored bytes; the source
view records that projection separately and requires it to remain stable. The
target must reproduce both views. API output never overwrites the stored model.

## Equality and layout

`ntfs_attestation::same_security` compares control and RM-control values,
owner/group SIDs, and both ACLs' absent/null/present state, revision and ordered
complete ACE bytes. Only component offsets and padding are ignored. Conditional
and resource ACE application bytes stay opaque and are preserved, not evaluated.
An empty ACL with an actual header remains distinct from null and absent ACLs.

The native boundary independently validates self-relative layout before Windows
can follow pointers: header, aligned bounded offsets, SID lengths, ACL revisions
2/4, counts, ACE sizes, optional object GUIDs and SID/application spans. The
current profile permits known ACE types `0..3` and `5..21`; compound and unknown
forms remain refused. The descriptor bound is 65,536 bytes with 8,192 ACEs per
ACL. This is an implementation profile, not an unlimited Windows-format claim.

Native validity and descriptor-length checks follow safe bounds validation.
No validator result grants source-write or conversion authority.

## Native restoration

The owning shadow constructor holds canonical metadata handles with the needed
security rights and enables backup, restore and security privileges. It finishes
directory inheritance in parent order before restoring files. Payload is not
copied once per hard-link name, and all names share the same restored security.

`restore_acl_protection` handles DACL and SACL protection separately. Nonzero ACL
pointers refer only to validated ACL ranges. A null ACL uses a null pointer;
an absent ACL omits the corresponding ACL setter bit. Offset zero is never
interpreted as an ACL at the descriptor header. Unsupported protection requests
remain errors; absence is never replaced with a null ACL to obtain a match.

`BackupWrite` then receives the complete `BACKUP_SECURITY_DATA` descriptor with
security processing enabled and mandatory context cleanup. Actual kernel and
API readback must match the source semantics. Basic timestamps are restored
after inheritance, security and EA work; volume flush and final readback remain
part of completion. Accepted backup bytes alone do not prove fidelity.

## Observed fixture and remaining scope

The disposable NTFS fixture has eight identities: an audited directory and
seven files. Actual native source states include auditing plus a mandatory
label, null DACL, present empty DACL, inherited SACL and null SACL. Restricted
files are independently read with backup semantics; their ACLs are not relaxed.

Windows normalized a requested absent DACL to null and a requested empty SACL
to null while creating/restoring this **source fixture**. The manifest records
requested and actual states separately. Those files therefore provide no native
qualification for a genuinely absent source DACL or present empty source SACL.
Inheritance can likewise change requested control/ACE state before inventory;
conversion must preserve the actual frozen source, not the creation request.

No system audit policy is changed. Descriptor preservation is not evidence that
Windows generated particular audit events. This work also establishes no new
boot, geometry, arbitrary ACE-policy, interruption/recovery or power-loss support.
