#[allow(
    dead_code,
    reason = "Shared fixture module also supports other integration suites."
)]
use crate::support;

use ntfs2refs::ntfs_inspect::{
    FileInventory, MetadataRole as Role, MetadataRoleIssue as Issue, NtfsInspection, inspect,
};
use std::io::Cursor;

fn filename(name: &str, parent: u64, sequence: u16, namespace: u8, instance: u16) -> Vec<u8> {
    let units: Vec<u16> = name.encode_utf16().collect();
    let mut value = vec![0; 66 + units.len() * 2];
    value[..8].copy_from_slice(&(parent | (u64::from(sequence) << 48)).to_le_bytes());
    value[64] = units.len() as u8;
    value[65] = namespace;
    for (index, unit) in units.iter().enumerate() {
        value[66 + index * 2..68 + index * 2].copy_from_slice(&unit.to_le_bytes());
    }
    support::resident(0x30, "", &value, instance)
}

fn record(name: &str, parent: u64, directory: bool) -> Vec<u8> {
    support::record(
        &[filename(name, parent, 1, 1, 0)],
        if directory { 3 } else { 1 },
        1,
    )
}

fn image(records: &[(usize, Vec<u8>)]) -> Vec<u8> {
    let count = (records.iter().map(|(n, _)| n + 1).max().unwrap_or(0)).max(20);
    let mft_clusters = count.div_ceil(4);
    let size = (4 * 4096 + mft_clusters * 4096 + 4096).max(2 * 1024 * 1024);
    let mut bytes = vec![0; size];
    bytes[..512].copy_from_slice(&support::boot());
    bytes[40..48].copy_from_slice(&(size as u64 / 512).to_le_bytes());
    let mut mft_bitmap = vec![0; count.div_ceil(8)];
    for number in [0, 3, 5, 6]
        .into_iter()
        .chain(records.iter().map(|(n, _)| *n))
    {
        mft_bitmap[number / 8] |= 1 << (number % 8);
    }
    let runs = [0x12, mft_clusters as u8, (mft_clusters >> 8) as u8, 4, 0];
    let mft = support::record(
        &[
            support::nonresident(0x80, &runs, count as u64 * 1024, mft_clusters as u64),
            support::resident(0xb0, "", &mft_bitmap, 1),
        ],
        1,
        1,
    );
    let mut version = vec![0; 12];
    version[8] = 3;
    version[9] = 1;
    let volume = support::record(&[support::resident(0x70, "", &version, 0)], 1, 1);
    let bitmap = support::record(
        &[support::resident(
            0x80,
            "",
            &vec![0; (size / 4096).div_ceil(8)],
            0,
        )],
        1,
        1,
    );
    for (number, record) in [
        (0, mft),
        (3, volume),
        (5, record(".", 5, true)),
        (6, bitmap),
    ]
    .iter()
    .chain(records.iter())
    {
        let at = 4 * 4096 + number * 1024;
        bytes[at..at + 1024].copy_from_slice(record);
    }
    bytes
}

fn inspect_records(records: &[(usize, Vec<u8>)]) -> NtfsInspection {
    let bytes = image(records);
    let original = bytes.clone();
    let mut reader = Cursor::new(bytes);
    let length = reader.get_ref().len() as u64;
    let report = inspect(&mut reader, length).unwrap();
    assert_eq!(reader.into_inner(), original);
    assert!(!report.inventory_complete);
    for code in [
        "directory_indexes_unverified",
        "allocation_ownership_unverified",
    ] {
        assert!(report.blockers.iter().any(|blocker| blocker.code == code));
    }
    report
}

fn file(report: &NtfsInspection, number: u64) -> &FileInventory {
    report
        .files
        .iter()
        .find(|file| file.record_number == number)
        .unwrap()
}

fn assert_unresolved(report: &NtfsInspection, number: u64, issue: Issue) {
    let item = file(report, number);
    assert_eq!(item.metadata_role, Role::Unresolved);
    assert_eq!(item.metadata_role_issue, Some(issue));
    assert!(!item.is_metadata);
    assert!(report.blockers.iter().any(|blocker| {
        blocker.code == "metadata_role_ancestry_unresolved"
            && blocker.file_record_number == Some(number)
    }));
}

/// A file `compact /exe` left: its WOF reparse point as WOF writes it on
/// the disk (16 bytes of data), its unnamed stream and WofCompressedData.
fn wof_record(algorithm: u32) -> Vec<u8> {
    let mut point = Vec::new();
    point.extend_from_slice(&0x8000_0017u32.to_le_bytes());
    point.extend_from_slice(&16u16.to_le_bytes());
    point.extend_from_slice(&0u16.to_le_bytes());
    for value in [1u32, 2, 1, algorithm] {
        point.extend_from_slice(&value.to_le_bytes());
    }
    support::record(
        &[
            filename("wof-lzx.bin", 5, 1, 1, 0),
            support::resident(0x80, "", b"", 1),
            support::resident(0x80, "WofCompressedData", b"compressed chunks", 2),
            support::resident(0xc0, "", &point, 3),
        ],
        1,
        1,
    )
}

/// The reading `--check`, a conversion's check before its question and its
/// admission of the frozen source all begin with: a WOF file must come out
/// of it with its point retained, for the plain census to classify, not
/// stop it (lab, wof-plain: "a reparse point of tag 0x80000017 ... is not
/// one the converter recreates").
#[test]
fn the_reading_keeps_a_wof_file_for_the_plain_census() {
    for algorithm in 0..=3 {
        let report = inspect_records(&[(20, wof_record(algorithm))]);
        let wof = file(&report, 20);
        let point = wof.reparse.as_ref().expect("the WOF point is retained");
        assert_eq!(
            n2r_win32::reparse_layout::wof_file_algorithm(&point.buffer),
            Some(algorithm)
        );
        assert_eq!(wof.streams.len(), 2);
        // Nothing the reading reports of the file refuses it by its tag.
        assert!(
            !report
                .blockers
                .iter()
                .any(|blocker| blocker.file_record_number == Some(20)
                    && blocker.message.contains("0x80000017")),
            "{:?}",
            report.blockers
        );
    }
}

/// A cloud provider's placeholder that is wholly on the volume, as the
/// Cloud Files API leaves it: a cloud reparse point (tag 0x9000x01A) with
/// the provider's own bytes, its pinned mark, and its data.
fn cloud_record(tag: u32) -> Vec<u8> {
    let mut information = vec![0u8; 72];
    // ARCHIVE | REPARSE_POINT | PINNED.
    information[32..36].copy_from_slice(&0x8_0420u32.to_le_bytes());
    let mut point = Vec::new();
    point.extend_from_slice(&tag.to_le_bytes());
    point.extend_from_slice(&12u16.to_le_bytes());
    point.extend_from_slice(&0u16.to_le_bytes());
    point.extend_from_slice(b"provider-own");
    support::record(
        &[
            support::resident(0x10, "", &information, 3),
            filename("synced.txt", 5, 1, 1, 0),
            support::resident(0x80, "", b"the file's contents", 1),
            support::resident(0xc0, "", &point, 2),
        ],
        1,
        1,
    )
}

/// The reading `--check`, a conversion's check before its question and its
/// admission of the frozen source begin with: a cloud placeholder comes out
/// of it with its point retained, every byte of it, for the plain census to
/// classify, and nothing the reading reports of it refuses it by its tag.
#[test]
fn the_reading_keeps_a_cloud_placeholder_for_the_plain_census() {
    for tag in [0x9000_001au32, 0x9000_601a] {
        let report = inspect_records(&[(20, cloud_record(tag))]);
        let cloud = file(&report, 20);
        let point = cloud.reparse.as_ref().expect("the cloud point is retained");
        assert_eq!(point.tag(), tag);
        assert!(point.buffer.ends_with(b"provider-own"));
        assert_eq!(cloud.streams.len(), 1);
        assert!(
            !report.blockers.iter().any(|blocker| {
                blocker.file_record_number == Some(20)
                    && blocker.message.contains(&format!("{tag:#010x}"))
            }),
            "{:?}",
            report.blockers
        );
    }
}

/// An EFS-encrypted file as the raw reading sees it: the encrypted mark in
/// its standard information, an encrypted unnamed stream and its $EFS.
fn efs_record() -> Vec<u8> {
    let mut information = vec![0u8; 72];
    information[32..36].copy_from_slice(&0x4020u32.to_le_bytes());
    let mut data = support::resident(0x80, "", b"ciphertext", 1);
    // The attribute header's flags: encrypted.
    data[12..14].copy_from_slice(&0x4000u16.to_le_bytes());
    support::record(
        &[
            support::resident(0x10, "", &information, 3),
            filename("encrypted.txt", 5, 1, 1, 0),
            data,
            support::resident(0x100, "$EFS", &[0u8; 64], 2),
        ],
        1,
        1,
    )
}

/// The reading `--check`, a conversion's check before its question and its
/// admission of the frozen source begin with: what it reports of an EFS
/// file is all of a kind a run that makes the file plain settles for that
/// file (`ntfs_inspect::efs_blocker`), so nothing of it refuses the volume
/// before the plain census has classified the file.
#[test]
fn the_reading_reports_an_efs_file_only_as_efs() {
    let report = inspect_records(&[(20, efs_record())]);
    let blockers: Vec<_> = report
        .blockers
        .iter()
        .filter(|blocker| blocker.file_record_number == Some(20))
        .collect();
    assert!(
        blockers
            .iter()
            .any(|blocker| blocker.code == "ntfs_encryption"),
        "{blockers:?}"
    );
    for blocker in &blockers {
        assert!(
            ntfs2refs::ntfs_inspect::efs_blocker(&blocker.code, &blocker.message),
            "{blocker:?} is reported of an EFS file and is not settled as one"
        );
    }
    // Nothing else is settled as EFS's.
    assert!(!ntfs2refs::ntfs_inspect::efs_blocker(
        "unsupported_attribute",
        "Attribute type 0xd0 needs a preservation policy"
    ));
    assert!(!ntfs2refs::ntfs_inspect::efs_blocker(
        "logical_stream_hash_unavailable",
        "DATA attribute 1 has no complete logical hash: UnsupportedCompression"
    ));
}

#[test]
fn follows_nested_extend_ancestry_and_retains_every_stream() {
    let data = support::record(
        &[
            filename("ordinary-looking-name", 17, 1, 0, 0),
            support::resident(0x80, "", b"do not discard candidate metadata data", 1),
        ],
        1,
        1,
    );
    let report = inspect_records(&[
        (11, record("$Extend", 5, true)),
        (16, record("$RmMetadata", 11, true)),
        (17, record("$TxfLog", 16, true)),
        (18, data),
        (19, record("$Quota", 11, false)),
    ]);
    for number in 16..=19 {
        let item = file(&report, number);
        assert_eq!(item.metadata_role, Role::ExtendDescendantCandidate);
        assert!(item.is_metadata);
        assert_eq!(item.metadata_role_issue, None);
    }
    assert_eq!(file(&report, 11).metadata_role, Role::ReservedSystemRecord);
    assert_eq!(file(&report, 18).streams.len(), 1);
    assert!(file(&report, 18).streams[0].logical_sha256.is_some());
    assert!(
        !report
            .blockers
            .iter()
            .any(|b| b.code == "metadata_role_ancestry_unresolved")
    );
}

#[test]
fn dollar_names_and_fake_extend_directories_remain_outside_candidates() {
    let report = inspect_records(&[
        (11, record("$Extend", 5, true)),
        (16, record("$Extend", 5, true)),
        (17, record("$Quota", 16, false)),
        (18, record("$ObjId", 5, false)),
    ]);
    for number in 16..=18 {
        let item = file(&report, number);
        assert_eq!(item.metadata_role, Role::OutsideExtendCandidate);
        assert!(!item.is_metadata);
        assert_eq!(item.metadata_role_issue, None);
    }
}

#[test]
fn missing_stale_and_non_directory_parents_are_unresolved() {
    for (parent_record, name_attribute, issue) in [
        (None, filename("x", 19, 1, 1, 0), Issue::MissingParent),
        (
            Some(record("folder", 5, true)),
            filename("x", 19, 2, 1, 0),
            Issue::ParentSequenceMismatch,
        ),
        (
            Some(record("file", 5, false)),
            filename("x", 19, 1, 1, 0),
            Issue::ParentNotDirectory,
        ),
    ] {
        let mut records = vec![(16, support::record(&[name_attribute], 1, 1))];
        if let Some(parent) = parent_record {
            records.push((19, parent));
        }
        let report = inspect_records(&records);
        assert_unresolved(&report, 16, issue);
    }
}

#[test]
fn mixed_user_and_extend_hard_links_are_never_metadata_candidates() {
    // Two names, so a header count of two, whether the second is a hard link
    // or a DOS alias: the header counts every $FILE_NAME attribute.
    for (second_namespace, links) in [(1, 2), (2, 2)] {
        let mixed = support::record(
            &[
                filename("internal", 11, 1, 1, 0),
                filename("user-link", 5, 1, second_namespace, 1),
            ],
            1,
            links,
        );
        let report = inspect_records(&[(11, record("$Extend", 5, true)), (16, mixed)]);
        assert_unresolved(&report, 16, Issue::MixedAncestry);
    }
}

#[test]
fn hard_links_with_two_outside_paths_are_preserved_as_outside_candidates() {
    let linked = support::record(
        &[filename("a", 5, 1, 1, 0), filename("b", 17, 1, 1, 1)],
        1,
        2,
    );
    let report = inspect_records(&[(16, linked), (17, record("folder", 5, true))]);
    assert_eq!(
        file(&report, 16).metadata_role,
        Role::OutsideExtendCandidate
    );
    assert_eq!(file(&report, 16).names.len(), 2);
    assert_eq!(file(&report, 16).hard_link_count, 2);
}

#[test]
fn dos_aliases_count_in_the_header_link_count() {
    let pair = |links: u16| {
        support::record(
            &[
                filename("long name", 11, 1, 1, 0),
                filename("LONGNA~1", 11, 1, 2, 1),
            ],
            1,
            links,
        )
    };
    // The header counts both $FILE_NAME attributes. A count that leaves the
    // alias out, or a name the header does not count at all, is not a record
    // NTFS writes.
    let report = inspect_records(&[(11, record("$Extend", 5, true)), (16, pair(1))]);
    assert_unresolved(&report, 16, Issue::LinkCountMismatch);
    let alias_only = support::record(&[filename("ALIAS~1", 11, 1, 2, 0)], 1, 0);
    let report = inspect_records(&[(11, record("$Extend", 5, true)), (16, alias_only)]);
    assert_unresolved(&report, 16, Issue::LinkCountMismatch);

    let report = inspect_records(&[(11, record("$Extend", 5, true)), (16, pair(2))]);
    assert_eq!(file(&report, 16).hard_link_count, 2);
    assert_eq!(
        file(&report, 16).metadata_role,
        Role::ExtendDescendantCandidate
    );
    assert_eq!(file(&report, 16).names.len(), 2);
    assert!(report.blockers.iter().any(|b| b.code == "dos_short_name"));
}

#[test]
fn cycles_and_dependents_remain_unresolved() {
    let report = inspect_records(&[
        (16, record("a", 17, true)),
        (17, record("b", 16, true)),
        (18, record("c", 16, false)),
    ]);
    assert_unresolved(&report, 17, Issue::Cycle);
    assert_unresolved(&report, 16, Issue::AncestorUnresolved);
    assert_unresolved(&report, 18, Issue::AncestorUnresolved);
    let self_loop = inspect_records(&[(16, record("self", 16, true))]);
    assert_unresolved(&self_loop, 16, Issue::Cycle);
}

#[test]
fn incomplete_or_inconsistent_records_cannot_gain_a_candidate_role() {
    let mut extension = record("x", 11, false);
    extension[32..40].copy_from_slice(&(17 | (1u64 << 48)).to_le_bytes());
    let mut zero_sequence = record("x", 11, false);
    zero_sequence[16..18].fill(0);
    let mut mismatched_links = record("x", 11, false);
    mismatched_links[18..20].copy_from_slice(&2u16.to_le_bytes());
    for (candidate, issue) in [
        (extension, Issue::ExtensionRecord),
        (zero_sequence, Issue::ZeroSequenceNumber),
        (support::record(&[], 1, 0), Issue::MissingNames),
        (mismatched_links, Issue::LinkCountMismatch),
        (record("..", 11, false), Issue::InvalidName),
    ] {
        let report = inspect_records(&[(11, record("$Extend", 5, true)), (16, candidate)]);
        assert_unresolved(&report, 16, issue);
    }
}

#[test]
fn invalid_root_or_extend_anchor_does_not_authorize_descendants() {
    for invalid in [
        record("$EXTEND", 5, true),
        record("$Extend", 5, false),
        record("$Extend", 16, true),
    ] {
        let report = inspect_records(&[(11, invalid), (16, record("x", 11, false))]);
        assert_eq!(
            file(&report, 11).metadata_role_issue,
            Some(Issue::InvalidExtendAnchor)
        );
        assert_eq!(file(&report, 16).metadata_role, Role::Unresolved);
        assert!(!file(&report, 16).is_metadata);
    }
    let report = inspect_records(&[
        (5, record("wrong", 5, true)),
        (11, record("$Extend", 5, true)),
        (16, record("x", 11, false)),
    ]);
    assert_eq!(
        file(&report, 5).metadata_role_issue,
        Some(Issue::InvalidRootAnchor)
    );
    assert_unresolved(&report, 16, Issue::AncestorUnresolved);
}

#[test]
fn unsupported_reserved_directory_parent_is_not_treated_as_user_or_extend() {
    let report = inspect_records(&[
        (12, record("reserved", 5, true)),
        (16, record("x", 12, false)),
    ]);
    assert_eq!(file(&report, 12).metadata_role, Role::ReservedSystemRecord);
    assert_unresolved(&report, 16, Issue::AncestorUnresolved);
}

#[test]
fn bounded_iterative_walk_refuses_overdeep_ancestry_without_recursion() {
    let mut records = Vec::new();
    for number in 16..=4112 {
        records.push((
            number,
            record(
                "d",
                if number == 4112 { 5 } else { number as u64 + 1 },
                true,
            ),
        ));
    }
    let report = inspect_records(&records);
    assert_unresolved(&report, 4111, Issue::DepthLimit);
    assert_unresolved(&report, 16, Issue::AncestorUnresolved);
}

#[test]
fn legacy_reports_do_not_acquire_ancestry_evidence_when_deserialized() {
    let report = inspect_records(&[(16, record("x", 5, false))]);
    let mut value = serde_json::to_value(file(&report, 16)).unwrap();
    value.as_object_mut().unwrap().remove("metadata_role");
    value.as_object_mut().unwrap().remove("metadata_role_issue");
    // A legacy summary boolean is not evidence for a modern role.
    value["is_metadata"] = true.into();
    let restored: FileInventory = serde_json::from_value(value).unwrap();
    assert_eq!(restored.metadata_role, Role::NotClassified);
    assert_eq!(restored.metadata_role_issue, None);
}

#[test]
#[ignore = "requires N2R_NATIVE_NTFS_CONTROL pointing to the pinned full native control.raw"]
fn native_windows_control_classifies_extend_tree_and_keeps_user_inventory() {
    use sha2::{Digest, Sha256};
    use std::io::{Read, Seek, SeekFrom};
    let path = std::env::var_os("N2R_NATIVE_NTFS_CONTROL").expect("explicit native corpus path");
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.share_mode(1);
    }
    let mut source = options.open(path).unwrap();
    let metadata = source.metadata().unwrap();
    assert!(metadata.is_file());
    assert_eq!(metadata.len(), 1073741824);
    let mut hash = Sha256::new();
    let mut buffer = [0; 64 * 1024];
    loop {
        let count = source.read(&mut buffer).unwrap();
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
    }
    assert_eq!(
        hex::encode(hash.finalize()),
        "86573a248b1ba615940688d1a60014a74a997bff779faa51ce781899f2e94727"
    );
    source.seek(SeekFrom::Start(0)).unwrap();
    let report = inspect(&mut source, metadata.len()).unwrap();
    for number in 0..16 {
        assert_eq!(
            file(&report, number).metadata_role,
            Role::ReservedSystemRecord
        );
    }
    for number in 24..36 {
        let item = file(&report, number);
        assert_eq!(
            item.metadata_role,
            Role::ExtendDescendantCandidate,
            "record {number}"
        );
        assert_eq!(item.metadata_role_issue, None);
        assert!(item.is_metadata);
    }
    for number in 36..44 {
        let item = file(&report, number);
        assert_eq!(
            item.metadata_role,
            Role::OutsideExtendCandidate,
            "record {number}"
        );
        assert_eq!(item.metadata_role_issue, None);
        assert!(!item.is_metadata);
    }
    let linked = file(&report, 40);
    assert_eq!(linked.hard_link_count, 2);
    assert_eq!(linked.names.len(), 2);
    assert_eq!(linked.streams.len(), 2);
    assert!(
        linked
            .streams
            .iter()
            .all(|stream| stream.logical_sha256.is_some())
    );
    assert!(!report.inventory_complete);
    assert!(
        report
            .blockers
            .iter()
            .any(|b| b.code == "directory_indexes_unverified")
    );
    assert!(
        report
            .blockers
            .iter()
            .any(|b| b.code == "allocation_ownership_unverified")
    );
    assert!(
        !report
            .blockers
            .iter()
            .any(|b| b.code == "metadata_role_ancestry_unresolved")
    );
}
