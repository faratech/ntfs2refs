//! An NTFS 1.2 (Windows NT 4.0) volume, read as the converter reads it.
use crate::ntfs12_volume as ntfs12;
use ntfs2refs::{ntfs_admission, ntfs_inspect, ntfs_internal, ntfs_namespace, ntfs_security};
use std::io::Cursor;

const PARTITION: u64 = 16 * 1024 * 1024;

fn inspect(image: &[u8]) -> ntfs_inspect::NtfsInspection {
    ntfs_inspect::inspect(&mut Cursor::new(image), image.len() as u64)
        .unwrap_or_else(|error| panic!("{error:#}"))
}

fn codes(report: &ntfs_inspect::NtfsInspection) -> Vec<(String, Option<u64>)> {
    report
        .blockers
        .iter()
        .map(|b| (b.code.clone(), b.file_record_number))
        .collect()
}

/// What only a version the converter does not read, or a layout it does not
/// know, would block; the rest (native and frozen-source checks still to be
/// made) every inspection reports.
const LAYOUT_BLOCKERS: [&str; 3] = [
    "unsupported_ntfs_version",
    "metadata_role_ancestry_unresolved",
    "logical_stream_hash_unavailable",
];

#[test]
fn an_ntfs_12_volume_is_read_as_nt4_laid_it_out() {
    let volume = ntfs12::volume(PARTITION, 2048, (1, 2));
    let image = volume.image();
    let report = inspect(&image);
    assert_eq!(report.volume_version.as_deref(), Some("1.2"));
    let blocked: Vec<_> = codes(&report)
        .into_iter()
        .filter(|(code, _)| LAYOUT_BLOCKERS.contains(&code.as_str()))
        .collect();
    // $BadClus's $Bad is the one stream not hashed, as on every volume.
    assert_eq!(
        blocked,
        [("logical_stream_hash_unavailable".to_owned(), Some(8))],
        "{:#?}",
        report.blockers
    );
    assert_eq!(
        report.allocation_reconciliation.as_ref().unwrap().status,
        ntfs_inspect::AllocationReconciliationStatus::ConsistentRawModel
    );
    let namespace = report.namespace_reconciliation.as_ref().unwrap();
    assert_eq!(
        namespace.status,
        ntfs_namespace::Status::ConsistentRawModel,
        "{}",
        namespace.detail
    );
    // No $Secure: every file's descriptor is its own.
    let security = report.security_reconciliation.as_ref().unwrap();
    assert_eq!(
        security.status,
        ntfs_security::Status::ConsistentRawModel,
        "{}",
        security.detail
    );
    assert_eq!(security.central_descriptors, 0);
    assert_eq!(security.legacy_descriptors, report.files.len());
    assert_eq!(security.bound_files, report.files.len());
    // As Windows requires of $MFT (lab n12-image: a resident $BITMAP there
    // made Windows 11 refuse record 0, NTFS event 55): its bitmap and data
    // are nonresident.
    let mft = report.files.iter().find(|f| f.record_number == 0).unwrap();
    for kind in [0x80, 0xb0] {
        let attribute = mft
            .attributes
            .iter()
            .find(|a| a.type_code == kind && a.name_utf16.is_empty())
            .unwrap();
        assert!(!attribute.resident, "{kind:#x}");
    }
    // The 48-byte $STANDARD_INFORMATION: no security ID.
    assert!(report.files.iter().all(|f| {
        f.standard_information
            .as_ref()
            .unwrap()
            .security_id
            .is_none()
    }));
    // The files, in the root and in SUB.
    let names = |number: u64| -> Vec<String> {
        report
            .files
            .iter()
            .find(|f| f.record_number == number)
            .unwrap()
            .names
            .iter()
            .map(|n| n.name.clone())
            .collect()
    };
    assert_eq!(names(16), ["README.TXT"]);
    assert_eq!(names(17), ["BIG.BIN"]);
    assert_eq!(names(18), ["SUB"]);
    assert_eq!(names(19), ["INNER.TXT"]);
    let big = report.files.iter().find(|f| f.record_number == 17).unwrap();
    assert_eq!(big.streams[0].logical_size, ntfs12::BIG_BYTES as u64);
    let mut content = Vec::new();
    ntfs_inspect::copy_plain_stream(&mut Cursor::new(&image), &report, 17, 1 << 20, &mut content)
        .unwrap();
    assert_eq!(content, ntfs12::big_content());
}

#[test]
fn nt4_system_records_have_their_own_roles() {
    let image = ntfs12::volume(PARTITION, 2048, (1, 2)).image();
    let report = inspect(&image);
    let role = |number: u64| {
        ntfs_admission::internal_role(
            &report,
            report
                .files
                .iter()
                .find(|f| f.record_number == number)
                .unwrap(),
        )
    };
    assert_eq!(role(9).as_deref(), Some("$Quota"));
    for number in 11..16 {
        assert_eq!(
            role(number).as_deref(),
            Some("reserved_mft_slot"),
            "{number}"
        );
    }
    for (number, name) in [
        (0, "$MFT"),
        (3, "$Volume"),
        (8, "$BadClus"),
        (10, "$UpCase"),
    ] {
        assert_eq!(role(number).as_deref(), Some(name));
    }
    // No $Extend: no internal index and no transaction metadata to verify.
    let indexes = ntfs_internal::verify(&mut Cursor::new(&image), &report).unwrap();
    assert!(indexes.indexes.is_empty() && indexes.replacement_supported);
    let scope = ntfs2refs::ntfs_transactions::inspect_scope(&report).unwrap();
    assert!(scope.transactional_records.is_empty() && scope.deferred_directories.is_empty());
}

/// The NT 4.0 layout is read only where $Volume states 1.2: the same volume
/// stating 3.0 lacks the $Secure and $Extend a 3.x volume has, and is refused.
#[test]
fn the_nt4_layout_is_not_taken_for_a_3x_volume() {
    let image = ntfs12::volume(PARTITION, 2048, (3, 0)).image();
    let report = inspect(&image);
    assert!(
        report
            .blockers
            .iter()
            .any(|b| b.code == "metadata_role_ancestry_unresolved"
                && b.file_record_number == Some(11)),
        "{:#?}",
        report.blockers
    );
    let security = report.security_reconciliation.as_ref().unwrap();
    assert_eq!(security.status, ntfs_security::Status::Rejected);
    assert!(ntfs_internal::verify(&mut Cursor::new(&image), &report).is_err());
}

/// The lab's volume: tests/support/ntfs12.rs's head of an NTFS 1.2 volume
/// for a partition of `N2R_NTFS12_PARTITION_BYTES`, written to
/// `N2R_NTFS12_IMAGE`, for `Invoke-DataVolumeAttempt.ps1 -Features ntfs12
/// -Ntfs12Image <it>` (lab/README.md).
#[test]
#[ignore = "writes the lab's NTFS 1.2 image where N2R_NTFS12_IMAGE says"]
fn write_the_lab_ntfs12_image() {
    let output = std::env::var("N2R_NTFS12_IMAGE").expect("N2R_NTFS12_IMAGE");
    let partition: u64 = std::env::var("N2R_NTFS12_PARTITION_BYTES")
        .expect("N2R_NTFS12_PARTITION_BYTES")
        .parse()
        .expect("a number of bytes");
    let volume = ntfs12::volume(partition, 0, (1, 2));
    std::fs::write(&output, &volume.head).unwrap();
    eprintln!(
        "{output}: {} bytes, the head of an NTFS 1.2 volume of {} clusters for a partition of {partition} bytes",
        volume.head.len(),
        volume.total_clusters
    );
}
