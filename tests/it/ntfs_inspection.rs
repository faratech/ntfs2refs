#![allow(
    clippy::single_range_in_vec_init,
    reason = "These vectors enumerate forbidden I/O ranges, not the values inside a range."
)]

use crate::support;

use ntfs2refs::ntfs_inspect::{
    InspectionLimits, LogicalHashStatus, NtfsInspection, inspect, inspect_boot_sector,
    inspect_with_limits,
};
use std::io::{Cursor, Read, Seek, SeekFrom};

#[test]
fn validates_standard_geometry() {
    let g = inspect_boot_sector(&support::boot(), 2 * 1024 * 1024).unwrap();
    assert_eq!(g.cluster_size, 4096);
    assert_eq!(g.file_record_size, 1024);
    assert_eq!(g.total_clusters, 512);
    assert_eq!(g.serial_number, 0x1122_3344_5566_7788);
}

#[test]
fn permits_only_a_whole_backup_sector_after_declared_volume() {
    let boot = support::boot();
    let size = 2 * 1024 * 1024;
    assert!(inspect_boot_sector(&boot, size + 512).is_ok());
    assert!(inspect_boot_sector(&boot, size + 1).is_err());
    assert!(inspect_boot_sector(&boot, size + 511).is_err());
}

#[test]
fn inventories_names_streams_and_allocations_without_mutation() {
    let bytes = support::image();
    let original = bytes.clone();
    let length = bytes.len() as u64;
    let mut reader = Cursor::new(bytes);
    let report = inspect(&mut reader, length).unwrap();
    assert_eq!(reader.into_inner(), original);
    assert_eq!(report.volume_version.as_deref(), Some("3.1"));
    assert_eq!(report.dirty, Some(false));
    assert_eq!(report.records_scanned, 5);
    assert_eq!(report.allocated_clusters, Some(8));
    assert_eq!(report.free_clusters, Some(504));
    let file = report.files.iter().find(|f| f.record_number == 16).unwrap();
    assert_eq!(file.hard_link_count, 2);
    assert_eq!(
        file.names
            .iter()
            .map(|n| n.name.as_str())
            .collect::<Vec<_>>(),
        ["hello.txt", "alias.txt"]
    );
    assert_eq!(file.streams.len(), 2);
    assert_eq!(file.streams[0].extents[0].physical_offset, Some(409600));
    assert_eq!(file.streams[0].logical_size, 17);
    assert_eq!(file.streams[1].name, "note");
    assert!(file.streams[1].resident_sha256.is_some());
    assert!(!report.inventory_complete);
    assert!(
        report
            .blockers
            .iter()
            .any(|b| b.code == "security_descriptors_unresolved")
    );
}

#[test]
fn rejects_truncated_image() {
    let mut bytes = support::image();
    bytes.truncate(1024);
    let length = bytes.len() as u64;
    assert!(
        inspect(&mut Cursor::new(bytes), length)
            .unwrap_err()
            .to_string()
            .contains("exceeds")
    );
}

#[test]
fn rejects_arithmetic_overflow() {
    let mut b = support::boot();
    b[40..48].copy_from_slice(&u64::MAX.to_le_bytes());
    assert!(
        inspect_boot_sector(&b, u64::MAX)
            .unwrap_err()
            .to_string()
            .contains("overflow")
    );
}

#[test]
fn rejects_invalid_cluster_and_record_exponents() {
    let mut b = support::boot();
    b[13] = 3;
    assert!(inspect_boot_sector(&b, 2 * 1024 * 1024).is_err());
    b = support::boot();
    b[64] = 0x80;
    assert!(inspect_boot_sector(&b, 2 * 1024 * 1024).is_err());
}

#[test]
fn rejects_out_of_volume_mft_and_non_ntfs() {
    let mut b = support::boot();
    b[48..56].copy_from_slice(&512u64.to_le_bytes());
    assert!(inspect_boot_sector(&b, 2 * 1024 * 1024).is_err());
    b = support::boot();
    b[3..11].copy_from_slice(b"MSDOS5.0");
    let refusal = inspect_boot_sector(&b, 2 * 1024 * 1024)
        .unwrap_err()
        .to_string();
    assert!(
        refusal.contains("not an NTFS") && refusal.contains("MSDOS5.0"),
        "{refusal}"
    );
}

#[test]
fn a_bitlocker_volume_is_refused_by_name_with_what_to_do() {
    // What the disk holds under an unlocked BitLocker volume that Windows
    // shows as NTFS.
    let mut b = support::boot();
    b[3..11].copy_from_slice(b"-FVE-FS-");
    let refusal = inspect_boot_sector(&b, 2 * 1024 * 1024)
        .unwrap_err()
        .to_string();
    assert!(
        refusal.contains("BitLocker")
            && refusal.contains("manage-bde -off")
            && !refusal.contains("not an NTFS"),
        "{refusal}"
    );
}

#[test]
fn rejects_torn_mft_record() {
    let mut b = support::image();
    b[4 * 4096 + 16 * 1024 + 510] ^= 1;
    let n = b.len() as u64;
    assert!(
        format!("{:#}", inspect(&mut Cursor::new(b), n).unwrap_err()).contains("torn file record")
    );
}

#[test]
fn rejects_non_progressing_attribute() {
    let mut b = support::image();
    let at = 4 * 4096 + 16 * 1024 + 56;
    b[at + 4..at + 8].fill(0);
    let n = b.len() as u64;
    assert!(
        format!("{:#}", inspect(&mut Cursor::new(b), n).unwrap_err())
            .contains("invalid attribute length")
    );
}

#[test]
fn refuses_unsupported_mft_list_profiles_instead_of_returning_partial_inventory() {
    let mut b = support::image();
    let at = 4 * 4096 + 56 + 72;
    b[at..at + 4].copy_from_slice(&0x20u32.to_le_bytes());
    let n = b.len() as u64;
    assert!(
        format!("{:#}", inspect(&mut Cursor::new(b), n).unwrap_err())
            .contains("attribute-list assembly is unsupported")
    );
}

#[test]
fn rejects_missing_mft_allocation_bit_for_root() {
    let mut b = support::image();
    let at = 4 * 4096 + 56 + 72 + 24;
    b[at] &= !(1 << 5);
    let n = b.len() as u64;
    assert!(
        format!("{:#}", inspect(&mut Cursor::new(b), n).unwrap_err())
            .contains("missing allocated root")
    );
}

#[test]
fn report_budget_counts_nested_inventory_and_refuses_partial_results() {
    let bytes = support::image();
    let length = bytes.len() as u64;
    let mut reader = Cursor::new(bytes.clone());
    let report = inspect(&mut reader, length).unwrap();
    assert_eq!(report.inventory_memory_limit_bytes, 64 * 1024 * 1024);
    assert!(report.inventory_memory_bytes > 4096);
    assert!(report.inventory_memory_bytes <= report.inventory_memory_limit_bytes);

    let error = inspect_with_limits(
        &mut reader,
        length,
        InspectionLimits {
            max_report_bytes: 4096,
            ..InspectionLimits::default()
        },
    )
    .unwrap_err();
    assert!(format!("{error:#}").contains("inventory report budget exceeded"));
    assert_eq!(reader.into_inner(), bytes);
}

#[test]
fn adequate_custom_report_budget_preserves_inventory_and_accounting() {
    let bytes = support::image();
    let length = bytes.len() as u64;
    let standard = inspect(&mut Cursor::new(&bytes), length).unwrap();
    let constrained = inspect_with_limits(
        &mut Cursor::new(&bytes),
        length,
        InspectionLimits {
            max_report_bytes: 1024 * 1024,
            ..InspectionLimits::default()
        },
    )
    .unwrap();
    assert_eq!(constrained.files.len(), standard.files.len());
    assert_eq!(constrained.blockers.len(), standard.blockers.len());
    assert_eq!(
        constrained.inventory_memory_bytes,
        standard.inventory_memory_bytes
    );
    assert!(!constrained.inventory_complete);
    assert!(constrained.inventory_memory_bytes <= 1024 * 1024);
}

#[test]
fn zero_report_budget_fails_before_source_reads() {
    let error = inspect_with_limits(
        &mut Cursor::new(Vec::<u8>::new()),
        0,
        InspectionLimits {
            max_report_bytes: 0,
            ..InspectionLimits::default()
        },
    )
    .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("inventory report budget exceeded")
    );
}

fn image_with_data_attributes(attributes: &[Vec<u8>]) -> Vec<u8> {
    let mut bytes = support::image();
    let offset = 4 * 4096 + 16 * 1024;
    bytes[offset..offset + 1024].copy_from_slice(&support::record(attributes, 1, 1));
    bytes
}

fn data_attribute(runs: &[u8], size: u64, initialized: u64, clusters: u64, flags: u16) -> Vec<u8> {
    let mut attribute = support::nonresident(0x80, runs, size, clusters);
    attribute[12..14].copy_from_slice(&flags.to_le_bytes());
    attribute[56..64].copy_from_slice(&initialized.to_le_bytes());
    if flags & 0x80ff != 0 {
        attribute.splice(64..64, [0u8; 8]);
        let length = attribute.len() as u32;
        attribute[4..8].copy_from_slice(&length.to_le_bytes());
        attribute[32..34].copy_from_slice(&72u16.to_le_bytes());
        attribute[34] = 4;
    }
    attribute
}

fn user_stream(report: &NtfsInspection) -> &ntfs2refs::ntfs_inspect::StreamInventory {
    &report
        .files
        .iter()
        .find(|file| file.record_number == 16)
        .unwrap()
        .streams[0]
}

// The content digest the inspector records for a stream's logical bytes.
fn digest(bytes: &[u8]) -> String {
    n2r_win32::content_digest::of(bytes)
}

struct GuardedReader {
    cursor: Cursor<Vec<u8>>,
    forbidden: Vec<std::ops::Range<u64>>,
    data_bytes_read: u64,
    largest_read: usize,
}

impl GuardedReader {
    fn new(bytes: Vec<u8>, forbidden: Vec<std::ops::Range<u64>>) -> Self {
        Self {
            cursor: Cursor::new(bytes),
            forbidden,
            data_bytes_read: 0,
            largest_read: 0,
        }
    }
}

impl Read for GuardedReader {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let start = self.cursor.position();
        let end = start + buffer.len() as u64;
        if self
            .forbidden
            .iter()
            .any(|range| start < range.end && end > range.start)
        {
            return Err(std::io::Error::other(
                "forbidden sparse/uninitialized/slack DATA read",
            ));
        }
        self.largest_read = self.largest_read.max(buffer.len());
        let count = self.cursor.read(buffer)?;
        if start >= 100 * 4096 {
            self.data_bytes_read += count as u64;
        }
        Ok(count)
    }
}

impl Seek for GuardedReader {
    fn seek(&mut self, position: SeekFrom) -> std::io::Result<u64> {
        self.cursor.seek(position)
    }
}

#[test]
fn hashes_initialized_prefix_and_zero_tail_without_reading_tail_or_eof_slack() {
    let attribute = data_attribute(&[0x11, 2, 100, 0], 5001, 4099, 2, 0);
    let mut bytes = image_with_data_attributes(&[attribute]);
    let start = 100 * 4096;
    bytes[start..start + 8192].fill(0xdd);
    let expected = [&bytes[start..start + 4099], &vec![0; 902]].concat();
    let length = bytes.len() as u64;
    let mut reader = GuardedReader::new(bytes, vec![(start as u64 + 4099)..(start as u64 + 8192)]);
    let report = inspect(&mut reader, length).unwrap();
    let stream = user_stream(&report);
    assert_eq!(
        stream.logical_sha256.as_deref(),
        Some(digest(&expected).as_str())
    );
    assert_eq!(stream.logical_hash_status, LogicalHashStatus::Complete);
    assert_eq!(
        (
            stream.logical_size,
            stream.initialized_size,
            stream.extents[0].length
        ),
        (5001, 4099, 8192)
    );
    assert_eq!(reader.data_bytes_read, 4099);
    assert!(!report.inventory_complete);
}

#[test]
fn hashes_sparse_holes_and_fragmented_partial_cluster_eof_in_logical_order() {
    let attribute = data_attribute(
        &[0x11, 1, 100, 0x01, 1, 0x11, 1, 2, 0],
        8209,
        8209,
        3,
        0x8000,
    );
    let mut bytes = image_with_data_attributes(&[attribute]);
    bytes[100 * 4096..101 * 4096].fill(0x41);
    bytes[101 * 4096..102 * 4096].fill(0xee);
    bytes[102 * 4096..103 * 4096].fill(0x42);
    let expected = [vec![0x41; 4096], vec![0; 4096], vec![0x42; 17]].concat();
    let length = bytes.len() as u64;
    let mut reader = GuardedReader::new(
        bytes,
        vec![101 * 4096..102 * 4096, (102 * 4096 + 17)..103 * 4096],
    );
    let report = inspect(&mut reader, length).unwrap();
    let stream = user_stream(&report);
    assert_eq!(stream.logical_sha256, Some(digest(&expected)));
    assert_eq!(
        stream
            .extents
            .iter()
            .map(|e| e.physical_offset)
            .collect::<Vec<_>>(),
        [Some(409600), None, Some(417792)]
    );
    assert_eq!(reader.data_bytes_read, 4113);
    assert_eq!(stream.logical_hash_status, LogicalHashStatus::Complete);
}

#[test]
fn hashes_fragments_with_backwards_physical_offsets() {
    let attribute = data_attribute(&[0x11, 1, 102, 0x11, 1, 0xfe, 0], 8192, 8192, 2, 0);
    let mut bytes = image_with_data_attributes(&[attribute]);
    bytes[102 * 4096..103 * 4096].fill(0x31);
    bytes[100 * 4096..101 * 4096].fill(0x32);
    let length = bytes.len() as u64;
    let report = inspect(&mut Cursor::new(bytes), length).unwrap();
    assert_eq!(
        user_stream(&report).logical_sha256,
        Some(digest(&[vec![0x31; 4096], vec![0x32; 4096]].concat()))
    );
}

#[test]
fn empty_and_fully_uninitialized_nonresident_streams_hash_logical_zeros() {
    for (runs, size, clusters) in [(vec![0], 0, 0), (vec![0x11, 1, 100, 0], 17, 1)] {
        let bytes = image_with_data_attributes(&[data_attribute(&runs, size, 0, clusters, 0)]);
        let length = bytes.len() as u64;
        let mut reader = GuardedReader::new(bytes, vec![100 * 4096..101 * 4096]);
        let report = inspect(&mut reader, length).unwrap();
        assert_eq!(
            user_stream(&report).logical_sha256,
            Some(digest(&vec![0; size as usize]))
        );
        assert_eq!(reader.data_bytes_read, 0);
    }
}

#[test]
fn supported_resident_data_has_complete_logical_digest() {
    let bytes =
        image_with_data_attributes(&[support::resident(0x80, "note", b"resident-content", 1)]);
    let length = bytes.len() as u64;
    let report = inspect(&mut Cursor::new(bytes), length).unwrap();
    let stream = user_stream(&report);
    assert_eq!(stream.logical_hash_status, LogicalHashStatus::Complete);
    assert_eq!(stream.logical_sha256, Some(digest(b"resident-content")));
    assert_eq!(stream.logical_sha256, stream.resident_sha256);
}

#[test]
fn hashing_uses_bounded_reads_for_large_extents() {
    let bytes =
        image_with_data_attributes(&[data_attribute(&[0x11, 20, 100, 0], 81920, 81920, 20, 0)]);
    let length = bytes.len() as u64;
    let expected = digest(&bytes[100 * 4096..120 * 4096]);
    let mut reader = GuardedReader::new(bytes, vec![]);
    let report = inspect(&mut reader, length).unwrap();
    assert_eq!(user_stream(&report).logical_sha256, Some(expected));
    assert_eq!(reader.data_bytes_read, 81920);
    assert!(reader.largest_read <= 64 * 1024);
}

#[test]
fn refuses_gaps_overlapping_physical_runs_and_inconsistent_sizes_before_hash() {
    let good = data_attribute(&[0x11, 1, 100, 0], 17, 17, 1, 0);
    let mut initialized_past_eof = good.clone();
    initialized_past_eof[56..64].copy_from_slice(&18u64.to_le_bytes());
    let mut bad_allocation = good.clone();
    bad_allocation[40..48].copy_from_slice(&8192u64.to_le_bytes());
    let mut unaligned_allocation = good.clone();
    unaligned_allocation[40..48].copy_from_slice(&17u64.to_le_bytes());
    for (attribute, message) in [
        (
            data_attribute(&[0x11, 1, 100, 0], 8192, 17, 1, 0),
            "coverage gap before logical EOF",
        ),
        (
            data_attribute(&[0x11, 1, 100, 0x11, 1, 0, 0], 8192, 8192, 2, 0),
            "overlapping physical extents",
        ),
        (
            data_attribute(&[0x01, 1, 0], 17, 17, 1, 0),
            "lacks the sparse attribute flag",
        ),
        (
            initialized_past_eof,
            "initialized size exceeds logical size",
        ),
        (
            bad_allocation,
            "allocated size differs from mapped coverage",
        ),
        (
            unaligned_allocation,
            "allocated size is not cluster aligned",
        ),
    ] {
        let bytes = image_with_data_attributes(&[attribute]);
        let length = bytes.len() as u64;
        let mut reader = GuardedReader::new(bytes, vec![100 * 4096..103 * 4096]);
        let error = inspect(&mut reader, length).unwrap_err();
        assert!(format!("{error:#}").contains(message), "{error:#}");
        assert_eq!(reader.data_bytes_read, 0);
    }
}

#[test]
fn unsupported_flags_never_produce_complete_logical_hashes() {
    for (flags, status) in [
        (1, LogicalHashStatus::UnsupportedCompression),
        (2, LogicalHashStatus::UnsupportedCompression),
        (0x4000, LogicalHashStatus::UnsupportedEncryption),
        (0x0100, LogicalHashStatus::UnsupportedFlags),
    ] {
        for resident in [false, true] {
            let mut attribute = if resident {
                support::resident(0x80, "", b"raw", 1)
            } else {
                data_attribute(&[0x11, 1, 100, 0], 17, 17, 1, flags)
            };
            attribute[12..14].copy_from_slice(&flags.to_le_bytes());
            let bytes = image_with_data_attributes(&[attribute]);
            let length = bytes.len() as u64;
            let mut reader = GuardedReader::new(bytes, vec![100 * 4096..101 * 4096]);
            let report = inspect(&mut reader, length).unwrap();
            if flags == 1 && resident {
                // A resident value carries the compression policy without any
                // encoded bytes, so it is hashed as the plain content it is.
                assert_eq!(
                    user_stream(&report).logical_hash_status,
                    LogicalHashStatus::Complete
                );
                assert_eq!(user_stream(&report).logical_sha256, Some(digest(b"raw")));
                continue;
            }
            assert_eq!(user_stream(&report).logical_hash_status, status);
            assert_eq!(user_stream(&report).logical_sha256, None);
            assert!(
                report
                    .blockers
                    .iter()
                    .any(|blocker| blocker.code == "logical_stream_hash_unavailable")
            );
        }
    }
}

#[test]
fn compressed_data_is_decoded_and_hashed_as_its_logical_content() {
    // One compression unit: a single physical cluster of LZNT1, then fifteen
    // clusters of padding. The encoded bytes are two chunks, each a literal
    // and one overlapping match: 4,096 'A', then 904 'B'.
    let mut attribute = data_attribute(&[0x11, 1, 100, 0x01, 15, 0], 5000, 5000, 16, 1);
    attribute[64..72].copy_from_slice(&4096u64.to_le_bytes()); // physically allocated bytes
    let mut bytes = image_with_data_attributes(&[attribute]);
    let encoded = [
        0x03, 0xb0, 0b10, b'A', 0xfc, 0x0f, // 1 + 4,095
        0x03, 0xb0, 0b10, b'B', 0x84, 0x03, // 1 + 903
    ];
    bytes[100 * 4096..101 * 4096].fill(0);
    bytes[100 * 4096..100 * 4096 + encoded.len()].copy_from_slice(&encoded);
    let logical = [vec![b'A'; 4096], vec![b'B'; 904]].concat();

    let length = bytes.len() as u64;
    // The padding has no bytes on disk; whatever lies after the one physical
    // cluster belongs to something else and must not be read.
    let mut reader = GuardedReader::new(bytes, vec![101 * 4096..116 * 4096]);
    let report = inspect(&mut reader, length).unwrap();
    assert_eq!(reader.data_bytes_read, 4096);
    let stream = user_stream(&report);
    assert_eq!(stream.logical_hash_status, LogicalHashStatus::Complete);
    assert_eq!(stream.logical_size, 5000);
    // The digest is of the decoded content, not of the bytes on disk.
    assert_eq!(stream.logical_sha256, Some(digest(&logical)));
    assert_ne!(stream.logical_sha256, Some(digest(&encoded)));
}

#[test]
fn unexpected_compression_unit_including_high_byte_has_no_logical_digest() {
    for unit in [4u16, 0x100] {
        let mut attribute = data_attribute(&[0x11, 1, 100, 0], 17, 17, 1, 0);
        attribute[34..36].copy_from_slice(&unit.to_le_bytes());
        let bytes = image_with_data_attributes(&[attribute]);
        let length = bytes.len() as u64;
        let mut reader = GuardedReader::new(bytes, vec![100 * 4096..101 * 4096]);
        let report = inspect(&mut reader, length).unwrap();
        assert_eq!(
            user_stream(&report).logical_hash_status,
            LogicalHashStatus::UnsupportedCompressionUnit
        );
        assert_eq!(user_stream(&report).logical_sha256, None);
    }
}

#[test]
fn an_empty_attribute_list_is_refused_rather_than_hashed_around() {
    // Attribute lists are assembled now (tests/ntfs_attribute_list.rs), so a
    // record that carries one is no longer merely left unhashed. A list with
    // no entries cannot describe the record's attributes: the inspection
    // stops, naming the record, before any DATA is read.
    let bytes = image_with_data_attributes(&[
        data_attribute(&[0x11, 1, 100, 0], 17, 17, 1, 0),
        support::resident(0x80, "note", b"raw-resident", 1),
        support::resident(0x20, "", &[], 2),
    ]);
    let length = bytes.len() as u64;
    let mut reader = GuardedReader::new(bytes, vec![100 * 4096..101 * 4096]);
    let error = format!("{:#}", inspect(&mut reader, length).unwrap_err());
    assert!(
        error.contains("assembling ordinary DATA for MFT record 16")
            && error.contains("attribute-list bytes must be completely initialized and bounded"),
        "{error}"
    );
    assert_eq!(reader.data_bytes_read, 0);
}

#[test]
fn extension_records_and_continuation_attributes_never_hash_as_whole_streams() {
    for continuation in [false, true] {
        let mut attribute = data_attribute(&[0x11, 1, 100, 0], 17, 17, 1, 0);
        if continuation {
            attribute[16..24].copy_from_slice(&1u64.to_le_bytes());
            attribute[24..32].copy_from_slice(&1u64.to_le_bytes());
            attribute[40..64].fill(0);
            // Continuation size fields are undefined, not an empty logical stream.
            attribute[56..64].copy_from_slice(&u64::MAX.to_le_bytes());
        }
        let mut bytes = image_with_data_attributes(&[attribute]);
        if !continuation {
            bytes[4 * 4096 + 16 * 1024 + 32..4 * 4096 + 16 * 1024 + 40]
                .copy_from_slice(&17u64.to_le_bytes());
        }
        let length = bytes.len() as u64;
        let mut reader = GuardedReader::new(bytes, vec![100 * 4096..101 * 4096]);
        let report = inspect(&mut reader, length).unwrap();
        assert_eq!(
            user_stream(&report).logical_hash_status,
            if continuation {
                LogicalHashStatus::UnsupportedAttributeList
            } else {
                LogicalHashStatus::UnsupportedExtensionRecord
            }
        );
        assert_eq!(user_stream(&report).logical_sha256, None);
    }
}

#[test]
fn duplicate_data_names_without_attribute_list_are_refused() {
    let attribute = data_attribute(&[0x11, 1, 100, 0], 17, 17, 1, 0);
    let bytes = image_with_data_attributes(&[attribute.clone(), attribute]);
    let length = bytes.len() as u64;
    let error = inspect(&mut Cursor::new(bytes), length).unwrap_err();
    assert!(format!("{error:#}").contains("duplicate DATA stream name"));
}

#[test]
fn cumulative_hash_budget_counts_repeated_physical_content_across_records() {
    let attribute = data_attribute(&[0x11, 1, 100, 0], 4096, 4096, 1, 0);
    let mut bytes = image_with_data_attributes(std::slice::from_ref(&attribute));
    bytes[4 * 4096 + 56 + 72 + 24 + 2] |= 1 << 1;
    let offset = 4 * 4096 + 17 * 1024;
    bytes[offset..offset + 1024].copy_from_slice(&support::record(&[attribute], 1, 1));
    let length = bytes.len() as u64;
    let baseline_cost = 20 * 1024 + 64;
    let mut reader = GuardedReader::new(bytes.clone(), vec![]);
    let error = inspect_with_limits(
        &mut reader,
        length,
        InspectionLimits {
            max_stream_hash_bytes: baseline_cost + 4096,
            ..InspectionLimits::default()
        },
    )
    .unwrap_err();
    assert!(format!("{error:#}").contains("cumulative stream hash byte limit exceeded"));
    assert_eq!(reader.data_bytes_read, 4096);
    let report = inspect_with_limits(
        &mut Cursor::new(bytes),
        length,
        InspectionLimits {
            max_stream_hash_bytes: baseline_cost + 8192,
            ..InspectionLimits::default()
        },
    )
    .unwrap();
    assert_eq!(report.stream_hash_bytes, baseline_cost + 8192);
    assert_eq!(report.stream_hash_limit_bytes, baseline_cost + 8192);
}

#[test]
fn hash_budget_counts_sparse_and_uninitialized_zero_bytes() {
    for attribute in [
        data_attribute(&[0x01, 2, 0], 8192, 8192, 2, 0x8000),
        data_attribute(&[0x11, 2, 100, 0], 8192, 0, 2, 0),
    ] {
        let bytes = image_with_data_attributes(&[attribute]);
        let length = bytes.len() as u64;
        let mut reader = GuardedReader::new(bytes, vec![100 * 4096..102 * 4096]);
        let error = inspect_with_limits(
            &mut reader,
            length,
            InspectionLimits {
                max_stream_hash_bytes: 20 * 1024 + 64 + 8191,
                ..InspectionLimits::default()
            },
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("cumulative stream hash byte limit exceeded"));
        assert_eq!(reader.data_bytes_read, 0);
    }
}

#[test]
fn default_hash_budget_refuses_huge_sparse_logical_stream_in_small_image() {
    let bytes = image_with_data_attributes(&[data_attribute(
        &[0x03, 0, 0, 8, 0],
        2 * 1024 * 1024 * 1024,
        0,
        524288,
        0x8000,
    )]);
    let length = bytes.len() as u64;
    let mut reader = GuardedReader::new(bytes, vec![100 * 4096..101 * 4096]);
    let error = inspect(&mut reader, length).unwrap_err();
    assert!(format!("{error:#}").contains("cumulative stream hash byte limit exceeded"));
    assert_eq!(
        InspectionLimits::default().max_stream_hash_bytes,
        1024 * 1024 * 1024
    );
    assert_eq!(reader.data_bytes_read, 0);
}

#[test]
fn data_read_failure_returns_error_instead_of_a_partial_digest_report() {
    let bytes = image_with_data_attributes(&[data_attribute(&[0x11, 1, 100, 0], 17, 17, 1, 0)]);
    let length = bytes.len() as u64;
    let mut reader = GuardedReader::new(bytes, vec![100 * 4096..101 * 4096]);
    let error = inspect(&mut reader, length).unwrap_err();
    assert!(format!("{error:#}").contains("hashing DATA attribute"));
    assert!(format!("{error:#}").contains("forbidden sparse/uninitialized/slack DATA read"));
}

#[test]
fn legacy_stream_without_hash_fields_never_deserializes_as_complete() {
    let bytes = support::image();
    let length = bytes.len() as u64;
    let report = inspect(&mut Cursor::new(bytes), length).unwrap();
    let mut value = serde_json::to_value(user_stream(&report)).unwrap();
    let object = value.as_object_mut().unwrap();
    object.remove("logical_sha256");
    object.remove("logical_hash_status");
    let stream: ntfs2refs::ntfs_inspect::StreamInventory = serde_json::from_value(value).unwrap();
    assert_eq!(stream.logical_sha256, None);
    assert_eq!(stream.logical_hash_status, LogicalHashStatus::NotComputed);
}

#[test]
fn sparse_mapping_pairs_cannot_overlap_extended_header() {
    let mut attribute = support::nonresident(0x80, &[0x11, 1, 100, 0], 17, 1);
    attribute[12..14].copy_from_slice(&0x8000u16.to_le_bytes());
    let bytes = image_with_data_attributes(&[attribute]);
    let length = bytes.len() as u64;
    let error = inspect(&mut Cursor::new(bytes), length).unwrap_err();
    assert!(format!("{error:#}").contains("invalid run-list offset"));
}

fn unflagged_system_stream_image(record_number: usize, name: &str, runs: &[u8]) -> Vec<u8> {
    let mut attribute = data_attribute(runs, 2 * 1024 * 1024, 0, 512, 0);
    let name: Vec<u16> = name.encode_utf16().collect();
    let name_bytes = name.len() * 2;
    let padded_name_bytes = name_bytes.div_ceil(8) * 8;
    attribute.splice(64..64, vec![0; padded_name_bytes]);
    let attribute_size = attribute.len() as u32;
    attribute[4..8].copy_from_slice(&attribute_size.to_le_bytes());
    attribute[9] = name.len() as u8;
    attribute[10..12].copy_from_slice(&64u16.to_le_bytes());
    attribute[32..34].copy_from_slice(&(64u16 + padded_name_bytes as u16).to_le_bytes());
    for (index, unit) in name.into_iter().enumerate() {
        attribute[64 + index * 2..66 + index * 2].copy_from_slice(&unit.to_le_bytes());
    }
    let mut bytes = support::image();
    // The synthetic MFT bitmap is a resident attribute following the MFT DATA.
    let bitmap_value = 4 * 4096 + 56 + 72 + 24;
    bytes[bitmap_value + record_number / 8] |= 1 << (record_number % 8);
    let offset = 4 * 4096 + record_number * 1024;
    bytes[offset..offset + 1024].copy_from_slice(&support::record(&[attribute], 1, 1));
    bytes
}

#[test]
fn bad_cluster_metadata_with_unflagged_holes_is_explicitly_unhashed() {
    let baseline = support::image();
    let length = baseline.len() as u64;
    let baseline = inspect(&mut Cursor::new(baseline), length).unwrap();
    let bytes = unflagged_system_stream_image(8, "$Bad", &[0x02, 0, 2, 0]);
    let report = inspect_with_limits(
        &mut Cursor::new(bytes),
        length,
        InspectionLimits {
            max_stream_hash_bytes: baseline.stream_hash_bytes,
            ..InspectionLimits::default()
        },
    )
    .unwrap();
    let file = report
        .files
        .iter()
        .find(|file| file.record_number == 8)
        .unwrap();
    let stream = &file.streams[0];
    assert_eq!(stream.name, "$Bad");
    assert_eq!(stream.flags, 0);
    assert_eq!(stream.logical_size, length);
    assert_eq!(stream.extents.len(), 1);
    assert_eq!(stream.extents[0].physical_offset, None);
    assert_eq!(stream.extents[0].length, length);
    assert_eq!(stream.logical_sha256, None);
    assert_eq!(
        stream.logical_hash_status,
        LogicalHashStatus::UnsupportedBadClusterMetadata
    );
    assert_eq!(
        serde_json::to_value(stream.logical_hash_status).unwrap(),
        "unsupported_bad_cluster_metadata"
    );
    assert_eq!(file.attributes[0].flags, 0);
    assert_eq!(file.attributes[0].extents, stream.extents);
    assert_eq!(report.stream_hash_bytes, baseline.stream_hash_bytes);
    assert!(!report.inventory_complete);
    assert!(report.blockers.iter().any(|blocker| {
        blocker.code == "logical_stream_hash_unavailable" && blocker.file_record_number == Some(8)
    }));
}

#[test]
fn bad_cluster_exception_never_relaxes_ordinary_holes_or_parser_bounds() {
    for (record_number, name) in [(16, "$Bad"), (8, "$Bog"), (8, "")] {
        let bytes = unflagged_system_stream_image(record_number, name, &[0x02, 0, 2, 0]);
        let length = bytes.len() as u64;
        let error = inspect(&mut Cursor::new(bytes), length).unwrap_err();
        assert!(format!("{error:#}").contains("sparse DATA run lacks the sparse attribute flag"));
    }
    // A physical run starts at LCN 512, beyond this 512-cluster partition.
    // Even an otherwise matching $Bad stream must fail during run-list parsing.
    let bytes = unflagged_system_stream_image(8, "$Bad", &[0x01, 1, 0x22, 0xff, 1, 0, 2, 0]);
    let length = bytes.len() as u64;
    let error = inspect(&mut Cursor::new(bytes), length).unwrap_err();
    assert!(format!("{error:#}").contains("data run outside volume"));
}
