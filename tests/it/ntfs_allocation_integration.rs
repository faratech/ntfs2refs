use crate::support;

use ntfs2refs::ntfs_inspect::{self, AllocationReconciliationStatus};
use std::io::Cursor;

const MFT: usize = 4 * 4096;

fn attribute(image: &[u8], record: usize, ty: u32) -> usize {
    let base = MFT + record * 1024;
    let mut at = base + 56;
    loop {
        let kind = u32::from_le_bytes(image[at..at + 4].try_into().unwrap());
        assert_ne!(kind, u32::MAX, "attribute missing");
        if kind == ty {
            return at;
        }
        at += u32::from_le_bytes(image[at + 4..at + 8].try_into().unwrap()) as usize;
    }
}

fn resident_value(image: &[u8], record: usize, ty: u32) -> usize {
    let at = attribute(image, record, ty);
    at + usize::from(u16::from_le_bytes(
        image[at + 20..at + 22].try_into().unwrap(),
    ))
}

fn put_record(image: &mut [u8], number: usize, attrs: &[Vec<u8>]) {
    let at = MFT + number * 1024;
    image[at..at + 1024].copy_from_slice(&support::record(attrs, 1, 1));
}

// Extends the synthetic corpus with actual owners for its allocated boot/mirror
// clusters. This is a parser/ledger fixture, never a native NTFS acceptance disk.
fn complete_model() -> Vec<u8> {
    let mut image = support::image();
    let data = attribute(&image, 16, 0x80);
    image[data + 14..data + 16].copy_from_slice(&3u16.to_le_bytes());
    put_record(
        &mut image,
        1,
        &[support::nonresident(0x80, &[0x11, 1, 30, 0], 4096, 1)],
    );
    put_record(
        &mut image,
        7,
        &[support::nonresident(0x80, &[0x11, 1, 0, 0], 4096, 1)],
    );
    let bitmap = resident_value(&image, 0, 0xb0);
    image[bitmap] |= 0x82; // Include records 1 and 7.
    image
}

fn inspect(image: &[u8]) -> ntfs_inspect::NtfsInspection {
    ntfs_inspect::inspect(&mut Cursor::new(image), image.len() as u64).unwrap()
}

#[test]
fn reconciles_all_attributes_once_without_promoting_source_admission() {
    let image = complete_model();
    let before = image.clone();
    let report = inspect(&image);
    let allocation = report.allocation_reconciliation.unwrap();
    assert_eq!(
        allocation.status,
        AllocationReconciliationStatus::ConsistentRawModel
    );
    assert_eq!(allocation.physical_intervals, 4);
    assert_eq!(allocation.domain_clusters, 512);
    assert_eq!(allocation.bitmap_sha256.len(), 64);
    assert_eq!(report.allocated_clusters, Some(8));
    assert!(!report.inventory_complete);
    assert!(
        report
            .blockers
            .iter()
            .any(|b| b.code == "allocation_ownership_unverified")
    );
    assert_eq!(image, before);
}

#[test]
fn detects_cross_file_overlap_even_for_system_metadata() {
    let mut image = complete_model();
    put_record(
        &mut image,
        1,
        &[support::nonresident(0x80, &[0x11, 1, 100, 0], 4096, 1)],
    );
    let allocation = inspect(&image).allocation_reconciliation.unwrap();
    assert_eq!(allocation.status, AllocationReconciliationStatus::Rejected);
    assert!(allocation.detail.contains("PhysicalOverlap"));
}

#[test]
fn detects_a_data_extent_marked_free() {
    let mut image = complete_model();
    let bitmap = resident_value(&image, 6, 0x80);
    image[bitmap + 100 / 8] &= !(1 << (100 % 8));
    let allocation = inspect(&image).allocation_reconciliation.unwrap();
    assert_eq!(allocation.status, AllocationReconciliationStatus::Rejected);
    assert!(allocation.detail.contains("ClaimedFree"));
}

#[test]
fn detects_allocated_clusters_without_any_attribute_owner() {
    let mut image = complete_model();
    let bitmap = resident_value(&image, 6, 0x80);
    image[bitmap + 101 / 8] |= 1 << (101 % 8);
    let allocation = inspect(&image).allocation_reconciliation.unwrap();
    assert_eq!(allocation.status, AllocationReconciliationStatus::Rejected);
    assert!(allocation.detail.contains("AllocatedUnowned { lcn: 101 }"));
}

#[test]
fn accounts_for_allocation_past_logical_eof() {
    let mut image = complete_model();
    let mut data = support::nonresident(0x80, &[0x11, 2, 100, 0], 17, 2);
    data[14..16].copy_from_slice(&3u16.to_le_bytes());
    put_record(&mut image, 16, &[data]);
    let bitmap = resident_value(&image, 6, 0x80);
    image[bitmap + 101 / 8] |= 1 << (101 % 8);
    let report = inspect(&image);
    assert_eq!(report.allocated_clusters, Some(9));
    assert_eq!(
        report.allocation_reconciliation.unwrap().status,
        AllocationReconciliationStatus::ConsistentRawModel
    );
}

#[test]
fn never_assesses_an_unassembled_system_attribute_list_as_complete() {
    let mut image = complete_model();
    let mut data = support::nonresident(0x80, &[0x11, 1, 0, 0], 4096, 1);
    data[14..16].copy_from_slice(&1u16.to_le_bytes());
    put_record(&mut image, 7, &[support::resident(0x20, "", &[], 0), data]);
    let allocation = inspect(&image).allocation_reconciliation.unwrap();
    assert_eq!(
        allocation.status,
        AllocationReconciliationStatus::IncompleteAttributeInventory
    );
    assert!(allocation.detail.contains("record 7"));
}

#[test]
fn repeated_attribute_instances_do_not_create_trusted_ownership_keys() {
    let mut image = complete_model();
    let data = attribute(&image, 16, 0x80);
    image[data + 14..data + 16].copy_from_slice(&0u16.to_le_bytes());
    let allocation = inspect(&image).allocation_reconciliation.unwrap();
    assert_eq!(
        allocation.status,
        AllocationReconciliationStatus::IncompleteAttributeInventory
    );
    assert!(allocation.detail.contains("repeats an attribute instance"));
}

#[test]
fn allocated_mft_bits_beyond_eof_are_refused_before_inventory() {
    let mut image = complete_model();
    let bitmap = resident_value(&image, 0, 0xb0);
    image[bitmap + 2] |= 0x80; // Record 23 is outside the 20-record MFT.
    let error = ntfs_inspect::inspect(&mut Cursor::new(&image), image.len() as u64).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("allocated records beyond MFT EOF")
    );
}

#[test]
fn an_uninitialized_volume_bitmap_cannot_hide_allocations_as_zeroes() {
    let mut image = complete_model();
    let mut bitmap = support::nonresident(0x80, &[0x11, 1, 110, 0], 64, 1);
    bitmap[56..64].copy_from_slice(&0u64.to_le_bytes());
    put_record(&mut image, 6, &[bitmap]);
    let error = ntfs_inspect::inspect(&mut Cursor::new(&image), image.len() as u64).unwrap_err();
    assert!(error.to_string().contains("bitmap must have initialized"));
}

#[test]
fn an_uninitialized_mft_bitmap_cannot_hide_allocated_file_records() {
    let mut image = complete_model();
    let data = support::nonresident(0x80, &[0x11, 5, 4, 0], 20 * 1024, 5);
    let mut bitmap = support::nonresident(0xb0, &[0x11, 1, 111, 0], 3, 1);
    bitmap[14..16].copy_from_slice(&1u16.to_le_bytes());
    bitmap[56..64].copy_from_slice(&1u64.to_le_bytes());
    put_record(&mut image, 0, &[data, bitmap]);
    let error = ntfs_inspect::inspect(&mut Cursor::new(&image), image.len() as u64).unwrap_err();
    assert!(error.to_string().contains("bitmap must have initialized"));
}
