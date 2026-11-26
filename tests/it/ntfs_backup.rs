#[allow(dead_code, reason = "Shared synthetic parser fixture")]
use crate::support;
use ntfs2refs::{
    ntfs_backup,
    ntfs_inspect::{self, NtfsInspection},
};
use std::io::Cursor;
const MFT: usize = 4 * 4096;
const MIRROR: usize = 30 * 4096;
fn fixture() -> (Vec<u8>, NtfsInspection) {
    let mut b = support::image();
    let mft = support::record(
        &[
            support::nonresident(0x80, &[0x11, 5, 4, 0], 20 * 1024, 5),
            support::resident(0xb0, "", &[0x6f, 0, 1], 1),
        ],
        1,
        1,
    );
    b[MFT..MFT + 1024].copy_from_slice(&mft);
    b[MFT + 1024..MFT + 2048].copy_from_slice(&support::record(
        &[support::nonresident(0x80, &[0x11, 1, 30, 0], 4096, 1)],
        1,
        1,
    ));
    b[MFT + 2048..MFT + 3072].copy_from_slice(&support::record(&[], 1, 1));
    let first_records = b[MFT..MFT + 4096].to_vec();
    b[MIRROR..MIRROR + 4096].copy_from_slice(&first_records);
    let end = b.len();
    let boot = b[..512].to_vec();
    b[end - 512..].copy_from_slice(&boot);
    let raw = ntfs_inspect::inspect(&mut Cursor::new(&b), b.len() as u64).unwrap();
    (b, raw)
}
/// The fixture for a sector and FILE record size: four records mirrored at
/// cluster 30, which is one cluster or four records, whichever is larger,
/// and the backup boot sector in the volume's last sector.
fn fixture_geometry(sector: u16, record: usize) -> (Vec<u8>, NtfsInspection) {
    let mut b = support::image_geometry(sector, record);
    let clusters = support::mft_clusters(record);
    let mirror_bytes = 4096.max(4 * record);
    let mft = support::record_sized(
        &[
            support::nonresident(
                0x80,
                &[0x11, clusters as u8, 4, 0],
                (20 * record) as u64,
                clusters as u64,
            ),
            support::resident(0xb0, "", &[0x6f, 0, 1], 1),
        ],
        1,
        1,
        record,
    );
    b[MFT..MFT + record].copy_from_slice(&mft);
    b[MFT + record..MFT + 2 * record].copy_from_slice(&support::record_sized(
        &[support::nonresident(
            0x80,
            &[0x11, (mirror_bytes / 4096) as u8, 30, 0],
            mirror_bytes as u64,
            (mirror_bytes / 4096) as u64,
        )],
        1,
        1,
        record,
    ));
    b[MFT + 2 * record..MFT + 3 * record].copy_from_slice(&support::record_sized(
        &[],
        1,
        1,
        record,
    ));
    let first_records = b[MFT..MFT + mirror_bytes].to_vec();
    b[MIRROR..MIRROR + mirror_bytes].copy_from_slice(&first_records);
    let sector = usize::from(sector);
    let end = b.len();
    let boot = b[..sector].to_vec();
    b[end - sector..].copy_from_slice(&boot);
    let raw = ntfs_inspect::inspect(&mut Cursor::new(&b), b.len() as u64).unwrap();
    (b, raw)
}

#[test]
fn verifies_backups_for_every_sector_and_file_record_size() {
    for sector in [512u16, 1024, 2048, 4096] {
        for record in [1024usize, 2048, 4096] {
            let (b, r) = fixture_geometry(sector, record);
            let proof = ntfs_backup::verify(&mut Cursor::new(&b), b.len() as u64, &r)
                .unwrap_or_else(|error| panic!("{sector}/{record}: {error:#}"));
            assert!(proof.binds(&r));
            // The backup boot sector is the whole last sector of its size,
            // and each of the four mirrored records is compared.
            let sector = usize::from(sector);
            for at in [
                b.len() - sector + 72,
                b.len() - 1,
                MIRROR + 8,
                MIRROR + 3 * record + 8,
            ] {
                let mut damaged = b.clone();
                damaged[at] ^= 1;
                assert!(
                    ntfs_backup::verify(&mut Cursor::new(&damaged), b.len() as u64, &r).is_err(),
                    "{sector}/{record}: {at}"
                );
            }
        }
    }
}

#[test]
fn verifies_actual_boot_and_four_mirrored_records() {
    let (b, r) = fixture();
    let proof = ntfs_backup::verify(&mut Cursor::new(&b), b.len() as u64, &r).unwrap();
    assert!(proof.binds(&r));
    let mut foreign = r;
    foreign.files[0].sequence_number += 1;
    assert!(!proof.binds(&foreign));
}
#[test]
fn damaged_backup_boot_and_mirror_changes_are_refused() {
    let (original, r) = fixture();
    for at in [original.len() - 512 + 72, MIRROR + 8, MIRROR + 3 * 1024 + 8] {
        let mut b = original.clone();
        b[at] ^= 1;
        assert!(ntfs_backup::verify(&mut Cursor::new(&b), b.len() as u64, &r).is_err());
    }
}
#[test]
fn torn_record_is_rejected_even_when_primary_and_mirror_match() {
    let (mut b, r) = fixture();
    b[MFT + 510] ^= 1;
    b[MIRROR + 510] ^= 1;
    let e = ntfs_backup::verify(&mut Cursor::new(&b), b.len() as u64, &r).unwrap_err();
    assert!(format!("{e:#}").contains("update sequence mismatch"));
}
#[test]
fn incomplete_uninitialized_or_wrong_bootstrap_mapping_is_refused() {
    let (b, r) = fixture();
    for change in 0..4 {
        let mut raw = r.clone();
        let mirror = raw.files.iter_mut().find(|f| f.record_number == 1).unwrap();
        let data = mirror
            .attributes
            .iter_mut()
            .find(|a| a.type_code == 0x80)
            .unwrap();
        match change {
            0 => data.initialized_size -= 1,
            1 => data.extents[0].physical_offset = None,
            2 => data.extents[0].physical_offset = Some(31 * 4096),
            _ => data.logical_size += 4096,
        }
        assert!(ntfs_backup::verify(&mut Cursor::new(&b), b.len() as u64, &raw).is_err());
    }
}
#[test]
fn missing_mirror_or_short_source_is_refused() {
    let (b, mut r) = fixture();
    assert!(ntfs_backup::verify(&mut Cursor::new(&b[..b.len() - 1]), b.len() as u64, &r).is_err());
    r.files.retain(|f| f.record_number != 1);
    assert!(ntfs_backup::verify(&mut Cursor::new(&b), b.len() as u64, &r).is_err());
}
