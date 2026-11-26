//! An NTFS 1.2 (Windows NT 4.0) volume, read as the converter reads it.
use crate::ntfs12_volume as ntfs12;
use ntfs2refs::ntfs_inspect;
use std::io::Cursor;

const PARTITION: u64 = 16 * 1024 * 1024;

/// The synthetic volume is one the converter's own readers take apart: its
/// boot sector, every record in the 1.2 header form, $Volume stating 1.2,
/// its directories and its files.
#[test]
fn the_synthetic_nt4_volume_is_well_formed() {
    let volume = ntfs12::volume(PARTITION, 2048, (1, 2));
    let image = volume.image();
    let geometry = ntfs_inspect::inspect_boot_sector(&image[..512], image.len() as u64).unwrap();
    assert_eq!(geometry.total_clusters, volume.total_clusters);
    assert_eq!(
        ntfs_inspect::read_volume_version(&mut Cursor::new(&image), &geometry).unwrap(),
        (1, 2)
    );
    let report = ntfs_inspect::inspect(&mut Cursor::new(&image), image.len() as u64).unwrap();
    assert_eq!(
        report.allocation_reconciliation.as_ref().unwrap().status,
        ntfs_inspect::AllocationReconciliationStatus::ConsistentRawModel
    );
    let names: Vec<_> = report
        .files
        .iter()
        .flat_map(|f| f.names.iter().map(|n| n.name.clone()))
        .collect();
    for name in [
        "$MFT",
        "$Quota",
        "README.TXT",
        "BIG.BIN",
        "SUB",
        "INNER.TXT",
    ] {
        assert!(names.iter().any(|n| n == name), "{name}: {names:?}");
    }
    // The backup boot sector is the boot sector.
    assert_eq!(&image[image.len() - 512..], &image[..512]);
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
