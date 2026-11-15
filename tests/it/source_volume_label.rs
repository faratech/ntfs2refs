#[allow(dead_code, reason = "shared synthetic parser fixtures")]
use crate::support;
use n2r_win32::volume_label::VolumeLabel;
use ntfs2refs::{ntfs_inspect, source_volume_label};
use std::io::Cursor;
fn fixture(label: Option<&[u16]>) -> Vec<u8> {
    let mut image = support::image();
    let mut version = [0u8; 12];
    version[8] = 3;
    version[9] = 1;
    let mut attrs = vec![support::resident(0x70, "", &version, 0)];
    if let Some(label) = label {
        let bytes: Vec<_> = label.iter().flat_map(|unit| unit.to_le_bytes()).collect();
        attrs.push(support::resident(0x60, "", &bytes, 1));
    }
    let record = support::record(&attrs, 1, 1);
    let start = 4 * 4096 + 3 * 1024;
    image[start..start + 1024].copy_from_slice(&record);
    image
}
#[test]
fn frozen_label_matches_the_actual_resident_ntfs_value_without_case_or_unicode_normalization() {
    let label = VolumeLabel::from_text(" 工程 Δ 😀 ").unwrap();
    let bytes = fixture(Some(label.utf16()));
    let raw = ntfs_inspect::inspect(&mut Cursor::new(&bytes), bytes.len() as u64).unwrap();
    let proof = source_volume_label::verify(&mut Cursor::new(&bytes), &raw, &label).unwrap();
    assert_eq!(proof.label, label);
    assert!(proof.volume_name_attribute_present);
    assert!(
        source_volume_label::verify(
            &mut Cursor::new(&bytes),
            &raw,
            &VolumeLabel::from_text("工程 Δ 😀").unwrap()
        )
        .is_err()
    );
    let other = fixture(Some(&"changed".encode_utf16().collect::<Vec<_>>()));
    assert!(source_volume_label::verify(&mut Cursor::new(&other), &raw, &label).is_err());
}
#[test]
fn missing_or_explicitly_empty_volume_name_is_empty_but_never_a_stale_nonempty_capture() {
    for value in [None, Some(&[][..])] {
        let bytes = fixture(value);
        let raw = ntfs_inspect::inspect(&mut Cursor::new(&bytes), bytes.len() as u64).unwrap();
        let proof = source_volume_label::verify(
            &mut Cursor::new(&bytes),
            &raw,
            &VolumeLabel::from_text("").unwrap(),
        )
        .unwrap();
        assert_eq!(proof.volume_name_attribute_present, value.is_some());
        assert!(
            source_volume_label::verify(
                &mut Cursor::new(&bytes),
                &raw,
                &VolumeLabel::from_text("stale").unwrap()
            )
            .is_err()
        );
    }
}
