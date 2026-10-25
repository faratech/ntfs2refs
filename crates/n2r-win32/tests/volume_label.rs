use n2r_win32::{
    general_layout::GeneralDiskBinding,
    layout::PartitionIdentity,
    volume_label::{VolumeLabel, require_expected_current, validate_original_partition},
};
fn binding() -> GeneralDiskBinding {
    GeneralDiskBinding {
        disk_number: 7,
        volume_guid: "12345678-1234-1234-abcd-123456789abc".into(),
        identity: PartitionIdentity {
            disk_guid: "23456789-2345-2345-bcde-23456789abcd".into(),
            partition_guid: "3456789a-3456-3456-cdef-3456789abcde".into(),
            partition_number: 2,
            disk_bytes: 8 << 30,
            partition_offset: 16 << 20,
            partition_bytes: 6 << 30,
            logical_sector_bytes: 512,
            physical_sector_bytes: 4096,
        },
    }
}
#[test]
fn labels_preserve_empty_spaces_unicode_and_utf16_without_truncation() {
    for text in ["", " Source Data ", "工程 Δ 😀", "x:|?*<>"] {
        let label = VolumeLabel::from_text(text).unwrap();
        assert_eq!(label.text().as_deref(), Some(text));
        let encoded: Vec<u16> = text.encode_utf16().collect();
        assert_eq!(label.utf16(), encoded);
        let mut terminated = encoded;
        terminated.push(0);
        assert_eq!(label.terminated().unwrap(), terminated);
        let replay: VolumeLabel =
            serde_json::from_str(&serde_json::to_string(&label).unwrap()).unwrap();
        assert_eq!(replay, label);
    }
    assert_eq!(
        VolumeLabel::from_text("").unwrap().terminated().unwrap(),
        [0]
    );
    assert!(VolumeLabel::from_text(&"A".repeat(32)).is_ok());
    assert!(VolumeLabel::from_text(&"😀".repeat(16)).is_ok());
    assert!(VolumeLabel::from_text(&"A".repeat(33)).is_err());
    assert!(VolumeLabel::from_text(&"😀".repeat(17)).is_err());
    assert!(VolumeLabel::from_utf16(vec![65, 0, 66]).is_err());
    let raw = VolumeLabel::from_utf16(vec![0xd800]).unwrap();
    assert!(raw.text().is_none());
    assert_eq!(raw.utf16(), [0xd800]);
}
#[test]
fn deserialized_label_data_must_validate_before_it_can_be_passed_to_windows() {
    let oversized: VolumeLabel =
        serde_json::from_value(serde_json::json!({"utf16":vec![65;33]})).unwrap();
    assert!(oversized.validate().is_err());
    assert!(oversized.terminated().is_err());
    let nul: VolumeLabel = serde_json::from_value(serde_json::json!({"utf16":[65,0,66]})).unwrap();
    assert!(nul.terminated().is_err());
    assert!(
        serde_json::from_value::<VolumeLabel>(serde_json::json!({"utf16":[],"force":true}))
            .is_err()
    );
}
#[test]
fn restoration_rejects_a_different_device_partition_or_extent_before_mutation() {
    let original = binding();
    let mut alias = original.clone();
    alias.volume_guid = "456789ab-4567-4567-def0-456789abcdef".into();
    validate_original_partition(&original, &alias).unwrap();
    for case in 0..7 {
        let mut changed = alias.clone();
        match case {
            0 => changed.disk_number += 1,
            1 => changed.identity.disk_guid = "56789abc-5678-5678-ef01-56789abcdef0".into(),
            2 => changed.identity.partition_guid = "6789abcd-6789-6789-f012-6789abcdef01".into(),
            3 => changed.identity.partition_number += 1,
            4 => changed.identity.partition_offset += 4096,
            5 => changed.identity.partition_bytes -= 4096,
            _ => changed.identity.physical_sector_bytes = 512,
        }
        assert!(
            validate_original_partition(&original, &changed).is_err(),
            "case {case}"
        );
    }
}
#[test]
fn enrollment_guard_refuses_foreign_labels_and_supports_idempotent_completion() {
    let enrollment = VolumeLabel::from_text("n2r-retained-shadow").unwrap();
    let desired = VolumeLabel::from_text("工程 Δ 😀").unwrap();
    assert!(require_expected_current(&enrollment, &enrollment, &desired).unwrap());
    assert!(!require_expected_current(&desired, &enrollment, &desired).unwrap());
    assert!(
        require_expected_current(
            &VolumeLabel::from_text("foreign data").unwrap(),
            &enrollment,
            &desired
        )
        .is_err()
    );
    assert!(
        require_expected_current(
            &enrollment,
            &enrollment,
            &VolumeLabel::from_text("").unwrap()
        )
        .unwrap()
    );
}
