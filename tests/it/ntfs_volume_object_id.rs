#[path = "../support/volume_object_id.rs"]
mod volume_identity_fixture;
use ntfs2refs::{ntfs_inspect, ntfs_internal};
use std::io::Cursor;
use volume_identity_fixture::{ID, MFT, fixture, index_value};
fn inspect(bytes: &[u8]) -> ntfs_inspect::NtfsInspection {
    ntfs_inspect::inspect(&mut Cursor::new(bytes), bytes.len() as u64).unwrap()
}
fn object_index_supported(proof: &ntfs_internal::VerifiedIndexes) -> bool {
    proof
        .indexes
        .iter()
        .find(|index| index.role == "$Extend\\$ObjId")
        .unwrap()
        .replacement_supported
}

#[test]
fn sole_reserved_volume_identity_is_cross_bound_and_archived_without_claiming_refs_identity() {
    let bytes = fixture(Some(&ID), &[(ID.to_vec(), index_value(3, 3))], false);
    let original = bytes.clone();
    let raw = inspect(&bytes);
    let proof = ntfs_internal::verify(&mut Cursor::new(&bytes), &raw).unwrap();
    assert!(proof.binds(&raw));
    assert!(object_index_supported(&proof));
    assert!(!proof.replacement_supported); // Native disabled quota policy remains required.
    assert!(proof.covers_volume_object_id(&raw, 3));
    assert!(!proof.covers_volume_object_id(&raw, 16));
    let identity = proof.internal_volume_object_id().unwrap();
    assert!(identity.binds(&raw));
    assert_eq!(identity.record_number(), 3);
    assert_eq!(identity.sequence_number(), 3);
    assert_eq!(identity.object_id_hex(), hex::encode(ID));
    assert_eq!(
        identity.disposition(),
        "replace-filesystem-internal-volume-identity"
    );
    let evidence = serde_json::to_value(identity).unwrap();
    assert_eq!(evidence["object_index_record_number"], 17);
    assert_eq!(evidence["same_refs_object_id_preserved"], false);
    assert_eq!(
        evidence["object_id_sha256"],
        "7e01ca45d8b66df4b0a422ea3e6e7972f34c4ecbac33ea30d0296733ad7e42e2"
    );
    let mut changed = raw.clone();
    changed
        .files
        .iter_mut()
        .find(|file| file.record_number == 3)
        .unwrap()
        .sequence_number = 4;
    assert!(!proof.covers_volume_object_id(&changed, 3));
    assert_eq!(bytes, original);
}

#[test]
fn user_ids_unknown_entries_birth_fields_and_wrong_references_remain_refused() {
    let valid = (ID.to_vec(), index_value(3, 3));
    let mut birth = valid.clone();
    birth.1[8] = 1;
    let mut domain = valid.clone();
    domain.1[55] = 1;
    let mut wrong_key = valid.clone();
    wrong_key.0[0] ^= 1;
    let mut short = valid.clone();
    short.1.pop();
    for entries in [
        vec![],
        vec![(ID.to_vec(), index_value(3, 4))],
        vec![(ID.to_vec(), index_value(16, 3))],
        vec![birth],
        vec![domain],
        vec![wrong_key],
        vec![short],
        vec![valid.clone(), (vec![0xff; 16], index_value(3, 3))],
    ] {
        let bytes = fixture(Some(&ID), &entries, false);
        let raw = inspect(&bytes);
        let proof = ntfs_internal::verify(&mut Cursor::new(&bytes), &raw).unwrap();
        assert!(proof.internal_volume_object_id().is_none());
        assert!(!object_index_supported(&proof));
        assert!(!proof.covers_volume_object_id(&raw, 3));
    }
    for bytes in [
        fixture(Some(&ID), std::slice::from_ref(&valid), true),
        fixture(None, &[(ID.to_vec(), index_value(16, 1))], true),
        fixture(Some(&[0; 16]), &[(vec![0; 16], index_value(3, 3))], false),
        fixture(Some(&[0; 64]), std::slice::from_ref(&valid), false),
    ] {
        let raw = inspect(&bytes);
        let proof = ntfs_internal::verify(&mut Cursor::new(&bytes), &raw).unwrap();
        assert!(proof.internal_volume_object_id().is_none());
        assert!(!object_index_supported(&proof));
    }
}

#[test]
fn proof_rereads_resident_values_and_usa_instead_of_trusting_inventory_hex() {
    let bytes = fixture(Some(&ID), &[(ID.to_vec(), index_value(3, 3))], false);
    let raw = inspect(&bytes);
    let volume_start = MFT + 3 * 1024;
    let relative = bytes[volume_start..volume_start + 1024]
        .windows(16)
        .position(|value| value == ID)
        .unwrap();
    let mut changed = bytes.clone();
    changed[volume_start + relative] ^= 1;
    assert!(ntfs_internal::verify(&mut Cursor::new(&changed), &raw).is_err());
    let mut torn = bytes.clone();
    torn[volume_start + 510] ^= 1;
    assert!(ntfs_internal::verify(&mut Cursor::new(&torn), &raw).is_err());
    let mut forged = raw.clone();
    let attribute = forged
        .files
        .iter_mut()
        .find(|file| file.record_number == 3)
        .unwrap()
        .attributes
        .iter_mut()
        .find(|attribute| attribute.type_code == 0x40)
        .unwrap();
    attribute.resident_metadata_hex = Some("ff".repeat(16));
    assert!(ntfs_internal::verify(&mut Cursor::new(&bytes), &forged).is_err());
    let mut changed_index = bytes.clone();
    changed_index[MFT + 17 * 1024 + 510] ^= 1;
    assert!(ntfs_internal::verify(&mut Cursor::new(&changed_index), &raw).is_err());
}
