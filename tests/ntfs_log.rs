use ntfs2refs::{ntfs_inspect::NtfsInspection, ntfs_log};

#[test]
#[ignore = "requires N2R_NATIVE_NTFS_CORPUS; reads Windows-created raw NTFS image read-only"]
fn clean_windows_restart_pages_survive_fixups_and_reject_torn_sector() {
    let corpus = std::path::PathBuf::from(
        std::env::var_os("N2R_NATIVE_NTFS_CORPUS").expect("explicit NTFS corpus directory"),
    );
    let inspection =
        std::fs::read(corpus.join("analysis-20261023T214015406Z/control-inspection.json")).unwrap();
    let value: serde_json::Value = serde_json::from_slice(&inspection).unwrap();
    let raw: NtfsInspection =
        serde_json::from_value(value["filesystem"]["details"].clone()).unwrap();
    let mut file = std::fs::File::open(corpus.join("control.raw")).unwrap();
    assert_eq!(file.metadata().unwrap().len(), 1073741824);
    let proof = ntfs_log::verify(&mut file, &raw).unwrap();
    assert!(proof.binds(&raw));
    assert!(proof.restart.candidate_clean_dismount);
    assert!(!proof.complete_log_recovery_proven);
    assert_eq!(proof.restart.first.flags, 2);
    assert_eq!(proof.restart.second.flags, 2);
    let mut log =
        ntfs2refs::ntfs_inspect::read_plain_stream(&mut file, &raw, 2, 128 * 1024 * 1024).unwrap();
    log[510] ^= 1;
    assert!(ntfs_log::parse_restart_pair(&log).is_err());
}
