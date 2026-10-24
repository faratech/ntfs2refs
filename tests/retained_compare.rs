use ntfs2refs::retained_compare::{
    RetainedCompareRequest, RetainedComparison, RetainedRangeRequest, compare_retained,
};
use sha2::{Digest, Sha256};
use std::{fs, path::PathBuf};

fn sha(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

struct Fixture {
    _dir: tempfile::TempDir,
    source: PathBuf,
    shadow: PathBuf,
    left: Vec<u8>,
    right: Vec<u8>,
    request: RetainedCompareRequest,
}
impl Fixture {
    fn new(left: Vec<u8>, right: Vec<u8>, ranges: &[(usize, usize)], sector_size: u32) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("source.raw");
        let shadow = dir.path().join("shadow.raw");
        fs::write(&source, &left).unwrap();
        fs::write(&shadow, &right).unwrap();
        let request = RetainedCompareRequest {
            schema_version: 1,
            sector_size,
            expected_length: left.len() as u64,
            source_sha256: sha(&left),
            shadow_sha256: sha(&right),
            retained_ranges: ranges
                .iter()
                .map(|&(offset, length)| RetainedRangeRequest {
                    offset: offset as u64,
                    length: length as u64,
                    source_sha256: sha(&left[offset..offset + length]),
                    shadow_sha256: sha(&right[offset..offset + length]),
                })
                .collect(),
            max_change_bytes: left.len() as u64,
            max_ranges: 65_536,
        };
        Self {
            _dir: dir,
            source,
            shadow,
            left,
            right,
            request,
        }
    }
    fn compare(&self) -> RetainedComparison {
        compare_retained(&self.source, &self.shadow, &self.request).unwrap()
    }
    fn reject(&self) -> String {
        compare_retained(&self.source, &self.shadow, &self.request)
            .unwrap_err()
            .to_string()
    }
    /// Actually apply the report in memory, independently build the expected
    /// mosaic, and compare every byte. This test never writes a target image.
    fn verify_reconstruction(&self, report: &RetainedComparison) {
        let mut reconstructed = self.left.clone();
        let mut end = 0;
        let mut patch_bytes = 0;
        for patch in &report.patches {
            assert!(patch.offset >= end && patch.length > 0);
            assert_eq!(patch.offset % u64::from(self.request.sector_size), 0);
            assert_eq!(patch.length % u64::from(self.request.sector_size), 0);
            let first = patch.offset as usize;
            let last = (patch.offset + patch.length) as usize;
            for retained in &self.request.retained_ranges {
                assert!(
                    patch.offset + patch.length <= retained.offset
                        || retained.offset + retained.length <= patch.offset
                );
            }
            assert_eq!(patch.before_sha256, sha(&self.left[first..last]));
            assert_eq!(patch.after_sha256, sha(&self.right[first..last]));
            reconstructed[first..last].copy_from_slice(&self.right[first..last]);
            end = patch.offset + patch.length;
            patch_bytes += patch.length;
        }
        let mut expected = self.right.clone();
        for retained in &self.request.retained_ranges {
            let start = retained.offset as usize;
            let end = (retained.offset + retained.length) as usize;
            expected[start..end].copy_from_slice(&self.left[start..end]);
        }
        assert_eq!(reconstructed, expected);
        assert_eq!(report.expected_postimage_sha256, sha(&expected));
        assert_eq!(report.patch_bytes, patch_bytes);
        assert_eq!(report.compared_bytes, self.left.len() as u64);
        assert_eq!(
            report.full_scan_input_bytes_read,
            self.left.len() as u64 * 4
        );
        assert_eq!(
            report.total_input_bytes_read,
            self.left.len() as u64 * 4 + 32
        );
        assert!(report.source_shadow_unchanged_after_comparison);
        assert!(!report.executable && !report.conversion_qualified && !report.boot_qualified);
        assert!(
            !report.native_attestations_verified
                && !report.retained_file_semantics_verified
                && !report.allocation_qualified
        );
        assert_eq!(fs::read(&self.source).unwrap(), self.left);
        assert_eq!(fs::read(&self.shadow).unwrap(), self.right);
    }
}

#[test]
fn preserves_complete_64k_payload_and_all_other_changed_sectors() {
    let mut source = vec![0; 131_072];
    for (i, byte) in source[16_384..81_920].iter_mut().enumerate() {
        *byte = (i.wrapping_mul(29) % 251 + 1) as u8;
    }
    let mut shadow = source.clone();
    shadow[16_384..81_920].fill(0x72);
    shadow[0] = 7;
    shadow[512..1024].fill(0x41);
    shadow[12_000] = 8;
    shadow[131_071] = 9;
    let fixture = Fixture::new(source, shadow, &[(16_384, 65_536)], 512);
    let report = fixture.compare();
    assert_eq!(report.patches.len(), 3);
    assert_eq!(
        (report.patches[0].offset, report.patches[0].length),
        (0, 1024)
    );
    assert_eq!(report.patch_bytes, 2048);
    assert_eq!(report.nonretained_differing_bytes, 515);
    assert_eq!(report.retained_ranges[0].bytes_compared, 65_536);
    assert!(report.retained_ranges[0].differing_bytes > 0);
    fixture.verify_reconstruction(&report);
}

#[test]
fn exhaustive_small_sector_masks_reconstruct_the_mosaic() {
    for mask in 0_u32..256 {
        let source = vec![0x21; 4096];
        let mut shadow = source.clone();
        for sector in 0..8 {
            if mask & (1 << sector) != 0 {
                shadow[sector * 512 + 37] ^= 0xff;
            }
        }
        let fixture = Fixture::new(source, shadow, &[(512, 512), (2560, 1024)], 512);
        let report = fixture.compare();
        let retained_changed = (mask & ((1 << 1) | (1 << 5) | (1 << 6))).count_ones() as u64;
        assert_eq!(report.differing_bytes, u64::from(mask.count_ones()));
        assert_eq!(report.retained_differing_bytes, retained_changed);
        assert_eq!(
            report.patch_bytes,
            (u64::from(mask.count_ones()) - retained_changed) * 512
        );
        fixture.verify_reconstruction(&report);
    }
}

#[test]
fn coalesces_across_streaming_buffer_boundaries() {
    let source = vec![0x31; 2 * 1024 * 1024];
    let mut shadow = source.clone();
    shadow[1024 * 1024 - 512..1024 * 1024 + 1024].fill(0x43);
    let fixture = Fixture::new(source, shadow, &[(512, 512)], 512);
    let report = fixture.compare();
    assert_eq!(report.patches.len(), 1);
    assert_eq!(report.patches[0].length, 1536);
    fixture.verify_reconstruction(&report);
}

#[test]
fn adjacent_retained_ranges_and_4kn_have_independent_full_hash_proofs() {
    let fixture = Fixture::new(
        vec![0x23; 32_768],
        vec![0x45; 32_768],
        &[(4096, 4096), (8192, 4096)],
        4096,
    );
    let report = fixture.compare();
    assert_eq!(report.retained_ranges.len(), 2);
    assert_eq!(report.retained_differing_sectors, 2);
    assert_eq!(report.patch_bytes, 24_576);
    fixture.verify_reconstruction(&report);
}

#[test]
fn equal_retained_bytes_and_identical_input_alias_are_allowed() {
    let mut fixture = Fixture::new(vec![0; 4096], vec![0; 4096], &[(512, 512)], 512);
    fixture.request.max_change_bytes = 0;
    let report = compare_retained(&fixture.source, &fixture.source, &fixture.request).unwrap();
    assert_eq!(report.retained_differing_bytes, 0);
    assert!(report.patches.is_empty());
    fixture.verify_reconstruction(&report);
}

#[test]
fn wholly_retained_image_has_no_patches_but_checks_all_bytes() {
    let mut fixture = Fixture::new(vec![1; 4096], vec![2; 4096], &[(0, 4096)], 512);
    fixture.request.max_change_bytes = 0;
    let report = fixture.compare();
    assert_eq!(report.expected_postimage_sha256, sha(&fixture.left));
    assert_eq!(report.retained_differing_bytes, 4096);
    assert_eq!(report.nonretained_differing_bytes, 0);
    fixture.verify_reconstruction(&report);
}

#[test]
fn sector_budget_counts_unchanged_bytes_in_differing_sectors() {
    let mut shadow = vec![0; 4096];
    shadow[0] = 1;
    let mut fixture = Fixture::new(vec![0; 4096], shadow, &[(1024, 512)], 512);
    fixture.request.max_change_bytes = 511;
    assert!(
        fixture
            .reject()
            .contains("changed-sector byte budget exceeded")
    );
    fixture.request.max_change_bytes = 512;
    assert_eq!(fixture.compare().patch_bytes, 512);
}

#[test]
fn range_budget_fails_instead_of_truncating() {
    let mut shadow = vec![0; 4096];
    shadow[0] = 1;
    shadow[2048] = 1;
    let mut fixture = Fixture::new(vec![0; 4096], shadow, &[(1024, 512)], 512);
    fixture.request.max_ranges = 1;
    assert!(fixture.reject().contains("patch range budget exceeded"));
    fixture.request.max_ranges = 2;
    assert_eq!(fixture.compare().patches.len(), 2);
}

#[test]
fn retained_interval_splits_adjacent_differences() {
    let fixture = Fixture::new(vec![1; 4096], vec![2; 4096], &[(1536, 512)], 512);
    let report = fixture.compare();
    assert_eq!(report.patches.len(), 2);
    assert_eq!(
        (report.patches[0].offset, report.patches[0].length),
        (0, 1536)
    );
    assert_eq!(
        (report.patches[1].offset, report.patches[1].length),
        (2048, 2048)
    );
    fixture.verify_reconstruction(&report);
}

#[test]
fn rejects_bad_full_image_and_retained_pins() {
    let fixture = Fixture::new(vec![1; 4096], vec![2; 4096], &[(512, 512)], 512);
    for field in 0..4 {
        let mut request = fixture.request.clone();
        match field {
            0 => request.source_sha256 = "0".repeat(64),
            1 => request.shadow_sha256 = "0".repeat(64),
            2 => request.retained_ranges[0].source_sha256 = "0".repeat(64),
            _ => request.retained_ranges[0].shadow_sha256 = "0".repeat(64),
        }
        assert!(
            compare_retained(&fixture.source, &fixture.shadow, &request)
                .unwrap_err()
                .to_string()
                .contains("pin differs")
        );
    }
}

#[test]
fn retained_last_byte_is_covered_not_just_a_prefix() {
    let mut fixture = Fixture::new(vec![1; 131_072], vec![2; 131_072], &[(16_384, 65_536)], 512);
    fixture.left[81_919] = 3;
    fs::write(&fixture.source, &fixture.left).unwrap();
    fixture.request.source_sha256 = sha(&fixture.left);
    assert!(
        fixture
            .reject()
            .contains("retained range SHA-256 pin differs")
    );
}

#[test]
fn rejects_invalid_range_shapes_and_request_budgets() {
    let fixture = Fixture::new(
        vec![1; 4096],
        vec![2; 4096],
        &[(512, 512), (2048, 512)],
        512,
    );
    for case in 0..14 {
        let mut request = fixture.request.clone();
        match case {
            0 => request.schema_version = 2,
            1 => request.sector_size = 1024,
            2 => request.expected_length = 4095,
            3 => request.expected_length = 128 * 1024 * 1024 * 1024 + 512,
            4 => request.retained_ranges.clear(),
            5 => request.retained_ranges[0].length = 0,
            6 => request.retained_ranges[0].offset = 513,
            7 => request.retained_ranges[0].length = 513,
            8 => request.retained_ranges.swap(0, 1),
            9 => request.retained_ranges[1].offset = 512,
            10 => request.retained_ranges[1].length = 4096,
            11 => request.max_ranges = 0,
            12 => request.max_ranges = 65_537,
            _ => request.max_change_bytes = 4097,
        }
        assert!(
            compare_retained(&fixture.source, &fixture.shadow, &request).is_err(),
            "case {case}"
        );
    }
    let mut request = fixture.request.clone();
    request.retained_ranges[0].offset = u64::MAX - 511;
    assert!(
        compare_retained(&fixture.source, &fixture.shadow, &request)
            .unwrap_err()
            .to_string()
            .contains("overflow")
    );
    request = fixture.request.clone();
    request.retained_ranges = vec![request.retained_ranges[0].clone(); 1025];
    assert!(compare_retained(&fixture.source, &fixture.shadow, &request).is_err());
}

#[test]
fn rejects_noncanonical_hashes_and_unknown_request_fields() {
    let fixture = Fixture::new(vec![1; 4096], vec![2; 4096], &[(512, 512)], 512);
    for hash in ["a".repeat(63), "g".repeat(64), "A".repeat(64)] {
        let mut request = fixture.request.clone();
        request.source_sha256 = hash;
        assert!(compare_retained(&fixture.source, &fixture.shadow, &request).is_err());
    }
    let mut value = serde_json::to_value(&fixture.request).unwrap();
    value["executable"] = true.into();
    assert!(serde_json::from_value::<RetainedCompareRequest>(value).is_err());
    let mut value = serde_json::to_value(&fixture.request).unwrap();
    value["retained_ranges"][0]["semantics_verified"] = true.into();
    assert!(serde_json::from_value::<RetainedCompareRequest>(value).is_err());
}

#[test]
fn rejects_wrong_lengths_directories_and_parent_traversal() {
    let fixture = Fixture::new(vec![1; 4096], vec![2; 4096], &[(512, 512)], 512);
    fs::write(&fixture.shadow, vec![2; 4095]).unwrap();
    assert!(fixture.reject().contains("length/type"));
    assert!(
        compare_retained(
            fixture.source.parent().unwrap(),
            &fixture.source,
            &fixture.request
        )
        .is_err()
    );
    let traversed = fixture
        .source
        .parent()
        .unwrap()
        .join("child")
        .join("..")
        .join("source.raw");
    assert!(
        compare_retained(&traversed, &fixture.source, &fixture.request)
            .unwrap_err()
            .to_string()
            .contains("parent traversal")
    );
}

#[test]
fn rejects_container_signatures_even_with_matching_pins() {
    for (at, magic) in [
        (0, b"vhdxfile"),
        (0, b"conectix"),
        (4096 - 512, b"conectix"),
    ] {
        let mut source = vec![0; 4096];
        source[at..at + 8].copy_from_slice(magic);
        let fixture = Fixture::new(source, vec![0; 4096], &[(512, 512)], 512);
        assert!(fixture.reject().contains("not a raw image"));
    }
}

#[test]
fn rejects_redirected_regular_files() {
    let fixture = Fixture::new(vec![1; 4096], vec![2; 4096], &[(512, 512)], 512);
    let link = fixture.source.parent().unwrap().join("link.raw");
    #[cfg(windows)]
    if let Err(error) = std::os::windows::fs::symlink_file(&fixture.source, &link) {
        if error.kind() == std::io::ErrorKind::PermissionDenied {
            eprintln!(
                "Skipping Windows symlink test: creating the test link requires elevation or Developer Mode."
            );
            return;
        }
        panic!("create test symlink: {error}");
    }
    #[cfg(unix)]
    std::os::unix::fs::symlink(&fixture.source, &link).unwrap();
    assert!(compare_retained(&link, &fixture.shadow, &fixture.request).is_err());
}

#[cfg(windows)]
#[test]
fn rejects_windows_devices_namespaces_and_alternate_streams_before_open() {
    let fixture = Fixture::new(vec![1; 4096], vec![2; 4096], &[(512, 512)], 512);
    for path in [
        r"NUL",
        r"COM1.raw",
        r"\\.\PhysicalDrive0",
        r"\\?\C:\source.raw",
        r"C:source.raw",
        r"\source.raw",
        r"C:\source.raw:payload",
    ] {
        assert!(
            compare_retained(
                std::path::Path::new(path),
                &fixture.shadow,
                &fixture.request
            )
            .is_err()
        );
    }
}
