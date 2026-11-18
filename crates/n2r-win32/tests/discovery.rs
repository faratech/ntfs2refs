use n2r_win32::{
    discovery::{self, Role, StorageEvidence},
    layout::guid_bytes,
};
const DISK: u64 = 8 * 1024 * 1024 * 1024;
const OFFSET: u64 = 16 * 1024 * 1024;
const SIZE: u64 = 6 * 1024 * 1024 * 1024;
const VOLUME: &str = "5f2d3e41-5555-4444-aabb-123456789abc";
fn p32(b: &mut [u8], at: usize, n: u32) {
    b[at..at + 4].copy_from_slice(&n.to_le_bytes());
}
fn p64(b: &mut [u8], at: usize, n: u64) {
    b[at..at + 8].copy_from_slice(&n.to_le_bytes());
}
fn fixture() -> StorageEvidence {
    let mut e = StorageEvidence {
        volume_extents: vec![0; 32],
        device: vec![0; 12],
        disk_length: DISK.to_le_bytes().to_vec(),
        alignment: vec![0; 28],
        gpt_layout: vec![0; 48 + 2 * 144],
        disk_attributes: vec![0; 16],
    };
    p32(&mut e.volume_extents, 0, 1);
    p32(&mut e.volume_extents, 8, 7);
    p64(&mut e.volume_extents, 16, OFFSET);
    p64(&mut e.volume_extents, 24, SIZE);
    p32(&mut e.device, 0, 7);
    p32(&mut e.device, 4, 7);
    for (at, n) in [(0, 28), (4, 28), (16, 512), (20, 4096)] {
        p32(&mut e.alignment, at, n);
    }
    p32(&mut e.disk_attributes, 0, 16);
    let g = &mut e.gpt_layout;
    p32(g, 0, 1);
    p32(g, 4, 2);
    g[8..24].copy_from_slice(&guid_bytes("12345678-1111-2222-aaaa-123456789abc").unwrap());
    p64(g, 24, 1 << 20);
    p64(g, 32, DISK - 2 * (1 << 20));
    for (index, number, start, size, kind, id) in [
        (
            0,
            1,
            1 << 20,
            15 << 20,
            "e3c9e316-0b5c-4db8-817d-f92df00215ae",
            "34567890-3333-4444-cccc-123456789abc",
        ),
        (
            1,
            2,
            OFFSET,
            SIZE,
            "ebd0a0a2-b9e5-4433-87c0-68b6b72699c7",
            "23456789-2222-3333-bbbb-123456789abc",
        ),
    ] {
        let at = 48 + index * 144;
        p32(g, at, 1);
        p64(g, at + 8, start);
        p64(g, at + 16, size);
        p32(g, at + 24, number);
        g[at + 32..at + 48].copy_from_slice(&guid_bytes(kind).unwrap());
        g[at + 48..at + 64].copy_from_slice(&guid_bytes(id).unwrap());
    }
    e
}
#[test]
fn explicit_roots_reject_paths_that_could_silently_resolve_to_another_volume() {
    for root in [
        "F:\\",
        "C:\\Mount\\Data\\",
        "\\\\?\\Volume{5f2d3e41-5555-4444-aabb-123456789abc}\\",
    ] {
        discovery::validate_root(root).unwrap();
    }
    for root in [
        "F:",
        "relative\\",
        "\\\\server\\share\\",
        "\\Device\\HarddiskVolume1\\",
        "C:\\..\\",
        "C:\\path \\",
        "C:\\foo\\\\",
        "C:\\x:y\\",
        "C:/",
        "C:\\*\\",
    ] {
        assert!(discovery::validate_root(root).is_err(), "{root}");
    }
}
#[test]
fn binding_is_derived_from_the_single_actual_gpt_extent_and_sector_geometry() {
    let e = fixture();
    let b = discovery::binding_from_evidence(VOLUME, &e, Role::Source, 0).unwrap();
    assert_eq!(b.disk_number, 7);
    assert_eq!(b.volume_guid, VOLUME);
    assert_eq!(b.identity.partition_number, 2);
    assert_eq!(b.identity.disk_guid, "12345678-1111-2222-aaaa-123456789abc");
    assert_eq!(
        b.identity.partition_guid,
        "23456789-2222-3333-bbbb-123456789abc"
    );
    assert_eq!(b.identity.partition_offset, OFFSET);
    assert_eq!(b.identity.partition_bytes, SIZE);
    assert_eq!(b.identity.logical_sector_bytes, 512);
    assert_eq!(b.identity.physical_sector_bytes, 4096);
    assert_eq!(
        discovery::volume_guid(&format!("\\\\?\\Volume{{{VOLUME}}}\\")).unwrap(),
        VOLUME
    );
}
#[test]
fn windows_and_additional_partition_roles_require_explicit_journal_permission() {
    let e = fixture();
    for role in [
        Role::Source,
        Role::Shadow,
        Role::Journal {
            allow_additional_partitions: false,
        },
    ] {
        assert!(discovery::binding_from_evidence(VOLUME, &e, role, 7).is_err());
    }
    discovery::binding_from_evidence(
        VOLUME,
        &e,
        Role::Journal {
            allow_additional_partitions: true,
        },
        7,
    )
    .unwrap();
    let mut with_efi = e;
    with_efi.gpt_layout[80..96]
        .copy_from_slice(&guid_bytes("c12a7328-f81f-11d2-ba4b-00a0c93ec93b").unwrap());
    // A data volume beside another partition is bound as a shared data
    // disk, unless the disk is the running Windows disk. A shadow never is.
    let shared = discovery::binding_from_evidence(VOLUME, &with_efi, Role::Source, 0).unwrap();
    assert_eq!(
        shared.layout_profile,
        n2r_win32::general_layout::GeneralDiskLayoutProfile::SharedData
    );
    assert!(discovery::binding_from_evidence(VOLUME, &with_efi, Role::Source, 7).is_err());
    assert!(discovery::binding_from_evidence(VOLUME, &with_efi, Role::Shadow, 0).is_err());
    // With nothing beside it but the reserved partition, a dedicated one.
    assert_eq!(
        discovery::binding_from_evidence(VOLUME, &fixture(), Role::Source, 0)
            .unwrap()
            .layout_profile,
        n2r_win32::general_layout::GeneralDiskLayoutProfile::DedicatedData
    );
    assert!(
        discovery::binding_from_evidence(
            VOLUME,
            &with_efi,
            Role::Journal {
                allow_additional_partitions: false
            },
            0
        )
        .is_err()
    );
    discovery::binding_from_evidence(
        VOLUME,
        &with_efi,
        Role::Journal {
            allow_additional_partitions: true,
        },
        7,
    )
    .unwrap();
}
#[test]
fn multi_extent_incomplete_mbr_overlap_alias_and_changed_native_routes_are_refused() {
    for case in 0..13 {
        let mut e = fixture();
        match case {
            0 => p32(&mut e.volume_extents, 0, 2),
            1 => {
                e.volume_extents.pop();
            }
            2 => p32(&mut e.gpt_layout, 0, 0),
            3 => p32(&mut e.gpt_layout, 4, 3),
            4 => p64(&mut e.gpt_layout, 48 + 144 + 8, 8 << 20),
            5 => p32(&mut e.gpt_layout, 48 + 144 + 24, 1),
            6 => {
                let id = e.gpt_layout[96..112].to_vec();
                e.gpt_layout[48 + 144 + 48..48 + 144 + 64].copy_from_slice(&id);
            }
            7 => p32(&mut e.device, 4, 8),
            8 => p64(&mut e.volume_extents, 24, SIZE - 4096),
            9 => p32(&mut e.alignment, 20, 0),
            10 => p64(&mut e.disk_attributes, 8, 2),
            11 => p64(&mut e.gpt_layout, 48 + 144 + 64, 1),
            _ => {
                e.gpt_layout[8..24].fill(0);
            }
        }
        assert!(
            discovery::binding_from_evidence(VOLUME, &e, Role::Source, 0).is_err(),
            "case {case}"
        );
    }
}

fn mbr_fixture() -> StorageEvidence {
    let mut e = fixture();
    let g = &mut e.gpt_layout;
    g.fill(0);
    p32(g, 4, 2);
    p32(g, 8, 0x9abc_def0);
    for (index, number, start, size) in [(0, 1, 1 << 20, 15 << 20), (1, 2, OFFSET, SIZE)] {
        let at = 48 + index * 144;
        p64(g, at + 8, start);
        p64(g, at + 16, size);
        p32(g, at + 24, number);
        g[at + 32] = 0x07;
        g[at + 34] = 1;
    }
    e
}

#[test]
fn working_storage_and_a_data_volume_may_lie_on_an_mbr_disk_identified_by_its_signature() {
    let e = mbr_fixture();
    let working = Role::Journal {
        allow_additional_partitions: true,
    };
    let b = discovery::binding_from_evidence(VOLUME, &e, working, 0).unwrap();
    assert_eq!(b.disk_number, 7);
    assert_eq!(b.identity.partition_number, 2);
    assert_eq!(b.identity.disk_guid, "9abcdef0-4d42-5220-6469-736b00000000");
    assert!(n2r_win32::mbr_layout::is_mbr_disk(&b.identity.disk_guid));
    assert_ne!(b.identity.partition_guid, b.identity.disk_guid);
    assert_eq!(b.identity.partition_offset, OFFSET);
    assert_eq!(b.identity.partition_bytes, SIZE);
    // The same disk read again is the same binding: a recovery compares them.
    assert_eq!(
        b,
        discovery::binding_from_evidence(VOLUME, &e, working, 0).unwrap()
    );
    assert_eq!(
        n2r_win32::journal_file::enrolled_disk_label(&b.identity.disk_guid),
        "mbr-9abcdef0"
    );
    assert_eq!(
        n2r_win32::journal_file::enrolled_disk_label("{12345678-1111-2222-aaaa-123456789abc}"),
        "gpt-12345678-1111-2222-aaaa-123456789abc"
    );
    // A data volume to convert is found the same way, with a partition
    // beside it as where it has the disk to itself: the disk is a shared
    // one, whose other volumes go offline with it, as on GPT.
    let shared = discovery::binding_from_evidence(VOLUME, &e, Role::Source, 0).unwrap();
    assert_eq!(shared.identity, b.identity);
    assert_eq!(
        shared.layout_profile,
        n2r_win32::general_layout::GeneralDiskLayoutProfile::SharedData
    );
    assert_eq!(
        shared,
        discovery::binding_from_evidence(VOLUME, &e, Role::Source, 0).unwrap()
    );
    let mut alone = mbr_fixture();
    alone.gpt_layout[48..48 + 144].fill(0);
    let alone = discovery::binding_from_evidence(VOLUME, &alone, Role::Source, 0).unwrap();
    assert_eq!(alone.identity, b.identity);
    assert_eq!(
        alone.layout_profile,
        n2r_win32::general_layout::GeneralDiskLayoutProfile::DedicatedData
    );
    // The Windows disk is no source, MBR or not.
    let mut on_windows_disk = mbr_fixture();
    on_windows_disk.gpt_layout[48..48 + 144].fill(0);
    assert!(discovery::binding_from_evidence(VOLUME, &on_windows_disk, Role::Source, 7).is_err());
    // An installed Windows to convert, the shadow, and working storage that
    // must have a disk to itself stay with GPT.
    for role in [
        Role::OfflineWindowsSource,
        Role::Shadow,
        Role::ShadowReadOnly,
        Role::Journal {
            allow_additional_partitions: false,
        },
    ] {
        let error = discovery::binding_from_evidence(VOLUME, &e, role, 0).unwrap_err();
        assert!(error.to_string().contains("GPT disk required"), "{error}");
    }
}
