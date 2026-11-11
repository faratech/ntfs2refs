//! Recover-only enrolled-lab marker fault receipt. This owns only its new C0
//! signal and engine-produced fixed marker buffers, never a journal/device
//! handle. The sealed native owner performs every prerequisite and marker I/O.
use super::*;
use sha2::{Digest, Sha256};
use std::{
    fs::{File, OpenOptions},
    io::{Cursor, Seek, SeekFrom, Write},
    os::windows::{fs::MetadataExt, fs::OpenOptionsExt, io::AsRawHandle},
    path::{Path, PathBuf},
};
use windows_sys::Win32::{
    Foundation::FILETIME,
    Storage::FileSystem::{
        FILE_INFO_BY_HANDLE_CLASS, FileAttributeTagInfo, FileIdInfo, FileStandardInfo,
        GetFileInformationByHandleEx,
    },
    System::Threading::{GetCurrentProcess, GetProcessTimes},
};

const SIGNAL_BYTES: usize = 32768;
const MARKER_BYTES: usize = 4096;
const C0_VOLUME: &str = "c6c3318f-a7c8-47b9-be6d-6dde5e00862f";
const ZERO_DIGEST: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LabMarkerFaultCopy {
    Ap2,
    Rb2,
    Hnd2,
    Abt2,
}

impl LabMarkerFaultCopy {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Ap2 => "AP2",
            Self::Rb2 => "RB2",
            Self::Hnd2 => "HND2",
            Self::Abt2 => "ABT2",
        }
    }

    pub(super) const fn slot(self) -> usize {
        match self {
            Self::Ap2 => 1,
            Self::Rb2 => 3,
            Self::Hnd2 => 5,
            Self::Abt2 => 7,
        }
    }
}

impl std::str::FromStr for LabMarkerFaultCopy {
    type Err = io::Error;

    fn from_str(value: &str) -> io::Result<Self> {
        match value {
            "AP2" => Ok(Self::Ap2),
            "RB2" => Ok(Self::Rb2),
            "HND2" => Ok(Self::Hnd2),
            "ABT2" => Ok(Self::Abt2),
            _ => Err(invalid("marker fault copy must be AP2/RB2/HND2/ABT2")),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LabMarkerFaultKind {
    CorruptPeer,
    WriteError,
    FlushError,
    ReadbackError,
}

impl LabMarkerFaultKind {
    pub const fn label(self) -> &'static str {
        match self {
            Self::CorruptPeer => "corrupt-peer",
            Self::WriteError => "write-error",
            Self::FlushError => "flush-error",
            Self::ReadbackError => "readback-error",
        }
    }

    const fn synthetic(self) -> bool {
        !matches!(self, Self::CorruptPeer)
    }

    const fn skipped_api(self) -> Option<&'static str> {
        match self {
            Self::CorruptPeer => None,
            Self::WriteError => Some("WriteFile"),
            Self::FlushError => Some("FlushFileBuffers"),
            Self::ReadbackError => Some("ReadFile"),
        }
    }

    const fn observed_peer_scope(self) -> &'static str {
        match self {
            Self::CorruptPeer => "post-corruption-uncached-readback",
            Self::WriteError => "pre-write-inactive-zero-peer",
            Self::FlushError | Self::ReadbackError => "unobserved-after-written-peer",
        }
    }
}

impl std::str::FromStr for LabMarkerFaultKind {
    type Err = io::Error;

    fn from_str(value: &str) -> io::Result<Self> {
        match value {
            "corrupt-peer" => Ok(Self::CorruptPeer),
            "write-error" => Ok(Self::WriteError),
            "flush-error" => Ok(Self::FlushError),
            "readback-error" => Ok(Self::ReadbackError),
            _ => Err(invalid(
                "marker fault kind must be corrupt-peer/write-error/flush-error/readback-error",
            )),
        }
    }
}

/// Lab intent only; fixed engine-produced marker bytes and actual owned-storage
/// checks are still required. This request grants no source or journal access.
pub struct LabMarkerFaultRequest {
    pub marker_copy: LabMarkerFaultCopy,
    pub kind: LabMarkerFaultKind,
    pub signal_path: PathBuf,
}

pub struct LabMarkerFault {
    copy: LabMarkerFaultCopy,
    kind: LabMarkerFaultKind,
    signal_path: PathBuf,
    file: Option<File>,
    signal_snapshot: crate::reference_file::ReferenceFileSnapshot,
    argv: Vec<String>,
    pid: u32,
    created: u64,
    created_unix_ms: u64,
    maximum_journal_bytes: u64,
    expected_first: Box<[u8; MARKER_BYTES]>,
    expected_peer: Box<[u8; MARKER_BYTES]>,
    corrupt_peer: Box<[u8; MARKER_BYTES]>,
    expected_first_digest: [u8; 32],
    expected_peer_digest: [u8; 32],
    corrupt_peer_digest: [u8; 32],
    zero_peer_digest: [u8; 32],
    bytes: Box<[u8; SIGNAL_BYTES]>,
    patches: Option<DigestPatches>,
}

struct DigestPatches {
    first: usize,
    peer: usize,
    observed: Option<usize>,
}

/// Borrowed serialization writes directly into the reserved signal buffer.
/// No Value tree, temporary JSON Vec or formatter allocation is needed at bind.
#[derive(Serialize)]
struct FaultReceipt<'a> {
    schema_version: u32,
    kind: &'static str,
    lab_only: bool,
    native_marker_qualified: bool,
    computer_name: &'static str,
    argv: &'a [String],
    pid: u32,
    process_creation_filetime_100ns: u64,
    process_creation_unix_ms: u64,
    journal_format_version: u32,
    journal_format: &'static str,
    journal_profile: &'static str,
    maximum_journal_bytes: u64,
    marker_profile: &'static str,
    marker_copy: &'static str,
    marker_slot: usize,
    marker_file_offset: usize,
    marker_device_offset: u64,
    marker_bytes: usize,
    first_peer_file_offset: usize,
    signal_path: &'a Path,
    signal_bytes: usize,
    fault_kind: &'static str,
    synthetic_error: bool,
    actual_os_error: bool,
    injected_win32_error: Option<u32>,
    skipped_api: Option<&'static str>,
    skipped_api_issued: bool,
    io_fact_scope: &'static str,
    marker_write_issued: bool,
    marker_write_completed: bool,
    marker_flush_issued: bool,
    marker_flush_completed: bool,
    marker_readback_issued: bool,
    marker_readback_completed: bool,
    intact_first_peer_verified_before_fault: bool,
    inactive_peer_verified_exact_zero_before_fault: bool,
    intact_first_peer_verified_after_fault: bool,
    storage_revalidated_before_fault: bool,
    storage_revalidated_after_fault: bool,
    corruption: Option<&'static str>,
    observed_peer_sha256_scope: &'static str,
    intact_first_peer_sha256: &'static str,
    requested_peer_sha256: &'static str,
    observed_peer_sha256: Option<&'static str>,
    journal_poisoned: bool,
    journal_owner_retained_at_signal_publish: bool,
    data_plane_writes_by_facility: bool,
    signal_synced_before_readable: bool,
    automatic_continue: bool,
    timeout: bool,
    parks_after_publish: bool,
    requires_external_hard_poweroff: bool,
    expected_native_exit: Option<i32>,
    serialized_record_grants_authority: bool,
    storage: &'a MarkerStorageObservation,
    signal_identity: &'a crate::reference_file::ReferenceFileSnapshot,
}

fn birth() -> io::Result<u64> {
    let zero = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    let (mut created, mut exited, mut kernel, mut user) = (zero, zero, zero, zero);
    // SAFETY: borrowed current-process pseudo-handle and initialized outputs.
    if unsafe {
        GetProcessTimes(
            GetCurrentProcess(),
            &mut created,
            &mut exited,
            &mut kernel,
            &mut user,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok((u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime))
}

impl LabMarkerFaultRequest {
    #[allow(clippy::too_many_arguments)]
    pub fn reserve(
        self,
        output: &Path,
        binding: &GeneralJournalStorageBinding,
        source: &crate::general_layout::GeneralDiskBinding,
        shadow: &crate::general_layout::GeneralDiskBinding,
        profile: JournalProfile,
        expected_first: [u8; MARKER_BYTES],
        expected_peer: [u8; MARKER_BYTES],
        corrupt_peer: [u8; MARKER_BYTES],
    ) -> io::Result<LabMarkerFault> {
        let identity = &binding.disk.identity;
        require(
            std::env::var("COMPUTERNAME").ok().as_deref() == Some("N2R-WIN11")
                && matches!(profile, JournalProfile::CapacityPinnedV3 { max_journal_bytes } if max_journal_bytes == 8 * 1024 * 1024 * 1024)
                && binding.disk.disk_number == 0
                && binding.disk.volume_guid.eq_ignore_ascii_case(C0_VOLUME)
                && identity
                    .disk_guid
                    .eq_ignore_ascii_case("1f804918-e98f-4a71-9022-fc00c3cb7c26")
                && identity.partition_guid.eq_ignore_ascii_case(C0_VOLUME)
                && identity.partition_number == 3
                && identity.disk_bytes == 68719476736
                && identity.partition_offset == 331350016
                && identity.partition_bytes == 66238545920
                && identity.logical_sector_bytes == 512
                && identity.physical_sector_bytes == 4096
                && binding.allow_additional_partitions
                && binding.externally_enrolled_disk_unique_id
                    == "gpt-1f804918-e98f-4a71-9022-fc00c3cb7c26"
                && source.disk_number != 0
                && shadow.disk_number != 0
                && !source
                    .identity
                    .disk_guid
                    .eq_ignore_ascii_case(&identity.disk_guid)
                && !shadow
                    .identity
                    .disk_guid
                    .eq_ignore_ascii_case(&identity.disk_guid)
                && !source.volume_guid.eq_ignore_ascii_case(C0_VOLUME)
                && !shadow.volume_guid.eq_ignore_ascii_case(C0_VOLUME),
            "marker fault requires the exact independent enrolled C0 native lab profile",
        )?;
        require(
            expected_first != expected_peer
                && corrupt_peer[..MARKER_BYTES - 1] == expected_peer[..MARKER_BYTES - 1]
                && corrupt_peer[MARKER_BYTES - 1] == (expected_peer[MARKER_BYTES - 1] ^ 1),
            "engine marker fault buffers must differ only by the fixed peer self-hash bit",
        )?;
        let output_text = output
            .to_str()
            .ok_or_else(|| invalid("marker fault output must be Unicode"))?;
        require(
            output_text.starts_with("C:\\ntfs2refs\\")
                && output_text.len() <= 384
                && !output_text.contains(['/', '\0'])
                && self.signal_path == output.join("marker-fault.json"),
            "marker fault signal must be marker-fault.json directly inside the fresh C0 output",
        )?;
        for component in output_text[3..].split('\\') {
            require(
                !component.is_empty()
                    && component.len() <= 96
                    && !component.starts_with('.')
                    && !component.ends_with(['.', ' '])
                    && component
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.')),
                "marker fault output requires bounded ordinary path components",
            )?;
        }
        for ancestor in output.ancestors() {
            let metadata = std::fs::symlink_metadata(ancestor)?;
            require(
                metadata.is_dir() && metadata.file_attributes() & 0x400 == 0,
                "marker fault ancestry must be ordinary existing directories",
            )?;
        }
        let mut argv = Vec::with_capacity(64);
        let mut argv_units = 0usize;
        for argument in std::env::args_os() {
            let argument = argument
                .into_string()
                .map_err(|_| invalid("marker fault argv must be Unicode"))?;
            argv_units = argv_units
                .checked_add(argument.encode_utf16().count())
                .ok_or_else(|| invalid("marker fault argv overflow"))?;
            require(
                argv.len() < 64 && argument.len() <= 2048 && argv_units <= 8192,
                "marker fault exact argv exceeds bounded metadata capacity",
            )?;
            argv.push(argument);
        }
        require(
            argv.iter().any(|arg| arg == "recover") && !argv.iter().any(|arg| arg == "fresh"),
            "marker fault is recover-only and cannot enter a fresh source path",
        )?;
        let created = birth()?;
        let created_unix_ms = created
            .checked_sub(116444736000000000)
            .ok_or_else(|| invalid("marker fault process birth predates Unix epoch"))?
            / 10000;
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .share_mode(0)
            .custom_flags(0x0020_0000 | 0x8000_0000)
            .open(&self.signal_path)?;
        let snapshot = crate::reference_file::observe_reference_file_handle(&file)?;
        let expected_path = format!(
            "\\\\?\\Volume{{{C0_VOLUME}}}\\{}\\marker-fault.json",
            &output_text[3..]
        );
        require(
            snapshot.file_bytes == 0
                && snapshot.number_of_links == 1
                && snapshot.final_path.eq_ignore_ascii_case(&expected_path),
            "marker fault signal is not the exact fresh ordinary C0 file",
        )?;
        observe_general_journal_file_with_profile(&file, binding, profile)?;
        let bytes = Box::new([0; SIGNAL_BYTES]);
        file.write_all(&bytes[..])?;
        file.sync_all()?;
        file.seek(SeekFrom::Start(0))?;
        let signal_snapshot = crate::reference_file::observe_reference_file_handle(&file)?;
        require(
            signal_snapshot.file_bytes == SIGNAL_BYTES as u64
                && signal_snapshot.number_of_links == 1
                && signal_snapshot.file_id_128 == snapshot.file_id_128
                && signal_snapshot.final_path == snapshot.final_path,
            "marker fault preallocated signal identity changed",
        )?;
        Ok(LabMarkerFault {
            copy: self.marker_copy,
            kind: self.kind,
            signal_path: self.signal_path,
            file: Some(file),
            signal_snapshot,
            argv,
            pid: std::process::id(),
            created,
            created_unix_ms,
            maximum_journal_bytes: profile.max_journal_bytes(),
            expected_first_digest: Sha256::digest(expected_first).into(),
            expected_peer_digest: Sha256::digest(expected_peer).into(),
            corrupt_peer_digest: Sha256::digest(corrupt_peer).into(),
            zero_peer_digest: Sha256::digest([0u8; MARKER_BYTES]).into(),
            expected_first: Box::new(expected_first),
            expected_peer: Box::new(expected_peer),
            corrupt_peer: Box::new(corrupt_peer),
            bytes,
            patches: None,
        })
    }
}

fn digest_placeholder(bytes: &[u8], prefix: &[u8]) -> io::Result<usize> {
    let mut found = None;
    for (index, part) in bytes.windows(prefix.len()).enumerate() {
        if part == prefix {
            require(found.is_none(), "marker fault digest field is duplicated")?;
            found = Some(index + prefix.len());
        }
    }
    let at = found.ok_or_else(|| invalid("marker fault digest field is missing"))?;
    require(
        bytes.get(at..at + 64) == Some(&[b'0'; 64][..]),
        "marker fault digest placeholder differs",
    )?;
    Ok(at)
}

#[repr(C, align(8))]
struct InfoBuffer<const N: usize>([u8; N]);

fn signal_info<const N: usize>(
    file: &File,
    class: FILE_INFO_BY_HANDLE_CLASS,
) -> io::Result<[u8; N]> {
    let mut buffer = InfoBuffer([0; N]);
    // SAFETY: a live retained signal handle and aligned initialized fixed output.
    if unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle(),
            class,
            buffer.0.as_mut_ptr().cast(),
            N as u32,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(buffer.0)
}

fn revalidate_signal(
    file: &File,
    snapshot: &crate::reference_file::ReferenceFileSnapshot,
) -> io::Result<()> {
    let id = signal_info::<24>(file, FileIdInfo)?;
    let standard = signal_info::<24>(file, FileStandardInfo)?;
    let tag = signal_info::<8>(file, FileAttributeTagInfo)?;
    require(
        u64_at(&id, 0)? == snapshot.volume_serial_number
            && id[8..] == snapshot.file_id_128
            && u64_at(&standard, 0)? == snapshot.allocation_bytes
            && u64_at(&standard, 8)? == snapshot.file_bytes
            && u32_at(&standard, 16)? == snapshot.number_of_links
            && standard[20] == 0
            && standard[21] == 0
            && u32_at(&tag, 0)? == snapshot.file_attributes
            && tag[4..] == [0; 4],
        "marker fault retained signal identity or reserved capacity changed",
    )
}

impl LabMarkerFault {
    pub(super) const fn copy(&self) -> LabMarkerFaultCopy {
        self.copy
    }

    pub(super) const fn kind(&self) -> LabMarkerFaultKind {
        self.kind
    }

    pub(super) fn first(&self) -> &[u8; MARKER_BYTES] {
        &self.expected_first
    }

    pub(super) fn peer(&self) -> &[u8; MARKER_BYTES] {
        &self.expected_peer
    }

    pub(super) fn corrupt(&self) -> &[u8; MARKER_BYTES] {
        &self.corrupt_peer
    }

    pub(super) fn bind(&mut self, storage: &MarkerStorageObservation) -> io::Result<()> {
        require(self.patches.is_none(), "marker fault already bound")?;
        require(
            storage.identity.volume_guid == guid_bytes(C0_VOLUME)?
                && storage.identity.disk_guid
                    == guid_bytes("1f804918-e98f-4a71-9022-fc00c3cb7c26")?
                && storage.identity.volume_serial_number
                    == self.signal_snapshot.volume_serial_number
                && storage.logical_sector_bytes == 512
                && storage.physical_sector_bytes == 4096
                && storage.journal_length > SIGNAL_BYTES as u64
                && storage.journal_length <= self.maximum_journal_bytes,
            "marker fault must bind the actual independent C0 journal owner",
        )?;
        let corrupt = self.kind == LabMarkerFaultKind::CorruptPeer;
        let observed = matches!(
            self.kind,
            LabMarkerFaultKind::CorruptPeer | LabMarkerFaultKind::WriteError
        );
        let written = self.kind != LabMarkerFaultKind::WriteError;
        let flushed = matches!(
            self.kind,
            LabMarkerFaultKind::CorruptPeer | LabMarkerFaultKind::ReadbackError
        );
        let receipt = FaultReceipt {
            schema_version: 1,
            kind: "lab-selected-marker-fault",
            lab_only: true,
            native_marker_qualified: false,
            computer_name: "N2R-WIN11",
            argv: &self.argv,
            pid: self.pid,
            process_creation_filetime_100ns: self.created,
            process_creation_unix_ms: self.created_unix_ms,
            journal_format_version: 6,
            journal_format: "N2RFRE02",
            journal_profile: "CapacityPinnedV3",
            maximum_journal_bytes: self.maximum_journal_bytes,
            marker_profile: "RedundantSourceFreeV1",
            marker_copy: self.copy.label(),
            marker_slot: self.copy.slot(),
            marker_file_offset: self.copy.slot() * MARKER_BYTES,
            marker_device_offset: storage.marker_device_offsets[self.copy.slot()],
            marker_bytes: MARKER_BYTES,
            first_peer_file_offset: (self.copy.slot() - 1) * MARKER_BYTES,
            signal_path: &self.signal_path,
            signal_bytes: SIGNAL_BYTES,
            fault_kind: self.kind.label(),
            synthetic_error: self.kind.synthetic(),
            actual_os_error: false,
            injected_win32_error: self.kind.synthetic().then_some(1117),
            skipped_api: self.kind.skipped_api(),
            skipped_api_issued: false,
            io_fact_scope: "selected-second-peer-write-path; prerequisite reads are recorded separately",
            marker_write_issued: written,
            marker_write_completed: written,
            marker_flush_issued: flushed,
            marker_flush_completed: flushed,
            marker_readback_issued: corrupt,
            marker_readback_completed: corrupt,
            intact_first_peer_verified_before_fault: true,
            inactive_peer_verified_exact_zero_before_fault: true,
            intact_first_peer_verified_after_fault: corrupt,
            storage_revalidated_before_fault: true,
            storage_revalidated_after_fault: corrupt,
            corruption: corrupt.then_some("one-fixed-bit-in-peer-self-hash"),
            observed_peer_sha256_scope: self.kind.observed_peer_scope(),
            intact_first_peer_sha256: ZERO_DIGEST,
            requested_peer_sha256: ZERO_DIGEST,
            observed_peer_sha256: observed.then_some(ZERO_DIGEST),
            journal_poisoned: self.kind.synthetic(),
            journal_owner_retained_at_signal_publish: true,
            data_plane_writes_by_facility: false,
            signal_synced_before_readable: true,
            automatic_continue: false,
            timeout: false,
            parks_after_publish: corrupt,
            requires_external_hard_poweroff: corrupt,
            expected_native_exit: self.kind.synthetic().then_some(1),
            serialized_record_grants_authority: false,
            storage,
            signal_identity: &self.signal_snapshot,
        };
        self.bytes.fill(b' ');
        let used = {
            let mut writer = Cursor::new(&mut self.bytes[..]);
            serde_json::to_writer(&mut writer, &receipt).map_err(io::Error::other)?;
            writer.position() as usize
        };
        self.patches = Some(DigestPatches {
            first: digest_placeholder(&self.bytes[..used], b"\"intact_first_peer_sha256\":\"")?,
            peer: digest_placeholder(&self.bytes[..used], b"\"requested_peer_sha256\":\"")?,
            observed: if observed {
                Some(digest_placeholder(
                    &self.bytes[..used],
                    b"\"observed_peer_sha256\":\"",
                )?)
            } else {
                None
            },
        });
        Ok(())
    }

    pub(super) fn publish(
        &mut self,
        intact_first_sha256: [u8; 32],
        requested_peer_sha256: [u8; 32],
        observed_peer_sha256: Option<[u8; 32]>,
        journal_poisoned: bool,
    ) -> io::Result<()> {
        require(
            intact_first_sha256 == self.expected_first_digest
                && requested_peer_sha256 == self.expected_peer_digest
                && journal_poisoned == self.kind.synthetic()
                && match self.kind {
                    LabMarkerFaultKind::CorruptPeer => {
                        observed_peer_sha256 == Some(self.corrupt_peer_digest)
                    }
                    LabMarkerFaultKind::WriteError => {
                        observed_peer_sha256 == Some(self.zero_peer_digest)
                    }
                    LabMarkerFaultKind::FlushError | LabMarkerFaultKind::ReadbackError => {
                        observed_peer_sha256.is_none()
                    }
                },
            "marker fault publication differs from its actual authorized branch",
        )?;
        let patches = self
            .patches
            .as_ref()
            .ok_or_else(|| invalid("marker fault not bound before target opening"))?;
        hex::encode_to_slice(
            intact_first_sha256,
            &mut self.bytes[patches.first..patches.first + 64],
        )
        .map_err(io::Error::other)?;
        hex::encode_to_slice(
            requested_peer_sha256,
            &mut self.bytes[patches.peer..patches.peer + 64],
        )
        .map_err(io::Error::other)?;
        if let (Some(at), Some(digest)) = (patches.observed, observed_peer_sha256) {
            hex::encode_to_slice(digest, &mut self.bytes[at..at + 64]).map_err(io::Error::other)?;
        }
        let file = self
            .file
            .as_mut()
            .ok_or_else(|| invalid("marker fault signal already closed"))?;
        revalidate_signal(file, &self.signal_snapshot)?;
        if file
            .write_all(&self.bytes[..])
            .and_then(|()| file.sync_all())
            .is_err()
        {
            // Never unwind and expose a partial/unsynced receipt after a
            // publication write has started. Retain every caller-owned handle.
            let _ = std::io::stderr().write_all(b"LAB marker fault signal write/sync failed; all owners retained; no readable receipt; parked indefinitely.\n");
            loop {
                std::thread::park();
            }
        }
        drop(self.file.take());
        Ok(())
    }
}
