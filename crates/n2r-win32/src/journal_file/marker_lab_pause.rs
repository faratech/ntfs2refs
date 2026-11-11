//! Explicit enrolled-guest hard-power experiment support. This owns only its
//! fresh bounded signal; it never receives a raw device or journal handle.
use super::*;
use sha2::{Digest, Sha256};
use std::{
    fs::{File, OpenOptions},
    io::{Seek, SeekFrom, Write},
    os::windows::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};
use windows_sys::Win32::{
    Foundation::FILETIME,
    System::Threading::{GetCurrentProcess, GetProcessTimes},
};

const SIGNAL_BYTES: usize = 32768;
const C0_VOLUME: &str = "c6c3318f-a7c8-47b9-be6d-6dde5e00862f";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum LabMarkerCopy {
    #[serde(rename = "AP1")]
    Ap1,
    #[serde(rename = "AP2")]
    Ap2,
    #[serde(rename = "RB1")]
    Rb1,
    #[serde(rename = "RB2")]
    Rb2,
    #[serde(rename = "HND1")]
    Hnd1,
    #[serde(rename = "HND2")]
    Hnd2,
    #[serde(rename = "ABT1")]
    Abt1,
    #[serde(rename = "ABT2")]
    Abt2,
}

impl LabMarkerCopy {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Ap1 => "AP1",
            Self::Ap2 => "AP2",
            Self::Rb1 => "RB1",
            Self::Rb2 => "RB2",
            Self::Hnd1 => "HND1",
            Self::Hnd2 => "HND2",
            Self::Abt1 => "ABT1",
            Self::Abt2 => "ABT2",
        }
    }
    const fn slot(self) -> usize {
        match self {
            Self::Ap1 => 0,
            Self::Ap2 => 1,
            Self::Rb1 => 2,
            Self::Rb2 => 3,
            Self::Hnd1 => 4,
            Self::Hnd2 => 5,
            Self::Abt1 => 6,
            Self::Abt2 => 7,
        }
    }
    fn magic(self) -> &'static [u8; 8] {
        match self {
            Self::Ap1 | Self::Ap2 => b"N2RSAP02",
            Self::Rb1 | Self::Rb2 => b"N2RSRB02",
            Self::Hnd1 | Self::Hnd2 => b"N2RSHN02",
            Self::Abt1 | Self::Abt2 => b"N2RSAB02",
        }
    }
}

impl std::str::FromStr for LabMarkerCopy {
    type Err = io::Error;
    fn from_str(value: &str) -> io::Result<Self> {
        match value {
            "AP1" => Ok(Self::Ap1),
            "AP2" => Ok(Self::Ap2),
            "RB1" => Ok(Self::Rb1),
            "RB2" => Ok(Self::Rb2),
            "HND1" => Ok(Self::Hnd1),
            "HND2" => Ok(Self::Hnd2),
            "ABT1" => Ok(Self::Abt1),
            "ABT2" => Ok(Self::Abt2),
            _ => Err(invalid(
                "marker copy must be AP1/AP2/RB1/RB2/HND1/HND2/ABT1/ABT2",
            )),
        }
    }
}

/// Descriptive lab request only. It does not confer storage or write authority.
pub struct LabMarkerPauseRequest {
    pub marker_copy: LabMarkerCopy,
    pub signal_path: PathBuf,
}

/// Prepared before source construction. No callback or handle escapes this
/// owner. The signal remains share-zero until it has been synced at the actual
/// selected marker boundary, so a host cannot read a pre-sync JSON receipt.
pub struct LabMarkerCopyPause {
    copy: LabMarkerCopy,
    file: Option<File>,
    signal_snapshot: crate::reference_file::ReferenceFileSnapshot,
    record: serde_json::Value,
    bytes: Box<[u8; SIGNAL_BYTES]>,
    digest_at: Option<usize>,
}

fn birth() -> io::Result<u64> {
    let zero = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    let (mut created, mut exited, mut kernel, mut user) = (zero, zero, zero, zero);
    // SAFETY: borrowed current-process pseudo-handle and separate initialized
    // synchronous output structures. No handle or output pointer escapes.
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

impl LabMarkerPauseRequest {
    pub fn reserve(
        self,
        output: &Path,
        binding: &GeneralJournalStorageBinding,
        source: &crate::general_layout::GeneralDiskBinding,
        shadow: &crate::general_layout::GeneralDiskBinding,
        profile: JournalProfile,
    ) -> io::Result<LabMarkerCopyPause> {
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
            "marker pause requires the exact independent enrolled C0 native lab profile",
        )?;
        let output_text = output
            .to_str()
            .ok_or_else(|| invalid("marker pause output must be Unicode"))?;
        require(
            output_text.starts_with("C:\\ntfs2refs\\")
                && output_text.len() <= 384
                && !output_text.contains(['/', '\0'])
                && self.signal_path == output.join("marker-pause.json"),
            "marker pause signal must be marker-pause.json directly inside the fresh C0 output",
        )?;
        // Strict components forbid aliases, alternate streams and ambiguous
        // Win32 normalization. Final same-handle volume identity is checked too.
        for component in output_text[3..].split('\\') {
            require(
                !component.is_empty()
                    && component.len() <= 96
                    && !component.starts_with('.')
                    && !component.ends_with(['.', ' '])
                    && component
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.')),
                "marker pause output requires bounded ordinary path components",
            )?;
        }
        for ancestor in output.ancestors() {
            let metadata = std::fs::symlink_metadata(ancestor)?;
            require(
                metadata.is_dir() && metadata.file_attributes() & 0x400 == 0,
                "marker pause ancestry must be ordinary existing directories",
            )?;
        }
        let mut argv = Vec::with_capacity(64);
        let mut argv_units = 0usize;
        for argument in std::env::args_os() {
            let argument = argument
                .into_string()
                .map_err(|_| invalid("marker pause argv must be Unicode"))?;
            argv_units = argv_units
                .checked_add(argument.encode_utf16().count())
                .ok_or_else(|| invalid("marker pause argv overflow"))?;
            require(
                argv.len() < 64 && argument.len() <= 2048 && argv_units <= 8192,
                "marker pause exact argv exceeds bounded metadata capacity",
            )?;
            argv.push(argument);
        }
        let created = birth()?;
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .share_mode(0)
            .custom_flags(0x0020_0000 | 0x8000_0000)
            .open(&self.signal_path)?;
        let snapshot = crate::reference_file::observe_reference_file_handle(&file)?;
        let expected_path = format!(
            "\\\\?\\Volume{{{C0_VOLUME}}}\\{}\\marker-pause.json",
            &output_text[3..]
        );
        require(
            snapshot.file_bytes == 0
                && snapshot.number_of_links == 1
                && snapshot.final_path.eq_ignore_ascii_case(&expected_path),
            "marker pause signal is not the exact fresh ordinary C0 file",
        )?;
        // The full native observer verifies the actual disk/partition route,
        // not merely a caller-supplied path or saved descriptive file identity.
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
            "marker pause preallocated signal identity changed",
        )?;
        let record = serde_json::json!({
            "schema_version":1,"kind":"lab-selected-marker-copy-pause",
            "lab_only":true,"native_marker_qualified":false,"computer_name":"N2R-WIN11",
            "argv":argv,"pid":std::process::id(),"process_creation_filetime_100ns":created,
            "process_creation_unix_ms":created.checked_sub(116444736000000000).ok_or_else(|| invalid("process birth predates Unix epoch"))? / 10000,
            "journal_format_version":6,"journal_format":"N2RFRE02",
            "journal_profile":"CapacityPinnedV3","maximum_journal_bytes":profile.max_journal_bytes(),
            "marker_profile":"RedundantSourceFreeV1","marker_copy":self.marker_copy,
            "marker_slot":self.marker_copy.slot(),"marker_file_offset":self.marker_copy.slot() * 4096,
            "marker_bytes":4096,"signal_path":self.signal_path,"signal_bytes":SIGNAL_BYTES,
            "durable_stage":"actual-slot-written-flushed-uncached-readback-and-storage-revalidated",
            "marker_sha256":"0000000000000000000000000000000000000000000000000000000000000000",
            "signal_synced_before_readable":true,"journal_owner_retained":true,
            "automatic_continue":false,"timeout":false,"requires_external_hard_poweroff":true,
        });
        Ok(LabMarkerCopyPause {
            copy: self.marker_copy,
            file: Some(file),
            signal_snapshot,
            record,
            bytes,
            digest_at: None,
        })
    }
}

impl LabMarkerCopyPause {
    /// Bind and finish all serialization before source activation. Only the
    /// fixed digest field is filled after the actual selected write completes.
    pub(super) fn bind(&mut self, storage: &MarkerStorageObservation) -> io::Result<()> {
        require(self.digest_at.is_none(), "marker pause already bound")?;
        self.record["storage"] = serde_json::to_value(storage).map_err(io::Error::other)?;
        self.record["marker_device_offset"] =
            storage.marker_device_offsets[self.copy.slot()].into();
        self.record["signal_identity"] =
            serde_json::to_value(&self.signal_snapshot).map_err(io::Error::other)?;
        let serialized = serde_json::to_vec(&self.record).map_err(io::Error::other)?;
        require(
            serialized.len() <= SIGNAL_BYTES,
            "marker pause receipt exceeds reserved capacity",
        )?;
        self.bytes.fill(b' ');
        self.bytes[..serialized.len()].copy_from_slice(&serialized);
        let prefix = b"\"marker_sha256\":\"";
        let at = serialized
            .windows(prefix.len())
            .position(|part| part == prefix)
            .ok_or_else(|| invalid("marker pause digest field missing"))?
            + prefix.len();
        require(
            self.bytes[at..at + 64] == [b'0'; 64],
            "marker pause digest placeholder differs",
        )?;
        self.digest_at = Some(at);
        // The receipt now occupies its bounded prepared buffer; release the
        // construction value before activation, not at the power boundary.
        self.record = serde_json::Value::Null;
        Ok(())
    }

    pub(super) fn after_validated_copy(&mut self, offset: u64, marker: &[u8]) -> io::Result<()> {
        if offset != (self.copy.slot() * 4096) as u64 {
            return Ok(());
        }
        require(
            marker.len() == 4096
                && marker[..8] == *self.copy.magic()
                && u32_at(marker, 8)? == 6
                && u32_at(marker, 12)? == (self.copy.slot() % 2 + 1) as u32
                && marker[4064..] == Sha256::digest(&marker[..4064])[..],
            "marker pause selected slot is not a valid actual format-six copy",
        )?;
        let at = self
            .digest_at
            .ok_or_else(|| invalid("marker pause not prepared before activation"))?;
        hex::encode_to_slice(Sha256::digest(marker), &mut self.bytes[at..at + 64])
            .map_err(io::Error::other)?;
        let file = self
            .file
            .as_mut()
            .ok_or_else(|| invalid("marker pause signal already closed"))?;
        require(
            crate::reference_file::observe_reference_file_handle(file)? == self.signal_snapshot,
            "marker pause signal identity or reserved capacity changed",
        )?;
        if file
            .write_all(&self.bytes[..])
            .and_then(|()| file.sync_all())
            .is_err()
        {
            // Once receipt publication starts, an error must never unwind and
            // make partially written or unsynced JSON readable. Retain this
            // share-zero signal handle and every caller-owned journal/source
            // handle indefinitely. A locked signal is never poweroff evidence.
            let _ = std::io::stderr().write_all(
                b"LAB marker pause signal write/sync failed; all owners retained; no readable receipt; parked indefinitely.\n",
            );
            loop {
                std::thread::park();
            }
        }
        // Closing only this signal makes its fully synced JSON readable. The
        // caller never returns: the actual journal/source owner stays held and
        // no next slot, target write, callback or mount transition can advance.
        drop(self.file.take());
        loop {
            std::thread::park();
        }
    }
}
