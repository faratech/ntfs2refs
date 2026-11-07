//! Durable cancellation of a preparation that has never issued an AP owner.
//! The immutable external pin locates an actual two-copy state-file owner.
//! Neither deserialization nor this module exposes a source payload writer.
use crate::{
    general_layout::{GeneralDiskBinding, GeneralSourceShadowBinding},
    journal_file::GeneralJournalStorageBinding,
    native::{self, GeneralDiskState, GeneralFrozenPartition, NativeEvent},
    reference_file::{ReferenceFileSnapshot, observe_reference_file_handle_with_limit},
    volume_label::VolumeLabel,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    os::windows::fs::{MetadataExt, OpenOptionsExt},
    path::{Component, Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

pub const SLOT_BYTES: u64 = 65536;
pub const STATE_BYTES: u64 = SLOT_BYTES * 2;

// Cancellation is a sequence of independently bounded native observations.
// Retain every completed/failed batch for the caller's observer, while a prior
// phase's event history cannot exhaust the next operation's control budget.
pub(super) fn native_batch<T>(events: &mut Vec<NativeEvent>, operation: impl FnOnce(&mut Vec<NativeEvent>) -> io::Result<T>) -> io::Result<T> {
    let mut batch = Vec::new();
    let result = operation(&mut batch);
    events.extend(batch);
    result
}
const HEADER: usize = 64;
const MAGIC: &[u8; 8] = b"N2RPRE01";
fn bad(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
fn require(ok: bool, message: &str) -> io::Result<()> {
    if ok { Ok(()) } else { Err(bad(message)) }
}
fn json<T: Serialize>(value: &T) -> io::Result<Vec<u8>> {
    serde_json::to_vec(value).map_err(io::Error::other)
}
fn hash(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn canonical(pin: &str) -> bool {
    pin.len() == 64
        && pin
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn ordinary(path: &Path) -> io::Result<()> {
    require(
        path.is_absolute()
            && !path
                .components()
                .any(|c| matches!(c, Component::ParentDir | Component::CurDir)),
        "absolute ordinary preparation path required",
    )?;
    for parent in path
        .parent()
        .ok_or_else(|| bad("preparation parent absent"))?
        .ancestors()
    {
        let m = fs::symlink_metadata(parent)?;
        require(
            m.is_dir() && m.file_attributes() & 0x400 == 0,
            "preparation ancestry is redirected",
        )?;
    }
    Ok(())
}
fn normalized(state: &GeneralDiskState) -> io::Result<String> {
    let mut state = state.clone();
    state.disk_attributes = 0;
    Ok(hash(&json(&state)?))
}
fn journal_route(intent: &Intent) -> io::Result<()> {
    let root = format!(
        "{}\\",
        intent.journal.disk.volume_path()?.trim_end_matches('\\')
    );
    let actual = crate::discovery::discover(
        &root,
        crate::discovery::Role::Journal {
            allow_additional_partitions: intent.journal.allow_additional_partitions,
        },
    )?;
    require(
        actual.binding == intent.journal.disk && actual.observed_twice_unchanged,
        "actual preparation journal route changed",
    )
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PublicationPin {
    pub path: PathBuf,
    pub sha256: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct StateIdentity {
    path: String,
    volume_serial: u64,
    file_id: [u8; 16],
    bytes: u64,
    attributes: u32,
    maximum_allocation: u64,
}
impl StateIdentity {
    fn from_snapshot(s: &ReferenceFileSnapshot, maximum_allocation: u64) -> Self {
        Self {
            path: s.final_path.clone(),
            volume_serial: s.volume_serial_number,
            file_id: s.file_id_128,
            bytes: s.file_bytes,
            attributes: s.file_attributes,
            maximum_allocation,
        }
    }
    fn check(&self, file: &File) -> io::Result<()> {
        let s = observe_reference_file_handle_with_limit(file, STATE_BYTES)?;
        require(
            s.final_path.eq_ignore_ascii_case(&self.path)
                && s.volume_serial_number == self.volume_serial
                && s.file_id_128 == self.file_id
                && s.file_bytes == self.bytes
                && self.bytes == STATE_BYTES
                && s.file_attributes == self.attributes
                && s.number_of_links == 1
                && s.allocation_bytes >= STATE_BYTES
                && s.allocation_bytes <= self.maximum_allocation,
            "actual preparation state-file identity or allocation changed",
        )
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Intent {
    schema_version: u32,
    kind: String,
    nonce: String,
    source: GeneralDiskBinding,
    shadow: GeneralDiskBinding,
    journal: GeneralJournalStorageBinding,
    original_state_sha256: String,
    ntfs_serial: u64,
    bytes_per_sector: u16,
    sectors_per_cluster: u8,
    mount_paths: Vec<String>,
    label: VolumeLabel,
    state_file: StateIdentity,
    serialized_intent_grants_authority: bool,
}
impl Intent {
    fn validate(&self) -> io::Result<()> {
        self.source.validate()?;
        self.shadow.validate()?;
        self.journal.validate()?;
        self.label.validate()?;
        super::validate_mount_paths(&self.mount_paths)?;
        require(
            self.schema_version == 1
                && self.kind == "resource-preparation-cancellation-intent-v1"
                && canonical(&self.nonce)
                && canonical(&self.original_state_sha256)
                && !self.serialized_intent_grants_authority
                && self.state_file.bytes == STATE_BYTES
                && matches!(self.bytes_per_sector, 512 | 4096)
                && self.sectors_per_cluster.is_power_of_two(),
            "invalid preparation intent",
        )?;
        for data in [&self.source, &self.shadow] {
            require(
                data.disk_number != self.journal.disk.disk_number
                    && crate::layout::guid_bytes(&data.identity.disk_guid)?
                        != crate::layout::guid_bytes(&self.journal.disk.identity.disk_guid)?,
                "preparation metadata aliases a data disk",
            )?;
        }
        require(
            self.source.disk_number != self.shadow.disk_number
                && crate::layout::guid_bytes(&self.source.identity.disk_guid)?
                    != crate::layout::guid_bytes(&self.shadow.identity.disk_guid)?,
            "preparation source and shadow alias",
        )?;
        let root = format!(
            "{}\\",
            self.journal.disk.volume_path()?.trim_end_matches('\\')
        );
        require(
            self.state_file
                .path
                .to_lowercase()
                .starts_with(&root.to_lowercase()),
            "preparation state is not on the bound journal volume",
        )
    }
}
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct State {
    schema_version: u32,
    nonce: String,
    phase: String,
    locked_boot_hex: Option<String>,
    delegated: Option<PublicationPin>,
}
fn frame(state: &State) -> io::Result<Vec<u8>> {
    let body = json(state)?;
    require(
        body.len() <= SLOT_BYTES as usize - HEADER,
        "preparation state exceeds its fixed slot",
    )?;
    let mut slot = vec![0; SLOT_BYTES as usize];
    slot[..8].copy_from_slice(MAGIC);
    slot[8..16].copy_from_slice(&(body.len() as u64).to_le_bytes());
    slot[16..48].copy_from_slice(&Sha256::digest(&body));
    slot[HEADER..HEADER + body.len()].copy_from_slice(&body);
    Ok(slot)
}
fn parse(slot: &[u8]) -> io::Result<State> {
    require(
        slot.len() == SLOT_BYTES as usize
            && &slot[..8] == MAGIC
            && slot[48..HEADER].iter().all(|b| *b == 0),
        "preparation state frame differs",
    )?;
    let n = usize::try_from(u64::from_le_bytes(slot[8..16].try_into().unwrap()))
        .map_err(|_| bad("preparation state length overflow"))?;
    require(
        n > 0 && n <= slot.len() - HEADER,
        "preparation state body bounds differ",
    )?;
    let body = &slot[HEADER..HEADER + n];
    require(
        Sha256::digest(body).as_slice() == &slot[16..48]
            && slot[HEADER + n..].iter().all(|b| *b == 0),
        "preparation state checksum differs",
    )?;
    serde_json::from_slice(body).map_err(io::Error::other)
}

/// Actual held metadata owner. Mutable preparation has no source writer;
/// delegation closes its mutation handle and retains a read-only file instead.
pub struct PreparationGuard {
    intent: Intent,
    intent_file: File,
    intent_snapshot: ReferenceFileSnapshot,
    intent_sha256: String,
    state_file: Option<File>,
    state: State,
    sealed: bool,
    maximum_metadata_bytes: u64,
    repair: Option<DelegationRepair>,
}
struct DelegationRepair {
    first: [u8; 32],
    second: [u8; 32],
    publication: PublicationPin,
}
fn repair_pair(
    nonce: &str,
    first: &State,
    second: &State,
    publication: &PublicationPin,
) -> io::Result<()> {
    require(
        first.schema_version == 1
            && second.schema_version == 1
            && first.nonce == nonce
            && second.nonce == nonce
            && first.locked_boot_hex == second.locked_boot_hex
            && first.locked_boot_hex.as_ref().is_some_and(|s| {
                s.len() == 8192
                    && s.bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            }),
        "mixed preparation copies do not share the same locked source witness",
    )?;
    for state in [first, second] {
        require(
            match state.phase.as_str() {
                "Frozen" => state.delegated.is_none(),
                "Delegated" => state.delegated.as_ref().is_some_and(|p| {
                    p.sha256 == publication.sha256
                        && p.path
                            .to_string_lossy()
                            .eq_ignore_ascii_case(&publication.path.to_string_lossy())
                }),
                _ => false,
            },
            "mixed preparation copy cannot retire toward this exact publication",
        )?;
    }
    Ok(())
}
#[derive(Clone, Serialize)]
pub struct Routes {
    pub source: GeneralDiskBinding,
    pub shadow: GeneralDiskBinding,
    pub journal: GeneralJournalStorageBinding,
    pub phase: String,
    pub delegated: Option<PublicationPin>,
}
impl PreparationGuard {
    pub fn create(
        pair: &GeneralSourceShadowBinding,
        journal: &GeneralJournalStorageBinding,
        state_path: &Path,
        intent_path: &Path,
        maximum_intent: u64,
        maximum_state_allocation: u64,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<Self> {
        ordinary(state_path)?;
        ordinary(intent_path)?;
        let before = native::observe_general_disk_state_readonly(pair.source.clone(), events)?;
        require(
            before.disk_attributes == 0,
            "preparation must start on the original online disk",
        )?;
        let mut reader = native::GeneralPartitionReader::open(pair.source.clone(), events)?;
        let mut boot = [0; 512];
        reader.read_exact(&mut boot)?;
        reader.revalidate_route(events)?;
        drop(reader);
        require(
            &boot[3..11] == b"NTFS    " && boot[510..512] == [0x55, 0xaa],
            "preparation source is not NTFS",
        )?;
        let mounts = native::capture_mount_paths_general(pair.source.clone(), events)?;
        require(
            mounts.all_paths_resolve_to_bound_volume,
            "preparation mount routes differ",
        )?;
        let label = crate::volume_label::capture_source_label(pair.source.clone())?;
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .share_mode(0)
            .custom_flags(0x0020_0000)
            .open(state_path)?;
        crate::file_storage::preallocate_empty_file(&file, STATE_BYTES, maximum_state_allocation)?;
        file.set_len(STATE_BYTES)?;
        let snap = observe_reference_file_handle_with_limit(&file, STATE_BYTES)?;
        let nonce = hash(&json(&(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(io::Error::other)?
                .as_nanos(),
            std::process::id(),
            &snap.file_id_128,
            snap.volume_serial_number,
        ))?);
        let state = State {
            schema_version: 1,
            nonce: nonce.clone(),
            phase: "Preparing".into(),
            locked_boot_hex: None,
            delegated: None,
        };
        let bytes = frame(&state)?;
        file.seek(SeekFrom::Start(0))?;
        file.write_all(&bytes)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        let intent = Intent {
            schema_version: 1,
            kind: "resource-preparation-cancellation-intent-v1".into(),
            nonce,
            source: pair.source.clone(),
            shadow: pair.shadow.clone(),
            journal: journal.clone(),
            original_state_sha256: normalized(&before)?,
            ntfs_serial: u64::from_le_bytes(boot[72..80].try_into().unwrap()),
            bytes_per_sector: u16::from_le_bytes(boot[11..13].try_into().unwrap()),
            sectors_per_cluster: boot[13],
            mount_paths: mounts.paths,
            label: label.label().clone(),
            state_file: StateIdentity::from_snapshot(&snap, maximum_state_allocation),
            serialized_intent_grants_authority: false,
        };
        intent.validate()?;
        journal_route(&intent)?;
        let body = json(&intent)?;
        require(
            body.len() as u64 <= maximum_intent,
            "preparation intent exceeds its prepaid workspace",
        )?;
        let mut out = OpenOptions::new()
            .write(true)
            .create_new(true)
            .share_mode(0)
            .custom_flags(0x0020_0000)
            .open(intent_path)?;
        out.write_all(&body)?;
        out.sync_all()?;
        drop(out);
        let intent_file = OpenOptions::new()
            .read(true)
            .share_mode(1)
            .custom_flags(0x0020_0000)
            .open(intent_path)?;
        let intent_snapshot =
            observe_reference_file_handle_with_limit(&intent_file, maximum_intent)?;
        let root = format!("{}\\", journal.disk.volume_path()?.trim_end_matches('\\'));
        require(
            intent_snapshot
                .final_path
                .to_lowercase()
                .starts_with(&root.to_lowercase())
                && native::observe_general_disk_state_readonly(pair.source.clone(), events)?
                    == before,
            "preparation intent or original device route changed",
        )?;
        let mut guard = Self {
            intent,
            intent_file,
            intent_snapshot,
            intent_sha256: hash(&body),
            state_file: Some(file),
            state,
            sealed: false,
            maximum_metadata_bytes: maximum_intent,
            repair: None,
        };
        guard.revalidate()?;
        Ok(guard)
    }
    pub fn open(
        path: &Path,
        expected_sha256: [u8; 32],
        maximum_intent: u64,
        mutable: bool,
    ) -> io::Result<Self> {
        Self::open_inner(path, expected_sha256, maximum_intent, mutable, None)
    }
    pub fn open_sized(
        path: &Path,
        expected_sha256: [u8; 32],
        expected_intent_bytes: u64,
        maximum_metadata_bytes: u64,
        mutable: bool,
    ) -> io::Result<Self> {
        require(
            expected_intent_bytes > 0 && expected_intent_bytes <= maximum_metadata_bytes,
            "preparation intent length exceeds its independently pinned budget",
        )?;
        let mut guard =
            Self::open_inner(path, expected_sha256, expected_intent_bytes, mutable, None)?;
        require(
            guard.intent_bytes() == expected_intent_bytes,
            "preparation intent length differs from its external pin",
        )?;
        guard.maximum_metadata_bytes = maximum_metadata_bytes;
        Ok(guard)
    }
    /// Called only inside the product's actual PreparedClear/OLD-proved
    /// abandonment callback. Both checksum-valid copies are mandatory. This
    /// finishes retirement only; it cannot cancel a pending or delegated guard.
    pub fn open_for_clear_delegation(
        path: &Path,
        expected_sha256: [u8; 32],
        expected_intent_bytes: u64,
        maximum_metadata_bytes: u64,
        publication: &Path,
        publication_sha: &str,
    ) -> io::Result<Self> {
        ordinary(publication)?;
        require(
            canonical(publication_sha),
            "complete clear-publication pin required",
        )?;
        let file = OpenOptions::new()
            .read(true)
            .share_mode(1)
            .custom_flags(0x0020_0000)
            .open(publication)?;
        let final_path = crate::file_storage::final_path_guid(&file)?;
        require(
            expected_intent_bytes > 0 && expected_intent_bytes <= maximum_metadata_bytes,
            "preparation intent length exceeds its external pin budget",
        )?;
        let mut guard = Self::open_inner(
            path,
            expected_sha256,
            expected_intent_bytes,
            true,
            Some(PublicationPin {
                path: PathBuf::from(final_path),
                sha256: publication_sha.into(),
            }),
        )?;
        require(
            guard.intent_bytes() == expected_intent_bytes,
            "preparation intent length differs from final publication",
        )?;
        guard.maximum_metadata_bytes = maximum_metadata_bytes;
        Ok(guard)
    }
    fn open_inner(
        path: &Path,
        expected_sha256: [u8; 32],
        maximum_intent: u64,
        mutable: bool,
        repair_publication: Option<PublicationPin>,
    ) -> io::Result<Self> {
        ordinary(path)?;
        let mut intent_file = OpenOptions::new()
            .read(true)
            .share_mode(1)
            .custom_flags(0x0020_0000)
            .open(path)?;
        let intent_snapshot =
            observe_reference_file_handle_with_limit(&intent_file, maximum_intent)?;
        require(
            intent_snapshot.number_of_links == 1 && intent_snapshot.file_bytes > 0,
            "ordinary single-link preparation intent required",
        )?;
        let mut body = Vec::new();
        (&mut intent_file)
            .take(maximum_intent.saturating_add(1))
            .read_to_end(&mut body)?;
        require(
            body.len() as u64 == intent_snapshot.file_bytes
                && Sha256::digest(&body).as_slice() == expected_sha256,
            "preparation intent differs from independently supplied SHA-256",
        )?;
        let intent: Intent = serde_json::from_slice(&body).map_err(io::Error::other)?;
        intent.validate()?;
        journal_route(&intent)?;
        ordinary(Path::new(&intent.state_file.path))?;
        let root = format!(
            "{}\\",
            intent.journal.disk.volume_path()?.trim_end_matches('\\')
        );
        require(
            intent_snapshot
                .final_path
                .to_lowercase()
                .starts_with(&root.to_lowercase()),
            "intent journal volume differs",
        )?;
        let file = OpenOptions::new()
            .read(true)
            .write(mutable)
            .share_mode(if mutable { 0 } else { 1 })
            .custom_flags(0x0020_0000)
            .open(&intent.state_file.path)?;
        let placeholder = State {
            schema_version: 1,
            nonce: intent.nonce.clone(),
            phase: "Preparing".into(),
            locked_boot_hex: None,
            delegated: None,
        };
        let mut guard = Self {
            intent,
            intent_file,
            intent_snapshot,
            intent_sha256: hex::encode(expected_sha256),
            state_file: Some(file),
            state: placeholder,
            sealed: !mutable,
            maximum_metadata_bytes: maximum_intent,
            repair: None,
        };
        if let Some(publication) = repair_publication {
            let file = guard
                .state_file
                .as_mut()
                .ok_or_else(|| bad("preparation state handle absent"))?;
            guard.intent.state_file.check(file)?;
            file.seek(SeekFrom::Start(0))?;
            let mut first = vec![0; SLOT_BYTES as usize];
            let mut second = vec![0; SLOT_BYTES as usize];
            file.read_exact(&mut first)?;
            file.read_exact(&mut second)?;
            let a = parse(&first)?;
            let b = parse(&second)?;
            repair_pair(&guard.intent.nonce, &a, &b, &publication)?;
            if first != second {
                guard.repair = Some(DelegationRepair {
                    first: Sha256::digest(&first).into(),
                    second: Sha256::digest(&second).into(),
                    publication: publication.clone(),
                });
                guard.state = State {
                    schema_version: 1,
                    nonce: guard.intent.nonce.clone(),
                    phase: "DelegationPending".into(),
                    locked_boot_hex: a.locked_boot_hex,
                    delegated: Some(publication),
                };
                guard.revalidate()?;
                return Ok(guard);
            }
        }
        guard.state = guard.read_state()?;
        guard.revalidate()?;
        Ok(guard)
    }
    pub fn intent_file(&self) -> &File {
        &self.intent_file
    }
    pub fn intent_path(&self) -> &str {
        &self.intent_snapshot.final_path
    }
    pub fn intent_sha256(&self) -> &str {
        &self.intent_sha256
    }
    pub fn intent_bytes(&self) -> u64 {
        self.intent_snapshot.file_bytes
    }
    pub fn routes(&self) -> Routes {
        Routes {
            source: self.intent.source.clone(),
            shadow: self.intent.shadow.clone(),
            journal: self.intent.journal.clone(),
            phase: self.state.phase.clone(),
            delegated: self.state.delegated.clone(),
        }
    }
    pub fn state_readonly_file(&self) -> io::Result<&File> {
        require(self.sealed, "preparation state still has a mutable owner")?;
        self.state_file
            .as_ref()
            .ok_or_else(|| bad("preparation state handle absent"))
    }
    pub fn state_sha256(&mut self) -> io::Result<String> {
        self.revalidate()?;
        let file = self
            .state_file
            .as_mut()
            .ok_or_else(|| bad("preparation state handle absent"))?;
        file.seek(SeekFrom::Start(0))?;
        let mut bytes = vec![0; STATE_BYTES as usize];
        file.read_exact(&mut bytes)?;
        Ok(hash(&bytes))
    }
    fn read_state(&mut self) -> io::Result<State> {
        let file = self
            .state_file
            .as_mut()
            .ok_or_else(|| bad("preparation state handle absent"))?;
        self.intent.state_file.check(file)?;
        file.seek(SeekFrom::Start(0))?;
        let mut a = vec![0; SLOT_BYTES as usize];
        let mut b = vec![0; SLOT_BYTES as usize];
        file.read_exact(&mut a)?;
        file.read_exact(&mut b)?;
        let first = parse(&a)?;
        let second = parse(&b)?;
        if let Some(repair) = &self.repair {
            require(
                <[u8; 32]>::from(Sha256::digest(&a)) == repair.first
                    && <[u8; 32]>::from(Sha256::digest(&b)) == repair.second,
                "pending retirement copies changed outside their actual owner",
            )?;
            repair_pair(&self.intent.nonce, &first, &second, &repair.publication)?;
            self.intent.state_file.check(file)?;
            return Ok(State {
                schema_version: 1,
                nonce: self.intent.nonce.clone(),
                phase: "DelegationPending".into(),
                locked_boot_hex: first.locked_boot_hex,
                delegated: Some(repair.publication.clone()),
            });
        }
        require(
            a == b
                && first == second
                && first.schema_version == 1
                && first.nonce == self.intent.nonce,
            "preparation copies disagree; no permissive fallback exists",
        )?;
        require(
            match first.phase.as_str() {
                "Preparing" | "UnstartedCancelled" => {
                    first.locked_boot_hex.is_none() && first.delegated.is_none()
                }
                "Frozen" | "CancelIntent" | "Cancelled" => {
                    first
                        .locked_boot_hex
                        .as_ref()
                        .is_some_and(|s| s.len() == 8192)
                        && first.delegated.is_none()
                }
                "Delegated" => {
                    first
                        .locked_boot_hex
                        .as_ref()
                        .is_some_and(|s| s.len() == 8192)
                        && first
                            .delegated
                            .as_ref()
                            .is_some_and(|p| p.path.is_absolute() && canonical(&p.sha256))
                }
                _ => false,
            },
            "preparation state is not a complete known phase",
        )?;
        self.intent.state_file.check(file)?;
        Ok(first)
    }
    pub fn revalidate(&mut self) -> io::Result<()> {
        let current = observe_reference_file_handle_with_limit(
            &self.intent_file,
            self.intent_snapshot.file_bytes,
        )?;
        require(
            current == self.intent_snapshot,
            "preparation intent identity changed",
        )?;
        self.intent_file.seek(SeekFrom::Start(0))?;
        let mut body = Vec::new();
        (&mut self.intent_file)
            .take(self.intent_snapshot.file_bytes + 1)
            .read_to_end(&mut body)?;
        require(
            body.len() as u64 == self.intent_snapshot.file_bytes
                && hash(&body) == self.intent_sha256,
            "held preparation intent contents changed",
        )?;
        require(
            self.read_state()? == self.state,
            "preparation state changed outside its actual owner",
        )
    }
    fn persist(&mut self, next: State) -> io::Result<()> {
        require(!self.sealed, "sealed preparation state cannot mutate")?;
        self.revalidate()?;
        let slot = frame(&next)?;
        let file = self
            .state_file
            .as_mut()
            .ok_or_else(|| bad("preparation state handle absent"))?;
        for n in 0..2 {
            file.seek(SeekFrom::Start(n * SLOT_BYTES))?;
            file.write_all(&slot)?;
            file.sync_all()?;
        }
        self.state = next;
        self.repair = None;
        self.revalidate()
    }
    pub(crate) fn record_locked(
        &mut self,
        binding: &GeneralDiskBinding,
        original: &GeneralDiskState,
        boot: &[u8; 4096],
    ) -> io::Result<()> {
        require(
            self.state.phase == "Preparing"
                && *binding == self.intent.source
                && original.disk_attributes == 0
                && normalized(original)? == self.intent.original_state_sha256
                && &boot[3..11] == b"NTFS    "
                && boot[510..512] == [0x55, 0xaa]
                && u64::from_le_bytes(boot[72..80].try_into().unwrap()) == self.intent.ntfs_serial
                && u16::from_le_bytes(boot[11..13].try_into().unwrap())
                    == self.intent.bytes_per_sector
                && boot[13] == self.intent.sectors_per_cluster,
            "actual post-lock preparation baseline differs",
        )?;
        let mut state = self.state.clone();
        state.phase = "Frozen".into();
        state.locked_boot_hex = Some(hex::encode(boot));
        self.persist(state)
    }
    pub fn delegate(&mut self, publication: &Path, sha256: &str) -> io::Result<()> {
        journal_route(&self.intent)?;
        ordinary(publication)?;
        require(
            canonical(sha256),
            "complete final publication SHA-256 required",
        )?;
        if self.state.phase == "Delegated" {
            return self.require_delegated(publication, sha256);
        }
        require(
            matches!(self.state.phase.as_str(), "Frozen" | "DelegationPending"),
            "only actual frozen preparation may delegate",
        )?;
        let mut file = OpenOptions::new()
            .read(true)
            .share_mode(1)
            .custom_flags(0x0020_0000)
            .open(publication)?;
        let snap = observe_reference_file_handle_with_limit(&file, self.maximum_metadata_bytes)?;
        if let Some(repair) = &self.repair {
            require(
                repair.publication.sha256 == sha256
                    && repair
                        .publication
                        .path
                        .to_string_lossy()
                        .eq_ignore_ascii_case(&snap.final_path),
                "pending guard retirement cannot redirect its publication",
            )?;
        }
        require(
            snap.number_of_links == 1 && snap.file_bytes > 0,
            "ordinary final publication required",
        )?;
        let mut digest = Sha256::new();
        let mut bytes = [0u8; 65536];
        let mut left = snap.file_bytes;
        while left > 0 {
            let n = left.min(bytes.len() as u64) as usize;
            file.read_exact(&mut bytes[..n])?;
            digest.update(&bytes[..n]);
            left -= n as u64;
        }
        require(
            hex::encode(digest.finalize()) == sha256,
            "final publication not independently pinned",
        )?;
        let mut state = self.state.clone();
        state.phase = "Delegated".into();
        state.delegated = Some(PublicationPin {
            path: PathBuf::from(snap.final_path),
            sha256: sha256.into(),
        });
        self.persist(state)?;
        drop(self.state_file.take());
        self.state_file = Some(
            OpenOptions::new()
                .read(true)
                .share_mode(1)
                .custom_flags(0x0020_0000)
                .open(&self.intent.state_file.path)?,
        );
        self.sealed = true;
        self.require_delegated(publication, sha256)
    }
    pub fn require_delegated(&mut self, publication: &Path, sha256: &str) -> io::Result<()> {
        self.revalidate()?;
        let actual = crate::file_storage::final_path_guid(
            &OpenOptions::new()
                .read(true)
                .share_mode(1)
                .custom_flags(0x0020_0000)
                .open(publication)?,
        )?;
        require(
            self.state.phase == "Delegated"
                && self.state.delegated.as_ref().is_some_and(|p| {
                    p.sha256 == sha256 && p.path.to_string_lossy().eq_ignore_ascii_case(&actual)
                }),
            "early preparation has not delegated to this actual final publication",
        )
    }
    /// Close ordinary live cancellation without bypassing the caller's
    /// existing source/fingerprint/full-hash checks or exposing a writer.
    pub fn mark_live_cancel_intent(&mut self) -> io::Result<()> {
        self.revalidate()?;
        require(
            matches!(self.state.phase.as_str(), "Frozen" | "CancelIntent"),
            "live cancellation cannot consume delegated or closed preparation",
        )?;
        let mut next = self.state.clone();
        next.phase = "CancelIntent".into();
        self.persist(next)
    }
    pub fn mark_live_cancelled(&mut self, events: &mut Vec<NativeEvent>) -> io::Result<()> {
        self.revalidate()?;
        require(
            self.state.phase == "CancelIntent",
            "actual live cancellation intent absent",
        )?;
        let state =
            native::observe_general_disk_state_readonly(self.intent.source.clone(), events)?;
        require(
            state.disk_attributes == 0
                && normalized(&state)? == self.intent.original_state_sha256
                && native::mounted_filesystem_general(self.intent.source.clone(), events)?
                    == "NTFS",
            "live preparation cancellation has not restored original NTFS",
        )?;
        let label = crate::volume_label::observe_label(self.intent.source.clone(), "NTFS")?;
        require(
            label.label == self.intent.label,
            "live cancellation original label differs",
        )?;
        let mut next = self.state.clone();
        next.phase = "Cancelled".into();
        self.persist(next)
    }
    /// Cancellation changes availability only, never source payload bytes.
    /// The exact durable phase must predate AP; attrs1 and delegated phases fail.
    pub fn cancel(&mut self, events: &mut Vec<NativeEvent>) -> io::Result<serde_json::Value> {
        self.revalidate()?;
        journal_route(&self.intent)?;
        require(
            !self.sealed
                && matches!(
                    self.state.phase.as_str(),
                    "Preparing" | "UnstartedCancelled" | "Frozen" | "CancelIntent" | "Cancelled"
                ),
            "preparation cannot cancel after delegation or without its locked baseline",
        )?;
        let binding = self.intent.source.clone();
        let observed = native_batch(events, |batch| native::observe_general_disk_state_readonly(binding.clone(), batch))?;
        require(
            normalized(&observed)? == self.intent.original_state_sha256,
            "preparation cancellation physical layout changed",
        )?;
        require(
            !matches!(
                self.state.phase.as_str(),
                "Cancelled" | "UnstartedCancelled"
            ) || observed.disk_attributes == 0,
            "closed preparation cannot change a later disk exclusion",
        )?;
        if observed.disk_attributes == 0 {
            require(
                matches!(
                    self.state.phase.as_str(),
                    "Preparing" | "UnstartedCancelled" | "Frozen" | "CancelIntent" | "Cancelled"
                ),
                "unresolved preparation source is unexpectedly writable",
            )?;
            require(
                native_batch(events, |batch| native::mounted_filesystem_general(binding.clone(), batch))? == "NTFS",
                "terminal preparation source is not NTFS",
            )?;
            // Both Frozen records precede the first persistent exclusion
            // request. A crash in that interval leaves original NTFS online.
            // Reconcile the actual identity without stale-byte replay or an
            // attribute transition on this writable terminal route.
            let mut reader = native_batch(events, |batch| native::GeneralPartitionReader::open(binding.clone(), batch))?;
            let mut boot = [0; 512];
            reader.read_exact(&mut boot)?;
            native_batch(events, |batch| reader.revalidate_route(batch))?;
            drop(reader);
            require(
                &boot[3..11] == b"NTFS    "
                    && boot[510..512] == [0x55, 0xaa]
                    && u64::from_le_bytes(boot[72..80].try_into().unwrap())
                        == self.intent.ntfs_serial
                    && u16::from_le_bytes(boot[11..13].try_into().unwrap())
                        == self.intent.bytes_per_sector
                    && boot[13] == self.intent.sectors_per_cluster
                    && native_batch(events, |batch| native::observe_general_disk_state_readonly(binding.clone(), batch))?
                        == observed,
                "online preparation NTFS identity changed",
            )?;
        } else {
            require(
                matches!(
                    self.state.phase.as_str(),
                    "Frozen" | "CancelIntent" | "Cancelled"
                ) && matches!(observed.disk_attributes, 2 | 3),
                "preparation source may have entered AP or is not protected",
            )?;
            if observed.disk_attributes == 2 {
                let (source, _) =
                    native_batch(events, |batch| GeneralFrozenPartition::restore_exclusion(binding.clone(), batch))?;
                drop(source);
            }
            let mut privileges =
                crate::attestation_native::Privileges::enable_for(&["SeManageVolumePrivilege"])?;
            let mut file = OpenOptions::new()
                .read(true)
                .write(true)
                .share_mode(0)
                .custom_flags(0x8000_0000)
                .open(format!("\\\\.\\PhysicalDrive{}", binding.disk_number))?;
            let before = native_batch(events, |batch| native::general_disk_state(&file, &binding, batch))?;
            require(
                before.disk_attributes == 3
                    && normalized(&before)? == self.intent.original_state_sha256,
                "exclusive preparation source differs",
            )?;
            file.seek(SeekFrom::Start(binding.identity.partition_offset))?;
            let mut boot = [0; 4096];
            file.read_exact(&mut boot)?;
            require(
                self.state.locked_boot_hex.as_ref() == Some(&hex::encode(boot)),
                "locked original NTFS boot changed",
            )?;
            self.revalidate()?;
            super::preflight_mount_paths(&binding, &self.intent.mount_paths)?;
            let mut next = self.state.clone();
            next.phase = "CancelIntent".into();
            self.persist(next)?;
            journal_route(&self.intent)?;
            require(
                native_batch(events, |batch| native::general_disk_state(&file, &binding, batch))? == before,
                "source changed before preparation cancellation",
            )?;
            native_batch(events, |batch| native::set_attributes(&file, 0, batch))?;
            native_batch(events, |batch| native::refresh_disk_properties(&file, batch))?;
            let after = native_batch(events, |batch| native::general_disk_state(&file, &binding, batch))?;
            require(
                after.disk_attributes == 0
                    && normalized(&after)? == self.intent.original_state_sha256,
                "preparation cancellation availability transition differs",
            )?;
            native_batch(events, |batch| native::close_file(file, "close-preparation-cancellation-source", batch))?;
            privileges.restore()?;
        }
        self.revalidate()?;
        let paths =
            native_batch(events, |batch| super::restore_ntfs_mount_paths(binding.clone(), &self.intent.mount_paths, batch))?;
        let label = crate::volume_label::observe_label(binding.clone(), "NTFS")?;
        require(
            label.label == self.intent.label,
            "restored preparation source label differs",
        )?;
        let mut next = self.state.clone();
        next.phase = if next.locked_boot_hex.is_some() {
            "Cancelled"
        } else {
            "UnstartedCancelled"
        }
        .into();
        self.persist(next)?;
        Ok(
            serde_json::json!({"kind":"resource-preparation-cancellation-v1","source":binding,
            "original_ntfs_online":true,"source_payload_writes":0,"complete_partition_hash":false,
            "preservation_basis":"durable pre-AP guard, exact native layout and locked NTFS boot; no raw source writer issued",
            "mount_paths":paths,"label_preserved":true,"journal_replayed":false}),
        )
    }
}
