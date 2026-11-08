//! Ordinary scratch metadata in authenticated bounded chunks. No device I/O.
use super::source_domain::{SourceMetadataBudget, SourceMetadataRange};
use anyhow::{Context, Result, ensure};
use n2r_win32::metadata_pages::{PageBudget, Reader, Writer};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    cell::RefCell,
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    os::windows::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    rc::Rc,
    time::SystemTime,
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourcePagePin {
    pub path: PathBuf,
    pub purpose: [u8; 8],
    pub file_sha256: String,
    pub logical_sha256: String,
    pub logical_bytes: u64,
    pub wire_bytes: u64,
    pub chunk_bytes: u32,
    pub page_budget: PageBudget,
}
struct Ledger {
    budget: SourceMetadataBudget,
    wire: u64,
    ram: u64,
    poisoned: bool,
    created: BTreeMap<PathBuf, CreatedFile>,
    arena: Option<crate::artifact_arena::ArtifactGroupPermit>,
    sealed: bool,
    writers: u64,
    temporary_creations: u64,
    extra_artifacts: Vec<crate::artifact_arena::ArtifactLease>,
}
struct CreatedFile {
    pin: SourcePagePin,
    file_id: String,
    parent_id: String,
    canonical_parent: PathBuf,
    modified: SystemTime,
    readers: u64,
    ram: u64,
    _arena_ram: Option<crate::artifact_arena::ArenaRamLease>,
    artifact: Option<crate::artifact_arena::ArtifactLease>,
}
#[derive(Clone)]
pub struct SourceScratch(Rc<RefCell<Ledger>>);
impl SourceScratch {
    pub fn new(budget: SourceMetadataBudget) -> Result<Self> {
        budget.validate()?;
        Ok(Self(Rc::new(RefCell::new(Ledger {
            budget,
            wire: 0,
            ram: 0,
            poisoned: false,
            created: BTreeMap::new(),
            arena: None,
            sealed: false,
            writers: 0,
            temporary_creations: 0,
            extra_artifacts: Vec::new(),
        }))))
    }
    pub fn new_in_arena(
        budget: SourceMetadataBudget,
        permit: crate::artifact_arena::ArtifactGroupPermit,
    ) -> Result<Self> {
        ensure!(
            permit.group() == crate::artifact_arena::ArtifactGroup::Source
                && budget.scratch_bytes <= permit.maximum_bytes()?,
            "source scratch requires its actual source group permit"
        );
        let scratch = Self::new(budget)?;
        scratch.0.borrow_mut().arena = Some(permit);
        Ok(scratch)
    }
    pub fn artifact_group(&self) -> Option<crate::artifact_arena::ArtifactGroupPermit> {
        self.0.borrow().arena.clone()
    }
    pub fn new_auxiliary_in_arena(
        mut budget: SourceMetadataBudget,
        permit: crate::artifact_arena::ArtifactGroupPermit,
    ) -> Result<Self> {
        ensure!(
            matches!(
                permit.group(),
                crate::artifact_arena::ArtifactGroup::Auxiliary
                    | crate::artifact_arena::ArtifactGroup::Capture
                    | crate::artifact_arena::ArtifactGroup::RecoveryCopy
            ),
            "non-source scratch requires an auxiliary/capture/recovery group"
        );
        budget.scratch_bytes = permit.maximum_bytes()?;
        let scratch = Self::new(budget)?;
        scratch.0.borrow_mut().arena = Some(permit);
        Ok(scratch)
    }
    /// Keep a canonical sub-stage page budget while every file/RAM lease is
    /// still charged to the actual, possibly larger auxiliary group. This
    /// neither enlarges the supplied budget nor grants an independent quota.
    pub fn new_bounded_auxiliary_in_arena(
        budget: SourceMetadataBudget,
        permit: crate::artifact_arena::ArtifactGroupPermit,
    ) -> Result<Self> {
        ensure!(
            matches!(
                permit.group(),
                crate::artifact_arena::ArtifactGroup::Auxiliary
                    | crate::artifact_arena::ArtifactGroup::Capture
                    | crate::artifact_arena::ArtifactGroup::RecoveryCopy
            ) && budget.scratch_bytes <= permit.maximum_bytes()?,
            "bounded non-source scratch requires its actual auxiliary/capture/recovery group"
        );
        let scratch = Self::new(budget)?;
        scratch.0.borrow_mut().arena = Some(permit);
        Ok(scratch)
    }
    pub fn seal(&self) -> Result<crate::artifact_arena::ArtifactGroupSeal> {
        let permit = {
            let ledger = self.0.borrow();
            ensure!(
                !ledger.poisoned && ledger.writers == 0 && ledger.temporary_creations == 0,
                "source scratch has active writers/temp creations or poison"
            );
            ledger
                .arena
                .clone()
                .context("standalone source scratch has no shared arena capability")?
        };
        let seal = permit.seal()?;
        let mut ledger = self.0.borrow_mut();
        ledger.wire = seal.wire_bytes();
        ledger.sealed = true;
        Ok(seal)
    }
    pub fn is_sealed(&self) -> bool {
        self.0.borrow().sealed
    }
    pub fn remaining_bytes(&self) -> u64 {
        let ledger = self.0.borrow();
        ledger.budget.scratch_bytes - ledger.wire
    }
    pub fn budget(&self) -> SourceMetadataBudget {
        self.0.borrow().budget
    }
    pub fn used_bytes(&self) -> u64 {
        self.0.borrow().wire
    }
    pub fn working_ram_bytes(&self) -> u64 {
        self.0.borrow().ram
    }
    pub fn is_poisoned(&self) -> bool {
        self.0.borrow().poisoned
    }
    fn parent_handles(path: &Path) -> Result<(Vec<File>, String, PathBuf)> {
        let parent = path.parent().context("source scratch parent absent")?;
        let mut handles = Vec::new();
        for ancestor in parent.ancestors().filter(|p| !p.as_os_str().is_empty()) {
            let metadata = fs::symlink_metadata(ancestor)?;
            ensure!(
                metadata.is_dir() && metadata.file_attributes() & 0x400 == 0,
                "ordinary scratch parent required"
            );
            let handle = OpenOptions::new()
                .access_mode(0x80)
                .share_mode(3)
                .custom_flags(0x0200_0000 | 0x0020_0000)
                .open(ancestor)?;
            ensure!(
                handle.metadata()?.is_dir() && handle.metadata()?.file_attributes() & 0x400 == 0,
                "scratch parent handle differs"
            );
            handles.try_reserve(1)?;
            handles.push(handle);
        }
        let id = n2r_win32::file_storage::file_id_info(
            handles.first().context("scratch parent handle absent")?,
        )?;
        Ok((handles, id, fs::canonicalize(parent)?))
    }
    fn register_created(
        &self,
        pin: &SourcePagePin,
        artifact: Option<crate::artifact_arena::ArtifactLease>,
    ) -> Result<()> {
        let (_parents, parent_id, canonical_parent) = Self::parent_handles(&pin.path)?;
        let file = OpenOptions::new()
            .read(true)
            .share_mode(1)
            .custom_flags(0x0020_0000)
            .open(&pin.path)?;
        let metadata = file.metadata()?;
        ensure!(
            metadata.is_file()
                && metadata.file_attributes() & 0x400 == 0
                && n2r_win32::file_storage::number_of_links(&file)? == 1
                && metadata.len() == pin.wire_bytes,
            "new scratch file identity differs"
        );
        let file_id = n2r_win32::file_storage::file_id_info(&file)?;
        let ram = (std::mem::size_of::<CreatedFile>() as u64)
            .checked_add(256)
            .and_then(|n| n.checked_add((pin.path.as_os_str().as_encoded_bytes().len() as u64) * 4))
            .and_then(|n| {
                n.checked_add((canonical_parent.as_os_str().as_encoded_bytes().len() as u64) * 4)
            })
            .and_then(|n| n.checked_add(256))
            .context("scratch registry memory overflow")?;
        let mut ledger = self.0.borrow_mut();
        ensure!(
            !ledger.poisoned && !ledger.created.contains_key(&pin.path),
            "duplicate or poisoned created scratch registry"
        );
        let total = ledger
            .ram
            .checked_add(ram)
            .context("scratch registry RAM overflow")?;
        ensure!(
            total <= ledger.budget.ram_bytes,
            "created scratch identity registry RAM exhausted"
        );
        let arena_ram = ledger
            .arena
            .as_ref()
            .map(|permit| permit.arena().reserve_ram(ram))
            .transpose()?;
        ledger.ram = total;
        ledger.created.insert(
            pin.path.clone(),
            CreatedFile {
                pin: pin.clone(),
                file_id,
                parent_id,
                canonical_parent,
                modified: metadata.modified()?,
                readers: 0,
                ram,
                _arena_ram: arena_ram,
                artifact,
            },
        );
        Ok(())
    }
    fn reader_lease(&self, pin: &SourcePagePin) -> Result<Option<CreatedReaderLease>> {
        let file = OpenOptions::new()
            .read(true)
            .share_mode(1)
            .custom_flags(0x0020_0000)
            .open(&pin.path)?;
        let identity = n2r_win32::file_storage::file_id_info(&file)?;
        let metadata = file.metadata()?;
        let mut ledger = self.0.borrow_mut();
        if let Some(created) = ledger.created.get_mut(&pin.path) {
            ensure!(
                &created.pin == pin
                    && created.file_id == identity
                    && metadata.len() == pin.wire_bytes
                    && metadata.modified()? == created.modified,
                "created source pin or held identity differs from registry"
            );
            created.readers = created
                .readers
                .checked_add(1)
                .context("scratch reader count overflow")?;
            return Ok(Some(CreatedReaderLease {
                scratch: self.clone(),
                path: pin.path.clone(),
            }));
        }
        Ok(None)
    }
    /// Delete only an exact closed file created by this same private ledger.
    /// JSON pins supply no credit. No pathname deletion or permission change.
    pub fn retire_created(&self, pin: &SourcePagePin) -> Result<()> {
        let result = (|| -> Result<()> {
            let artifact = {
                let mut ledger = self.0.borrow_mut();
                ensure!(!ledger.poisoned, "source scratch is poisoned");
                let entry = ledger
                    .created
                    .get_mut(&pin.path)
                    .context("scratch file was not created by this ledger")?;
                ensure!(
                    entry.pin == *pin && entry.readers == 0,
                    "scratch pin differs or readers survive"
                );
                entry.artifact.take()
            };
            if let Some(artifact) = artifact {
                artifact.retire()?;
                let mut ledger = self.0.borrow_mut();
                let entry = ledger
                    .created
                    .remove(&pin.path)
                    .context("created scratch registration disappeared")?;
                ledger.wire = ledger
                    .wire
                    .checked_sub(entry.pin.wire_bytes)
                    .context("scratch wire credit underflow")?;
                ledger.ram = ledger
                    .ram
                    .checked_sub(entry.ram)
                    .context("scratch RAM credit underflow")?;
                return Ok(());
            }
            let _ram = self.lease_ram(65536)?;
            let (id, parent, canonical, modified, bytes, registry_ram) = {
                let ledger = self.0.borrow();
                ensure!(!ledger.poisoned, "source scratch is poisoned");
                let entry = ledger
                    .created
                    .get(&pin.path)
                    .context("scratch file was not created by this ledger")?;
                ensure!(
                    entry.pin == *pin && entry.readers == 0,
                    "scratch file pin differs or an owner still reads it"
                );
                (
                    entry.file_id.clone(),
                    entry.parent_id.clone(),
                    entry.canonical_parent.clone(),
                    entry.modified,
                    entry.pin.wire_bytes,
                    entry.ram,
                )
            };
            let (_parents, current_parent, current_canonical) = Self::parent_handles(&pin.path)?;
            ensure!(
                current_parent == parent && current_canonical == canonical,
                "scratch parent identity changed"
            );
            // DELETE access is obtained without delete-on-close. Nothing can
            // be removed before the same-handle identity and full SHA pass.
            let mut file = OpenOptions::new()
                .access_mode(0x8000_0000 | 0x0001_0000)
                .share_mode(0)
                .custom_flags(0x0020_0000)
                .open(&pin.path)?;
            let metadata = file.metadata()?;
            ensure!(
                metadata.is_file()
                    && metadata.file_attributes() & 0x400 == 0
                    && n2r_win32::file_storage::number_of_links(&file)? == 1
                    && metadata.len() == bytes
                    && metadata.modified()? == modified
                    && n2r_win32::file_storage::file_id_info(&file)? == id,
                "registered scratch handle identity differs"
            );
            let mut hash = Sha256::new();
            let mut buffer = [0u8; 65536];
            let mut left = bytes;
            file.seek(SeekFrom::Start(0))?;
            while left > 0 {
                let n = left.min(buffer.len() as u64) as usize;
                file.read_exact(&mut buffer[..n])?;
                hash.update(&buffer[..n]);
                left -= n as u64;
            }
            ensure!(
                hex::encode(hash.finalize()) == pin.file_sha256
                    && file.metadata()?.len() == bytes
                    && file.metadata()?.modified()? == modified,
                "registered scratch bytes changed"
            );
            n2r_win32::file_storage::mark_delete_on_close(&file)?;
            drop(file);
            match fs::symlink_metadata(&pin.path) {
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                _ => anyhow::bail!("registered scratch deletion was not observed complete"),
            }
            let mut ledger = self.0.borrow_mut();
            let entry = ledger
                .created
                .remove(&pin.path)
                .context("created scratch registration disappeared")?;
            ensure!(
                entry.readers == 0 && entry.pin == *pin,
                "created scratch owner changed"
            );
            ledger.wire = ledger
                .wire
                .checked_sub(bytes)
                .context("scratch wire credit underflow")?;
            ledger.ram = ledger
                .ram
                .checked_sub(registry_ram)
                .context("scratch RAM credit underflow")?;
            Ok(())
        })();
        if result.is_err() {
            self.0.borrow_mut().poisoned = true;
        }
        result
    }
    fn reserve_wire(&self, bytes: u64) -> Result<()> {
        let mut ledger = self.0.borrow_mut();
        ensure!(
            !ledger.poisoned && !ledger.sealed,
            "source scratch is poisoned or sealed"
        );
        let used = ledger
            .wire
            .checked_add(bytes)
            .context("source scratch byte overflow")?;
        ensure!(
            used <= ledger.budget.scratch_bytes,
            "source metadata scratch exhausted"
        );
        ledger.wire = used;
        Ok(())
    }
    pub fn lease_ram(&self, bytes: u64) -> Result<SourceRamLease> {
        let mut ledger = self.0.borrow_mut();
        ensure!(!ledger.poisoned, "source scratch is poisoned");
        let used = ledger
            .ram
            .checked_add(bytes)
            .context("metadata RAM overflow")?;
        ensure!(
            used <= ledger.budget.ram_bytes,
            "source metadata working RAM exhausted: active={}, requested={}, limit={}",
            ledger.ram,
            bytes,
            ledger.budget.ram_bytes
        );
        let arena_ram = ledger
            .arena
            .as_ref()
            .map(|permit| permit.arena().reserve_ram(bytes))
            .transpose()?;
        ledger.ram = used;
        Ok(SourceRamLease {
            scratch: self.clone(),
            bytes,
            _arena_ram: arena_ram,
        })
    }
    fn lease_window(&self) -> Result<SourceRamLease> {
        let bytes = u64::from(self.budget().page_bytes)
            .checked_mul(3)
            .context("metadata RAM overflow")?;
        self.lease_ram(bytes)
    }
    pub fn reserve_temporary(
        &self,
        wire_bytes: u64,
        ram_bytes: u64,
    ) -> Result<SourceTemporaryLease> {
        ensure!(
            self.0.borrow().arena.is_none() || wire_bytes == 0,
            "arena source temporary files require reserve_temporary_file with an owned path"
        );
        self.reserve_temporary_inner(None, wire_bytes, ram_bytes)
    }
    pub fn reserve_temporary_file(
        &self,
        path: &Path,
        wire_bytes: u64,
        ram_bytes: u64,
    ) -> Result<SourceTemporaryLease> {
        let permit = self
            .artifact_group()
            .map(|group| group.reserve_file(path, wire_bytes))
            .transpose()?;
        self.reserve_temporary_inner(permit, wire_bytes, ram_bytes)
    }
    fn reserve_temporary_inner(
        &self,
        permit: Option<crate::artifact_arena::ArtifactPathPermit>,
        wire_bytes: u64,
        ram_bytes: u64,
    ) -> Result<SourceTemporaryLease> {
        let ram = self.lease_ram(ram_bytes)?;
        self.reserve_wire(wire_bytes)?;
        let mut ledger = self.0.borrow_mut();
        ledger.temporary_creations = ledger
            .temporary_creations
            .checked_add(1)
            .context("source temporary count overflow")?;
        drop(ledger);
        Ok(SourceTemporaryLease {
            _ram: ram,
            bytes: wire_bytes,
            scratch: self.clone(),
            permit,
            complete: false,
        })
    }
    pub fn writer(&self, path: &Path, purpose: [u8; 8]) -> Result<SourceRangeWriter> {
        ensure!(
            !self.0.borrow().sealed,
            "sealed source scratch refuses all new writers"
        );
        let artifact = self
            .artifact_group()
            .map(|group| group.reserve_file(path, 1024))
            .transpose()?;
        let path = artifact
            .as_ref()
            .map_or_else(|| path.to_path_buf(), |p| p.path().to_path_buf());
        let ram = self.lease_window()?;
        let page = self.0.borrow().budget.page_bytes;
        // Both count ceilings derive from physical scratch bytes and minimum
        // record/frame sizes. They impose no independent filesystem limit.
        let budget = self.0.borrow().budget.page_budget()?;
        budget.validate()?;
        let chunk_bytes = page
            .checked_sub(192)
            .context("source page cannot hold a chunk")?
            / 4
            * 3;
        ensure!(chunk_bytes != 0, "source page cannot hold a chunk");
        self.reserve_wire(1024)?;
        let mut writer = Writer::new(&path, purpose, budget)?;
        writer.push(
            &[],
            &serde_json::to_vec(&RangeHeader {
                schema_version: 1,
                chunk_bytes,
            })?,
        )?;
        let mut body = Vec::new();
        body.try_reserve_exact(chunk_bytes as usize)
            .context("source chunk RAM unavailable")?;
        {
            let mut ledger = self.0.borrow_mut();
            ledger.writers = ledger
                .writers
                .checked_add(1)
                .context("source writer count overflow")?;
        }
        Ok(SourceRangeWriter {
            writer: Some(writer),
            scratch: self.clone(),
            _ram: ram,
            path,
            purpose,
            budget,
            chunk_bytes,
            body,
            logical_bytes: 0,
            chunks: 0,
            hash: Sha256::new(),
            reserved: 1024,
            charged: 1024,
            complete: false,
            artifact,
        })
    }
}
pub struct SourceRamLease {
    scratch: SourceScratch,
    bytes: u64,
    _arena_ram: Option<crate::artifact_arena::ArenaRamLease>,
}
impl SourceRamLease {
    /// Return only verified unused RAM while retaining the same local/global
    /// owner. The source ledger and shared arena receive exactly one credit.
    pub fn shrink_to(&mut self, bytes: u64) -> Result<()> {
        ensure!(
            bytes <= self.bytes,
            "source RAM lease cannot grow by shrinking"
        );
        let delta = self.bytes - bytes;
        let remaining = self
            .scratch
            .0
            .borrow()
            .ram
            .checked_sub(delta)
            .context("source RAM shrink underflow")?;
        if let Some(lease) = self._arena_ram.as_mut() {
            lease.shrink_to(bytes)?;
        }
        self.scratch.0.borrow_mut().ram = remaining;
        self.bytes = bytes;
        Ok(())
    }
}
struct CreatedReaderLease {
    scratch: SourceScratch,
    path: PathBuf,
}
impl Drop for CreatedReaderLease {
    fn drop(&mut self) {
        if let Some(entry) = self.scratch.0.borrow_mut().created.get_mut(&self.path) {
            entry.readers -= 1;
        }
    }
}
impl Drop for SourceRamLease {
    fn drop(&mut self) {
        self.scratch.0.borrow_mut().ram -= self.bytes;
    }
}
pub struct SourceTemporaryLease {
    bytes: u64,
    scratch: SourceScratch,
    permit: Option<crate::artifact_arena::ArtifactPathPermit>,
    complete: bool,
    _ram: SourceRamLease,
}
impl SourceTemporaryLease {
    pub fn bytes(&self) -> u64 {
        self.bytes
    }
    pub fn verify_closed(
        mut self,
        expected_sha256: &str,
    ) -> Result<crate::artifact_arena::ArtifactLease> {
        let artifact = self
            .permit
            .take()
            .context("temporary has no arena path permit")?
            .verify_closed(expected_sha256)?;
        {
            let mut ledger = self.scratch.0.borrow_mut();
            let unused = self
                .bytes
                .checked_sub(artifact.wire_bytes())
                .context("source temporary length exceeds reservation")?;
            ledger.wire = ledger
                .wire
                .checked_sub(unused)
                .context("source temporary credit underflow")?;
            ledger.extra_artifacts.push(artifact.clone());
        }
        self.complete = true;
        Ok(artifact)
    }
}
impl Drop for SourceTemporaryLease {
    fn drop(&mut self) {
        if !self.complete {
            if let Some(permit) = self.permit.take() {
                match permit.verify_closed_current() {
                    Ok(artifact) => {
                        let mut ledger = self.scratch.0.borrow_mut();
                        if let Some(credit) = self
                            .bytes
                            .checked_sub(artifact.wire_bytes())
                            .and_then(|n| ledger.wire.checked_sub(n))
                        {
                            ledger.wire = credit;
                            ledger.extra_artifacts.push(artifact);
                        } else {
                            ledger.poisoned = true;
                        }
                    }
                    Err(_) => self.scratch.0.borrow_mut().poisoned = true,
                }
            }
        }
        let mut ledger = self.scratch.0.borrow_mut();
        ledger.temporary_creations -= 1;
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RangeHeader {
    schema_version: u32,
    chunk_bytes: u32,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RangeFooter {
    logical_bytes: u64,
    chunks: u64,
    logical_sha256: String,
}

struct Base64<'a>(&'a [u8]);
impl std::fmt::Display for Base64<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        const ABC: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        for value in self.0.chunks(3) {
            let a = value[0];
            let b = value.get(1).copied();
            let c = value.get(2).copied();
            let encoded = [
                ABC[(a >> 2) as usize],
                ABC[(((a & 3) << 4) | (b.unwrap_or(0) >> 4)) as usize],
                b.map_or(b'=', |b| {
                    ABC[(((b & 15) << 2) | (c.unwrap_or(0) >> 6)) as usize]
                }),
                c.map_or(b'=', |c| ABC[(c & 63) as usize]),
            ];
            f.write_str(std::str::from_utf8(&encoded).map_err(|_| std::fmt::Error)?)?;
        }
        Ok(())
    }
}
impl Serialize for Base64<'_> {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}
fn decode(payload: &[u8], maximum: usize) -> Result<Vec<u8>> {
    let text: &str = serde_json::from_slice(payload)?;
    let input = text.as_bytes();
    ensure!(
        !input.is_empty() && input.len().is_multiple_of(4),
        "source chunk base64 length differs"
    );
    let padding = input.iter().rev().take_while(|b| **b == b'=').count();
    ensure!(padding <= 2, "source chunk base64 padding differs");
    let length = (input.len() / 4)
        .checked_mul(3)
        .and_then(|n| n.checked_sub(padding))
        .context("source chunk length overflow")?;
    ensure!(
        length > 0 && length <= maximum,
        "source chunk exceeds working window"
    );
    let digit = |b| -> Result<u8> {
        Ok(match b {
            b'A'..=b'Z' => b - b'A',
            b'a'..=b'z' => b - b'a' + 26,
            b'0'..=b'9' => b - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => anyhow::bail!("noncanonical source chunk alphabet"),
        })
    };
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(length)?;
    for (index, value) in input.chunks_exact(4).enumerate() {
        let last = index + 1 == input.len() / 4;
        let a = digit(value[0])?;
        let b = digit(value[1])?;
        bytes.push((a << 2) | (b >> 4));
        if value[2] == b'=' {
            ensure!(
                last && value[3] == b'=' && b & 15 == 0,
                "noncanonical source chunk padding"
            );
        } else {
            let c = digit(value[2])?;
            bytes.push((b << 4) | (c >> 2));
            if value[3] == b'=' {
                ensure!(last && c & 3 == 0, "noncanonical source chunk padding");
            } else {
                bytes.push((c << 6) | digit(value[3])?);
            }
        }
    }
    ensure!(bytes.len() == length, "source chunk decoded length differs");
    Ok(bytes)
}

pub struct SourceRangeWriter {
    writer: Option<Writer>,
    scratch: SourceScratch,
    path: PathBuf,
    purpose: [u8; 8],
    budget: PageBudget,
    chunk_bytes: u32,
    body: Vec<u8>,
    logical_bytes: u64,
    chunks: u64,
    hash: Sha256,
    reserved: u64,
    charged: u64,
    complete: bool,
    artifact: Option<crate::artifact_arena::ArtifactPathPermit>,
    // The charged writer buffers must be destroyed before releasing RAM.
    _ram: SourceRamLease,
}
impl SourceRangeWriter {
    pub fn byte_len(&self) -> u64 {
        self.logical_bytes
    }
    fn reserve_total(&mut self, bytes: u64) -> Result<()> {
        if bytes <= self.reserved {
            return Ok(());
        }
        let additional = bytes - self.reserved;
        if let Some(permit) = self.artifact.as_mut() {
            permit.extend(additional)?;
        }
        self.scratch.reserve_wire(additional)?;
        self.reserved = bytes;
        Ok(())
    }
    /// Reserve a complete logical prefix before an external irreversible IO.
    /// Full-size final chunks deliberately overestimate wire/framing; finish
    /// returns only the verified unused credit. Ordinary writers need no call.
    pub fn reserve_logical_bytes(&mut self, logical: u64) -> Result<()> {
        ensure!(
            logical >= self.logical_bytes,
            "source reservation precedes written bytes"
        );
        let chunks = logical.div_ceil(u64::from(self.chunk_bytes));
        let per_chunk = u64::from(self.chunk_bytes)
            .div_ceil(3)
            .checked_mul(4)
            .and_then(|n| n.checked_add(2 + 8 + 8 + 64 + 64))
            .context("source prepaid chunk wire overflow")?;
        let bytes = chunks
            .checked_mul(per_chunk)
            .and_then(|n| n.checked_add(1024))
            .context("source prepaid wire overflow")?;
        self.reserve_total(bytes)
    }
    fn chunk(&mut self) -> Result<()> {
        if self.body.is_empty() {
            return Ok(());
        }
        let payload = serde_json::to_vec(&Base64(&self.body))?;
        // Reserve the full encoded row plus its own page and index frames.
        // Shared concurrent writers cannot overrun aggregate scratch first.
        let bytes = (payload.len() as u64)
            .checked_add(8 + 8 + 64 + 64)
            .context("source wire overflow")?;
        let charged = self
            .charged
            .checked_add(bytes)
            .context("source chunk charge overflow")?;
        self.reserve_total(charged)?;
        self.charged = charged;
        self.writer
            .as_mut()
            .context("source writer absent")?
            .push(&self.chunks.to_be_bytes(), &payload)?;
        self.chunks = self
            .chunks
            .checked_add(1)
            .context("source chunk count overflow")?;
        self.body.clear();
        Ok(())
    }
    pub fn finish(mut self) -> Result<SourcePagePin> {
        self.chunk()?;
        let logical_sha256 = hex::encode(self.hash.clone().finalize());
        let footer = RangeFooter {
            logical_bytes: self.logical_bytes,
            chunks: self.chunks,
            logical_sha256: logical_sha256.clone(),
        };
        self.writer
            .as_mut()
            .context("source writer absent")?
            .push(&u64::MAX.to_be_bytes(), &serde_json::to_vec(&footer)?)?;
        let summary = self
            .writer
            .take()
            .context("source writer absent")?
            .finish()?;
        ensure!(
            summary.bytes <= self.reserved,
            "source wire accounting differs"
        );
        self.scratch.0.borrow_mut().wire -= self.reserved - summary.bytes;
        let pin = SourcePagePin {
            path: self.path.clone(),
            purpose: self.purpose,
            file_sha256: summary.sha256,
            logical_sha256,
            logical_bytes: self.logical_bytes,
            wire_bytes: summary.bytes,
            chunk_bytes: self.chunk_bytes,
            page_budget: self.budget,
        };
        let artifact = self
            .artifact
            .take()
            .map(|permit| permit.verify_closed(&pin.file_sha256))
            .transpose()?;
        self.scratch.register_created(&pin, artifact)?;
        self.complete = true;
        Ok(pin)
    }
}
impl Write for SourceRangeWriter {
    fn write(&mut self, mut bytes: &[u8]) -> io::Result<usize> {
        let total = bytes.len();
        let result = (|| -> Result<()> {
            ensure!(
                !self.scratch.0.borrow().poisoned,
                "source scratch is poisoned"
            );
            self.logical_bytes = self
                .logical_bytes
                .checked_add(total as u64)
                .context("source logical length overflow")?;
            self.hash.update(bytes);
            while !bytes.is_empty() {
                let n = bytes.len().min(self.chunk_bytes as usize - self.body.len());
                self.body.extend_from_slice(&bytes[..n]);
                bytes = &bytes[n..];
                if self.body.len() == self.chunk_bytes as usize {
                    self.chunk()?;
                }
            }
            Ok(())
        })();
        if result.is_err() {
            self.scratch.0.borrow_mut().poisoned = true;
        }
        result.map(|()| total).map_err(io::Error::other)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
impl Drop for SourceRangeWriter {
    fn drop(&mut self) {
        self.scratch.0.borrow_mut().writers -= 1;
        if !self.complete {
            self.scratch.0.borrow_mut().poisoned = true;
        }
    }
}

pub struct PagedMetadataRange {
    reader: RefCell<Reader>,
    decoded: RefCell<DecodedChunks>,
    resident: Option<ResidentMetadataCache>,
    pin: SourcePagePin,
    // Both possible decoded chunks are prepaid. Retain the same file-inventory
    // cache policy without allocating an independently maximum-sized window.
    second_chunk_cache: bool,
    _created: Option<CreatedReaderLease>,
    // All cache/path/registry payloads above drop before their RAM credits.
    _ram: SourceRamLease,
    _path_ram: SourceRamLease,
}
#[derive(Default)]
struct DecodedChunks {
    recent: Option<(u64, Vec<u8>)>,
    previous: Option<(u64, Vec<u8>)>,
}
struct ResidentMetadataCache {
    bytes: Vec<u8>,
    // Release the retained buffer before returning its aggregate RAM credit.
    _ram: SourceRamLease,
}
impl ResidentMetadataCache {
    fn try_new(purpose: [u8; 8], length: u64, scratch: &SourceScratch) -> Option<Self> {
        // Only canonical metadata stores qualify; source payload ranges never do.
        let divisor = if purpose == *b"N2RFILE1" {
            4
        } else if purpose == *b"N2RNSD01" || purpose == *b"N2RNSE01"
            || purpose == *b"N2RSCEN1" || purpose == *b"N2RSLEG1" || purpose == *b"N2RSBND1" {
            // Namespace/security joins revisit entries in different key orders.
            // Keep modest complete tables cached when the SAME aggregate
            // ledger can pay for them; refusal still uses paged fallback.
            32
        } else {
            return None;
        };
        let charge = length.checked_add(std::mem::size_of::<Self>() as u64)?;
        if length == 0 || charge > scratch.budget().ram_bytes / divisor { return None; }
        let size = usize::try_from(length).ok()?;
        // Optional quota/allocation refusals preserve the ordinary chunk reader.
        let ram = scratch.lease_ram(charge).ok()?;
        let mut bytes = Vec::new();
        if bytes.try_reserve_exact(size).is_err() || bytes.capacity() != size { return None; }
        Some(Self { bytes, _ram: ram })
    }
}
impl PagedMetadataRange {
    pub fn capture(
        path: &Path,
        purpose: [u8; 8],
        source: &mut impl Read,
        byte_len: u64,
        scratch: &SourceScratch,
    ) -> Result<SourcePagePin> {
        let mut writer = scratch.writer(path, purpose)?;
        let length = scratch.0.borrow().budget.page_bytes as usize / 4;
        let mut buffer = Vec::new();
        buffer.try_reserve_exact(length)?;
        buffer.resize(length, 0);
        let mut left = byte_len;
        while left > 0 {
            let n = left.min(buffer.len() as u64) as usize;
            source.read_exact(&mut buffer[..n])?;
            writer.write_all(&buffer[..n])?;
            left -= n as u64;
        }
        writer.finish()
    }
    pub fn open(pin: &SourcePagePin, scratch: &SourceScratch) -> Result<Self> {
        for digest in [&pin.file_sha256, &pin.logical_sha256] {
            ensure!(
                digest.len() == 64
                    && digest
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
                "source range requires canonical SHA-256 pins before allocation"
            );
        }
        ensure!(
            !scratch.is_poisoned(),
            "source range owner is poisoned before open"
        );
        ensure!(
            pin.wire_bytes <= scratch.budget().scratch_bytes,
            "source range wire bytes exceed owner scratch: wire={}, owner={}",
            pin.wire_bytes, scratch.budget().scratch_bytes
        );
        let declared_chunk = pin
            .page_budget
            .max_page_bytes
            .checked_sub(192)
            .context("source chunk window differs")?
            / 4
            * 3;
        ensure!(
            declared_chunk > 0 && pin.chunk_bytes == declared_chunk,
            "source chunk protocol differs before allocation"
        );
        // Prepay native path/snapshot construction before opening a file.
        // The fixed allowance covers native UTF16/GUID path workspace; the
        // retained amount below is then reduced using the actual held route.
        let path_work = (pin.path.as_os_str().as_encoded_bytes().len() as u64)
            .checked_mul(12)
            .and_then(|n| n.checked_add(32768 * 24 + 65536))
            .context("source reader path memory overflow")?;
        let mut path_ram = scratch.lease_ram(path_work)?;
        let file = OpenOptions::new()
            .read(true)
            .share_mode(1)
            .custom_flags(0x0020_0000)
            .open(&pin.path)?;
        let metadata = file.metadata()?;
        ensure!(
            metadata.is_file()
                && metadata.file_attributes() & 0x400 == 0
                && metadata.len() == pin.wire_bytes,
            "source range actual held length/type differs before cache allocation"
        );
        let body = Reader::body_capacity_for_file(pin.page_budget, metadata.len())? as u64;
        // A source chunk uses lossless base64, so no decoded chunk can exceed
        // the actual complete file length even before its logical footer closes.
        let initial_decoded = u64::from(declared_chunk).min(metadata.len());
        // The producer's page geometry is part of the authenticated format,
        // not a request to allocate that maximum in a different boot's owner.
        // Admit only the actual held-file body/decode bounds under this SAME
        // owner's existing page cap; the normal aggregate leases still follow.
        ensure!(body <= u64::from(scratch.budget().page_bytes)
            && initial_decoded <= u64::from(scratch.budget().page_bytes),
            "source range held buffers exceed owner page cap: wire={}, format_page={}, body={}, decoded={}, owner_page={}",
            metadata.len(), pin.page_budget.max_page_bytes, body, initial_decoded,
            scratch.budget().page_bytes);
        let initial_cache = body
            .checked_add(
                initial_decoded
                    .checked_mul(2)
                    .context("source decode memory overflow")?,
            )
            .context("source reader memory overflow")?;
        // Reader's complete key-order validation may briefly retain both the
        // previous and next key. Pay for arbitrary valid page keys before the
        // typed source header/footer has narrowed the retained cache sizes.
        let constructor = body
            .checked_mul(3)
            .context("source reader construction memory overflow")?;
        let mut ram = scratch.lease_ram(initial_cache.max(constructor))?;
        let mut reader = Reader::open_held(file, &pin.file_sha256, pin.purpose, pin.page_budget)?;
        ensure!(
            reader.byte_len() == pin.wire_bytes
                && reader.len() >= 2
                && reader.body_capacity() as u64 <= body,
            "source range wire length or actual cache capacity differs"
        );
        let header: RangeHeader = reader.with_record(0, |key, payload| {
            if !key.is_empty() {
                return Err(io::Error::other("source range header key differs"));
            }
            serde_json::from_slice(payload).map_err(io::Error::other)
        })?;
        ensure!(
            header.schema_version == 1 && header.chunk_bytes == declared_chunk,
            "source range actual chunk header differs"
        );
        let last = reader.len() - 1;
        let footer: RangeFooter = reader.with_record(last, |key, payload| {
            if key != u64::MAX.to_be_bytes() {
                return Err(io::Error::other("source range footer key differs"));
            }
            serde_json::from_slice(payload).map_err(io::Error::other)
        })?;
        ensure!(
            footer.logical_bytes == pin.logical_bytes
                && footer.logical_sha256 == pin.logical_sha256
                && footer.chunks.checked_add(2) == Some(reader.len())
                && footer.chunks == footer.logical_bytes.div_ceil(u64::from(declared_chunk)),
            "source range actual logical footer differs"
        );
        // Only actual held-file and authenticated logical sizes determine the
        // retained cache budget. No pin alone can reduce the prepaid window.
        let decoded = footer.logical_bytes.min(u64::from(declared_chunk));
        ram.shrink_to(
            body.checked_add(
                decoded
                    .checked_mul(2)
                    .context("source retained decode memory overflow")?,
            )
            .context("source retained reader memory overflow")?,
        )?;
        let mut resident = ResidentMetadataCache::try_new(pin.purpose, footer.logical_bytes, scratch);
        let mut hash = Sha256::new();
        let mut total = 0u64;
        for ordinal in 0..footer.chunks {
            let chunk = reader.with_record(ordinal + 1, |key, payload| {
                if key != ordinal.to_be_bytes() {
                    return Err(io::Error::other("source range chunk order differs"));
                }
                decode(payload, usize::try_from(decoded).map_err(io::Error::other)?)
                    .map_err(io::Error::other)
            })?;
            let expected = (footer.logical_bytes - total).min(u64::from(declared_chunk));
            ensure!(
                chunk.len() as u64 == expected,
                "source range has a short interior chunk"
            );
            hash.update(&chunk);
            if let Some(cache) = &mut resident {
                cache.bytes.extend_from_slice(&chunk);
            }
            total += chunk.len() as u64;
        }
        ensure!(
            total == footer.logical_bytes && hex::encode(hash.finalize()) == pin.logical_sha256,
            "complete source range logical SHA differs"
        );
        reader.revalidate()?;
        let created = scratch.reader_lease(pin)?;
        let second_chunk_cache = (pin.purpose == *b"N2RFILE1"
            || pin.purpose == *b"N2RNSD01" || pin.purpose == *b"N2RNSE01"
            || pin.purpose == *b"N2RSCEN1" || pin.purpose == *b"N2RSLEG1" || pin.purpose == *b"N2RSBND1")
            && footer.logical_bytes > u64::from(declared_chunk)
            && u64::from(declared_chunk) <= scratch.budget().ram_bytes / 64;
        // Both decoded slots were prepaid above, including the old/new overlap
        // on a miss. Namespace binary searches and cross-directory hard links
        // also alternate metadata chunks; retain their already-paid second
        // slot rather than repeatedly decoding megabytes for each name.
        let actual_path = (pin.path.as_os_str().as_encoded_bytes().len() as u64)
            .checked_add(reader.final_path().len() as u64)
            .and_then(|n| n.checked_mul(12))
            .and_then(|n| n.checked_add(65536 + 4096))
            .context("source retained path memory overflow")?;
        ensure!(
            actual_path <= path_work,
            "actual source route exceeds its prepaid path workspace"
        );
        path_ram.shrink_to(actual_path)?;
        Ok(Self {
            reader: RefCell::new(reader),
            decoded: RefCell::new(DecodedChunks::default()),
            resident,
            pin: pin.clone(),
            _ram: ram,
            second_chunk_cache,
            _created: created,
            _path_ram: path_ram,
        })
    }
    pub fn clear_resident_cache(&mut self) {
        self.resident = None;
    }
    pub fn slice(self: &Rc<Self>, offset: u64, bytes: u64) -> Result<SourceMetadataSlice> {
        ensure!(
            offset
                .checked_add(bytes)
                .is_some_and(|n| n <= self.pin.logical_bytes),
            "source metadata slice escapes owner"
        );
        Ok(SourceMetadataSlice {
            owner: Rc::clone(self),
            offset,
            bytes,
        })
    }
}
impl SourceMetadataRange for PagedMetadataRange {
    fn byte_len(&self) -> u64 {
        self.pin.logical_bytes
    }
    fn read_exact_at(&self, offset: u64, mut output: &mut [u8]) -> Result<()> {
        ensure!(
            offset
                .checked_add(output.len() as u64)
                .is_some_and(|n| n <= self.pin.logical_bytes),
            "source range read escapes metadata"
        );
        if let Some(cache) = &self.resident {
            let start = usize::try_from(offset).context("resident source address exceeds address space")?;
            let end = start.checked_add(output.len()).context("resident source address overflow")?;
            output.copy_from_slice(cache.bytes.get(start..end)
                .context("resident source range differs from complete metadata")?);
            return Ok(());
        }
        let mut at = offset;
        while !output.is_empty() {
            let ordinal = at / u64::from(self.pin.chunk_bytes);
            let skip = (at % u64::from(self.pin.chunk_bytes)) as usize;
            {
                let mut cache = self.decoded.borrow_mut();
                if !cache.recent.as_ref().is_some_and(|(n, _)| *n == ordinal)
                    && cache.previous.as_ref().is_some_and(|(n, _)| *n == ordinal)
                {
                    let previous = cache.previous.take();
                    cache.previous = cache.recent.take();
                    cache.recent = previous;
                }
            }
            if !self
                .decoded
                .borrow()
                .recent
                .as_ref()
                .is_some_and(|(n, _)| *n == ordinal)
            {
                {
                    let mut cache = self.decoded.borrow_mut();
                    cache.previous = if self.second_chunk_cache {
                        cache.recent.take()
                    } else {
                        cache.recent = None;
                        None
                    };
                }
                let chunk = self
                    .reader
                    .borrow_mut()
                    .with_record(ordinal + 1, |key, payload| {
                        if key != ordinal.to_be_bytes() {
                            return Err(io::Error::other("held source range chunk key differs"));
                        }
                        let maximum = self.pin.logical_bytes.min(u64::from(self.pin.chunk_bytes));
                        decode(payload, usize::try_from(maximum).map_err(io::Error::other)?)
                            .map_err(io::Error::other)
                    })?;
                let remaining = self.pin.logical_bytes - ordinal * u64::from(self.pin.chunk_bytes);
                ensure!(
                    chunk.len() as u64 == remaining.min(u64::from(self.pin.chunk_bytes)),
                    "held source range chunk length differs"
                );
                self.decoded.borrow_mut().recent = Some((ordinal, chunk));
            }
            let cached = self.decoded.borrow();
            let chunk = &cached
                .recent
                .as_ref()
                .context("source chunk cache absent")?
                .1;
            let n = output.len().min(chunk.len() - skip);
            output[..n].copy_from_slice(&chunk[skip..skip + n]);
            output = &mut output[n..];
            at += n as u64;
        }
        Ok(())
    }
    fn revalidate(&self) -> Result<()> {
        self.reader.borrow_mut().revalidate()?;
        Ok(())
    }
}
pub struct SourceMetadataSlice {
    owner: Rc<PagedMetadataRange>,
    offset: u64,
    bytes: u64,
}
impl SourceMetadataRange for SourceMetadataSlice {
    fn byte_len(&self) -> u64 {
        self.bytes
    }
    fn read_exact_at(&self, offset: u64, output: &mut [u8]) -> Result<()> {
        ensure!(
            offset
                .checked_add(output.len() as u64)
                .is_some_and(|n| n <= self.bytes),
            "source slice read escapes range"
        );
        self.owner.read_exact_at(self.offset + offset, output)
    }
    fn revalidate(&self) -> Result<()> {
        self.owner.revalidate()
    }
}
