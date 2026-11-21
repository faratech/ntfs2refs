//! Constructor-owned native-shadow security repair through the existing journal.
//!
//! This adapter never opens a source writer and never qualifies source security.
//! It journals only the graph planner's exact metadata clusters, uses the same
//! native AP/range-limited writer/HND/reseal protocol as conversion, and returns
//! the same shadow owner for the unchanged strict protected native observer.
//!
//! The caller supplies a separately admitted repair arena. NativeJournal is a
//! single-use arena group, so this must not consume the main conversion arena's
//! NativeJournal slot. Its storage/RAM must be carved out of the caller's actual
//! existing budget; constructing another arena does not create more capacity.
use crate::{
    artifact_arena::{ArtifactArena, ArtifactGroup, ArtifactGroupPermit, ArtifactLease},
    general_reconstruct::selected_native_journal::BoundNativeCreationJournal,
    lab_reconstruct::{DurableIo, ReadSeek},
    ntfs_inspect::paged_storage::SourceScratch,
    refs_security_patch::{SecurityClusterPatch, SecurityPatchPlan},
    selected_journal::{
        self as sj, SelectedLifecycle, SelectedPlan, SelectedRange, SelectedTicket,
    },
};
use anyhow::{Context, Result, ensure};
use n2r_win32::{
    GeneralFrozenPartition, NativeEvent,
    general_layout::GeneralDiskBinding,
    journal_file::{
        GeneralJournalStorageBinding, JournalFileIdentity, JournalProfile, MarkerStorageUse,
    },
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    fs::OpenOptions,
    io::{self, Read, Seek, SeekFrom, Write},
    mem,
    os::windows::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};

const CLUSTER: usize = 4096;
const MAX_CLUSTERS: usize = 16_384;
const PIN_BYTES: usize = 64 * 1024;
// Generic selected preparation/replay uses fixed MiB buffers and bounded
// record vectors. Index scanning prepays its own 12 MiB SourceScratch lease.
const WORKSPACE_BYTES: u64 = 24 * 1024 * 1024;

// The SDK bounds one native operation's batch, not all retained history.
// Append failed-operation evidence before returning its original error too.
fn native_step<T, E>(
    history: &mut Vec<NativeEvent>,
    operation: impl FnOnce(&mut Vec<NativeEvent>) -> std::result::Result<T, E>,
) -> std::result::Result<T, E> {
    let mut batch = Vec::new();
    let result = operation(&mut batch);
    history.append(&mut batch);
    result
}

#[derive(Clone, Copy)]
pub(crate) struct SecurityRepairBudget {
    pub(crate) maximum_changed_clusters: u32,
    pub(crate) maximum_journal_bytes: u64,
}

impl SecurityRepairBudget {
    /// Adapter workspace plus the existing scanner's simultaneous 12 MiB
    /// lease. The caller separately prepays graph-plan storage and arena/
    /// scratch registries before constructing those owners.
    pub(crate) fn required_working_ram_bytes(self) -> Result<u64> {
        ensure!(
            (1..=MAX_CLUSTERS as u32).contains(&self.maximum_changed_clusters),
            "security repair changed-cluster RAM bound is unsupported"
        );
        WORKSPACE_BYTES
            .checked_add(12 * 1024 * 1024)
            .and_then(|bytes| {
                bytes.checked_add(
                    u64::from(self.maximum_changed_clusters)
                        .checked_mul(mem::size_of::<SelectedRange>() as u64 + 256)?,
                )
            })
            .context("security repair maximum RAM overflow")
    }

    pub(crate) fn maximum_selected_bytes(self) -> Result<u64> {
        ensure!(
            (1..=MAX_CLUSTERS as u32).contains(&self.maximum_changed_clusters),
            "security repair changed-cluster storage bound is unsupported"
        );
        u64::from(self.maximum_changed_clusters)
            .checked_mul(CLUSTER as u64)
            .context("security repair maximum selected bytes overflow")
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct SecurityRepairReceipt {
    pub(crate) kind: &'static str,
    pub(crate) shadow: GeneralDiskBinding,
    pub(crate) patch_plan_sha256: String,
    pub(crate) prepared_pin_path: PathBuf,
    pub(crate) prepared_pin_sha256: String,
    pub(crate) journal_path: PathBuf,
    pub(crate) journal_bytes: u64,
    pub(crate) changed_clusters: u32,
    pub(crate) selected_bytes: u64,
    pub(crate) selected_after_sha256: String,
    pub(crate) native_bytes_written: u64,
    pub(crate) journal_handoff_closed: bool,
    pub(crate) shadow_resealed_readonly: bool,
    pub(crate) source_payload_write_calls: u64,
    pub(crate) native_security_preservation_qualified: bool,
    pub(crate) strict_original_security_readback_required: bool,
}

/// Retains the actual closed repair journal and its immutable metadata files.
/// This is a completed shadow-maintenance receipt, never source admission or
/// a substitute for strict native original-descriptor comparison.
pub(crate) struct CompletedSecurityRepair {
    receipt: SecurityRepairReceipt,
    _journal: BoundNativeCreationJournal,
    _index: ArtifactLease,
    _prepared_pin: ArtifactLease,
    _completed_pin: ArtifactLease,
    _arena: ArtifactArena,
}

impl CompletedSecurityRepair {
    pub(crate) fn receipt(&self) -> &SecurityRepairReceipt {
        &self.receipt
    }
}

#[derive(Serialize)]
struct PreparedRepairPin<'a> {
    kind: &'static str,
    original_source: &'a GeneralDiskBinding,
    shadow: &'a GeneralDiskBinding,
    journal_binding: &'a GeneralJournalStorageBinding,
    journal_identity: &'a JournalFileIdentity,
    journal_path: &'a Path,
    maximum_journal_bytes: u64,
    patch_plan_sha256: &'a str,
    ticket: &'a SelectedTicket,
    source_payload_write_calls: u64,
    native_security_preservation_qualified: bool,
}

/// A full-length *read-only* view with bytes only at the planned clusters.
/// An attempted complement read fails instead of scanning unrelated payload.
struct PlannedBytes<'a> {
    patches: &'a [SecurityClusterPatch],
    image_bytes: u64,
    position: u64,
}

impl Read for PlannedBytes<'_> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() || self.position == self.image_bytes {
            return Ok(0);
        }
        let index = self
            .patches
            .partition_point(|patch| patch.offset <= self.position);
        let patch = index
            .checked_sub(1)
            .and_then(|i| self.patches.get(i))
            .ok_or_else(|| invalid("repair candidate read outside planned metadata"))?;
        let within = self
            .position
            .checked_sub(patch.offset)
            .filter(|at| *at < CLUSTER as u64)
            .ok_or_else(|| invalid("repair candidate read in unselected complement"))?
            as usize;
        let count = output.len().min(CLUSTER - within);
        output[..count].copy_from_slice(&patch.after[within..within + count]);
        self.position += count as u64;
        Ok(count)
    }
}

impl Seek for PlannedBytes<'_> {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        self.position = bounded_seek(self.position, self.image_bytes, from)?;
        Ok(self.position)
    }
}

impl ReadSeek for PlannedBytes<'_> {
    fn byte_len(&mut self) -> io::Result<u64> {
        Ok(self.image_bytes)
    }
}

// Adapt the existing native range-limited writer to the existing generic
// selected-journal engine. No underlying file or additional write path exists.
struct JournalTarget<'a, 'writer>(&'a mut n2r_win32::BorrowedPagedWriter<'writer>);

impl Read for JournalTarget<'_, '_> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        self.0.read(output)
    }
}
impl Seek for JournalTarget<'_, '_> {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        self.0.seek(from)
    }
}
impl Write for JournalTarget<'_, '_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.write(bytes)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}
impl ReadSeek for JournalTarget<'_, '_> {
    fn byte_len(&mut self) -> io::Result<u64> {
        Ok(self.0.byte_len())
    }
}
impl DurableIo for JournalTarget<'_, '_> {
    fn sync_all(&mut self) -> io::Result<()> {
        self.0.sync_all()
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn bounded_seek(position: u64, length: u64, from: SeekFrom) -> io::Result<u64> {
    let next = match from {
        SeekFrom::Start(value) => i128::from(value),
        SeekFrom::Current(value) => i128::from(position) + i128::from(value),
        SeekFrom::End(value) => i128::from(length) + i128::from(value),
    };
    if next < 0 || next > i128::from(length) {
        return Err(invalid("repair metadata seek outside image"));
    }
    Ok(next as u64)
}

fn framed(hash: &mut Sha256, bytes: &[u8]) {
    hash.update((bytes.len() as u64).to_le_bytes());
    hash.update(bytes);
}

fn plan_digest(plan: &SecurityPatchPlan) -> String {
    let mut hash = Sha256::new();
    hash.update(b"n2r-constructor-native-security-repair-plan-v1");
    framed(&mut hash, plan.profile.as_bytes());
    for value in [plan.image_bytes, plan.volume_bytes, plan.volume_serial] {
        hash.update(value.to_le_bytes());
    }
    framed(&mut hash, plan.vbr_sha256.as_bytes());
    framed(&mut hash, plan.volume_guid_bytes_hex.as_bytes());
    hash.update(plan.page_reads.to_le_bytes());
    hash.update((plan.checkpoint_bindings.len() as u64).to_le_bytes());
    for checkpoint in &plan.checkpoint_bindings {
        hash.update(checkpoint.lcn.to_le_bytes());
        hash.update(checkpoint.virtual_clock.to_le_bytes());
        framed(&mut hash, checkpoint.before_sha256.as_bytes());
        framed(&mut hash, checkpoint.after_sha256.as_bytes());
        hash.update((checkpoint.descriptor_matches.len() as u64).to_le_bytes());
        for count in &checkpoint.descriptor_matches {
            hash.update(count.to_le_bytes());
        }
    }
    hash.update((plan.clusters.len() as u64).to_le_bytes());
    for patch in &plan.clusters {
        hash.update(patch.offset.to_le_bytes());
        framed(&mut hash, &patch.before);
        framed(&mut hash, &patch.after);
    }
    hex::encode(hash.finalize())
}

fn require_plan_shape(plan: &SecurityPatchPlan, budget: SecurityRepairBudget) -> Result<()> {
    ensure!(
        (1..=MAX_CLUSTERS as u32).contains(&budget.maximum_changed_clusters)
            && !plan.clusters.is_empty()
            && plan.clusters.len() <= budget.maximum_changed_clusters as usize
            && plan.image_bytes >= 2 * CLUSTER as u64
            && plan.image_bytes.is_multiple_of(CLUSTER as u64)
            && plan.volume_bytes == plan.image_bytes
            && plan.checkpoint_bindings.len() == 2,
        "bounded complete native-shadow repair plan required"
    );
    let mut previous_end = CLUSTER as u64;
    for patch in &plan.clusters {
        let end = patch
            .offset
            .checked_add(CLUSTER as u64)
            .context("security repair cluster overflow")?;
        ensure!(
            patch.before.len() == CLUSTER
                && patch.after.len() == CLUSTER
                && patch.before != patch.after
                && patch.offset.is_multiple_of(CLUSTER as u64)
                && patch.offset >= previous_end
                && end <= plan.image_bytes - CLUSTER as u64,
            "security repair clusters overlap, escape metadata bounds, or have invalid storage"
        );
        previous_end = end;
    }
    for checkpoint in &plan.checkpoint_bindings {
        let offset = checkpoint
            .lcn
            .checked_mul(CLUSTER as u64)
            .context("security checkpoint offset overflow")?;
        ensure!(
            offset >= CLUSTER as u64
                && offset
                    .checked_add(4 * CLUSTER as u64)
                    .is_some_and(|end| end <= plan.image_bytes)
                && checkpoint.before_sha256.len() == 64
                && checkpoint.after_sha256.len() == 64,
            "security repair checkpoint bounds differ"
        );
    }
    ensure!(
        plan.checkpoint_bindings[0].lcn != plan.checkpoint_bindings[1].lcn,
        "security repair checkpoint identities alias"
    );
    Ok(())
}

fn require_image(
    reader: &mut GeneralFrozenPartition,
    plan: &SecurityPatchPlan,
    after: bool,
) -> Result<()> {
    ensure!(
        reader.byte_len()? == plan.image_bytes,
        "security repair native image length differs"
    );
    let mut vbr = [0u8; 512];
    reader.seek(SeekFrom::Start(0))?;
    reader.read_exact(&mut vbr)?;
    let geometry = crate::refs_inspect::inspect_boot_sector(&vbr, plan.image_bytes)?;
    ensure!(
        hex::encode(Sha256::digest(vbr)) == plan.vbr_sha256
            && geometry.volume_serial == plan.volume_serial
            && geometry.volume_bytes == plan.volume_bytes
            && geometry.major_version == 3
            && geometry.minor_version == 14
            && geometry.bytes_per_sector == 512
            && geometry.bytes_per_cluster == CLUSTER as u32,
        "security repair native VBR identity or geometry differs"
    );
    let mut current = [0u8; CLUSTER];
    for patch in &plan.clusters {
        reader.seek(SeekFrom::Start(patch.offset))?;
        reader.read_exact(&mut current)?;
        ensure!(
            current.as_slice()
                == if after {
                    patch.after.as_slice()
                } else {
                    patch.before.as_slice()
                },
            "security repair actual selected metadata differs from the exact planned bytes"
        );
    }
    let mut checkpoint_bytes = [0u8; 4 * CLUSTER];
    for checkpoint in &plan.checkpoint_bindings {
        reader.seek(SeekFrom::Start(checkpoint.lcn * CLUSTER as u64))?;
        reader.read_exact(&mut checkpoint_bytes)?;
        let expected = if after {
            &checkpoint.after_sha256
        } else {
            &checkpoint.before_sha256
        };
        ensure!(
            &hex::encode(Sha256::digest(checkpoint_bytes)) == expected,
            "security repair actual checkpoint closure differs"
        );
    }
    Ok(())
}

struct BoundedJson(Vec<u8>);
impl Write for BoundedJson {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self
            .0
            .len()
            .checked_add(bytes.len())
            .is_none_or(|end| end > PIN_BYTES)
        {
            return Err(invalid("security repair metadata pin exceeds its bound"));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn persist_pin(
    group: &ArtifactGroupPermit,
    path: &Path,
    value: &impl Serialize,
) -> Result<(ArtifactLease, String)> {
    let permit = group.reserve_file(path, PIN_BYTES as u64)?;
    let mut bytes = BoundedJson(Vec::with_capacity(PIN_BYTES));
    serde_json::to_writer(&mut bytes, value)?;
    let digest = hex::encode(Sha256::digest(&bytes.0));
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .share_mode(0)
        .custom_flags(0x0020_0000)
        .open(permit.path())?;
    file.write_all(&bytes.0)?;
    file.sync_all()?;
    drop(file);
    Ok((permit.verify_closed(&digest)?, digest))
}

/// Patch only a constructor-owned disposable shadow, before target admission.
/// `source` is used solely by the existing native J creator's read-only identity
/// checks. The native write gate receives `shadow`; source is never activated.
/// Errors preserve journal/files and persistent exclusion; there is no retry,
/// automatic rollback, mount, or original-source recovery action here.
#[allow(clippy::too_many_arguments)]
pub(crate) fn repair_shadow(
    source: &mut GeneralFrozenPartition,
    mut shadow: GeneralFrozenPartition,
    plan: &SecurityPatchPlan,
    repair_arena: &ArtifactArena,
    group: &ArtifactGroupPermit,
    scratch: &SourceScratch,
    output: &Path,
    budget: SecurityRepairBudget,
    journal_binding: &GeneralJournalStorageBinding,
    events: &mut Vec<NativeEvent>,
) -> Result<(GeneralFrozenPartition, CompletedSecurityRepair)> {
    require_plan_shape(plan, budget)?;
    ensure!(
        matches!(
            group.group(),
            ArtifactGroup::Capture | ArtifactGroup::RecoveryCopy
        ) && group.arena().same_arena(repair_arena),
        "repair metadata group belongs to another arena"
    );
    let scratch_group = scratch
        .artifact_group()
        .context("repair scratch must retain the actual arena")?;
    ensure!(
        scratch_group.group() == group.group() && scratch_group.arena().same_arena(repair_arena),
        "repair scanner scratch and metadata group differ"
    );
    let root = OpenOptions::new()
        .access_mode(0x80)
        .share_mode(3)
        .custom_flags(0x0220_0000)
        .open(output)?;
    repair_arena.require_root_directory(&root)?;
    let workspace = WORKSPACE_BYTES
        .checked_add(
            (plan.clusters.len() as u64)
                .checked_mul(mem::size_of::<SelectedRange>() as u64 + 256)
                .context("repair range workspace overflow")?,
        )
        .context("repair workspace overflow")?;
    let _workspace = repair_arena.reserve_ram(workspace)?;
    let source_before = native_step(events, |batch| source.state(batch))?;
    let shadow_before = native_step(events, |batch| shadow.state(batch))?;
    ensure!(
        source_before.disk_attributes == 3
            && shadow_before.disk_attributes == 3
            && source.binding().disk_number != shadow.binding().disk_number,
        "repair requires distinct actual frozen source and disposable shadow"
    );
    require_image(&mut shadow, plan, false)?;
    let patch_plan_sha256 = plan_digest(plan);
    let selected_bytes = (plan.clusters.len() as u64)
        .checked_mul(CLUSTER as u64)
        .context("security repair selected bytes overflow")?;
    let selected = SelectedPlan {
        image_length: plan.image_bytes,
        ranges: plan
            .clusters
            .iter()
            .map(|patch| SelectedRange {
                offset: patch.offset,
                length: CLUSTER as u64,
            })
            .collect(),
        max_selected_bytes: selected_bytes,
        max_journal_bytes: budget.maximum_journal_bytes,
        new_zero_ranges: Vec::new(),
        new_copy_ranges: Vec::new(),
        old_zero_ranges: Vec::new(),
        source_free_ranges: Vec::new(),
    };
    let (_, journal_bytes) = selected.validate()?;
    let profile = JournalProfile::from_schema_and_capacity(3, Some(budget.maximum_journal_bytes))?;
    let journal_path = output.join("trust-label-repair.journal");
    let mut creation = native_step(events, |batch| {
        BoundNativeCreationJournal::create_new(
            source,
            &mut shadow,
            repair_arena,
            journal_bytes,
            &journal_path,
            journal_binding,
            profile,
            None,
            MarkerStorageUse::QualifiedProduction,
            batch,
        )
    })?;
    let prepared_pin_path = output.join("trust-label-repair-prepared.json");
    let completed_pin_path = output.join("trust-label-repair-completed.json");
    let (receipt, prepared_pin, completed_pin, index_lease) = (|| -> Result<_> {
        let (journal, facts) = creation.split_for_preparation()?;
        let mut candidate = PlannedBytes {
            patches: &plan.clusters,
            image_bytes: plan.image_bytes,
            position: 0,
        };
        let ticket = sj::prepare_exclusive(&mut shadow, &mut candidate, journal, &selected)?;
        let native_allocation = journal.fix_length_and_observe_allocation(&facts, &ticket)?;
        repair_arena.attach_native_journal(facts.journal_quota, native_allocation)?;
        let index_bytes = 128u64
            .checked_add(
                u64::from(ticket.range_count)
                    .checked_mul(32)
                    .context("repair index rows overflow")?,
            )
            .and_then(|n| n.checked_add(64))
            .context("repair index bytes overflow")?;
        let index = sj::resource_domain::reopen::JournalObservation::open(
            journal,
            &ticket,
            group,
            scratch,
            &output.join("trust-label-repair.index"),
            index_bytes,
        )?
        .into_prepared_index()?;
        index.require_same_sealed_journal(journal, &ticket)?;
        journal.revalidate_resource_preparation(&facts, &ticket)?;
        let prepared = PreparedRepairPin {
            kind: "constructor-native-shadow-security-repair-prepared-v1",
            original_source: facts.source,
            shadow: facts.shadow,
            journal_binding: facts.binding,
            journal_identity: facts.identity,
            journal_path: facts.path,
            maximum_journal_bytes: budget.maximum_journal_bytes,
            patch_plan_sha256: &patch_plan_sha256,
            ticket: &ticket,
            source_payload_write_calls: 0,
            native_security_preservation_qualified: false,
        };
        let (prepared_pin, prepared_pin_sha256) =
            persist_pin(group, &prepared_pin_path, &prepared)?;
        prepared_pin.revalidate()?;
        require_image(&mut shadow, plan, false)?;
        ensure!(
            native_step(events, |batch| source.state(batch))? == source_before
                && native_step(events, |batch| shadow.state(batch))? == shadow_before,
            "source or native shadow changed before repair activation"
        );
        let pins = n2r_win32::PagedRecoveryPins {
            journal_binding: facts.binding,
            journal_identity: facts.identity,
            journal_path: facts.path,
            journal_profile: facts.profile,
            digest: ticket.digest_algorithm(),
            immutable_sha256: ticket.immutable_sha256,
            old_selected_sha256: ticket.old_selected_sha256,
            old_restored_selected_sha256: ticket.old_restored_selected_sha256,
            new_selected_sha256: ticket.new_selected_sha256,
        };
        let native_bytes_written = {
            let mut native = native_step(events, |batch| {
                journal.begin_sealed_fresh_apply(&mut shadow, index.policy(), &pins, false, batch)
            })?;
            let mut target = JournalTarget(&mut native);
            // The native gate has already durably issued AP. Existing resume
            // retains every OLD/NEW/MIXED refusal and existing flush/readback.
            let applied = sj::resume(&mut target, journal, &selected, &ticket)?;
            ensure!(
                applied.selected_sha256 == ticket.new_selected_sha256 && !applied.replay_closed,
                "security repair selected NEW result differs"
            );
            prepared_pin.revalidate()?;
            index.require_same_sealed_journal(journal, &ticket)?;
            sj::handoff(&mut target, journal, &selected, &ticket)?;
            let (lifecycle, closed) = sj::verify_closed(&mut target, journal, &selected, &ticket)?;
            ensure!(
                lifecycle == SelectedLifecycle::Handoff
                    && closed.replay_closed
                    && closed.selected_sha256 == ticket.new_selected_sha256,
                "security repair actual journal HND/NEW verification differs"
            );
            drop(target);
            native.native_bytes_written()
        };
        native_step(events, |batch| {
            journal.seal_sealed_handoff_for_observation(&mut shadow, &index.policy(), &pins, batch)
        })?;
        require_image(&mut shadow, plan, true)?;
        let (lifecycle, closed) = sj::verify_closed(&mut shadow, journal, &selected, &ticket)?;
        ensure!(
            lifecycle == SelectedLifecycle::Handoff
                && closed.replay_closed
                && closed.selected_sha256 == ticket.new_selected_sha256
                && native_step(events, |batch| source.state(batch))? == source_before
                && native_step(events, |batch| shadow.state(batch))? == shadow_before,
            "security repair reseal or closing native identity differs"
        );
        prepared_pin.revalidate()?;
        index.require_same_sealed_journal(journal, &ticket)?;
        journal.revalidate_resource_preparation(&facts, &ticket)?;
        let receipt = SecurityRepairReceipt {
            kind: "constructor-native-shadow-security-repair-completed-v1",
            shadow: shadow.binding().clone(),
            patch_plan_sha256,
            prepared_pin_path: prepared_pin_path.clone(),
            prepared_pin_sha256,
            journal_path: facts.path.to_path_buf(),
            journal_bytes: ticket.journal_length,
            changed_clusters: ticket.range_count,
            selected_bytes: ticket.selected_bytes,
            selected_after_sha256: hex::encode(ticket.new_selected_sha256),
            native_bytes_written,
            journal_handoff_closed: true,
            shadow_resealed_readonly: true,
            source_payload_write_calls: 0,
            native_security_preservation_qualified: false,
            strict_original_security_readback_required: true,
        };
        let (completed_pin, _) = persist_pin(group, &completed_pin_path, &receipt)?;
        completed_pin.revalidate()?;
        Ok((
            receipt,
            prepared_pin,
            completed_pin,
            index.artifact_lease().clone(),
        ))
    })()
    .with_context(|| {
        format!(
            "native shadow security repair stopped; preserve {} and {}",
            journal_path.display(),
            prepared_pin_path.display()
        )
    })?;
    drop(root);
    Ok((
        shadow,
        CompletedSecurityRepair {
            receipt,
            _journal: creation,
            _index: index_lease,
            _prepared_pin: prepared_pin,
            _completed_pin: completed_pin,
            _arena: repair_arena.clone(),
        },
    ))
}
