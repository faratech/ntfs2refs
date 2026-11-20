//! Actual fresh-HND finalization. Publication provenance is retained before AP;
//! no after-the-fact checksum, JSON certificate or stale NTFS proof is issued.
use super::*;
use crate::{
    artifact_arena::ArenaRamLease,
    general_composite_target::paged_memory::ArenaReportMemory,
    general_shadow::PagedInputs,
    selected_journal::resource_domain::prepare::{
        PartitionApplyOutcome, PartitionResourcePreparedConversion,
    },
};
use n2r_win32::{
    partition_restoration::{
        PartitionLivePublicationFiles, PartitionRestorationObserver, PartitionRestorationReceipt,
        PartitionTerminalRestorationGuard,
    },
    reference_file::ReferenceFileSnapshot,
};
use std::io;

pub(super) struct PartitionPublishedFiles {
    publication: File,
    locator: File,
    publication_sha256: [u8; 32],
    publication_snapshot: ReferenceFileSnapshot,
    locator_snapshot: ReferenceFileSnapshot,
    _memory: ArenaRamLease,
}
fn publisher_hash(value: &str) -> Result<[u8; 32]> {
    ensure!(
        value.len() == 64
            && value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "actual publisher checksum is not canonical SHA256"
    );
    let decoded = hex::decode(value)?;
    Ok(decoded
        .as_slice()
        .try_into()
        .context("actual publisher SHA256 width differs")?)
}
fn held_snapshot(file: &File) -> Result<ReferenceFileSnapshot> {
    n2r_win32::file_storage::require_readonly_access(file)?;
    let snapshot = n2r_win32::reference_file::observe_reference_file_handle_with_limit(
        file,
        4 * 1024 * 1024 + 64,
    )?;
    ensure!(
        snapshot.file_bytes > 0 && snapshot.number_of_links == 1,
        "ordinary bounded single-link publication owner required"
    );
    Ok(snapshot)
}
fn deny_second_writer(snapshot: &ReferenceFileSnapshot) -> Result<()> {
    match OpenOptions::new()
        .read(true)
        .write(true)
        .share_mode(3)
        .custom_flags(0x0020_0000)
        .open(&snapshot.final_path)
    {
        Err(error) if error.raw_os_error() == Some(32) => Ok(()),
        Err(error) => Err(error).context("publication writer-exclusion proof is unknown"),
        Ok(contender) => {
            drop(contender);
            anyhow::bail!("held publication permits another ordinary RW writer")
        }
    }
}
impl PartitionPublishedFiles {
    pub(super) fn capture(
        published: &mut PartitionResourcePreparedConversion<'_, '_, '_, '_, '_, '_>,
        arena: &ArtifactArena,
    ) -> Result<Self> {
        // Covers fixed4MiB hashing plus bounded snapshots/path strings and the
        // retained handles; actual expected/native reports have separate leases.
        let memory = arena.reserve_ram(5 * 1024 * 1024)?;
        let publication_sha256 = publisher_hash(published.publication_sha256())?;
        let locator_sha256 = published.locator_sha256();
        let mut publication = OpenOptions::new()
            .read(true)
            .share_mode(1)
            .custom_flags(0x0020_0000)
            .open(published.publication_path())?;
        let mut locator = published.duplicate_locator_file()?;
        let publication_snapshot = held_snapshot(&publication)?;
        let locator_snapshot = held_snapshot(&locator)?;
        deny_second_writer(&publication_snapshot)?;
        deny_second_writer(&locator_snapshot)?;
        ensure!(
            n2r_win32::metadata_pages::pinning_digest(&mut publication, publication_snapshot.file_bytes)? == publication_sha256
                && n2r_win32::metadata_pages::pinning_digest(&mut locator, locator_snapshot.file_bytes)? == locator_sha256,
            "pre-AP publication/locator bytes differ from actual publisher owners"
        );
        ensure!(
            held_snapshot(&publication)? == publication_snapshot
                && held_snapshot(&locator)? == locator_snapshot,
            "pre-AP publication identity changed during capture"
        );
        // These expected hashes are captured from the actual publisher now,
        // while its ArtifactLease/locator and PreparedClear J are still held.
        Ok(Self {
            publication,
            locator,
            publication_sha256,
            publication_snapshot,
            locator_snapshot,
            _memory: memory,
        })
    }
    fn require_same_handles(&self) -> Result<()> {
        ensure!(
            held_snapshot(&self.publication)? == self.publication_snapshot
                && held_snapshot(&self.locator)? == self.locator_snapshot,
            "pending finalization lost pre-AP publication FileObjects"
        );
        deny_second_writer(&self.publication_snapshot)?;
        deny_second_writer(&self.locator_snapshot)
    }
}

/// Only execute_and_handoff constructs this from actual HND plus pre-AP held
/// publication owners. It is not serializable and exposes no writer authority.
pub(crate) struct PartitionPendingFinalization {
    outcome: PartitionApplyOutcome,
    files: PartitionPublishedFiles,
    pair: GeneralSourceShadowBinding,
}
impl PartitionPendingFinalization {
    pub(super) fn from_actual_handoff(
        outcome: PartitionApplyOutcome,
        files: PartitionPublishedFiles,
        pair: GeneralSourceShadowBinding,
    ) -> Self {
        Self {
            outcome,
            files,
            pair,
        }
    }
    pub(crate) fn trusted_publication_sha256(&self) -> [u8; 32] {
        self.files.publication_sha256
    }
}
#[derive(Debug, Serialize)]
pub(crate) struct PartitionFinalizationResult {
    pub restoration: PartitionRestorationReceipt,
    pub trusted_publication_sha256: String,
    pub metadata_objects_verified: u64,
    pub known_streams_hashed: u64,
    pub retained_streams_verified: u64,
    pub actual_terminal_native_and_maps_verified: bool,
    pub raw_replay_performed: bool,
}

/// Finish through actual native readonly fidelity and saved map owners, then
/// consume the SDK's original-handle HND guard to restore attrs/label/mounts.
pub(crate) fn finalize_partition_handoff(
    resources: PartitionPreparedResources,
    pending: PartitionPendingFinalization,
    observer: &mut impl PartitionRestorationObserver,
    events: &mut Vec<NativeEvent>,
    mut checkpoint: impl FnMut(&'static str, &mut Vec<NativeEvent>) -> Result<()>,
) -> Result<PartitionFinalizationResult> {
    pending.files.require_same_handles()?;
    let arena = resources.context.arena().clone();
    let admission = resources.context.resource_admission();
    let profile = n2r_win32::attestation::ResourceProfile::ResourceBoundedV4(Some(admission));
    resources.expected.require_resource_owner(admission)?;
    resources.expected.require_shared_memory(&arena)?;
    let PartitionPendingFinalization {
        outcome,
        files,
        pair,
    } = pending;
    let (witness, verification) = outcome.into_terminal_parts();
    // Drops capture/target/source read lanes and original-FileObject query
    // duplicates before the first mounted readonly ReFS observation.
    let (owner, native_admission, expected) = resources.into_terminal_inputs();
    ensure!(
        verification.source_token().same_owner(&owner.owner_token()),
        "terminal expected maps belong to another actual source"
    );
    let PartitionPublishedFiles {
        publication,
        locator,
        publication_sha256,
        _memory,
        ..
    } = files;
    checkpoint("partition-terminal-source-owner-transfer", events)?;
    let result = PartitionTerminalRestorationGuard::with_fresh_handoff(
        owner,
        native_admission,
        witness,
        PartitionLivePublicationFiles {
            publication,
            locator,
        },
        publication_sha256,
        events,
        |mut guard, events| {
            checkpoint("partition-terminal-readonly-transition", events)
                .map_err(io::Error::other)?;
            guard.enter_readonly(observer, events)?;
            checkpoint("partition-terminal-native-fidelity", events).map_err(io::Error::other)?;
            let native = {
                let readonly = guard.readonly_volume()?;
                if !verification
                    .source_token()
                    .same_owner(&readonly.owner_token())
                {
                    return Err(io::Error::other("readonly native source token changed"));
                }
                let actual_pair = GeneralSourceShadowBinding {
                    source: readonly.binding().clone(),
                    shadow: pair.shadow.clone(),
                };
                let observed = readonly.observe_converted_metadata_with_memory(
                    actual_pair,
                    &PagedInputs(&expected),
                    None,
                    |a, b| crate::ntfs_attestation::same_security(a, b).map_err(io::Error::other),
                    profile,
                    &ArenaReportMemory(arena.clone()),
                    true,
                    events,
                )?;
                verification
                    .verify_terminal_report(&expected, &observed)
                    .map_err(io::Error::other)?;
                observed
            };
            let count =
                u64::try_from(native.report().native.objects.len()).map_err(io::Error::other)?;
            let known = native
                .report()
                .content_observation
                .as_ref()
                .and_then(|c| c.known_content.as_ref())
                .ok_or_else(|| io::Error::other("actual terminal known-content report absent"))?;
            let hashed = u64::try_from(known.streams_hashed).map_err(io::Error::other)?;
            let retained =
                u64::try_from(known.streams_without_content_baseline).map_err(io::Error::other)?;
            checkpoint("partition-terminal-verified-before-restore", events)
                .map_err(io::Error::other)?;
            let restoration = guard.finish(native, observer, events)?;
            checkpoint("partition-terminal-restored", events).map_err(io::Error::other)?;
            Ok(PartitionFinalizationResult {
                restoration,
                trusted_publication_sha256: hex::encode(publication_sha256),
                metadata_objects_verified: count,
                known_streams_hashed: hashed,
                retained_streams_verified: retained,
                actual_terminal_native_and_maps_verified: true,
                raw_replay_performed: false,
            })
        },
    );
    drop(_memory);
    result.map_err(anyhow::Error::from)
}
