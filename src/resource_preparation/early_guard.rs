//! Cancellation-only V4 preparation ownership. An independently pinned intent
//! routes to real two-copy native state; neither JSON nor this owner can arm AP.
use crate::artifact_arena::{
    ArenaRamLease, ArtifactArena, ArtifactGroupPermit, ArtifactLease, ArtifactPathPermit,
};
use anyhow::{Context, Result, ensure};
use n2r_win32::{
    GeneralFrozenPartition, NativeEvent,
    general_layout::{GeneralDiskBinding, GeneralSourceShadowBinding},
    journal_file::GeneralJournalStorageBinding,
    source_cancel::preparation::{self, PreparationGuard},
    tree_resources::ResourceBudget,
};
use serde::{Deserialize, Serialize};
use std::{
    path::{Path, PathBuf},
    sync::{Mutex, MutexGuard},
};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GuardPin {
    pub path: PathBuf,
    pub sha256: String,
    pub bytes: u64,
}
pub(crate) struct GuardRoutes {
    pub source: GeneralDiskBinding,
    pub shadow: GeneralDiskBinding,
    pub journal: GeneralJournalStorageBinding,
    pub phase: String,
    pub delegated: Option<GuardPin>,
}
fn pin(guard: &PreparationGuard) -> GuardPin {
    GuardPin {
        path: PathBuf::from(guard.intent_path()),
        sha256: guard.intent_sha256().into(),
        bytes: guard.intent_bytes(),
    }
}
fn metadata_limit(resources: ResourceBudget) -> u64 {
    resources.max_row_bytes.min(1024 * 1024)
}
fn digest(value: &str) -> Result<[u8; 32]> {
    ensure!(
        value.len() == 64
            && value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "canonical preparation SHA-256 required"
    );
    let mut digest = [0; 32];
    hex::decode_to_slice(value, &mut digest)?;
    Ok(digest)
}
pub(crate) struct EarlyPreparationGuard {
    native: Mutex<PreparationGuard>,
    pin: GuardPin,
    state_permit: Option<ArtifactPathPermit>,
    _state_lease: Option<ArtifactLease>,
    _intent_lease: ArtifactLease,
    _memory: ArenaRamLease,
}
impl EarlyPreparationGuard {
    pub(crate) fn create(
        pair: &GeneralSourceShadowBinding,
        journal: &GeneralJournalStorageBinding,
        resources: ResourceBudget,
        output: &Path,
        arena: &ArtifactArena,
        group: &ArtifactGroupPermit,
        events: &mut Vec<NativeEvent>,
    ) -> Result<Self> {
        let maximum = metadata_limit(resources);
        ensure!(maximum > 0, "preparation intent has no metadata allowance");
        let mut memory = arena.reserve_ram(
            GeneralFrozenPartition::read_buffer_memory_bytes()
                .checked_add(maximum.checked_mul(4).context("guard RAM overflow")?)
                .and_then(|n| n.checked_add(preparation::STATE_BYTES * 8 + 2 * 1024 * 1024))
                .context("guard RAM overflow")?,
        )?;
        let state_path = output.join("preparation-state.bin");
        let intent_path = output.join("preparation-intent.json");
        let state_permit = group.reserve_file(&state_path, preparation::STATE_BYTES)?;
        let intent_permit = group.reserve_file(&intent_path, maximum)?;
        let native = PreparationGuard::create(
            pair,
            journal,
            state_permit.path(),
            intent_permit.path(),
            maximum,
            preparation::STATE_BYTES
                .checked_add(arena.allocation_slack_bytes())
                .context("guard allocation overflow")?,
            events,
        )?;
        let pin = pin(&native);
        let intent_lease = intent_permit.verify_closed_handle(native.intent_file(), &pin.sha256)?;
        memory.shrink_to(
            pin.bytes
                .checked_mul(4)
                .and_then(|n| n.checked_add(preparation::STATE_BYTES * 8 + 1024 * 1024))
                .context("guard retained RAM overflow")?,
        )?;
        Ok(Self {
            native: Mutex::new(native),
            pin,
            state_permit: Some(state_permit),
            _state_lease: None,
            _intent_lease: intent_lease,
            _memory: memory,
        })
    }
    fn native(&self) -> Result<MutexGuard<'_, PreparationGuard>> {
        self.native
            .lock()
            .map_err(|_| anyhow::anyhow!("preparation guard owner poisoned"))
    }
    pub(crate) fn pin(&self) -> GuardPin {
        self.pin.clone()
    }
    pub(crate) fn isolate(
        &mut self,
        binding: GeneralDiskBinding,
        budget: ResourceBudget,
        events: &mut Vec<NativeEvent>,
    ) -> Result<GeneralFrozenPartition> {
        let mut native = self.native()?;
        Ok(
            GeneralFrozenPartition::isolate_observed_ntfs_with_preparation_guard(
                binding,
                budget,
                &mut native,
                events,
            )?,
        )
    }
    pub(crate) fn revalidate(&self) -> Result<()> {
        self._intent_lease.revalidate()?;
        self.native()?.revalidate()?;
        if let Some(lease) = &self._state_lease {
            lease.revalidate()?;
        }
        Ok(())
    }
    pub(crate) fn delegate(
        &mut self,
        publication: &Path,
        sha: &str,
        _events: &mut Vec<NativeEvent>,
    ) -> Result<()> {
        self.revalidate()?;
        {
            let mut native = self.native()?;
            native.delegate(publication, sha)?;
        }
        if let Some(permit) = self.state_permit.take() {
            let lease = {
                let mut native = self.native()?;
                let sha = native.state_sha256()?;
                permit.verify_closed_handle(native.state_readonly_file()?, &sha)?
            };
            self._state_lease = Some(lease);
        }
        self.require_delegated(publication, sha, _events)
    }
    pub(crate) fn require_delegated(
        &self,
        publication: &Path,
        sha: &str,
        _events: &mut Vec<NativeEvent>,
    ) -> Result<()> {
        ensure!(
            self.state_permit.is_none() && self._state_lease.is_some(),
            "preparation state producer was not sealed before AP"
        );
        self.revalidate()?;
        self.native()?.require_delegated(publication, sha)?;
        Ok(())
    }
    pub(crate) fn delegated(&self) -> Result<bool> {
        Ok(self.native()?.routes().phase == "Delegated")
    }
    pub(crate) fn mark_live_cancel_intent(&mut self) -> Result<()> {
        self.native()?.mark_live_cancel_intent()?;
        Ok(())
    }
    pub(crate) fn mark_live_cancelled(&mut self, events: &mut Vec<NativeEvent>) -> Result<()> {
        self.native()?.mark_live_cancelled(events)?;
        Ok(())
    }
}

pub(crate) fn inspect_routes(path: &Path, sha: [u8; 32], maximum: u64) -> Result<GuardRoutes> {
    let native = PreparationGuard::open(path, sha, maximum, false)?;
    let routes = native.routes();
    Ok(GuardRoutes {
        source: routes.source,
        shadow: routes.shadow,
        journal: routes.journal,
        phase: routes.phase,
        delegated: routes.delegated.map(|p| GuardPin {
            path: p.path,
            sha256: p.sha256,
            bytes: 0,
        }),
    })
}
pub(crate) fn cancel_preparation(
    path: &Path,
    sha: [u8; 32],
    resources: ResourceBudget,
    events: &mut Vec<NativeEvent>,
) -> Result<serde_json::Value> {
    resources.validate()?;
    let maximum = metadata_limit(resources);
    ensure!(
        maximum
            .checked_mul(4)
            .and_then(|n| n.checked_add(preparation::STATE_BYTES * 8 + 1024 * 1024))
            .is_some_and(|n| n <= resources.ram_bytes),
        "preparation cancellation exceeds observed RAM budget"
    );
    let mut native = PreparationGuard::open(path, sha, maximum, true)?;
    Ok(native.cancel(events)?)
}
pub(crate) struct RestartGuard {
    native: PreparationGuard,
}
impl RestartGuard {
    pub(crate) fn require_delegated(
        &mut self,
        publication: &Path,
        sha: &str,
        _events: &mut Vec<NativeEvent>,
    ) -> Result<()> {
        self.native.require_delegated(publication, sha)?;
        Ok(())
    }
}
#[allow(clippy::too_many_arguments)]
pub(crate) fn open_for_recovery(
    intent: &GuardPin,
    publication: &Path,
    publication_sha: &str,
    pair: &GeneralSourceShadowBinding,
    journal: &GeneralJournalStorageBinding,
    allow_delegate_prepared_clear: bool,
    maximum: u64,
    events: &mut Vec<NativeEvent>,
) -> Result<RestartGuard> {
    ensure!(
        intent.bytes > 0 && intent.bytes <= maximum,
        "preparation intent length exceeds recovery budget"
    );
    let sha = digest(&intent.sha256)?;
    let mut native = if allow_delegate_prepared_clear {
        PreparationGuard::open_for_clear_delegation(
            &intent.path,
            sha,
            intent.bytes,
            maximum,
            publication,
            publication_sha,
        )?
    } else {
        PreparationGuard::open_sized(&intent.path, sha, intent.bytes, maximum, false)?
    };
    ensure!(
        native.intent_bytes() == intent.bytes,
        "preparation intent length differs from final publication"
    );
    let routes = native.routes();
    ensure!(
        routes.source == pair.source && routes.shadow == pair.shadow && routes.journal == *journal,
        "preparation guard routes differ from authenticated final recovery"
    );
    if allow_delegate_prepared_clear {
        native.delegate(publication, publication_sha)?;
    }
    native.require_delegated(publication, publication_sha)?;
    let _ = events;
    Ok(RestartGuard { native })
}
