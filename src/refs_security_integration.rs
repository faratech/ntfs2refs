//! Paid, constructor-only trust-label repair. Source expectations remain exact.
use crate::{
    artifact_arena::{ArenaRamLease, ArtifactArena, ArtifactGroup},
    general_source_admission::resource::ResourceSourceContext,
    ntfs_inspect::{SourceMetadataBudget, paged_storage::SourceScratch},
    refs_security_descriptor::{self, TrustLabelPlaceholder},
    refs_security_repair::{CompletedSecurityRepair, SecurityRepairBudget},
};
use anyhow::{Context, Result, ensure};
use n2r_win32::{
    GeneralFrozenPartition, NativeEvent,
    journal_file::GeneralJournalStorageBinding,
    shadow_native::input_domain::{InputDomain, ObjectInput},
    tree_resources::ResourceBudget,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    io::{Read, Seek, SeekFrom},
    path::Path,
};

const REPAIR_SCRATCH: u64 = 128 << 20;
const REPAIR_RAM: u64 = 96 << 20;
const GRAPH_RAM: u64 = 256 << 20;
const GRAPH_PAGES: u32 = 4096;
const CHANGED_CLUSTERS: u32 = 4096;
const JOURNAL_BYTES: u64 = 64 << 20;

/// Two real arenas receive disjoint parts of the caller's observed envelope.
/// The main arena never borrows the repair share, or vice versa.
#[derive(Clone, Copy, Serialize)]
pub(crate) struct TrustRepairAllocation {
    pub(crate) original: ResourceBudget,
    pub(crate) main: ResourceBudget,
    pub(crate) repair: ResourceBudget,
}
impl TrustRepairAllocation {
    pub(crate) fn split(original: ResourceBudget) -> Result<Self> {
        original.validate()?;
        let mut main = original;
        main.ram_bytes = main
            .ram_bytes
            .checked_sub(REPAIR_RAM)
            .context("Windows trust repair cannot fit its reserved RAM")?;
        main.scratch_bytes = main
            .scratch_bytes
            .checked_sub(REPAIR_SCRATCH)
            .context("Windows trust repair cannot fit its reserved scratch")?;
        main.retained_index_bytes = main
            .retained_index_bytes
            .checked_sub(1 << 20)
            .context("Windows trust repair cannot fit its reserved index state")?;
        main.handle_slots = main
            .handle_slots
            .checked_sub(64)
            .context("Windows trust repair cannot fit its reserved handles")?;
        let repair = ResourceBudget {
            schema_version: 1,
            ram_bytes: REPAIR_RAM,
            scratch_bytes: REPAIR_SCRATCH,
            page_bytes: 64 << 10,
            max_row_bytes: 64 << 10,
            retained_index_bytes: 1 << 20,
            handle_slots: 64,
        };
        main.validate()?;
        repair.validate()?;
        ensure!(
            main.ram_bytes.checked_add(repair.ram_bytes) == Some(original.ram_bytes)
                && main.scratch_bytes.checked_add(repair.scratch_bytes)
                    == Some(original.scratch_bytes)
                && main
                    .retained_index_bytes
                    .checked_add(repair.retained_index_bytes)
                    == Some(original.retained_index_bytes)
                && main.handle_slots.checked_add(repair.handle_slots)
                    == Some(original.handle_slots)
                && repair.page_bytes <= original.page_bytes
                && repair.max_row_bytes <= original.max_row_bytes,
            "trust repair resource shares do not exactly preserve the caller envelope"
        );
        Ok(Self {
            original,
            main,
            repair,
        })
    }
}

pub(crate) struct TrustLabelRecipes {
    values: Vec<TrustLabelPlaceholder>,
    _payments: Vec<ArenaRamLease>,
}
impl TrustLabelRecipes {
    pub(crate) fn is_empty(&self) -> bool {
        self.values.is_empty()
    }
    pub(crate) fn len(&self) -> usize {
        self.values.len()
    }
}

pub(crate) fn collect_recipes(
    inputs: &impl InputDomain,
    arena: &ArtifactArena,
) -> Result<TrustLabelRecipes> {
    let maximum = arena
        .budget()
        .max_row_bytes
        .min(refs_security_descriptor::MAX_DESCRIPTOR_BYTES as u64);
    let _working = arena.reserve_ram(refs_security_descriptor::constructor_working_bytes(
        maximum,
    )?)?;
    let mut seen = BTreeSet::<[u8; 32]>::new();
    let mut values = Vec::new();
    let mut payments = Vec::new();
    for index in 0..inputs.len() {
        let object = inputs.object(index)?;
        let input = object.input();
        ensure!(
            input.security.len() as u64 <= maximum,
            "trust-repair source SD exceeds its admitted row"
        );
        let key: [u8; 32] = Sha256::digest(input.security).into();
        if seen.contains(&key) {
            continue;
        }
        let bytes = (input.security.len() as u64)
            .checked_mul(4)
            .and_then(|n| n.checked_add(1024))
            .context("trust-recipe RAM overflow")?;
        let payment = arena.reserve_ram(bytes)?;
        let prepared =
            refs_security_descriptor::prepare_trust_label_placeholder(input.security, maximum)?;
        seen.insert(key);
        if let Some(prepared) = prepared {
            ensure!(
                values.len() < 16_384,
                "trust-repair descriptor domain exceeds the implemented graph profile"
            );
            values.push(prepared);
        }
        payments.push(payment);
    }
    Ok(TrustLabelRecipes {
        values,
        _payments: payments,
    })
}

pub(crate) fn repair_constructor_shadow(
    context: &mut ResourceSourceContext,
    mut shadow: GeneralFrozenPartition,
    recipes: &TrustLabelRecipes,
    allocation: TrustRepairAllocation,
    main_arena: &ArtifactArena,
    journal: &GeneralJournalStorageBinding,
    output: &Path,
    events: &mut Vec<NativeEvent>,
) -> Result<(GeneralFrozenPartition, CompletedSecurityRepair)> {
    ensure!(
        !recipes.is_empty() && main_arena.budget() == allocation.main,
        "actual Windows trust-repair owner or allocation is absent"
    );
    let graph_memory = main_arena.reserve_ram(GRAPH_RAM)?;
    let mut vbr = [0u8; 512];
    shadow.seek(SeekFrom::Start(0))?;
    shadow.read_exact(&mut vbr)?;
    let image_bytes = shadow.byte_len();
    let geometry = crate::refs_inspect::inspect_boot_sector(&vbr, image_bytes)?;
    let plan = crate::refs_security_patch::plan_native_canonical_trust_label_restoration(
        &mut shadow,
        image_bytes,
        &hex::encode(Sha256::digest(vbr)),
        geometry.volume_serial,
        &recipes.values,
        GRAPH_PAGES,
        CHANGED_CLUSTERS,
    )?;
    ensure!(
        !output.exists(),
        "fresh constructor security-repair arena required"
    );
    std::fs::create_dir(output)?;
    let source_binding = {
        let (source, _) = context.source_and_inspection()?;
        source.binding().clone()
    };
    let repair_arena = ArtifactArena::new(
        output,
        allocation.repair,
        &[source_binding, shadow.binding().clone()],
    )?;
    let metadata = repair_arena.reserve_group(ArtifactGroup::Capture, REPAIR_SCRATCH / 2)?;
    let scratch = SourceScratch::new_bounded_auxiliary_in_arena(
        SourceMetadataBudget::from_resource_budget(allocation.repair)?,
        metadata.clone(),
    )?;
    let (source, _) = context.source_and_inspection()?;
    let result = crate::refs_security_repair::repair_shadow(
        source,
        shadow,
        &plan,
        &repair_arena,
        &metadata,
        &scratch,
        output,
        SecurityRepairBudget {
            maximum_changed_clusters: CHANGED_CLUSTERS,
            maximum_journal_bytes: JOURNAL_BYTES,
        },
        journal,
        events,
    )?;
    drop(plan);
    drop(graph_memory);
    Ok(result)
}
