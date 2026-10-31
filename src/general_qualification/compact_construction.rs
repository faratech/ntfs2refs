//! Fresh native metadata construction while the observed NTFS source stays
//! frozen. Full-cluster payload is supplied by the later composite view.
use super::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CompactConstructionBudget {
    pub maximum_placement_bytes: u64,
    pub maximum_placement_submissions: usize,
    pub maximum_exception_bytes: u64,
}
impl CompactConstructionBudget {
    pub(crate) fn validate(&self, partition_bytes: u64) -> Result<()> {
        ensure!(
            self.maximum_placement_bytes > 0
                && self.maximum_placement_bytes <= partition_bytes.saturating_mul(4)
                && (1..=64 * 1024 * 1024).contains(&self.maximum_exception_bytes),
            "compact construction resource budget differs"
        );
        n2r_win32::shadow_native::private_tree::validate_placement_limits(
            self.maximum_placement_bytes,
            self.maximum_placement_submissions,
        )?;
        Ok(())
    }
}

pub(super) fn construct(
    source: &mut GeneralFrozenPartition,
    pair: &GeneralSourceShadowBinding,
    raw: &ntfs_inspect::NtfsInspection,
    tree: &shadow_tree::Tree,
    output: &Path,
    limits: CompactConstructionBudget,
    resources: crate::ntfs_admission::ResourceProfile,
    selected_devices: bool,
) -> Result<GeneralFrozenPartition> {
    use crate::ntfs_admission::ResourceProfile;
    ensure!(
        resources == ResourceProfile::ExperimentalStreamingTreeV2
            && source.binding() == &pair.source,
        "fresh compact construction requires the explicit streaming source profile"
    );
    limits.validate(pair.source.identity.partition_bytes)?;
    let mut events = Vec::new();
    let source_before = source.state(&mut events)?;
    ensure!(
        source_before.disk_attributes == 3,
        "construction source is not frozen"
    );
    save(
        output,
        "construction-intent.json",
        &serde_json::json!({
            "kind":"fresh-private-native-composite-construction", "pair":pair,
            "budget":limits,"source_before":source_before,"source_payload_writes_authorized":false,
            "full_cluster_payload_initialization":false,
            "construction_enrollment":if selected_devices {"original-freeze-and-selected-shadow"} else {"legacy-enrolled-laboratory"},
        }),
    )?;
    let selected: Vec<_> = tree
        .objects
        .iter()
        .enumerate()
        .filter(|(_, object)| {
            !object.directory
                && !object
                    .path
                    .first()
                    .is_some_and(|s| s == "System Volume Information")
        })
        .flat_map(|(index, object)| {
            object
                .data_streams()
                .filter(|stream| stream.tail_requires_materialization())
                .map(move |stream| {
                    (
                        index,
                        stream.name_utf16.to_vec(),
                        stream.length / 4096 * 4096,
                        (stream.length % 4096) as usize,
                    )
                })
        })
        .collect();
    let residual_bytes = selected.iter().try_fold(0u64, |sum, (_, _, _, count)| {
        sum.checked_add(*count as u64)
            .context("residual byte budget overflow")
    })?;
    let system_bytes = tree
        .objects
        .iter()
        .filter(|object| {
            !object.directory
                && object
                    .path
                    .first()
                    .is_some_and(|s| s == "System Volume Information")
        })
        .try_fold(0u64, |sum, object| {
            sum.checked_add(object.length)
                .context("system byte budget overflow")
        })?;
    ensure!(
        residual_bytes
            .checked_add(system_bytes)
            .is_some_and(|bytes| bytes <= limits.maximum_exception_bytes),
        "necessary system/residual writes exceed the construction exception budget"
    );
    let mut transfer = ntfs_inspect::StreamTransferBudget::new(
        resources.limits().maximum_stream_bytes,
        limits
            .maximum_exception_bytes
            .checked_mul(2)
            .context("exception source-read budget overflow")?,
    )?;
    // Validate slices from actual source bytes before allocating a namespace.
    let mut buffer = [0u8; 4096];
    for (index, name, offset, count) in &selected {
        let object = &tree.objects[*index];
        let stream = object
            .stream(name)
            .context("residual source stream absent")?;
        let file = raw
            .files
            .iter()
            .find(|file| file.record_number == object.record_number)
            .context("residual source identity absent")?;
        ensure!(
            file.sequence_number == object.sequence_number,
            "residual source sequence differs from canonical tree"
        );
        let read = if stream.sparse.is_some() {
            ntfs_inspect::read_sparse_named_stream_range_into(
                source,
                raw,
                object.record_number,
                name,
                *offset,
                &mut buffer[..*count],
                &mut transfer,
            )?
        } else {
            ntfs_inspect::read_plain_named_stream_range_into(
                source,
                raw,
                object.record_number,
                name,
                *offset,
                &mut buffer[..*count],
                &mut transfer,
            )?
        };
        ensure!(
            read.stream_logical_bytes == stream.length
                && read.expected_stream_sha256.as_deref() == stream.sha256,
            "residual source bytes differ from the fresh canonical tree"
        );
    }
    let input = general_shadow::native_inputs(tree);
    let mut private = if selected_devices {
        general_shadow::allocate_private_tree_enrolled(source, pair, tree)?
    } else {
        general_shadow::allocate_private_tree(pair, tree)?
    };
    let placement = private.place_source_prefixes_with_limits(
        &input,
        limits.maximum_placement_bytes,
        limits.maximum_placement_submissions,
    );
    let placement = match placement {
        Ok(value) => value,
        Err(error) => {
            save(
                output,
                "construction-placement-refusal.json",
                private.placement_progress(),
            )?;
            return Err(error.into());
        }
    };
    save(output, "construction-placement.json", &placement)?;
    private.prepare_source_backed_prefixes()?;
    let mut residual_receipts = Vec::with_capacity(selected.len());
    for (index, name, offset, count) in &selected {
        residual_receipts.push(general_shadow::materialize_private_named_range(
            source,
            raw,
            tree,
            &mut private,
            *index,
            name,
            *offset,
            *count,
            &mut transfer,
        )?);
    }
    let (system, _indexer_payload) = general_shadow::materialize_private_system_payloads(
        source,
        raw,
        tree,
        &mut private,
        &mut transfer,
    )?;
    save(
        output,
        "construction-exceptions.json",
        &serde_json::json!({
            "system":system,"residuals":residual_receipts,
            "residual_payload_bytes":residual_bytes,"system_payload_bytes":system_bytes,
            "source_payload_writes":0,"full_cluster_user_payload_bytes_written":0,
        }),
    )?;
    save(output, "construction-private.json", &private.report()?)?;
    let metadata = private.complete_source_metadata(&input, |left, right| {
        ntfs_attestation::same_security(left, right).map_err(io::Error::other)
    })?;
    save(output, "construction-metadata.json", &metadata)?;
    ensure!(
        source.state(&mut events)? == source_before,
        "source exclusion changed during native metadata construction"
    );
    // Consuming metadata completion closed all private file handles first.
    events.clear();
    let frozen = GeneralFrozenPartition::isolate(pair.shadow.clone(), &mut events)?;
    save(
        output,
        "construction-freeze.json",
        &serde_json::json!({
            "target":frozen.state(&mut events)?,"events":events,"source_payload_writes":0,
            "postfreeze_composite_verification_pending":true,
        }),
    )?;
    Ok(frozen)
}
