//! Actual-device shadow freeze. Serialized evidence cannot recreate this value
//! or authorize writes to the original source.
use crate::{refs_inspect, refs_write_set, shadow_tree::Tree, tree_placement::Plan};
use anyhow::{Result, ensure};
use n2r_win32::{
    NativeEvent, OfflinePartition, PartitionSnapshot, layout::DiskBinding, shadow_native::Report,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
#[derive(Debug, Serialize)]
pub struct FrozenShadow {
    schema_version: u32,
    kind: &'static str,
    before: PartitionSnapshot,
    after: PartitionSnapshot,
    partition_bytes: u64,
    sha256: String,
    native_evidence_sha256: String,
    tree_sha256: String,
    placement_sha256: String,
    header: refs_inspect::RefsInspection,
    candidate_write_set: Option<refs_write_set::WriteSetPlan>,
    candidate_write_set_error: Option<String>,
    raw_bytes_read: u64,
    raw_partition_write_requests: u64,
    conversion_qualified: bool,
}
impl FrozenShadow {
    /// Bind comparison inputs to this actual freeze and its measured placement.
    pub fn comparison_request(
        &self,
        placement: &Plan,
        source_sha256: &str,
        max_change_bytes: u64,
    ) -> Result<crate::retained_compare::RetainedCompareRequest> {
        ensure!(
            hex::encode(Sha256::digest(serde_json::to_vec(placement)?)) == self.placement_sha256,
            "placement differs from the actual shadow freeze"
        );
        placement.comparison_request(
            self.partition_bytes,
            source_sha256,
            &self.sha256,
            max_change_bytes,
        )
    }
    pub fn capture(
        binding: DiskBinding,
        native: &Report,
        tree: &Tree,
        placement: &Plan,
        events: &mut Vec<NativeEvent>,
    ) -> Result<Self> {
        ensure!(
            binding.disk_number == 3
                && native.binding == binding
                && native.before.disk_attributes == 0
                && native.after.disk_attributes == 0
                && native.root_security.matched_after
                && native.objects.len() == tree.objects.len()
                && !placement.executable,
            "live independent shadow evidence or bounds differ"
        );
        let mut disk = OfflinePartition::isolate(binding, true, events)?;
        let before = disk.inspect(events)?;
        ensure!(
            before.disk_attributes == 3 && disk.native_write_bytes_requested == 0,
            "shadow exclusion differs"
        );
        let length = disk.byte_len();
        let header = refs_inspect::inspect(&mut disk, length)?;
        ensure!(
            header.geometry.major_version == 3
                && header.geometry.minor_version == 14
                && header.geometry.bytes_per_sector == 512
                && header.geometry.bytes_per_cluster == 4096
                && header.backup_header_status == refs_inspect::BackupHeaderStatus::Matching,
            "frozen shadow header differs from the measured native profile"
        );
        // The mounted bitmap predates dismount/flush. Keep this optimization
        // diagnostic until a raw post-freeze allocator graph reconciles it.
        let candidate = (|| -> Result<_> {
            let allocation = native.metadata_allocation.as_ref().ok_or_else(|| {
                anyhow::anyhow!("native metadata-inclusive allocation map absent")
            })?;
            let anchors = refs_write_set::observed_anchors(&header)?;
            refs_write_set::plan(length, 4096, allocation, &anchors)
        })();
        let (candidate_write_set, candidate_write_set_error) = match candidate {
            Ok(plan) => (Some(plan), None),
            Err(error) => (None, Some(format!("{error:#}"))),
        };
        let sha256 = hex::encode(crate::lab_reconstruct::hash_range(&mut disk, 0, length)?);
        let after = disk.inspect(events)?;
        ensure!(
            after.disk_attributes == 3
                && before.binding == after.binding
                && before.device == after.device
                && before.length == after.length
                && before.layout == after.layout
                && before.alignment == after.alignment
                && disk.native_bytes_written == 0
                && disk.native_write_bytes_requested == 0,
            "frozen shadow identity or exclusion changed"
        );
        Ok(Self {
            schema_version: 1,
            kind: "native-existing-tree-shadow-freeze-v1",
            before,
            after,
            partition_bytes: length,
            sha256,
            native_evidence_sha256: hex::encode(Sha256::digest(serde_json::to_vec(native)?)),
            tree_sha256: hex::encode(Sha256::digest(serde_json::to_vec(tree)?)),
            placement_sha256: hex::encode(Sha256::digest(serde_json::to_vec(placement)?)),
            header,
            candidate_write_set,
            candidate_write_set_error,
            raw_bytes_read: disk.native_bytes_read,
            raw_partition_write_requests: 0,
            conversion_qualified: false,
        })
    }
    pub fn revalidate(
        &self,
        disk: &mut OfflinePartition,
        events: &mut Vec<NativeEvent>,
    ) -> Result<()> {
        let before = disk.inspect(events)?;
        ensure!(
            before.binding == self.after.binding
                && before.disk_attributes == 3
                && disk.byte_len() == self.partition_bytes
                && disk.native_write_bytes_requested == 0,
            "actual frozen shadow binding differs"
        );
        let digest = crate::lab_reconstruct::hash_range(disk, 0, self.partition_bytes)?;
        ensure!(
            hex::encode(digest) == self.sha256,
            "actual frozen shadow bytes changed"
        );
        let after = disk.inspect(events)?;
        ensure!(
            after.binding == before.binding
                && after.disk_attributes == 3
                && disk.native_write_bytes_requested == 0,
            "shadow exclusion changed during revalidation"
        );
        Ok(())
    }
}
