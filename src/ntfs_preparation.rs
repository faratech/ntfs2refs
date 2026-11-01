//! Optional NTFS-owned collision preparation before the converter's freeze.
//! Every later inspection/certificate is obtained anew; this plan/log cannot
//! authorize raw conversion or recovery. NTFS performs and journals all moves.
use crate::{ntfs_admission::ResourceProfile, ntfs_evacuation as planner, ntfs_inspect};
use anyhow::{Context, Result, ensure};
use n2r_win32::{general_layout::GeneralDiskBinding, ntfs_preparation as mover};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    path::Path,
};

#[derive(Clone, Copy, Debug, Serialize)]
pub struct Budget {
    pub metadata_bytes: u64,
    pub receipt_bytes: u64,
    pub maximum_moves: u64,
    pub maximum_move_bytes: u64,
    pub maximum_payload_bytes: u64,
}

#[derive(Debug, Serialize)]
pub struct Report {
    pub schema_version: u32,
    pub suggested_bytes: u64,
    pub moved_bytes: u64,
    pub verified_moves: u64,
    pub skipped_locked_files: u64,
    pub required_outside_headroom_bytes: u64,
    pub observed_outside_free_bytes: u64,
    pub receipt_bytes: u64,
    pub receipt_sha256: String,
    pub fresh_source_inventory_and_certificate_required: bool,
    pub final_native_placement_required: bool,
    pub source_admitted: bool,
}

struct Ledger {
    file: File,
    bytes: u64,
    limit: u64,
    digest: Sha256,
}
impl Write for Ledger {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        let next = self
            .bytes
            .checked_add(data.len() as u64)
            .filter(|n| *n <= self.limit)
            .ok_or_else(|| io::Error::other("preparation receipt budget exhausted"))?;
        self.file.write_all(data)?;
        self.digest.update(data);
        self.bytes = next;
        Ok(data.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}
fn save(path: &Path, value: &impl Serialize) -> Result<()> {
    let mut f = OpenOptions::new().write(true).create_new(true).open(path)?;
    serde_json::to_writer_pretty(&mut f, value)?;
    f.sync_all()?;
    Ok(())
}

pub fn prepare(
    source: GeneralDiskBinding,
    shadow: GeneralDiskBinding,
    resources: ResourceProfile,
    output: &Path,
    budget: Budget,
) -> Result<Report> {
    ensure!(
        source.disk_number != shadow.disk_number
            && source.identity.disk_guid != shadow.identity.disk_guid,
        "NTFS preparation and shadow storage overlap"
    );
    ensure!(
        budget.metadata_bytes > 0
            && budget.receipt_bytes > 0
            && budget.maximum_moves > 0
            && budget.maximum_move_bytes >= 4096
            && budget.maximum_payload_bytes > 0,
        "preparation resource budget invalid"
    );
    ensure!(!output.exists(), "fresh preparation output required");
    fs::create_dir(output)?;
    save(
        &output.join("intent.json"),
        &serde_json::json!({"schema_version":1,
        "kind":"ntfs-owned-collision-preparation","source":source,"shadow":shadow,"budget":budget,
        "raw_source_writes":false,"source_admission_granted":false,
        "rollback_baseline_is_post_preparation_ntfs":true}),
    )?;
    let mut moved = 0u64;
    let mut verified = 0u64;
    let mut skipped = 0u64;
    let attempted = (|| -> Result<Report> {
        let catalog =
            n2r_win32::vss_observation::observe_catalog(&format!("{}\\", source.volume_path()?))?;
        save(&output.join("vss-before-preparation.json"), &catalog)?;
        catalog.require_observed_catalog_clear()?;
        let occupancy = n2r_win32::preparation_shadow::observe(shadow, resources.native_profile())?;
        save(&output.join("shadow-occupancy.json"), &occupancy)?;
        let mut events = Vec::new();
        let mut reader = n2r_win32::GeneralPartitionReader::open(source.clone(), &mut events)?;
        let mut limits = ntfs_inspect::limits_for_resource_profile(resources);
        limits.max_report_bytes = limits.max_report_bytes.min(budget.metadata_bytes);
        let raw = ntfs_inspect::inspect_for_preparation(
            &mut reader,
            source.identity.partition_bytes,
            limits,
        )?;
        reader.revalidate_route(&mut events)?;
        drop(reader);
        let occupied: Vec<_> = occupancy
            .occupied
            .iter()
            .map(|r| planner::ByteInterval {
                offset: r.offset,
                length: r.length,
            })
            .collect();
        let anchors: Vec<_> = occupancy
            .bootstrap_avoidance
            .iter()
            .map(|r| planner::ByteInterval {
                offset: r.offset,
                length: r.length,
            })
            .collect();
        let plan = planner::plan(
            &raw,
            source.identity.partition_bytes,
            &occupied,
            &anchors,
            planner::Limits {
                max_metadata_bytes: budget.metadata_bytes,
            },
        )?;
        save(&output.join("plan.json"), &plan)?;
        let mut native = mover::OpenedSource::open(
            source,
            resources.native_profile(),
            raw.geometry.serial_number,
            raw.geometry.cluster_size,
            mover::Limits {
                maximum_moves: budget.maximum_moves,
                maximum_move_bytes: budget.maximum_move_bytes,
                maximum_total_move_bytes: budget.maximum_payload_bytes,
                ..mover::Limits::default()
            },
        )?;
        let cluster = u64::from(native.geometry().cluster_bytes);
        let max_clusters = (budget.maximum_move_bytes / cluster).min(u64::from(u32::MAX));
        ensure!(
            max_clusters > 0,
            "preparation move budget is smaller than an NTFS cluster"
        );
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(output.join("moves.jsonl"))?;
        let mut ledger = Ledger {
            file,
            bytes: 0,
            limit: budget.receipt_bytes,
            digest: Sha256::new(),
        };
        let mut index = 0;
        'files: while index < plan.moves.len() {
            let first = &plan.moves[index];
            let key = (first.record_number, first.sequence_number);
            let mut end = index + 1;
            while end < plan.moves.len()
                && (
                    plan.moves[end].record_number,
                    plan.moves[end].sequence_number,
                ) == key
            {
                end += 1
            }
            let identity = n2r_win32::attestation::FileIdentity {
                record_number: key.0,
                sequence_number: key.1,
            };
            let inventory = raw
                .files
                .iter()
                .find(|f| f.record_number == key.0 && f.sequence_number == key.1)
                .context("planned preparation identity absent")?;
            let logical = inventory
                .streams
                .get(first.stream_index)
                .context("planned stream absent")?
                .logical_size;
            let mut file = match native.open_file(identity.clone(), logical) {
                Ok(f) => f,
                Err(e) if matches!(e.raw_os_error(), Some(2 | 3 | 5 | 32 | 33)) => {
                    skipped += 1;
                    index = end;
                    continue;
                }
                Err(e) => return Err(e.into()),
            };
            for suggestion in &plan.moves[index..end] {
                let mut done = 0u64;
                while done < u64::from(suggestion.cluster_count) {
                    if verified >= budget.maximum_moves {
                        break 'files;
                    }
                    let count = (u64::from(suggestion.cluster_count) - done).min(max_clusters);
                    let bytes = count
                        .checked_mul(cluster)
                        .context("preparation byte count overflow")?;
                    if moved
                        .checked_add(bytes)
                        .is_none_or(|n| n > budget.maximum_payload_bytes)
                    {
                        break 'files;
                    }
                    let request = mover::MoveRequest {
                        identity: identity.clone(),
                        expected_logical_bytes: logical,
                        starting_vcn: suggestion.starting_vcn + done,
                        expected_source_lcn: suggestion.source_lcn + done,
                        destination_lcn: suggestion.destination_lcn + done,
                        cluster_count: u32::try_from(count)?,
                        length_bytes: bytes,
                    };
                    let observation = file.move_clusters(&request)?;
                    if observation.verified {
                        moved = moved
                            .checked_add(bytes)
                            .context("preparation moved-byte total overflow")?;
                        verified += 1;
                    }
                    serde_json::to_writer(&mut ledger, &observation)?;
                    ledger.write_all(b"\n")?;
                    ledger.file.sync_all()?;
                    ensure!(
                        observation.verified,
                        "NTFS preparation move failed or post-state is unverifiable; no retry/undo"
                    );
                    done += count;
                }
            }
            drop(file);
            index = end;
        }
        native.finish()?;
        ledger.file.sync_all()?;
        Ok(Report {
            schema_version: 1,
            suggested_bytes: plan.proposed_move_bytes,
            moved_bytes: moved,
            verified_moves: verified,
            skipped_locked_files: skipped,
            required_outside_headroom_bytes: plan.required_outside_headroom_bytes,
            observed_outside_free_bytes: plan.observed_outside_free_bytes,
            receipt_bytes: ledger.bytes,
            receipt_sha256: hex::encode(ledger.digest.finalize()),
            fresh_source_inventory_and_certificate_required: true,
            final_native_placement_required: true,
            source_admitted: false,
        })
    })();
    match attempted {
        Ok(report) => {
            save(&output.join("result.json"), &report)?;
            Ok(report)
        }
        Err(error) => {
            save(
                &output.join("failed.json"),
                &serde_json::json!({"error":format!("{error:#}"),"verified_moves":verified,
            "verified_moved_bytes":moved,"ntfs_driver_owned_all_moves":true,"retry_or_undo_performed":false,
            "fresh_inventory_required":true,"source_admitted":false}),
            )?;
            Err(error)
        }
    }
}
