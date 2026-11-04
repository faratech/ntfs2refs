//! A separately budgeted, incrementally allocated event ledger, opened before
//! preparation and can accept bounded evidence after the metadata arena closes.
//! Records are length/hash framed; a partial final record is never completion.
use super::*;
use n2r_win32::reference_file::ReferenceFileSnapshot;
use sha2::{Digest, Sha256};
use std::io::{self, BufWriter, Seek, SeekFrom};

const HEADER: u64 = 128;
const FRAME: u64 = 80;
const COMMIT: u64 = 40;
const BUFFER: usize = 65536;

pub(crate) struct FilePreparationObserver {
    writer: BufWriter<File>,
    snapshot: ReferenceFileSnapshot,
    parents: Vec<File>,
    capacity: u64,
    maximum_capacity: u64,
    growth_bytes: u64,
    minimum_free_bytes: u64,
    position: u64,
    records: u64,
    chain: [u8; 32],
    ram_bytes: u64,
    phase: Option<&'static str>,
    started: std::time::Instant,
    finished: bool,
    staging_meter: Option<n2r_win32::managed_shadow::StagingAllocationMeter>,
    staging_meter_error: Option<String>,
}
struct CountHash {
    bytes: u64,
    maximum: u64,
    hash: Sha256,
}
impl Write for CountHash {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.bytes = self
            .bytes
            .checked_add(bytes.len() as u64)
            .filter(|n| *n <= self.maximum)
            .ok_or_else(|| io::Error::other("native evidence ledger capacity exhausted"))?;
        self.hash.update(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
struct WrittenHash<'a> {
    writer: &'a mut BufWriter<File>,
    count: CountHash,
}
impl Write for WrittenHash<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.count.write_all(bytes)?;
        self.writer.write_all(bytes)?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }
}
impl FilePreparationObserver {
    pub(crate) fn attach_staging_meter(
        &mut self,
        meter: std::io::Result<Option<n2r_win32::managed_shadow::StagingAllocationMeter>>,
    ) {
        match meter {
            Ok(meter) => self.staging_meter = meter,
            Err(error) => {
                self.staging_meter_error = Some(error.to_string().chars().take(1024).collect())
            }
        }
    }

    pub(crate) fn required_ram(path: &Path) -> Result<u64> {
        // The native prefix hasher uses at most4MiB. Include streaming IO,
        // ordinary parent handles and their path encodings before allocation.
        let path_bytes = path.as_os_str().as_encoded_bytes().len() as u64;
        let parents = path.ancestors().count() as u64;
        path_bytes
            .checked_mul(
                parents
                    .checked_add(4)
                    .context("event path count overflow")?,
            )
            .and_then(|n| n.checked_mul(8))
            .and_then(|n| parents.checked_mul(512).and_then(|p| n.checked_add(p)))
            .and_then(|n| n.checked_add(5 * 1024 * 1024))
            .context("event ledger memory overflow")
    }

    /// `ram_allowance` and the observed physical allocation are subtracted
    /// from the caller's total resource pool before constructing its arena.
    pub(crate) fn create(
        path: &Path,
        pair: &GeneralSourceShadowBinding,
        journal: &GeneralJournalStorageBinding,
        maximum_bytes: u64,
        ram_allowance: u64,
        minimum_free_bytes: u64,
    ) -> Result<Self> {
        let required_ram = Self::required_ram(path)?;
        ensure!(
            required_ram <= ram_allowance
                && path.is_absolute()
                && !path
                    .components()
                    .any(|c| matches!(c, Component::CurDir | Component::ParentDir)),
            "event ledger path or prepaid memory differs"
        );
        pair.source.validate()?;
        pair.shadow.validate()?;
        journal.validate()?;
        for binding in [&pair.source, &pair.shadow] {
            ensure!(
                binding.disk_number != journal.disk.disk_number
                    && n2r_win32::layout::guid_bytes(&binding.identity.disk_guid)?
                        != n2r_win32::layout::guid_bytes(&journal.disk.identity.disk_guid)?,
                "event ledger must be independent of both data disks"
            );
        }
        let parent = path.parent().context("event ledger parent absent")?;
        let mut paths: Vec<_> = parent
            .ancestors()
            .filter(|p| !p.as_os_str().is_empty())
            .collect();
        paths.reverse();
        let mut parents = Vec::new();
        for p in paths {
            let file = OpenOptions::new()
                .access_mode(0x80)
                .share_mode(1)
                .custom_flags(0x0200_0000 | 0x0020_0000)
                .open(p)?;
            let m = file.metadata()?;
            ensure!(
                m.is_dir() && m.file_attributes() & 0x400 == 0,
                "event ledger ancestry must be actual ordinary held directories"
            );
            parents.push(file);
        }
        let parent_handle = parents
            .last()
            .context("event ledger parent handle absent")?;
        let route = n2r_win32::file_storage::final_path_guid(parent_handle)?;
        let expected_volume = format!("{}\\", journal.disk.volume_path()?);
        ensure!(
            route
                .to_ascii_lowercase()
                .starts_with(&expected_volume.to_ascii_lowercase()),
            "event ledger is not on the exact journal volume"
        );
        let actual = n2r_win32::discovery::discover(
            &expected_volume,
            n2r_win32::discovery::Role::Journal {
                allow_additional_partitions: journal.allow_additional_partitions,
            },
        )?;
        ensure!(
            actual.binding == journal.disk,
            "event ledger actual storage route changed"
        );
        let quantum = n2r_win32::file_storage::artifact_allocation_slack(parent_handle)?;
        ensure!(quantum > 0, "event ledger allocation unit absent");
        let maximum_capacity = maximum_bytes / quantum * quantum;
        let growth_bytes =
            (ram_allowance / 8).min(4 * 1024 * 1024).max(quantum) / quantum * quantum;
        let capacity = maximum_capacity.min(growth_bytes);
        ensure!(
            capacity > HEADER + FRAME + COMMIT && capacity <= i64::MAX as u64,
            "event ledger reservation is too small or exceeds file format"
        );
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .share_mode(0)
            .custom_flags(0x0020_0000)
            .open(path)?;
        ensure!(
            n2r_win32::resource_native::observe_available_resources(parent)?
                .scratch_available_bytes
                >= capacity
                    .checked_add(minimum_free_bytes)
                    .context("initial event reserve overflow")?,
            "initial event ledger chunk cannot preserve storage reserve"
        );
        file.set_len(capacity)?;
        let mut head = [0u8; HEADER as usize];
        head[..8].copy_from_slice(b"N2REVLG1");
        head[8..12].copy_from_slice(&1u32.to_le_bytes());
        head[16..24].copy_from_slice(&maximum_capacity.to_le_bytes());
        file.write_all(&head)?;
        file.sync_all()?;
        let snapshot =
            n2r_win32::reference_file::observe_reference_file_handle_with_limit(&file, capacity)?;
        ensure!(
            snapshot.file_bytes == capacity
                && snapshot.allocation_bytes >= capacity
                && snapshot.allocation_bytes <= maximum_capacity
                && snapshot.number_of_links == 1
                && file.metadata()?.file_attributes() & (0x400 | 0x800 | 0x200 | 0x4000) == 0
                && snapshot
                    .final_path
                    .to_ascii_lowercase()
                    .starts_with(&expected_volume.to_ascii_lowercase()),
            "event ledger lacks its actual ordinary physical reservation"
        );
        let leaf = path
            .file_name()
            .and_then(|n| n.to_str())
            .context("Unicode event filename required")?;
        ensure!(
            snapshot.final_path.eq_ignore_ascii_case(&format!(
                "{}\\{}",
                route.trim_end_matches('\\'),
                leaf
            )),
            "created event file is not under its actual held parent"
        );
        Ok(Self {
            writer: BufWriter::with_capacity(BUFFER, file),
            snapshot,
            parents,
            capacity,
            maximum_capacity,
            growth_bytes,
            minimum_free_bytes,
            position: HEADER,
            records: 0,
            chain: [0; 32],
            ram_bytes: required_ram,
            phase: None,
            started: std::time::Instant::now(),
            finished: false,
            staging_meter: None,
            staging_meter_error: None,
        })
    }
    pub(crate) fn allocation_bytes(&self) -> u64 {
        self.snapshot.allocation_bytes
    }
    pub(crate) fn ram_bytes(&self) -> u64 {
        self.ram_bytes
    }
    pub(crate) fn maximum_bytes(&self) -> u64 {
        self.maximum_capacity
    }
    pub(crate) fn remaining_reservation_bytes(&self) -> u64 {
        self.maximum_capacity
            .saturating_sub(self.snapshot.allocation_bytes)
    }

    fn grow_for(&mut self, end: u64) -> Result<()> {
        if end <= self.capacity {
            return Ok(());
        }
        let next = end
            .checked_add(self.growth_bytes - 1)
            .and_then(|n| n.checked_div(self.growth_bytes))
            .and_then(|n| n.checked_mul(self.growth_bytes))
            .map(|n| n.min(self.maximum_capacity))
            .context("event ledger growth overflow")?;
        ensure!(
            next >= end && next <= self.maximum_capacity,
            "event ledger maximum budget exhausted"
        );
        let parent = Path::new(&self.snapshot.final_path)
            .parent()
            .context("held event parent absent")?;
        let available = n2r_win32::resource_native::observe_available_resources(parent)?;
        let additional = next - self.capacity;
        ensure!(
            available.scratch_available_bytes
                >= additional
                    .checked_add(self.minimum_free_bytes)
                    .context("event growth reserve overflow")?,
            "event ledger growth cannot preserve working-space reserve"
        );
        self.writer.flush()?;
        self.writer.get_ref().set_len(next)?;
        self.writer.get_ref().sync_all()?;
        let updated = n2r_win32::reference_file::observe_reference_file_handle_with_limit(
            self.writer.get_ref(),
            self.maximum_capacity,
        )?;
        ensure!(
            updated.file_id_128 == self.snapshot.file_id_128
                && updated.volume_serial_number == self.snapshot.volume_serial_number
                && updated.final_path == self.snapshot.final_path
                && updated.number_of_links == 1
                && updated.file_bytes == next
                && updated.allocation_bytes >= next
                && updated.allocation_bytes <= self.maximum_capacity,
            "grown event ledger identity/allocation escaped its reserved budget"
        );
        self.capacity = next;
        self.snapshot = updated;
        Ok(())
    }

    fn append(&mut self, value: &impl Serialize) -> Result<()> {
        self.append_with_limit(value, self.maximum_capacity / 2)
    }
    fn append_with_limit(&mut self, value: &impl Serialize, limit: u64) -> Result<()> {
        ensure!(!self.finished, "event ledger is already closed");
        let remaining = limit
            .checked_sub(self.position)
            .and_then(|n| n.checked_sub(FRAME + COMMIT))
            .context("event ledger has no remaining frame capacity")?;
        let mut counted = CountHash {
            bytes: 0,
            maximum: remaining,
            hash: Sha256::new(),
        };
        serde_json::to_writer(&mut counted, value)?;
        let bytes = counted.bytes;
        let digest: [u8; 32] = counted.hash.finalize().into();
        ensure!(bytes != 0, "empty event batch");
        self.grow_for(
            self.position
                .checked_add(FRAME + bytes + COMMIT)
                .context("event ledger end overflow")?,
        )?;
        let before = n2r_win32::reference_file::observe_reference_file_handle_with_limit(
            self.writer.get_ref(),
            self.capacity,
        )?;
        ensure!(
            before == self.snapshot,
            "event ledger held identity or physical reservation changed"
        );
        let mut frame = [0u8; FRAME as usize];
        frame[..8].copy_from_slice(&bytes.to_le_bytes());
        frame[8..40].copy_from_slice(&digest);
        frame[40..72].copy_from_slice(&self.chain);
        self.writer.seek(SeekFrom::Start(self.position))?;
        self.writer.write_all(&frame)?;
        let mut actual = WrittenHash {
            writer: &mut self.writer,
            count: CountHash {
                bytes: 0,
                maximum: bytes,
                hash: Sha256::new(),
            },
        };
        serde_json::to_writer(&mut actual, value)?;
        ensure!(
            actual.count.bytes == bytes && <[u8; 32]>::from(actual.count.hash.finalize()) == digest,
            "native evidence changed while streaming"
        );
        let mut chain = Sha256::new();
        chain.update(self.chain);
        chain.update(bytes.to_le_bytes());
        chain.update(digest);
        let next: [u8; 32] = chain.finalize().into();
        self.writer.write_all(b"N2REVCMT")?;
        self.writer.write_all(&next)?;
        self.writer.flush()?;
        self.writer.get_ref().sync_all()?;
        self.position = self
            .position
            .checked_add(FRAME + bytes + COMMIT)
            .context("event ledger offset overflow")?;
        self.records = self
            .records
            .checked_add(1)
            .context("event count overflow")?;
        self.chain = next;
        ensure!(
            n2r_win32::reference_file::observe_reference_file_handle_with_limit(
                self.writer.get_ref(),
                self.capacity
            )? == self.snapshot,
            "event ledger changed around durable append"
        );
        Ok(())
    }
    pub(crate) fn finish(&mut self) -> Result<serde_json::Value> {
        let prior_records = self.records;
        let prior_chain = hex::encode(self.chain);
        self.append(&serde_json::json!({"kind":"native-event-ledger-closed","records_before_close":prior_records,"prior_chain_sha256":prior_chain}))?;
        self.writer.flush()?;
        self.writer.get_ref().sync_all()?;
        let digest = n2r_win32::sha256_native::hash_range(self.writer.get_mut(), 0, self.position)?;
        self.finished = true;
        let counters = n2r_win32::process_io::snapshot();
        Ok(
            serde_json::json!({"kind":"bounded-native-event-ledger","path":self.snapshot.final_path,
            "format":"N2REVLG1-length-hash-chain-v1","records":self.records,"used_bytes":self.position,
            "used_prefix_sha256":hex::encode(digest),"chain_sha256":hex::encode(self.chain),
            "reserved_file_bytes":self.capacity,"maximum_budget_bytes":self.maximum_capacity,"actual_allocation_bytes":self.snapshot.allocation_bytes,
            "reserved_ram_bytes":self.ram_bytes,"held_parent_handles":self.parents.len(),
            "observer_elapsed_ms":self.started.elapsed().as_millis(),
            "observer_close_process_io":counters.as_ref().ok(),
            "process_io_error":counters.as_ref().err().map(ToString::to_string),
            "process_io_is_advisory_not_physical_disk_traffic":true,
            "closed":true,"grants_source_or_replay_authority":false}),
        )
    }
}
impl PreparationObserver for FilePreparationObserver {
    fn restore_source_on_pre_ap_failure(&self) -> bool {
        true
    }
    fn native_events(&mut self, phase: &'static str, events: &mut Vec<NativeEvent>) -> Result<()> {
        if self.phase != Some(phase) {
            let label = if phase.contains("source") {
                "Inspecting NTFS"
            } else if phase.contains("journal") || phase.contains("publication") {
                "Preparing recovery records"
            } else if phase.contains("apply") || phase.contains("handoff") {
                "Applying conversion"
            } else {
                "Verifying ReFS metadata"
            };
            println!("{label}");
            self.phase = Some(phase);
        }
        // Sample the existing current-process counters at this already-required
        // boundary. This adds no payload scan and never contributes authority.
        // An unavailable sample stays explicit rather than failing conversion.
        let counters = n2r_win32::process_io::snapshot();
        self.append(
            &serde_json::json!({"kind":"native-events","phase":phase,"events":events,
            "observer_elapsed_ms":self.started.elapsed().as_millis(),
            "process_io":counters.as_ref().ok(),
            "process_io_error":counters.as_ref().err().map(ToString::to_string),
            "process_io_is_advisory_not_physical_disk_traffic":true}),
        )?;
        events.clear();
        Ok(())
    }
    fn note(&mut self, value: &serde_json::Value) -> Result<()> {
        if value.get("kind").and_then(serde_json::Value::as_str)
            != Some("pre-ap-resource-accounting-v1")
        {
            return self.append(value);
        }
        // Only the original held metadata handle is queried. Instrumentation
        // errors stay unknown; no admission/write/recovery policy changes.
        let observed = self.staging_meter.as_ref().map(|meter| meter.observe());
        let sample = observed.as_ref().and_then(|value| value.as_ref().ok());
        let error = observed
            .as_ref()
            .and_then(|value| value.as_ref().err())
            .map(ToString::to_string)
            .or_else(|| self.staging_meter_error.clone());
        let total_ram = value["admitted_resource_ram_bytes"]
            .as_u64()
            .and_then(|bytes| bytes.checked_add(self.ram_bytes));
        let report = serde_json::json!({
            "kind":"pre-ap-resource-accounting-v1","preparation":value,
            "staging_backing":sample,"staging_observation_error":error,
            "staging_meter_available":self.staging_meter.is_some(),
            "observer_admitted_ram_bytes":self.ram_bytes,
            "combined_admitted_preparation_and_observer_ram_bytes":total_ram,
            "admitted_ram_is_not_working_set_or_peak":true,
            "staging_allocation_is_not_provider_logical_capacity_or_peak":true,
            "grants_source_or_replay_authority":false,
        });
        self.append(&report)?;
        let text = |value: Option<u64>| {
            value
                .map(|n| n.to_string())
                .unwrap_or_else(|| "unknown".into())
        };
        let allocated = sample.map(|sample| sample.backing_file.allocation_bytes);
        let mut out = std::io::stdout().lock();
        // Human progress is advisory, not an additional refusal/write gate.
        let _ = writeln!(
            out,
            "Before apply: staging backing allocation {} bytes; encoded recovery journal {} bytes; admitted preparation RAM {} bytes.",
            text(allocated),
            text(value["encoded_journal_bytes"].as_u64()),
            text(total_ram)
        );
        let _ = writeln!(
            out,
            "Capture file lengths: literal {} bytes (recorded allocation {} bytes), index {} bytes (current allocation {} bytes). Logical source reads during capture: {} bytes; all-stage payload I/O totals unknown.",
            text(value["capture_literal_file_bytes"].as_u64()),
            text(value["capture_literal_recorded_allocation_bytes"].as_u64()),
            text(value["capture_index_wire_bytes"].as_u64()),
            text(value["capture_index_physical_allocation_bytes"].as_u64()),
            text(value["capture_source_logical_bytes"].as_u64())
        );
        let _ = out.flush();
        Ok(())
    }
    fn published(&mut self, path: &Path, sha: &str, locator_sha: [u8; 32]) -> Result<()> {
        self.append(&serde_json::json!({"kind":"published-recovery-route","path":path,"sha256":sha,"locator_sha256":hex::encode(locator_sha)}))?;
        let directory = path
            .parent()
            .context("published recovery directory absent")?;
        println!(
            "Recovery directory: {}\nRecovery checksum: {sha}",
            directory.display()
        );
        println!(
            "To recover: ntfs2refs --recover \"{}\" --recovery-sha256 {sha}",
            directory.display()
        );
        std::io::stdout().flush()?;
        Ok(())
    }
    fn incomplete_events(&mut self, phase: &'static str, events: &mut Vec<NativeEvent>) {
        // Normal batches leave half the fixed physical reservation untouched
        // for the final failed batch. Never dump native arrays into product UI.
        match self.append_with_limit(
            &serde_json::json!({"kind":"incomplete-native-events","phase":phase,"events":events}),
            self.maximum_capacity,
        ) {
            Ok(()) => events.clear(),
            Err(error) => eprintln!("The final native event batch could not be preserved: {error}"),
        }
    }
}
