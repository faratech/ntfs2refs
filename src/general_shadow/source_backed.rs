//! Read-only candidate for compact capture: metadata/tails come from a frozen
//! shadow, full-cluster payload comes from logical NTFS reads at measured ReFS
//! destinations. No payload-sized image or raw source writer is constructed.
//! Frozen metadata-graph reconciliation is still required before cutover.
use anyhow::{Context, Result, ensure};
use n2r_win32::{GeneralFrozenPartition, shadow_native::private_tree::SourceBackedRoutes};
use serde::Serialize;
use std::io::{self, Read, Seek, SeekFrom};

// Match the native partition reader's bounded aligned batch. Logical NTFS
// session reads use the same bound, so payload routes are not split into
// 64 KiB device requests.
const NATIVE_CAPTURE_BYTES: usize = 4 * 1024 * 1024;
const LOGICAL_SOURCE_READ_BYTES: usize = crate::ntfs_inspect::SESSION_READ_BYTES;

#[derive(Clone, Copy, Debug, Default, Serialize)]
pub struct ReadCounts {
    pub source_logical_bytes: u64,
    pub shadow_bytes: u64,
}

#[derive(Serialize)]
pub struct DifferenceCapture {
    pub layout: crate::refs_hybrid::delta::DeltaLayout,
    pub selected_bytes_compared: u64,
    pub equal_selected_bytes: u64,
    pub read_counts: ReadCounts,
    pub source_selected_sha256: String,
    pub candidate_selected_sha256: String,
    pub packed_sha256: String,
    pub input_plan_sha256: String,
    pub conversion_qualified: bool,
    // Only a fresh, complete source scan can issue this digest. Keep the
    // sidecar out of strict historical capture reports and recovery inputs.
    #[serde(skip)]
    source_raw_sha256: Option<String>,
}
impl DifferenceCapture {
    pub(crate) fn source_raw_sha256(&self) -> Option<&str> {
        self.source_raw_sha256.as_deref()
    }
}

pub struct SourceBackedShadow<'a> {
    source: &'a mut GeneralFrozenPartition,
    shadow: &'a mut GeneralFrozenPartition,
    raw: &'a crate::ntfs_inspect::NtfsInspection,
    tree: &'a crate::shadow_tree::Tree,
    routes: &'a SourceBackedRoutes,
    source_before: n2r_win32::GeneralDiskState,
    shadow_before: n2r_win32::GeneralDiskState,
    budget: crate::ntfs_inspect::StreamTransferBudget,
    length: u64,
    position: u64,
    counts: ReadCounts,
    poisoned: bool,
    session: Option<crate::ntfs_inspect::PlainStreamRangeSession>,
}

impl<'a> SourceBackedShadow<'a> {
    pub fn new(
        source: &'a mut GeneralFrozenPartition,
        shadow: &'a mut GeneralFrozenPartition,
        raw: &'a crate::ntfs_inspect::NtfsInspection,
        tree: &'a crate::shadow_tree::Tree,
        routes: &'a SourceBackedRoutes,
        max_source_logical_reads: u64,
    ) -> Result<Self> {
        ensure!(
            source.binding() == &routes.pair().source
                && shadow.binding() == &routes.pair().shadow
                && source.byte_len() == shadow.byte_len(),
            "source-backed device bindings differ"
        );
        let mut events = Vec::new();
        let source_before = source.state(&mut events)?;
        let shadow_before = shadow.state(&mut events)?;
        ensure!(
            source_before.disk_attributes == 3 && shadow_before.disk_attributes == 3,
            "source-backed candidate requires both disks frozen read-only/offline"
        );
        let max_stream = tree
            .objects
            .iter()
            .filter(|o| !o.directory)
            .map(|o| o.length)
            .max()
            .unwrap_or(1)
            .max(1);
        for route in routes.entries() {
            let object = tree
                .objects
                .get(route.object_index)
                .context("payload object absent")?;
            let identities: Vec<_> = raw
                .files
                .iter()
                .filter(|f| f.record_number == object.record_number)
                .collect();
            ensure!(
                !object.directory
                    && object.path == route.components
                    && object.length == route.stream_length
                    && object.sha256.as_deref() == Some(route.expected_sha256.as_str())
                    && identities.len() == 1
                    && identities[0].sequence_number == object.sequence_number,
                "source-backed canonical stream identity differs"
            );
        }
        let length = shadow.byte_len();
        Ok(Self {
            source,
            shadow,
            raw,
            tree,
            routes,
            source_before,
            shadow_before,
            budget: crate::ntfs_inspect::StreamTransferBudget::new(
                max_stream,
                max_source_logical_reads,
            )?,
            length,
            position: 0,
            counts: ReadCounts::default(),
            poisoned: false,
            session: None,
        })
    }

    pub fn read_counts(&self) -> ReadCounts {
        self.counts
    }

    /// Compare the complete conservative selected set, storing only differing
    /// clusters. This avoids filling both a shadow and its unused reservations.
    /// Equal bytes are proved by comparison, never by guessing their purpose.
    pub fn capture_differences_to_new_file(
        self,
        plan: &crate::refs_write_set::WriteSetPlan,
        output: &std::path::Path,
        max_changed_bytes: u64,
    ) -> Result<DifferenceCapture> {
        use sha2::{Digest, Sha256};
        ensure!(
            plan.partition_bytes == self.length,
            "delta capture geometry differs"
        );
        let selected_bytes = crate::refs_hybrid::packed::required_bytes(plan, &[])?;
        let payload: Vec<_> = self
            .routes
            .entries()
            .iter()
            .map(|r| crate::refs_write_set::ByteRange {
                offset: r.target_physical_offset,
                length: r.length,
            })
            .collect();
        ensure!(
            crate::refs_write_set::payload_coverage(plan, &payload)?.all_supplied_payloads_covered,
            "delta set omits measured user payload"
        );
        let input_plan_sha256 = hex::encode(Sha256::digest(serde_json::to_vec(plan)?));
        self.capture_difference_ranges(
            &plan.target_owned_ranges,
            selected_bytes,
            input_plan_sha256,
            output,
            max_changed_bytes,
        )
    }

    /// Complete native address-space comparison avoids relying on a metadata
    /// bitmap to prove required-byte completeness. Dirty free space can enlarge
    /// the delta; every output byte still faces the caller's hard budget.
    pub fn capture_complete_differences_to_new_file(
        self,
        output: &std::path::Path,
        max_changed_bytes: u64,
    ) -> Result<DifferenceCapture> {
        use sha2::{Digest, Sha256};
        let length = self.length;
        let selection = [crate::refs_write_set::ByteRange { offset: 0, length }];
        let identity = hex::encode(Sha256::digest(serde_json::to_vec(&serde_json::json!({
            "profile":"complete-native-address-space-source-backed-v1","partition_bytes":length,"granule_bytes":4096}))?));
        self.capture_difference_ranges(&selection, length, identity, output, max_changed_bytes)
    }

    /// Compare only the listed sorted, disjoint ranges and store their differing
    /// clusters. The caller owns the claim that unlisted bytes need not match;
    /// this capture records nothing about them.
    pub fn capture_listed_differences_to_new_file(
        self,
        selection: &[crate::refs_write_set::ByteRange],
        output: &std::path::Path,
        max_changed_bytes: u64,
    ) -> Result<DifferenceCapture> {
        use sha2::{Digest, Sha256};
        let mut selected_bytes = 0u64;
        for range in selection {
            selected_bytes = selected_bytes
                .checked_add(range.length)
                .context("listed selection overflow")?;
        }
        let identity = hex::encode(Sha256::digest(serde_json::to_vec(&serde_json::json!({
            "profile":"listed-ranges-source-backed-v1","partition_bytes":self.length,
            "granule_bytes":4096,"ranges":selection}))?));
        self.capture_difference_ranges(
            selection,
            selected_bytes,
            identity,
            output,
            max_changed_bytes,
        )
    }

    /// Retrospective planning over a coarse selection: compare the original
    /// bytes with this candidate view only inside `coarse` and return the
    /// differing granules as a selected plan, with the view's read counts and
    /// the original bytes read. Nothing outside `coarse` is read. This grants
    /// nothing and does not replace the complete capture.
    pub fn plan_changed_granules(
        mut self,
        coarse: &[crate::selected_journal::SelectedRange],
        max_selected_bytes: u64,
        max_journal_bytes: u64,
    ) -> Result<(crate::selected_journal::SelectedPlan, ReadCounts, u64)> {
        use crate::selected_journal as sj;
        let length = self.length;
        sj::validate_coarse(length, coarse)?;
        let mut original = vec![0u8; NATIVE_CAPTURE_BYTES];
        let mut candidate = vec![0u8; NATIVE_CAPTURE_BYTES];
        let mut runs = Vec::new();
        let mut original_bytes = 0u64;
        for range in coarse {
            let mut done = 0;
            while done < range.length {
                let count = (range.length - done).min(original.len() as u64) as usize;
                let at = range.offset + done;
                self.seek(SeekFrom::Start(at))?;
                self.read_exact(&mut candidate[..count])?;
                self.source.seek(SeekFrom::Start(at))?;
                self.source.read_exact(&mut original[..count])?;
                sj::record_differing_granules(
                    &mut runs,
                    at,
                    &original[..count],
                    &candidate[..count],
                )?;
                original_bytes += count as u64;
                done += count as u64;
            }
        }
        let counts = self.finish()?;
        let plan = sj::finish_changed_plan(length, runs, max_selected_bytes, max_journal_bytes)?;
        Ok((plan, counts, original_bytes))
    }

    fn capture_difference_ranges(
        mut self,
        selection: &[crate::refs_write_set::ByteRange],
        selected_bytes: u64,
        input_plan_sha256: String,
        output: &std::path::Path,
        max_changed_bytes: u64,
    ) -> Result<DifferenceCapture> {
        use crate::refs_hybrid::delta::{ChangedRange, DeltaLayout};
        use sha2::{Digest, Sha256};
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(output)?;
        ensure!(
            file.metadata()?.is_file() && file.metadata()?.len() == 0,
            "delta output must be a new ordinary file"
        );
        // One native read can satisfy each full image chunk instead of sixteen
        // 64 KiB requests. Keep these fixed-size buffers off the thread stack;
        // the exact 4 KiB comparison, budget and output loop is unchanged.
        let mut original = vec![0u8; NATIVE_CAPTURE_BYTES];
        let mut candidate = vec![0u8; NATIVE_CAPTURE_BYTES];
        let mut source_digest = crate::retained_compare::stream_digest::StreamDigest::new(true)?;
        let mut source_raw = if selection.len() == 1
            && selection[0].offset == 0
            && selection[0].length == self.length
            && selected_bytes == self.length
        {
            Some(n2r_win32::sha256_native::Sha256::new()?)
        } else {
            None
        };
        // Hash the candidate in parallel with source comparison on machines
        // with spare CPUs; the worker receives precisely the same framed bytes.
        let mut candidate_digest =
            crate::retained_compare::digest_pipeline::Overlapped::new(NATIVE_CAPTURE_BYTES)?;
        let mut packed_digest = Sha256::new();
        let mut changed = 0u64;
        let mut compared = 0u64;
        let mut ranges: Vec<ChangedRange> = Vec::new();
        for range in selection {
            let offset = range.offset.to_le_bytes();
            let length = range.length.to_le_bytes();
            source_digest.update(&offset)?;
            source_digest.update(&length)?;
            candidate_digest.update(&offset)?;
            candidate_digest.update(&length)?;
            let mut done = 0;
            while done < range.length {
                let count = (range.length - done).min(original.len() as u64) as usize;
                let at = range.offset + done;
                self.seek(SeekFrom::Start(at))?;
                self.read_exact(&mut candidate[..count])?;
                self.source.seek(SeekFrom::Start(at))?;
                self.source.read_exact(&mut original[..count])?;
                source_digest.update(&original[..count])?;
                if let Some(digest) = &mut source_raw {
                    digest.update(&original[..count])?;
                }
                candidate_digest.update(&candidate[..count])?;
                let mut offset = 0;
                while offset < count {
                    if original[offset..offset + 4096] == candidate[offset..offset + 4096] {
                        offset += 4096;
                        continue;
                    }
                    // Pack consecutive changed clusters in one write. Keep
                    // the budget boundary at a cluster: if only part of a
                    // run fits, write that prefix and refuse the next cluster
                    // exactly as the original per-cluster loop did.
                    let mut end = offset + 4096;
                    while end < count && original[end..end + 4096] != candidate[end..end + 4096] {
                        end += 4096;
                    }
                    let allowed = max_changed_bytes.saturating_sub(changed) / 4096;
                    ensure!(
                        allowed != 0,
                        "delta capture budget exhausted before next output write; preserve partial artifact"
                    );
                    let clusters =
                        usize::try_from(u64::try_from((end - offset) / 4096)?.min(allowed))?;
                    let bytes = clusters * 4096;
                    let next = changed
                        .checked_add(bytes as u64)
                        .context("delta byte count overflow")?;
                    let address = at + offset as u64;
                    if let Some(last) = ranges.last_mut().filter(|r| r.offset + r.length == address)
                    {
                        last.length += bytes as u64;
                    } else {
                        ensure!(
                            ranges.len() < 65536,
                            "delta range budget exhausted before output write"
                        );
                        ranges.push(ChangedRange {
                            offset: address,
                            length: bytes as u64,
                            packed_offset: changed,
                        });
                    }
                    file.write_all(&candidate[offset..offset + bytes])?;
                    packed_digest.update(&candidate[offset..offset + bytes]);
                    changed = next;
                    offset += bytes;
                }
                done += count as u64;
                compared = compared
                    .checked_add(count as u64)
                    .context("delta comparison overflow")?;
            }
        }
        file.sync_all()?;
        ensure!(
            compared == selected_bytes && file.metadata()?.len() == changed,
            "delta comparison/output accounting differs"
        );
        let layout = DeltaLayout::new(self.length, changed, ranges)?;
        let read_counts = self.finish()?;
        let source_raw_sha256 = match source_raw {
            Some(digest) => Some(hex::encode(digest.finish()?)),
            None => None,
        };
        Ok(DifferenceCapture {
            layout,
            selected_bytes_compared: compared,
            equal_selected_bytes: compared - changed,
            read_counts,
            source_selected_sha256: hex::encode(source_digest.finish()?),
            candidate_selected_sha256: hex::encode(candidate_digest.finish()?),
            packed_sha256: hex::encode(packed_digest.finalize()),
            input_plan_sha256,
            conversion_qualified: false,
            source_raw_sha256,
        })
    }

    /// Capture selected bytes directly from this source-backed view. Retained
    /// payload is compared against the actual original physical bytes before
    /// it is omitted. The output is a fresh ordinary file, never a device.
    /// A failed capture remains incomplete and returns no completion receipt.
    pub fn capture_to_new_file(
        mut self,
        plan: &crate::refs_write_set::WriteSetPlan,
        retained: &[crate::refs_write_set::ByteRange],
        output: &std::path::Path,
        max_packed_bytes: u64,
    ) -> Result<serde_json::Value> {
        use sha2::{Digest, Sha256};
        ensure!(
            plan.partition_bytes == self.length,
            "candidate capture geometry differs"
        );
        let required = crate::refs_hybrid::packed::required_bytes(plan, retained)?;
        ensure!(
            required <= max_packed_bytes,
            "compact capture exceeds explicit output budget"
        );
        // Every routed full-cluster user allocation must belong to the proposed
        // target write set, even if a later proof will allow omitting its bytes.
        let payload: Vec<_> = self
            .routes
            .entries()
            .iter()
            .map(|r| crate::refs_write_set::ByteRange {
                offset: r.target_physical_offset,
                length: r.length,
            })
            .collect();
        let coverage = crate::refs_write_set::payload_coverage(plan, &payload)?;
        ensure!(
            coverage.all_supplied_payloads_covered,
            "write set omits measured payload allocation"
        );
        let mut expected = [0u8; 65536];
        let mut original = [0u8; 65536];
        let mut compared = 0u64;
        let mut retained_digest = Sha256::new();
        retained_digest.update(b"n2r-source-backed-retained-comparison-v1\0");
        for range in retained {
            retained_digest.update(range.offset.to_le_bytes());
            retained_digest.update(range.length.to_le_bytes());
            let mut done = 0;
            while done < range.length {
                let position = range.offset + done;
                let index = self
                    .routes
                    .entries()
                    .partition_point(|r| r.target_physical_offset + r.length <= position);
                let route = self
                    .routes
                    .entries()
                    .get(index)
                    .context("retained payload route absent")?;
                ensure!(
                    route.target_physical_offset <= position,
                    "retained range crosses nonpayload bytes"
                );
                let count = (range.length - done)
                    .min(route.target_physical_offset + route.length - position)
                    .min(expected.len() as u64) as usize;
                self.seek(SeekFrom::Start(position))?;
                self.read_exact(&mut expected[..count])?;
                self.source.seek(SeekFrom::Start(position))?;
                self.source.read_exact(&mut original[..count])?;
                ensure!(
                    expected[..count] == original[..count],
                    "retained physical bytes differ from logical NTFS payload"
                );
                retained_digest.update(&expected[..count]);
                compared = compared
                    .checked_add(count as u64)
                    .context("retained comparison count overflow")?;
                done += count as u64;
            }
        }
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(output)?;
        ensure!(
            file.metadata()?.is_file() && file.metadata()?.len() == 0,
            "compact output must be a fresh ordinary file"
        );
        let packed =
            crate::refs_hybrid::packed::pack_with_retained(&mut self, &mut file, plan, retained)?;
        file.sync_all()?;
        ensure!(
            file.metadata()?.len() == required && packed.packed_bytes == required,
            "durable compact output length differs"
        );
        let counts = self.finish()?;
        Ok(
            serde_json::json!({"kind":"source-backed-compact-candidate","packed":packed,
            "read_counts":counts,"retained_physical_bytes_compared":compared,
            "retained_comparison_sha256":hex::encode(retained_digest.finalize()),
            "payload_shadow_initialization_bytes":0,"source_payload_writes":0,
            "frozen_required_byte_graph_verified":false,"conversion_qualified":false}),
        )
    }

    /// A consumer must require this bracket after capture. It does not prove
    /// required-byte graph completeness or authenticate a new filesystem.
    pub fn finish(mut self) -> Result<ReadCounts> {
        ensure!(!self.poisoned, "failed source-backed reader cannot finish");
        if let Some(session) = self.session.take() {
            session.finish(self.source, self.raw)?;
        }
        let mut events = Vec::new();
        ensure!(
            self.source.state(&mut events)? == self.source_before
                && self.shadow.state(&mut events)? == self.shadow_before,
            "source-backed disk state changed around capture"
        );
        ensure!(
            self.budget.reserved_bytes() == self.counts.source_logical_bytes,
            "source-backed read accounting differs"
        );
        Ok(self.counts)
    }

    fn read_inner(&mut self, output: &mut [u8]) -> Result<usize> {
        if output.is_empty() || self.position == self.length {
            return Ok(0);
        }
        let index = self
            .routes
            .entries()
            .partition_point(|r| r.target_physical_offset + r.length <= self.position);
        let route = self.routes.entries().get(index);
        let in_payload = route.is_some_and(|r| r.target_physical_offset <= self.position);
        let boundary = match route {
            Some(r) if in_payload => r.target_physical_offset + r.length,
            Some(r) => r.target_physical_offset,
            None => self.length,
        };
        // A logical source read must stay inside the NTFS session's read
        // bound; native shadow bytes use the aligned adapter batch. Both stop
        // at the next payload boundary and logical EOF.
        let limit = if in_payload {
            LOGICAL_SOURCE_READ_BYTES
        } else {
            NATIVE_CAPTURE_BYTES
        };
        let count = (boundary - self.position)
            .min(output.len() as u64)
            .min(limit as u64) as usize;
        if in_payload {
            let route = route.unwrap();
            let object = &self.tree.objects[route.object_index];
            let logical = route.logical_offset + self.position - route.target_physical_offset;
            if self
                .session
                .as_ref()
                .is_none_or(|s| s.record_number() != object.record_number)
            {
                if let Some(old) = self.session.take() {
                    old.finish(self.source, self.raw)?;
                }
                self.session = Some(crate::ntfs_inspect::PlainStreamRangeSession::open(
                    self.source,
                    self.raw,
                    object.record_number,
                    object.length,
                )?);
            }
            let session = self.session.as_mut().unwrap();
            ensure!(
                session.stream_length() == route.stream_length
                    && session.expected_sha256() == route.expected_sha256,
                "source-backed read differs from bound stream"
            );
            session.read(
                self.source,
                self.raw,
                logical,
                &mut output[..count],
                &mut self.budget,
            )?;
            self.counts.source_logical_bytes = self
                .counts
                .source_logical_bytes
                .checked_add(count as u64)
                .context("source-backed source accounting overflow")?;
        } else {
            self.shadow.seek(SeekFrom::Start(self.position))?;
            self.shadow.read_exact(&mut output[..count])?;
            self.counts.shadow_bytes = self
                .counts
                .shadow_bytes
                .checked_add(count as u64)
                .context("source-backed shadow accounting overflow")?;
        }
        self.position += count as u64;
        Ok(count)
    }
}

impl Read for SourceBackedShadow<'_> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if self.poisoned {
            return Err(io::Error::other("poisoned source-backed candidate"));
        }
        match self.read_inner(output) {
            Ok(count) => Ok(count),
            Err(error) => {
                self.poisoned = true;
                Err(io::Error::other(error))
            }
        }
    }
}

impl Seek for SourceBackedShadow<'_> {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        if self.poisoned {
            return Err(io::Error::other("poisoned source-backed candidate"));
        }
        let next = match from {
            SeekFrom::Start(v) => i128::from(v),
            SeekFrom::Current(v) => i128::from(self.position) + i128::from(v),
            SeekFrom::End(v) => i128::from(self.length) + i128::from(v),
        };
        if next < 0 || next > i128::from(self.length) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "source-backed seek escapes partition",
            ));
        }
        self.position = next as u64;
        Ok(self.position)
    }
}
