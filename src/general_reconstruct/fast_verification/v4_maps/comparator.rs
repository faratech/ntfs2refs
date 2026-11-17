//! Fact-only comparison of a held V4 ordinal map to a converted metadata
//! report. A public report or saved map is not a live post-HND authority.
use super::*;
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Header {
    pub(super) schema_version: u32,
    pub(super) kind: String,
    pub(super) source: n2r_win32::general_layout::GeneralDiskBinding,
    pub(super) shadow: n2r_win32::general_layout::GeneralDiskBinding,
    pub(super) native_base_sectors: u64,
    pub(super) source_sha256: String,
    pub(super) source_inspection_sha256: String,
    pub(super) source_views_sha256: String,
    pub(super) expected_tree_sha256: String,
    pub(super) ticket_sha256: String,
    pub(super) selected_bytes: u64,
    pub(super) journal_length: u64,
    pub(super) range_count: u32,
    pub(super) native_bindings: u64,
    pub(super) admission: n2r_win32::tree_resources::SourceResourceAdmission,
    pub(super) grants_write_authority: bool,
}

impl V4RecoveryMaps {
    /// Compare every stored map to a caller-supplied converted metadata report.
    /// The intended producer is `observe_general_converted_metadata_domain`.
    /// This method does not establish that a public report came from that
    /// observer, that HND is durable, or that post-reboot owners are authentic.
    pub(crate) fn compare_converted_diagnostic(
        &self,
        expected: &PagedExpectedTree,
        ticket: &SelectedTicket,
        converted: &shadow_native::GeneralConvertedReport,
    ) -> Result<serde_json::Value> {
        ensure!(
            expected
                .artifact_lease()
                .is_some_and(|owner| self.expected_owner.same_owner(owner))
                && expected.semantic_sha256() == self.expected_sha256
                && canonical_json_sha256(ticket)? == self.ticket_sha256,
            "V4 diagnostic expected owner or ticket differs"
        );
        expected.require_resource_owner(self.admission)?;
        let arena = self.source_owner.permit().arena();
        expected.require_shared_memory(arena)?;
        // Reader retains its own page lease. Pay independently for decoded
        // chunk copies, their base64 form and one bounded serialized native row.
        let budget = self.admission.map_page_budget()?;
        let bytes = u64::from(budget.max_page_bytes)
            .checked_mul(8)
            .and_then(|n| n.checked_add(self.admission.budget.max_row_bytes))
            .and_then(|n| n.checked_add(1024 * 1024))
            .context("V4 comparator RAM overflow")?;
        let _ram = arena.reserve_ram(bytes)?;
        self.revalidate()?;
        let mut reader = self.reader.borrow_mut();
        let first = reader.get(0)?;
        ensure!(first.key.is_empty(), "V4 map header key differs");
        let header: Header = serde_json::from_slice(&first.payload)?;
        let report = &converted.native;
        let observation = converted
            .content_observation
            .as_ref()
            .context("converted metadata observation absent")?;
        ensure!(
            header.schema_version == 4
                && header.kind == "protected-v4-ordinal-stream-maps"
                && !header.grants_write_authority
                && header.admission == self.admission
                && header.source_sha256 == self.source_sha256
                && header.source_inspection_sha256 == self.source_inspection_sha256
                && header.source_views_sha256 == self.source_views_sha256
                && header.expected_tree_sha256 == self.expected_sha256
                && header.ticket_sha256 == self.ticket_sha256
                && header.native_bindings == self.records
                && header.selected_bytes == ticket.selected_bytes
                && header.journal_length == ticket.journal_length
                && header.range_count == ticket.range_count
                && converted.pair.source.identity == header.source.identity
                && converted.pair.shadow.identity == header.shadow.identity
                && report.binding.identity == converted.pair.source.identity
                && report.resource_profile
                    == Some(n2r_win32::attestation::ResourceProfile::ResourceBoundedV4(
                        Some(self.admission)
                    ))
                && !converted.conversion_qualified
                && !observation.full_file_hashes
                && observation.admitted_payload_bytes_read == 0
                && observation.metadata_and_namespace_verified
                && observation.complete_stream_mappings_observed
                && observation.data_storage_validity_checked,
            "V4 diagnostic header/source/metadata observation differs"
        );
        // The current native observer initializes base_sectors to zero and
        // does not actually query a nonzero retrieval base. Compare LCNs in
        // volume-relative coordinates only under the diagnostic zero-base assumption.
        // In particular, never add either disk's different GPT start offset.
        ensure!(
            header.native_base_sectors == 0 && report.base_sectors == 0,
            "nonzero or unobserved retrieval base requires native normalization evidence"
        );
        ensure!(
            report.objects.len() == expected.len(),
            "V4 converted object coverage differs"
        );
        let bindings =
            compare_records(&mut reader, expected, report, self.admission, self.records)?;
        drop(reader);
        self.revalidate()?;
        Ok(
            serde_json::json!({"kind":"diagnostic-v4-ordinal-map-comparison",
            "matching_bindings":bindings,"volume_relative_lcn_comparison_assuming_zero_base":true,
            "retrieval_base_assumed_zero_not_independently_observed":true,
            "native_report_is_public_diagnostic":true,"post_handoff_or_restart_proven":false,
            "payload_content_hashes_verified":false,"execution_authorized":false,
            "conversion_qualified":false}),
        )
    }
}

/// Complete bounded comparison shared by live and reopened map owners.
pub(super) fn compare_records(
    reader: &mut metadata_pages::Reader,
    expected: &PagedExpectedTree,
    report: &shadow_native::Report,
    admission: n2r_win32::tree_resources::SourceResourceAdmission,
    records: u64,
) -> Result<u64> {
    let budget = admission.map_page_budget()?;
    let mut record = 1u64;
    let mut bindings = 0u64;
    report.objects.try_for_each(|index, native| -> Result<()> {
        let object = expected.object_leased(index)?;
        ensure!(
            native.components == object.path
                && native.before == native.after
                && native.named_streams.len() == object.named_streams.len(),
            "V4 converted object identity or stream coverage differs"
        );
        for ordinal in 0..=native.named_streams.len() {
            let named = ordinal.checked_sub(1);
            if let Some(i) = named {
                let stream = &native.named_streams[i];
                ensure!(
                    !stream.name_utf16.is_empty()
                        && stream.before == stream.after
                        && !native.named_streams[..i]
                            .iter()
                            .any(|s| s.name_utf16 == stream.name_utf16)
                        && object
                            .named_streams
                            .iter()
                            .filter(|s| s.name_utf16 == stream.name_utf16)
                            .count()
                            == 1,
                    "V4 converted named-stream identity differs"
                );
            }
            StreamLocation {
                object: index,
                named,
            }
            .view(report, |(components, name_utf16), map| {
                let entry = MapEntryRef {
                    components,
                    name_utf16,
                    map: PagedStreamMapRef::with_resources(map, Some(admission))?,
                };
                let size = row_size(&entry, admission.budget.max_row_bytes)?;
                validate_borrowed_row_memory(&entry, size, admission.budget.max_row_bytes)?;
                let mut expected_hash = HashSink {
                    hash: Sha256::new(),
                    bytes: 0,
                };
                serde_json::to_writer(&mut expected_hash, &entry)?;
                ensure!(
                    expected_hash.bytes == size && size != 0,
                    "V4 converted row length differs"
                );
                let expected_digest = expected_hash.hash.finalize();
                let key = key(index, ordinal)?;
                let max_chunk = chunk_capacity(budget, key.len())?;
                let mut actual_hash = Sha256::new();
                let mut actual_bytes = 0u64;
                let mut chunk = 0u64;
                while actual_bytes < size {
                    let saved = reader.get(record)?;
                    ensure!(
                        saved.key == chunk_key(&key, chunk),
                        "V4 map chunk identity/order differs"
                    );
                    let text: &str = serde_json::from_slice(&saved.payload)?;
                    let data = decode_base64(text, max_chunk)?;
                    ensure!(!data.is_empty(), "V4 map has an empty chunk");
                    actual_bytes = actual_bytes
                        .checked_add(data.len() as u64)
                        .filter(|n| *n <= size)
                        .context("V4 converted map row length differs")?;
                    actual_hash.update(&data);
                    record = record.checked_add(1).context("V4 record count overflow")?;
                    chunk = chunk.checked_add(1).context("V4 chunk count overflow")?;
                }
                ensure!(
                    actual_hash.finalize() == expected_digest,
                    "V4 converted stream map differs"
                );
                bindings = bindings
                    .checked_add(1)
                    .context("V4 binding count overflow")?;
                Ok(())
            })?;
        }
        Ok(())
    })?;
    ensure!(
        record == reader.len() && bindings == records,
        "V4 converted map comparison is incomplete"
    );
    Ok(bindings)
}
