//! Post-cutover physical ownership check over fresh native retrieval mappings.
use super::*;
use crate::retained_compare::RetainedCompareRequest;

#[derive(Debug, Serialize)]
pub struct NativeRetentionProof {
    pub profile: &'static str,
    pub requested_ranges: usize,
    pub verified_bytes: u64,
    pub verified_segments: Vec<Range>,
    pub native_whole_stream_hashes_matched: bool,
    pub range_hashes_recomputed: bool,
    pub original_physical_positions_verified: bool,
    pub execution_authorized: bool,
}

/// Uses independently collected native logical hashes and physical mappings.
/// It performs no raw reads, writes or new per-range content hashing. Expected
/// retained ranges must be covered by same-file/same-VCN original positions.
pub fn verify_native_retained_positions(
    tree: &Tree,
    mappings: &[Mapping],
    request: &RetainedCompareRequest,
) -> Result<NativeRetentionProof> {
    crate::retained_compare::validate_request(request)?;
    let measured = diagnose_impl(
        tree,
        mappings,
        request.expected_length,
        "native-post-cutover-position-check-v1",
        |_, object, start, end, _| {
            Ok((start == 0 && end == object.length)
                .then(|| object.sha256.clone())
                .flatten())
        },
    )?;
    let mut actual: Vec<_> = measured
        .ranges
        .into_iter()
        .filter(|range| matches!(range.disposition, Disposition::Retained))
        .collect();
    actual.sort_by_key(|range| range.source_offset);
    let mut verified = Vec::new();
    let mut verified_bytes = 0u64;
    let mut index = 0;
    for wanted in &request.retained_ranges {
        let end = wanted
            .offset
            .checked_add(wanted.length)
            .context("retained limit overflow")?;
        let mut cursor = wanted.offset;
        while cursor < end {
            while index < actual.len()
                && actual[index]
                    .source_offset
                    .context("native retained source missing")?
                    + actual[index].length
                    <= cursor
            {
                index += 1;
            }
            let observed = actual
                .get(index)
                .context("native retained coverage missing")?;
            let from = observed
                .source_offset
                .context("native retained offset missing")?;
            ensure!(
                from <= cursor && observed.destination_offset == Some(from),
                "native file no longer maps to an admitted original physical range"
            );
            let amount = end.min(from + observed.length) - cursor;
            ensure!(amount > 0, "empty native retained coverage");
            ensure!(
                verified.len() < 65536,
                "native retained evidence exceeds range budget"
            );
            verified.push(Range {
                record_number: observed.record_number,
                sequence_number: observed.sequence_number,
                path: observed.path.clone(),
                stream_name: "",
                target_file_id: observed.target_file_id,
                logical_offset: observed.logical_offset + cursor - from,
                source_offset: Some(cursor),
                destination_offset: Some(cursor),
                length: amount,
                sha256: None,
                disposition: Disposition::Retained,
                justification: "fresh native retrieval mapping preserves same-file original physical bytes",
            });
            verified_bytes = verified_bytes
                .checked_add(amount)
                .context("native retained sum overflow")?;
            cursor += amount;
        }
    }
    Ok(NativeRetentionProof {
        profile: "native-retained-physical-positions-v1",
        requested_ranges: request.retained_ranges.len(),
        verified_bytes,
        verified_segments: verified,
        native_whole_stream_hashes_matched: true,
        range_hashes_recomputed: false,
        original_physical_positions_verified: true,
        execution_authorized: false,
    })
}
