//! Data-stream identity is the canonical object plus an exact UTF-16 name.
//! Named data never becomes a second namespace object or a second hard link.
use super::*;
use std::collections::BTreeSet;

pub(super) const MAX_STREAMS: usize = 16_384;
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct StreamKey {
    pub object_index: usize,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub name_utf16: Vec<u16>,
}
impl StreamKey {
    pub fn unnamed(object_index: usize) -> Self {
        Self {
            object_index,
            name_utf16: Vec::new(),
        }
    }
    pub fn named(object_index: usize, name: &[u16]) -> Self {
        Self {
            object_index,
            name_utf16: name.to_vec(),
        }
    }
}

pub(super) fn valid_name(name: &[u16]) -> bool {
    (1..=255).contains(&name.len())
        && String::from_utf16(name).is_ok_and(|text| !text.chars().any(|c| c.is_control()))
        && name.iter().all(|c| ![47, 58, 92].contains(c))
}
pub(super) fn path(root: &str, components: &[String], name: &[u16]) -> io::Result<String> {
    let base = format!("{}\\{}", root.trim_end_matches('\\'), components.join("\\"));
    if name.is_empty() {
        return Ok(base);
    }
    if !valid_name(name) {
        return Err(invalid("invalid named data stream name"));
    }
    let name = String::from_utf16(name).map_err(|_| invalid("invalid stream UTF-16"))?;
    let result = format!("{base}:{name}:$DATA");
    if result.encode_utf16().count() >= 32767 {
        return Err(invalid("named stream path exceeds native bound"));
    }
    Ok(result)
}

pub(super) fn validate(input: &[Input<'_>], partition: u64) -> io::Result<()> {
    let mut count = 0usize;
    for object in input {
        count = count
            .checked_add(usize::from(!object.directory))
            .and_then(|n| n.checked_add(object.named_streams.len()))
            .ok_or_else(|| invalid("stream count overflow"))?;
        if count > MAX_STREAMS
            || object.named_streams.len() >= stream_layout::MAX_STREAMS
            || (object.directory && !object.named_streams.is_empty())
        {
            return Err(invalid(
                "named stream count or directory ADS exceeds profile",
            ));
        }
        if let Some(layout) = object.sparse {
            if object.directory {
                return Err(invalid("directory sparse data unsupported"));
            }
            layout.validate(object.logical_length())?;
        }
        let mut names = BTreeSet::new();
        for stream in &object.named_streams {
            if let Some(layout) = stream.sparse {
                layout.validate(stream.expected_length)?;
            }
            if !valid_name(stream.name_utf16)
                || !names.insert(
                    String::from_utf16(stream.name_utf16)
                        .unwrap()
                        .to_uppercase(),
                )
                || stream.expected_length > partition
                || !crate::content_digest::is_hex(stream.expected_sha256)
                || (stream.source_offset.is_some() && !stream.source_runs.is_empty())
            {
                return Err(invalid(
                    "named stream identity, size, digest or source mapping differs",
                ));
            }
        }
    }
    Ok(())
}

pub(super) fn view<'a>(input: &'a [Input<'_>], key: &StreamKey) -> io::Result<Input<'a>> {
    let object = input
        .get(key.object_index)
        .ok_or_else(|| invalid("stream object index absent"))?;
    let named = if key.name_utf16.is_empty() {
        None
    } else {
        Some(
            object
                .named_streams
                .iter()
                .find(|s| s.name_utf16 == key.name_utf16)
                .ok_or_else(|| invalid("named stream input absent"))?,
        )
    };
    Ok(Input {
        components: object.components,
        additional_names: object.additional_names,
        directory: object.directory,
        times: object.times,
        attributes: object.attributes,
        security: object.security,
        expected_api_security: object.expected_api_security,
        payload: if named.is_some() { &[] } else { object.payload },
        expected_length: named.map(|s| s.expected_length).or(object.expected_length),
        expected_sha256: named.map(|s| s.expected_sha256).or(object.expected_sha256),
        source_offset: named.map_or(object.source_offset, |s| s.source_offset),
        source_runs: named.map_or_else(|| object.source_runs.clone(), |s| s.source_runs.clone()),
        named_streams: Vec::new(),
        sparse: named.map_or(object.sparse, |s| s.sparse),
    })
}

pub(super) fn exact_list(bytes: &[u8], item: &Input<'_>) -> io::Result<()> {
    let (entries, _) = stream_layout::parse_streams(bytes)?;
    if entries.len() != 1 + item.named_streams.len() {
        return Err(invalid("native stream set count differs"));
    }
    for entry in entries {
        let length = if entry.name.is_empty() {
            item.logical_length()
        } else {
            item.named_streams
                .iter()
                .find(|s| s.name_utf16 == entry.name)
                .ok_or_else(|| invalid("unexpected native named stream"))?
                .expected_length
        };
        if entry.logical_size != length {
            return Err(invalid("native stream logical size differs"));
        }
    }
    Ok(())
}

#[derive(Debug, Serialize)]
pub struct Report {
    pub name_utf16: Vec<u16>,
    pub expected_sha256: String,
    pub before: Snapshot,
    pub after: Snapshot,
    pub logical_sha256: Option<String>,
    pub retrieval: Vec<u8>,
    pub retrieval_page_proof: Option<crate::retrieval_paging::Proof>,
    pub resident_data: bool,
    pub cached_validity: Vec<u8>,
    pub storage_validity: Vec<u8>,
    pub integrity: Vec<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sparse: Option<sparse_stream::Observation>,
}

pub(super) fn observe(
    root: &str,
    item: &Input<'_>,
    canonical: &Snapshot,
    protected: bool,
    hash: bool,
    clusters: u64,
) -> io::Result<Vec<Report>> {
    let mut reports = Vec::with_capacity(item.named_streams.len());
    for named in &item.named_streams {
        let path = path(root, item.components, named.name_utf16)?;
        let mut file = if protected {
            open_protected_readonly(&path, false)?
        } else {
            open(&path, false, false)?
        };
        let before = snapshot(&file);
        let standard = query_bytes(&before, 1, 24)?;
        if query_bytes(&before, 18, 24)? != query_bytes(canonical, 18, 24)?
            || layout::u64_at(standard, 8)? != named.expected_length
            || layout::u32_at(standard, 16)? != hard_links::count(item)?
            || standard[20] != 0
            || standard[21] != 0
        {
            return Err(invalid("named stream base identity or EOF differs"));
        }
        if (layout::u32_at(query_bytes(&before, 9, 8)?, 0)? & 0x200 != 0) != named.sparse.is_some()
        {
            return Err(invalid(
                "named stream sparse attribute differs from its declared layout",
            ));
        }
        let allocation = layout::u64_at(standard, 0)?;
        let (first, continuation) = crate::stream_native::retrieval_queries(&file);
        let resident_data = named.sparse.is_none()
            && resident_allocation(named.expected_length, allocation)
            && first.native_error == Some(38)
            && first.bytes.is_empty()
            && continuation.is_empty();
        let empty = named.expected_length == 0
            && allocation == 0
            && first.native_error.is_none()
            && continuation.is_empty()
            && first.bytes.len() == 16
            && layout::u32_at(&first.bytes, 0)? == 0
            && layout::u64_at(&first.bytes, 8)? == 0;
        let sparse_empty = named.sparse.is_some()
            && allocation == 0
            && first.native_error == Some(38)
            && first.bytes.is_empty()
            && continuation.is_empty();
        let (retrieval, retrieval_page_proof) = if resident_data || empty || sparse_empty {
            (Vec::new(), None)
        } else {
            let cap = crate::retrieval_paging::assemble_queries(&first, &continuation)?;
            let mut end = 0;
            for r in stream_layout::parse_complete_retrieval(&cap.canonical)? {
                if r.vcn != end
                    || match r.lcn {
                        Some(l) => l.checked_add(r.clusters).is_none_or(|e| e > clusters),
                        None => named.sparse.is_none(),
                    }
                {
                    return Err(invalid("named stream physical mapping invalid"));
                }
                end = r.vcn + r.clusters;
            }
            if named.sparse.is_none() && end < named.expected_length.div_ceil(4096) {
                return Err(invalid("named stream mapping is incomplete"));
            }
            (cap.canonical, Some(cap.proof))
        };
        let mut regions = Vec::new();
        for usage in [1u32, 2] {
            if named.sparse.is_some() || allocation == 0 || resident_data {
                regions.push(Vec::new());
                continue;
            }
            let mut q = [0; 24];
            q[8..16].copy_from_slice(&named.expected_length.to_le_bytes());
            q[16..20].copy_from_slice(&usage.to_le_bytes());
            let b = ctl(&file, 0x90284, &q, 16 + 24 * 1024)?;
            crate::region_layout::validate_logical(&b, named.expected_length, usage)?;
            regions.push(b);
        }
        let integrity = ctl(&file, 0x9027c, &[], 16)?;
        if integrity.len() != 16
            || integrity[..8] != [0; 8]
            || layout::u32_at(&integrity, 12)? != 4096
        {
            return Err(invalid("named stream integrity profile differs"));
        }
        let logical_sha256 = if hash {
            let actual = hash_exact_stream(&mut file, named.expected_length)?;
            if actual != named.expected_sha256 {
                return Err(invalid("named stream logical digest differs"));
            }
            Some(actual)
        } else {
            None
        };
        let after = snapshot(&file);
        if before != after {
            return Err(invalid("named stream metadata changed during observation"));
        }
        reports.push(Report {
            sparse: named
                .sparse
                .map(|s| sparse_stream::observe(&file, s, named.expected_length))
                .transpose()?,
            name_utf16: named.name_utf16.to_vec(),
            expected_sha256: named.expected_sha256.into(),
            before,
            after,
            logical_sha256,
            retrieval,
            retrieval_page_proof,
            resident_data,
            cached_validity: regions.remove(0),
            storage_validity: regions.remove(0),
            integrity,
        });
    }
    Ok(reports)
}

pub(super) fn verify(item: &Input<'_>, object: &ObjectReport, hash: bool) -> io::Result<()> {
    exact_list(&object.streams, item)?;
    if object.named_streams.len() != item.named_streams.len() {
        return Err(invalid("named stream report coverage differs"));
    }
    for (wanted, actual) in item.named_streams.iter().zip(&object.named_streams) {
        if actual.name_utf16 != wanted.name_utf16
            || actual.expected_sha256 != wanted.expected_sha256
            || actual.before != actual.after
            || query_bytes(&actual.before, 18, 24)? != query_bytes(&object.before, 18, 24)?
            || layout::u64_at(query_bytes(&actual.before, 1, 24)?, 8)? != wanted.expected_length
            || (hash && actual.logical_sha256.as_deref() != Some(wanted.expected_sha256))
            || (!hash && actual.logical_sha256.is_some())
        {
            return Err(invalid("named stream report differs"));
        }
        if actual.sparse.as_ref().map(|s| &s.expected) != wanted.sparse
            || (layout::u32_at(query_bytes(&actual.before, 9, 8)?, 0)? & 0x200 != 0)
                != wanted.sparse.is_some()
            || (layout::u32_at(query_bytes(&actual.after, 9, 8)?, 0)? & 0x200 != 0)
                != wanted.sparse.is_some()
            || actual
                .sparse
                .as_ref()
                .is_some_and(|s| !s.allocation_matches || !s.data_storage_valid)
        {
            return Err(invalid("named sparse evidence differs"));
        }
    }
    Ok(())
}
