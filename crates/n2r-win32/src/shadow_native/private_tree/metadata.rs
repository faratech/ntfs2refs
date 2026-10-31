//! Consuming metadata completion for a live, constructor-owned private tree.
//! No path/report can manufacture this capability; no payload is read here.
use super::*;
use windows_sys::Win32::Storage::FileSystem::ReOpenFile;

// Bind source semantics as well as names. Length-prefix every variable field
// and retain Option discriminants; report JSON is never used as authority.
pub(super) fn input_digest(input: &[Input<'_>]) -> [u8; 32] {
    fn bytes(hash: &mut Sha256, value: &[u8]) {
        hash.update((value.len() as u64).to_le_bytes());
        hash.update(value);
    }
    fn number(hash: &mut Sha256, value: Option<u64>) {
        hash.update([u8::from(value.is_some())]);
        hash.update(value.unwrap_or_default().to_le_bytes());
    }
    let mut hash = Sha256::new();
    hash.update(b"n2r-private-source-input-v1");
    hash.update((input.len() as u64).to_le_bytes());
    for item in input {
        hash.update((item.components.len() as u64).to_le_bytes());
        for part in item.components {
            bytes(&mut hash, part.as_bytes());
        }
        hash.update([u8::from(item.directory)]);
        for time in item.times {
            hash.update(time.to_le_bytes());
        }
        hash.update(item.attributes.to_le_bytes());
        bytes(&mut hash, item.security);
        hash.update([u8::from(item.expected_api_security.is_some())]);
        bytes(&mut hash, item.expected_api_security.unwrap_or_default());
        hash.update((item.payload.len() as u64).to_le_bytes());
        hash.update(Sha256::digest(item.payload));
        number(&mut hash, item.expected_length);
        hash.update([u8::from(item.expected_sha256.is_some())]);
        bytes(
            &mut hash,
            item.expected_sha256.unwrap_or_default().as_bytes(),
        );
        number(&mut hash, item.source_offset);
        hash.update((item.source_runs.len() as u64).to_le_bytes());
        for run in &item.source_runs {
            hash.update(run.logical_offset.to_le_bytes());
            number(&mut hash, run.physical_offset);
            hash.update(run.length.to_le_bytes());
        }
    }
    if input.iter().any(|i| !i.additional_names.is_empty()) {
        hash.update(b"n2r-private-hard-links-v1");
        for item in input {
            hash.update((item.additional_names.len() as u64).to_le_bytes());
            for path in item.additional_names {
                hash.update((path.len() as u64).to_le_bytes());
                for part in path {
                    bytes(&mut hash, part.as_bytes());
                }
            }
        }
    }
    if input.iter().any(|i| !i.named_streams.is_empty()) {
        hash.update(b"n2r-private-named-streams-v1");
        for item in input {
            hash.update((item.named_streams.len() as u64).to_le_bytes());
            for stream in &item.named_streams {
                hash.update((stream.name_utf16.len() as u64).to_le_bytes());
                for unit in stream.name_utf16 {
                    hash.update(unit.to_le_bytes());
                }
                hash.update(stream.expected_length.to_le_bytes());
                bytes(&mut hash, stream.expected_sha256.as_bytes());
                number(&mut hash, stream.source_offset);
                hash.update((stream.source_runs.len() as u64).to_le_bytes());
                for run in &stream.source_runs {
                    hash.update(run.logical_offset.to_le_bytes());
                    number(&mut hash, run.physical_offset);
                    hash.update(run.length.to_le_bytes());
                }
            }
        }
    }
    if input
        .iter()
        .any(|i| i.sparse.is_some() || i.named_streams.iter().any(|s| s.sparse.is_some()))
    {
        hash.update(b"n2r-private-sparse-streams-v1");
        for item in input {
            hash.update([u8::from(item.sparse.is_some())]);
            if let Some(s) = item.sparse {
                bytes(
                    &mut hash,
                    &serde_json::to_vec(s).expect("sparse layout serialization"),
                );
            }
            for stream in &item.named_streams {
                hash.update([u8::from(stream.sparse.is_some())]);
                if let Some(s) = stream.sparse {
                    bytes(
                        &mut hash,
                        &serde_json::to_vec(s).expect("sparse layout serialization"),
                    );
                }
            }
        }
    }
    if input.iter().any(|item| item.extended_attributes.is_some()) {
        hash.update(b"n2r-private-extended-attributes-v1");
        for item in input {
            hash.update([u8::from(item.extended_attributes.is_some())]);
            if let Some(set) = item.extended_attributes {
                bytes(
                    &mut hash,
                    &serde_json::to_vec(set).expect("EA set serialization"),
                );
            }
        }
    }
    if input.iter().any(|item| item.reparse.is_some()) {
        hash.update(b"n2r-private-reparse-v1");
        for item in input {
            hash.update([u8::from(item.reparse.is_some())]);
            if let Some(point) = item.reparse {
                bytes(&mut hash, &point.buffer);
            }
        }
    }
    hash.finalize().into()
}

fn reopen(file: &File, access: u32) -> io::Result<File> {
    // ReOpenFile's documented zero-access mode lets the transfer retain the
    // same object without requesting data access against the exclusive handle:
    // https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-reopenfile
    // SAFETY: reopen this actual owned object, not a pathname. Read/write
    // sharing permits the existing constructor handle; DELETE stays excluded.
    let handle = unsafe { ReOpenFile(file.as_raw_handle(), access, 3, 0x02200000) };
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: unique ownership of the newly returned native handle.
    Ok(unsafe { File::from_raw_handle(handle) })
}

pub(super) fn complete(
    mut tree: PrivateTree,
    input: &[Input<'_>],
    same_security: impl Fn(&[u8], &[u8]) -> io::Result<bool>,
) -> io::Result<serde_json::Value> {
    tree.require_bound_input(input)?;
    tree.require_source_excluded()?;
    if !tree.placement_complete || !tree.system_payloads_complete {
        return Err(invalid(
            "complete placement and system supply required before metadata",
        ));
    }
    tree.pair.validate_with_resource_profile(Some(
        crate::attestation::ResourceProfile::ExperimentalStreamingTreeV2,
    ))?;
    for (key, file) in &tree.files {
        let item = streams::view(input, key)?;
        let expected = tree
            .sparse_targets
            .get(key)
            .map_or(item.logical_length(), |s| s.dense_length);
        if item.directory || file.valid_prefix() != expected {
            return Err(invalid("private storage-valid stream completion required"));
        }
        tree.validate_stream_shape_named(
            key.object_index,
            &key.name_utf16,
            item.components,
            item.logical_length(),
        )?;
    }
    let (sparse_files, sparse_tails) = tree.finish_sparse_streams()?;
    let mut guards = BTreeMap::new();
    for (key, file) in &tree.files {
        // Exclusive placeholders cannot be reopened for metadata rights while
        // their read/write handle lives. First hold a zero-access identity
        // guard, which blocks delete/rename continuously across the transfer.
        let guard = reopen(file.metadata_handle(), 0)?;
        guards.insert(key.clone(), (info(file.metadata_handle(), 18, 24)?, guard));
    }
    for (key, file) in sparse_files {
        let guard = reopen(&file, 0)?;
        guards.insert(key, (info(&file, 18, 24)?, guard));
        drop(file);
    }
    tree.files.clear();
    let mut named_guards = BTreeMap::new();
    for (key, (identity, guard)) in guards {
        let handle = reopen(&guard, 0x011e01ff)?;
        suppress_access(&handle)?;
        validate_open_type(&handle, false)?;
        if info(&handle, 18, 24)? != identity {
            return Err(invalid("private metadata transfer identity differs"));
        }
        if key.name_utf16.is_empty() {
            if tree
                .metadata_targets
                .insert(key.object_index, handle)
                .is_some()
            {
                return Err(invalid("duplicate canonical metadata handle"));
            }
        } else {
            named_guards.insert(key, handle);
        }
    }
    tree.require_source_excluded()?;
    let links = super::super::hard_links::create_owned(input, &tree.metadata_targets)?;
    tree.require_source_excluded()?;
    // This consumes the only tree owner on success AND failure. A diagnostic
    // return cannot resume a partially public/private metadata transition.
    let mut report = super::super::cache_refresh::complete_owned_metadata(
        &tree.pair,
        &tree.source_before,
        &tree.volume,
        input,
        &tree.metadata_targets,
        same_security,
    )?;
    tree.require_source_excluded()?;
    if let Some(privileges) = tree.reparse_privileges.as_mut() {
        privileges.restore()?;
        report["reparse_privilege_states"] =
            serde_json::to_value(privileges.audit()).map_err(io::Error::other)?;
    }
    tree.privileges.restore()?;
    report["source_input_sha256"] = hex::encode(tree.metadata_input_sha256).into();
    if !sparse_tails.is_empty() {
        let tail_bytes = sparse_tails.iter().try_fold(0u64, |sum, (_, proof)| {
            sum.checked_add(proof.payload_bytes_read)
                .ok_or_else(|| invalid("sparse tail read count overflow"))
        })?;
        let padding_written = sparse_tails.iter().try_fold(0u64, |sum, (_, proof)| {
            sum.checked_add(proof.padding_bytes_written)
                .ok_or_else(|| invalid("sparse padding write count overflow"))
        })?;
        let padding_read = sparse_tails.iter().try_fold(0u64, |sum, (_, proof)| {
            sum.checked_add(proof.padding_bytes_readback)
                .ok_or_else(|| invalid("sparse padding read count overflow"))
        })?;
        report["user_payload_bytes_read"] = report["user_payload_bytes_read"]
            .as_u64()
            .unwrap_or(0)
            .checked_add(tail_bytes)
            .ok_or_else(|| invalid("sparse payload read count overflow"))?
            .into();
        report["sparse_tail_readback_bytes"] = tail_bytes.into();
        report["sparse_carrier_padding_bytes_written"] = padding_written.into();
        report["sparse_carrier_padding_bytes_readback"] = padding_read.into();
        report["sparse_tail_verification"]=serde_json::Value::Array(sparse_tails.into_iter().map(|(key,proof)|serde_json::json!({"object_index":key.object_index,"stream_name_utf16":key.name_utf16,"proof":proof})).collect());
    }
    if !links.is_empty() {
        report["hard_links"] = links.into();
    }
    report["privileges"] =
        serde_json::to_value(tree.privileges.audit()).map_err(io::Error::other)?;
    Ok(report)
}
