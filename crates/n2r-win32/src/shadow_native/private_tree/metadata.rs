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
    let mut guards = BTreeMap::new();
    for (&index, file) in &tree.files {
        let item = input
            .get(index)
            .ok_or_else(|| invalid("owned metadata input absent"))?;
        if item.directory || file.valid_prefix() != item.logical_length() {
            return Err(invalid("private storage-valid stream completion required"));
        }
        tree.validate_stream_shape(index, item.components, item.logical_length())?;
        // Exclusive placeholders cannot be reopened for metadata rights while
        // their read/write handle lives. First hold a zero-access identity
        // guard, which blocks delete/rename continuously across the transfer.
        let guard = reopen(file.metadata_handle(), 0)?;
        guards.insert(index, (info(file.metadata_handle(), 18, 24)?, guard));
    }
    tree.files.clear();
    for (index, (identity, guard)) in guards {
        let handle = reopen(&guard, 0x011e01ff)?;
        suppress_access(&handle)?;
        validate_open_type(&handle, false)?;
        if info(&handle, 18, 24)? != identity
            || tree.metadata_targets.insert(index, handle).is_some()
        {
            return Err(invalid("private metadata transfer identity differs"));
        }
    }
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
    tree.privileges.restore()?;
    report["source_input_sha256"] = hex::encode(tree.metadata_input_sha256).into();
    report["privileges"] =
        serde_json::to_value(tree.privileges.audit()).map_err(io::Error::other)?;
    Ok(report)
}
