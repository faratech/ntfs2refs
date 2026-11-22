//! Consuming metadata completion for a live, constructor-owned private tree.
//! No path/report can manufacture this capability; no payload is read here.
use super::super::input_domain::{InputDomain, ObjectInput, SliceInputs};
use super::*;
use windows_sys::Win32::Storage::FileSystem::ReOpenFile;

// Bind source semantics as well as names. Length-prefix every variable field
// and retain Option discriminants; report JSON is never used as authority.
pub(super) fn input_digest(input: &[Input<'_>]) -> [u8; 32] {
    input_digest_domain(&SliceInputs(input)).expect("in-memory input ordinal domain")
}

pub(in crate::shadow_native) fn input_digest_domain(
    input: &impl InputDomain,
) -> io::Result<[u8; 32]> {
    let Some(memo) = input.input_digest_memo() else {
        return compute_input_digest_domain(input);
    };
    if let Some(known) = memo.get() {
        return Ok(known);
    }
    let digest = compute_input_digest_domain(input)?;
    memo.set(digest);
    Ok(digest)
}

fn compute_input_digest_domain(input: &impl InputDomain) -> io::Result<[u8; 32]> {
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
    for index in 0..input.len() {
        let owner = input.object(index)?;
        let item = owner.input();
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
    if input.any(|i| !i.additional_names.is_empty())? {
        hash.update(b"n2r-private-hard-links-v1");
        for index in 0..input.len() {
            let owner = input.object(index)?;
            let item = owner.input();
            hash.update((item.additional_names.len() as u64).to_le_bytes());
            for path in item.additional_names {
                hash.update((path.len() as u64).to_le_bytes());
                for part in path {
                    bytes(&mut hash, part.as_bytes());
                }
            }
        }
    }
    if input.any(|i| !i.named_streams.is_empty())? {
        let optional_content = input.any(|item| {
            item.named_streams
                .iter()
                .any(|stream| stream.expected_sha256.is_none())
        })?;
        if optional_content {
            hash.update(b"n2r-private-named-streams-optional-content-v1".as_slice());
        } else {
            hash.update(b"n2r-private-named-streams-v1".as_slice());
        }
        for index in 0..input.len() {
            let owner = input.object(index)?;
            let item = owner.input();
            hash.update((item.named_streams.len() as u64).to_le_bytes());
            for stream in &item.named_streams {
                hash.update((stream.name_utf16.len() as u64).to_le_bytes());
                for unit in stream.name_utf16 {
                    hash.update(unit.to_le_bytes());
                }
                hash.update(stream.expected_length.to_le_bytes());
                if optional_content {
                    hash.update([u8::from(stream.expected_sha256.is_some())]);
                }
                bytes(
                    &mut hash,
                    stream.expected_sha256.unwrap_or_default().as_bytes(),
                );
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
    if input.any(|i| i.sparse.is_some() || i.named_streams.iter().any(|s| s.sparse.is_some()))? {
        hash.update(b"n2r-private-sparse-streams-v1");
        for index in 0..input.len() {
            let owner = input.object(index)?;
            let item = owner.input();
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
    if input.any(|item| item.extended_attributes.is_some())? {
        hash.update(b"n2r-private-extended-attributes-v1");
        for index in 0..input.len() {
            let owner = input.object(index)?;
            let item = owner.input();
            hash.update([u8::from(item.extended_attributes.is_some())]);
            if let Some(set) = item.extended_attributes {
                bytes(
                    &mut hash,
                    &serde_json::to_vec(set).expect("EA set serialization"),
                );
            }
        }
    }
    if input.any(|item| item.reparse.is_some())? {
        hash.update(b"n2r-private-reparse-v1");
        for index in 0..input.len() {
            let owner = input.object(index)?;
            let item = owner.input();
            hash.update([u8::from(item.reparse.is_some())]);
            if let Some(point) = item.reparse {
                bytes(&mut hash, &point.buffer);
            }
        }
    }
    Ok(hash.finalize().into())
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
    tree: PrivateTree,
    input: &[Input<'_>],
    same_security: impl Fn(&[u8], &[u8]) -> io::Result<bool>,
) -> io::Result<serde_json::Value> {
    complete_domain(tree, &SliceInputs(input), same_security)
}

pub(super) fn complete_domain(
    tree: PrivateTree,
    input: &impl InputDomain,
    same_security: impl Fn(&[u8], &[u8]) -> io::Result<bool>,
) -> io::Result<serde_json::Value> {
    complete_domain_inner(
        tree,
        input,
        None::<&super::super::windows_aliases::NoWindowsAliases>,
        false,
        same_security,
    )
    .map(|(report, _)| report)
}

pub(super) fn complete_windows_aliases_domain(
    tree: PrivateTree,
    input: &impl InputDomain,
    aliases: &impl super::super::windows_aliases::WindowsAliasInputDomain,
    same_security: impl Fn(&[u8], &[u8]) -> io::Result<bool>,
) -> io::Result<(
    serde_json::Value,
    super::super::windows_aliases::VerifiedWindowsAliases,
)> {
    let (report, proof) = complete_domain_inner(tree, input, Some(aliases), false, same_security)?;
    Ok((
        report,
        proof.ok_or_else(|| invalid("Windows alias completion witness absent"))?,
    ))
}

pub(super) fn complete_windows_aliases_domain_with_security_placeholders(
    tree: PrivateTree,
    input: &impl InputDomain,
    aliases: &impl super::super::windows_aliases::WindowsAliasInputDomain,
    same_security: impl Fn(&[u8], &[u8]) -> io::Result<bool>,
) -> io::Result<(
    serde_json::Value,
    super::super::windows_aliases::VerifiedWindowsAliases,
)> {
    let (report, proof) = complete_domain_inner(tree, input, Some(aliases), true, same_security)?;
    Ok((
        report,
        proof.ok_or_else(|| invalid("provisional Windows alias completion witness absent"))?,
    ))
}

fn complete_domain_inner(
    mut tree: PrivateTree,
    input: &impl InputDomain,
    aliases: Option<&impl super::super::windows_aliases::WindowsAliasInputDomain>,
    security_placeholders: bool,
    same_security: impl Fn(&[u8], &[u8]) -> io::Result<bool>,
) -> io::Result<(
    serde_json::Value,
    Option<super::super::windows_aliases::VerifiedWindowsAliases>,
)> {
    tree.require_dedicated_shadow_boundary()?;
    let result = complete_domain_body(
        &mut tree,
        input,
        aliases,
        security_placeholders,
        same_security,
    );
    let closing = tree.require_dedicated_shadow_boundary();
    let finish = if let Some(lease) = tree.dedicated_source.take() {
        lease.finish(&tree.pair, &tree.source_before, &mut Vec::new())
    } else {
        Ok(())
    };
    // The handle held on every object closes with the tree, after the checks
    // above, as before; now beside one another (`close_at_once`), and before
    // the volume handle and the privileges the tree also holds, which no
    // close needs.
    crate::perf::step("metadata: close the objects' handles");
    let payer = tree.memory.as_ref().map(|memory| memory.payer());
    super::super::close_at_once(
        payer.as_deref(),
        std::mem::take(&mut tree.metadata_targets).into_values(),
    );
    match (result, closing, finish) {
        (Ok(value), Ok(()), Ok(())) => Ok(value),
        (Err(error), closing, finish) => {
            let mut detail = error.to_string();
            if let Err(boundary) = closing {
                detail.push_str(&format!("; metadata closing roles failed: {boundary}"));
            }
            if let Err(boundary) = finish {
                detail.push_str(&format!("; query-reference finish failed: {boundary}"));
            }
            Err(io::Error::new(error.kind(), detail))
        }
        (_, Err(error), _) | (_, _, Err(error)) => Err(error),
    }
}

fn complete_domain_body(
    tree: &mut PrivateTree,
    input: &impl InputDomain,
    aliases: Option<&impl super::super::windows_aliases::WindowsAliasInputDomain>,
    security_placeholders: bool,
    same_security: impl Fn(&[u8], &[u8]) -> io::Result<bool>,
) -> io::Result<(
    serde_json::Value,
    Option<super::super::windows_aliases::VerifiedWindowsAliases>,
)> {
    tree.require_bound_input_domain(input)?;
    input.require_mutation_binding(&tree.pair.shadow)?;
    tree.require_source_excluded()?;
    // Pay for one bounded row's temporary stored/API views before allocating
    // them. The original admitted InputDomain and all of its digests stay held.
    let _security_working = if security_placeholders {
        if tree.pair.source.layout_profile
            != crate::general_layout::GeneralDiskLayoutProfile::OfflineWindows
        {
            return Err(invalid(
                "security placeholders require the explicit Windows constructor",
            ));
        }
        let admission = tree
            .metadata_resource_admission
            .ok_or_else(|| invalid("provisional security resource admission absent"))?;
        let memory = tree
            .memory
            .as_ref()
            .ok_or_else(|| invalid("provisional security memory owner absent"))?;
        Some(
            memory.working(crate::refs_security_descriptor::constructor_working_bytes(
                admission.budget.max_row_bytes,
            )?)?,
        )
    } else {
        None
    };
    if !tree.placement_complete || !tree.system_payloads_complete {
        return Err(invalid(
            "complete placement and system supply required before metadata",
        ));
    }
    tree.pair
        .validate_with_resource_profile(Some(tree.metadata_resource_admission.map_or(
            crate::attestation::ResourceProfile::ExperimentalStreamingTreeV2,
            |a| crate::attestation::ResourceProfile::ResourceBoundedV4(Some(a)),
        )))?;
    // This is the longest step of a full Windows conversion, and most of
    // its time is inside single file-system calls, which a stack profile
    // counts once each however long they take. Its passes are timed apart.
    crate::perf::step("metadata: check placed streams");
    let mut extent_only_tails = Vec::new();
    let stream_progress = |pass, completed, total| {
        input.progress(
            crate::progress::Update::new(
                crate::progress::Phase::MetadataRestoration,
                crate::progress::Unit::Streams,
                completed,
                Some(total),
            )
            .with_pass(pass),
        )
    };
    for (ordinal, (key, file)) in tree.files.iter().enumerate() {
        stream_progress(0, ordinal as u64, tree.files.len() as u64);
        let owner = input.object(key.object_index)?;
        let object = owner.input();
        let item = streams::view_object(&object, &key.name_utf16)?;
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
        if let Some(proof) = tree.require_materialized_tail(key, &item)? {
            extent_only_tails.push(proof);
        }
    }
    stream_progress(0, tree.files.len() as u64, tree.files.len() as u64);
    let (sparse_files, sparse_tails) = tree.finish_sparse_streams()?;
    for proof in &extent_only_tails {
        let key = StreamKey::named(proof.object_index, &proof.stream_name_utf16);
        if let Some(file) = sparse_files.get(&key) {
            let (_, tail) = sparse_tails
                .iter()
                .find(|(candidate, _)| candidate == &key)
                .ok_or_else(|| invalid("digest-free final carrier tail proof absent"))?;
            if tail.logical_offset != proof.offset
                || tail.visible_bytes != proof.bytes
                || tail.target_sha256 != proof.sha256
                || !tail.actual_bytes_equal
                || proof.native_file_id != info(file, 18, 24)?
            {
                return Err(invalid(
                    "digest-free carrier tail changed during final stream transfer",
                ));
            }
        }
    }
    crate::perf::step("metadata: take metadata handles");
    // Taking a stream's metadata handle is two reopens and a few queries,
    // each through a handle of that stream alone, which one thread made for
    // one stream after another. On a tree this run built, with a payer for
    // the helpers, the streams of a batch are taken on the available cores
    // (`each_at_once`): a helper is handed handles, never the tree. What
    // was taken is entered into the tree's maps on this thread, in the
    // streams' order, so a failure is reported for the same stream as
    // before. A recovered tree, and one without a payer, takes one stream
    // after another as before (a batch of one, on this thread).
    let helper_payer = if tree.recovery_origin.is_none() {
        tree.memory.as_ref().map(|memory| memory.payer())
    } else {
        None
    };
    let handle_batch = if helper_payer.is_some() {
        super::super::PARALLEL_BATCH
    } else {
        1
    };
    // What a helper holds for one stream beside its query buffer: a file
    // identity and the handle.
    const HANDLE_WORKSPACE: u64 = 65536;
    let mut guards = BTreeMap::new();
    {
        let total = tree.files.len() as u64;
        let mut files = tree.files.iter().enumerate().peekable();
        let mut batch: Vec<(&StreamKey, &File)> = Vec::with_capacity(handle_batch);
        while let Some(&(ordinal, _)) = files.peek() {
            stream_progress(1, ordinal as u64, total);
            batch.clear();
            batch.extend(
                files
                    .by_ref()
                    .take(handle_batch)
                    .map(|(_, (key, file))| (key, file.metadata_handle())),
            );
            let guarded = super::super::each_at_once(
                helper_payer.as_deref(),
                &batch,
                |_| Some(HANDLE_WORKSPACE),
                |(_, file)| -> io::Result<(Vec<u8>, File)> {
                    // Exclusive placeholders cannot be reopened for metadata
                    // rights while their read/write handle lives. First hold
                    // a zero-access identity guard, which blocks delete and
                    // rename continuously across the transfer.
                    let guard = reopen(file, 0)?;
                    Ok((info(file, 18, 24)?, guard))
                },
            );
            for ((key, _), guarded) in batch.iter().zip(guarded) {
                guards.insert((*key).clone(), guarded?);
            }
        }
        stream_progress(1, total, total);
    }
    let sparse_count = sparse_files.len() as u64;
    for (ordinal, (key, file)) in sparse_files.into_iter().enumerate() {
        stream_progress(2, ordinal as u64, sparse_count);
        let guard = reopen(&file, 0)?;
        guards.insert(key, (info(&file, 18, 24)?, guard));
        drop(file);
    }
    stream_progress(2, sparse_count, sparse_count);
    tree.files.clear();
    let mut named_guards = BTreeMap::new();
    let guard_count = guards.len() as u64;
    {
        let mut guards = guards.into_iter().enumerate().peekable();
        // The streams of a batch with their guards, and where each object's
        // streams lie among them. An object's streams are one item: a
        // helper takes them one after another, in their order, and no two
        // helpers work on the same file.
        let mut batch: Vec<(StreamKey, Vec<u8>, File)> = Vec::new();
        let mut objects: Vec<std::ops::Range<usize>> = Vec::with_capacity(handle_batch);
        while let Some(ordinal) = guards.peek().map(|(ordinal, _)| *ordinal) {
            stream_progress(3, ordinal as u64, guard_count);
            objects.clear();
            while objects.len() < handle_batch {
                let Some(object) = guards.peek().map(|(_, (key, _))| key.object_index) else {
                    break;
                };
                let start = batch.len();
                while let Some((_, (key, (identity, guard)))) =
                    guards.next_if(|(_, (key, _))| key.object_index == object)
                {
                    batch.push((key, identity, guard));
                }
                objects.push(start..batch.len());
            }
            let units: Vec<&[(StreamKey, Vec<u8>, File)]> = objects
                .iter()
                .map(|streams| &batch[streams.clone()])
                .collect();
            // One result for each stream of the object, up to and with the
            // first that fails: the streams after it are not asked.
            let opened = super::super::each_at_once(
                helper_payer.as_deref(),
                &units,
                |_| Some(HANDLE_WORKSPACE),
                |streams| -> Vec<io::Result<File>> {
                    let mut opened = Vec::with_capacity(streams.len());
                    for (_, identity, guard) in streams.iter() {
                        let handle = (|| -> io::Result<File> {
                            let handle =
                                reopen(guard, crate::shadow_native::METADATA_WRITE_ACCESS)?;
                            suppress_access(&handle)?;
                            validate_open_type(&handle, false)?;
                            if info(&handle, 18, 24)? != *identity {
                                return Err(invalid("private metadata transfer identity differs"));
                            }
                            Ok(handle)
                        })();
                        let failed = handle.is_err();
                        opened.push(handle);
                        if failed {
                            break;
                        }
                    }
                    opened
                },
            );
            drop(units);
            // In the streams' order: a stream's guard goes once its handle
            // is held, and the first failure ends the pass, so that no
            // result is taken for a stream after it.
            let mut streams = batch.drain(..);
            for handle in opened.into_iter().flatten() {
                let (key, _identity, _guard) = streams.next().ok_or_else(|| {
                    invalid("metadata handles: a handle was taken for a stream outside its batch")
                })?;
                let handle = handle?;
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
            if let Some((key, _, _)) = streams.next() {
                return Err(invalid(&format!(
                    "metadata handles: no handle was taken for a stream of object {}",
                    key.object_index
                )));
            }
        }
    }
    stream_progress(3, guard_count, guard_count);
    tree.require_source_excluded()?;
    let enumeration_payer = if tree.metadata_resource_admission.is_some() {
        Some(
            tree.memory
                .as_ref()
                .ok_or_else(|| invalid("resource metadata enumeration payer absent"))?
                .payer(),
        )
    } else {
        None
    };
    crate::perf::step("metadata: create hard links");
    let links = if let Some(admission) = tree.metadata_resource_admission {
        super::super::hard_links::create_owned_resource_domain(
            input,
            &tree.metadata_targets,
            admission.maximum_namespace_names()?,
            &format!("{}\\", tree.pair.shadow.volume_path()?),
            enumeration_payer
                .as_deref()
                .ok_or_else(|| invalid("resource hard-link enumeration payer absent"))?,
        )?
    } else {
        super::super::hard_links::MadeLinks::listed(super::super::hard_links::create_owned_domain(
            input,
            &tree.metadata_targets,
        )?)
    };
    tree.require_source_excluded()?;
    crate::perf::step("metadata: create short-name links");
    let mut alias_stage = if let Some(aliases) = aliases {
        let admission = tree
            .metadata_resource_admission
            .ok_or_else(|| invalid("Windows aliases require actual resource metadata ownership"))?;
        let memory = tree
            .memory
            .as_ref()
            .ok_or_else(|| invalid("Windows alias constructor RAM owner absent"))?;
        if tree.reparse_privileges.is_none() {
            tree.reparse_privileges =
                Some(Privileges::enable_for(&["SeCreateSymbolicLinkPrivilege"])?);
        }
        Some(super::super::windows_aliases::StagedWindowsAliases::create(
            input,
            aliases,
            &tree.pair,
            &tree.metadata_targets,
            admission,
            &memory.payer(),
        )?)
    } else {
        None
    };
    tree.require_source_excluded()?;
    // This consumes the only tree owner on success AND failure. A diagnostic
    // return cannot resume a partially public/private metadata transition.
    let completion = if security_placeholders {
        super::super::cache_refresh::complete_owned_metadata_scoped_windows_aliases_domain_with_security_placeholders(
            &tree.pair,
            &tree.source_before,
            tree.partition_source.as_ref().map(|lease|lease.witness()),
            &tree.volume,
            input,
            &tree.metadata_targets,
            tree.metadata_object_limit,
            tree.metadata_resource_admission,
            alias_stage.as_mut(),
            enumeration_payer.as_deref(),
            same_security,
        )
    } else {
        super::super::cache_refresh::complete_owned_metadata_scoped_windows_aliases_domain(
            &tree.pair,
            &tree.source_before,
            tree.partition_source.as_ref().map(|lease| lease.witness()),
            &tree.volume,
            input,
            &tree.metadata_targets,
            tree.metadata_object_limit,
            tree.metadata_resource_admission,
            alias_stage.as_mut(),
            enumeration_payer.as_deref(),
            same_security,
        )
    };
    let mut report = completion?;
    tree.require_source_excluded()?;
    if let Some(privileges) = tree.reparse_privileges.as_mut() {
        privileges.restore()?;
        report["reparse_privilege_states"] =
            serde_json::to_value(privileges.audit()).map_err(io::Error::other)?;
    }
    tree.privileges.restore()?;
    report["source_input_sha256"] = hex::encode(tree.metadata_input_sha256).into();
    if !extent_only_tails.is_empty() {
        report["extent_only_tail_materialization"] =
            serde_json::to_value(&extent_only_tails).map_err(io::Error::other)?;
    }
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
    links.record(&mut report);
    report["privileges"] =
        serde_json::to_value(tree.privileges.audit()).map_err(io::Error::other)?;
    if let Some(lease) = tree.partition_source.take() {
        let mut events = Vec::new();
        lease.finish(&mut events)?;
    }
    if let Some(aliases) = aliases {
        aliases.revalidate()?;
    }
    if let Some(stage) = alias_stage.as_ref() {
        report["derived_windows_aliases"] = stage.summary();
    }
    // Taking the links' ledger closes the handle held on each link.
    crate::perf::step("metadata: close the objects' handles");
    Ok((
        report,
        alias_stage
            .map(super::super::windows_aliases::StagedWindowsAliases::finish)
            .transpose()?,
    ))
}
