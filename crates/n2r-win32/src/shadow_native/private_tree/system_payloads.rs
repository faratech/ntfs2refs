//! Supply recognized small system streams before final source metadata is
//! restored. User prefixes remain private/source-backed and are not rewritten.
use super::super::input_domain::{InputDomain, ObjectInput, SliceInputs};
use super::*;

pub(super) fn validate_input_domain(
    input: &impl InputDomain,
    existing: impl Fn(&[String]) -> bool,
) -> io::Result<SystemPayloadInputPreflight> {
    let system = "System Volume Information";
    let mut total = 0u64;
    let mut result = SystemPayloadInputPreflight::default();
    let mut root_seen = false;
    for index in 0..input.len() {
        let owner = input.object(index)?;
        let item = owner.input();
        if !item.components.first().is_some_and(|s| s == system) {
            continue;
        }
        if item.components.len() > 2
            || !item.additional_names.is_empty()
            || !item.named_streams.is_empty()
            || item.reparse.is_some()
            || item.sparse.is_some()
        {
            return Err(invalid(
                "system namespace exceeds ordinary root files and empty immediate directories",
            ));
        }
        if item.directory {
            result.directories += 1;
            root_seen |= item.components == [system];
            if item.logical_length() != 0
                || !item.payload.is_empty()
                || item.source_offset.is_some()
                || !item.source_runs.is_empty()
            {
                return Err(invalid("system directory has source payload"));
            }
        } else if item.components.len() != 2
            || (existing(item.components) && !formatter_cache_name(&item.components[1]))
            || item.logical_length() > 1024 * 1024
            || item.expected_sha256.is_none()
        {
            return Err(invalid(
                "system payload outside bounded admitted-source profile",
            ));
        } else {
            result.files += 1;
            total = total
                .checked_add(item.logical_length())
                .ok_or_else(|| invalid("system supply total overflow"))?;
        }
    }
    if total > 3 * 1024 * 1024 {
        return Err(invalid("system payload budget exceeded"));
    }
    if result.directories + result.files != 0 && !root_seen {
        return Err(invalid(
            "system payload lacks its explicit source directory root",
        ));
    }
    result.logical_bytes = total;
    Ok(result)
}

fn require_owned_directories(tree: &PrivateTree, input: &impl InputDomain) -> io::Result<()> {
    let root_id = info(&tree.metadata_targets[&0], 18, 24)?;
    for &index in &tree.system_directory_indices {
        let owner = input.object(index)?;
        let item = owner.input();
        if !item.directory
            || !item
                .components
                .first()
                .is_some_and(|s| s == "System Volume Information")
            || !(1..=2).contains(&item.components.len())
        {
            return Err(invalid(
                "owned system directory ordinal differs from canonical input",
            ));
        }
        let handle = tree
            .metadata_targets
            .get(&index)
            .ok_or_else(|| invalid("owned system directory metadata handle absent"))?;
        validate_open_type(handle, true)?;
        let id = info(handle, 18, 24)?;
        if id[..8] != root_id[..8]
            || tree
                .system_identities
                .get(item.components)
                .is_none_or(|expected| id[8..24] != *expected)
        {
            return Err(invalid("owned system directory identity or volume changed"));
        }
        let mut seen = BTreeSet::new();
        for entry in enumerate(handle)? {
            if entry.name_utf16 == [46] || entry.name_utf16 == [46, 46] {
                continue;
            }
            if item.components.len() != 1 {
                return Err(invalid("source-empty system child directory is not empty"));
            }
            let name = String::from_utf16(&entry.name_utf16)
                .map_err(|_| invalid("system directory child UTF-16 differs"))?;
            let child = vec![item.components[0].clone(), name];
            if entry.attributes & 0x400 != 0
                || !seen.insert(entry.file_id)
                || tree
                    .system_identities
                    .get(&child)
                    .is_none_or(|expected| entry.file_id.as_slice() != expected)
            {
                return Err(invalid("system root contains an unknown or changed child"));
            }
        }
        if item.components.len() == 1
            && seen.len()
                != tree
                    .system_identities
                    .keys()
                    .filter(|path| path.len() == 2)
                    .count()
        {
            return Err(invalid("owned system root namespace coverage differs"));
        }
    }
    Ok(())
}

pub(super) fn run(
    tree: &mut PrivateTree,
    input: &[Input<'_>],
    writer: &mut dyn FnMut(usize, &mut File) -> io::Result<()>,
) -> io::Result<serde_json::Value> {
    run_domain(tree, &SliceInputs(input), writer)
}

pub(super) fn run_domain(
    tree: &mut PrivateTree,
    input: &impl InputDomain,
    writer: &mut dyn FnMut(usize, &mut File) -> io::Result<()>,
) -> io::Result<serde_json::Value> {
    tree.require_source_excluded()?;
    if tree.system_payloads_started
        || !tree.placement_complete
        || input.len() != tree.initial_objects.len()
    {
        return Err(invalid(
            "fresh complete placement required for system supply",
        ));
    }
    let system = "System Volume Information";
    let checked = validate_input_domain(input, |path| tree.system_identities.contains_key(path))?;
    if checked.directories != tree.system_directory_indices.len() {
        return Err(invalid(
            "system directory constructor enrollment is incomplete",
        ));
    }
    // Pay the existing bounded namespace decoder's native-call buffers and
    // decoded entries before either owned-directory enumeration.
    let _directory_query_memory = tree
        .memory
        .as_ref()
        .map(|memory| {
            let bytes = (namespace_layout::CAPACITY as u64)
                .checked_mul(namespace_layout::MAX_CALLS as u64)
                .and_then(|n| n.checked_mul(8))
                .and_then(|n| n.checked_add(65536))
                .ok_or_else(|| invalid("system directory query RAM overflow"))?;
            memory.working(bytes)
        })
        .transpose()?;
    let total = checked.logical_bytes;
    tree.system_payloads_started = true;
    let root = format!("{}\\", tree.pair.shadow.volume_path()?);
    let private = private_descriptor()?;
    let mut receipts = Vec::new();
    require_owned_directories(tree, input)?;
    for index in 0..input.len() {
        let owner = input.object(index)?;
        let item = owner.input();
        if item.directory || !item.components.first().is_some_and(|s| s == system) {
            continue;
        }
        let path = format!("{root}{}", item.components.join("\\"));
        if let Some(id) = tree.system_identities.get(item.components) {
            let mut file = open(&path, false, true)?;
            let before = snapshot(&file);
            let standard = query_bytes(&before, 1, 24)?;
            if query_bytes(&before, 18, 24)?[8..24] != *id
                || layout::u64_at(standard, 8)? > 1024 * 1024
                || layout::u32_at(standard, 16)? != 1
                || standard[20] != 0
            {
                return Err(invalid("existing system stream identity/shape differs"));
            }
            let stream_bytes = info(&file, 7, stream_layout::MAX_STREAM_BUFFER)?;
            let (streams, _) = stream_layout::parse_streams(&stream_bytes)?;
            if streams.len() != 1 || !streams[0].name.is_empty() {
                return Err(invalid("system ADS unsupported"));
            }
            file.set_len(0)?;
            file.seek(SeekFrom::Start(0))?;
            writer(index, &mut file)?;
            file.sync_all()?;
        } else {
            let target = Input {
                components: item.components,
                additional_names: &[],
                directory: false,
                times: item.times,
                attributes: 32,
                security: &private,
                expected_api_security: None,
                extended_attributes: None,
                reparse: None,
                payload: &[],
                expected_length: item.expected_length,
                expected_sha256: item.expected_sha256,
                source_offset: None,
                source_runs: vec![],
                named_streams: Vec::new(),
                sparse: None,
            };
            create(&path, &target, index, Some(&mut *writer))?;
        }
        let mut file = open(&path, false, false)?;
        let state = snapshot(&file);
        if layout::u64_at(query_bytes(&state, 1, 24)?, 8)? != item.logical_length() {
            return Err(invalid("system stream output length differs"));
        }
        file.seek(SeekFrom::Start(0))?;
        let actual = hash_exact_stream(&mut file, item.logical_length())?;
        if Some(actual.as_str()) != item.logical_sha256().as_deref() {
            return Err(invalid("system payload readback differs"));
        }
        let handle = open(&path, false, true)?;
        if query_bytes(&snapshot(&handle), 18, 24)? != query_bytes(&state, 18, 24)? {
            return Err(invalid("system metadata identity changed after supply"));
        }
        tree.system_identities.insert(
            item.components.to_vec(),
            query_bytes(&state, 18, 24)?[8..24].to_vec(),
        );
        tree.metadata_targets.insert(index, handle);
        receipts.push(
            serde_json::json!({"object_index":index,"components":item.components,
            "bytes":item.logical_length(),"sha256":actual,"readback_verified":true}),
        );
    }
    tree.volume.sync_all()?;
    require_owned_directories(tree, input)?;
    tree.require_source_excluded()?;
    tree.system_payloads_complete = true;
    Ok(
        serde_json::json!({"kind":"private-system-payload-supply","files":receipts,
        "owned_system_directories_verified":tree.system_directory_indices.len(),
        "payload_bytes_written":total,"source_payload_writes":0,"user_payload_bytes_written":0,
        "source_metadata_restoration_pending":true,"conversion_qualified":false}),
    )
}
