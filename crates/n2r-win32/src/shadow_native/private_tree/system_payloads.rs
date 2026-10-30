//! Supply recognized small system streams before final source metadata is
//! restored. User prefixes remain private/source-backed and are not rewritten.
use super::*;

pub(super) fn run(
    tree: &mut PrivateTree,
    input: &[Input<'_>],
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
    let mut total = 0u64;
    for item in input
        .iter()
        .filter(|i| i.components.first().is_some_and(|s| s == system))
    {
        if item.directory {
            if item.components != [system] {
                return Err(invalid("nested system directory unsupported"));
            }
        } else if item.components.len() != 2
            || (tree.system_identities.contains_key(item.components)
                && !formatter_cache_name(&item.components[1]))
            || item.logical_length() > 1024 * 1024
            || item.expected_sha256.is_none()
        {
            return Err(invalid(
                "system payload outside bounded admitted-source profile",
            ));
        } else {
            total = total
                .checked_add(item.logical_length())
                .ok_or_else(|| invalid("system supply total overflow"))?;
        }
    }
    if total > 3 * 1024 * 1024 {
        return Err(invalid("system payload budget exceeded"));
    }
    tree.system_payloads_started = true;
    let root = format!("{}\\", tree.pair.shadow.volume_path()?);
    let private = private_descriptor()?;
    let mut receipts = Vec::new();
    if input
        .iter()
        .any(|i| i.directory && i.components == [system])
        && !tree.system_identities.contains_key(&vec![system.into()])
    {
        let components = vec![system.to_owned()];
        let item = Input {
            components: &components,
            additional_names: &[],
            directory: true,
            times: [0; 4],
            attributes: 16,
            security: &private,
            expected_api_security: None,
            payload: &[],
            expected_length: None,
            expected_sha256: None,
            source_offset: None,
            source_runs: vec![],
            named_streams: Vec::new(),
            sparse: None,
        };
        create(&format!("{root}{system}"), &item, 0, None)?;
        let file = open(&format!("{root}{system}"), true, false)?;
        tree.system_identities.insert(
            components,
            query_bytes(&snapshot(&file), 18, 24)?[8..24].to_vec(),
        );
        let index = input
            .iter()
            .position(|i| i.directory && i.components == [system])
            .ok_or_else(|| invalid("system directory input absent"))?;
        tree.metadata_targets
            .insert(index, open(&format!("{root}{system}"), true, true)?);
    }
    for (index, item) in input
        .iter()
        .enumerate()
        .filter(|(_, i)| !i.directory && i.components.first().is_some_and(|s| s == system))
    {
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
        if actual != item.logical_sha256() {
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
    tree.require_source_excluded()?;
    tree.system_payloads_complete = true;
    Ok(
        serde_json::json!({"kind":"private-system-payload-supply","files":receipts,
        "payload_bytes_written":total,"source_payload_writes":0,"user_payload_bytes_written":0,
        "source_metadata_restoration_pending":true,"conversion_qualified":false}),
    )
}
