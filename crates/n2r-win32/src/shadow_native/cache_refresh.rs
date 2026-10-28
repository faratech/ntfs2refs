//! Small-cache and metadata synchronization on an existing disposable shadow.
//! User payloads are never rewritten; complete conversion admission follows.
use super::*;
use std::collections::{BTreeMap, BTreeSet};

fn guid_payload(bytes: &[u8]) -> bool {
    if bytes.len() != 76 {
        return false;
    }
    bytes.chunks_exact(2).enumerate().all(|(at, b)| {
        let c = u16::from_le_bytes([b[0], b[1]]);
        match at {
            0 => c == b'{' as u16,
            37 => c == b'}' as u16,
            9 | 14 | 19 | 24 => c == b'-' as u16,
            _ => c <= 127 && (c as u8).is_ascii_hexdigit(),
        }
    })
}

pub fn run(
    pair: &GeneralSourceShadowBinding,
    input: &[Input<'_>],
    payload: &[u8],
    same_security: impl Fn(&[u8], &[u8]) -> io::Result<bool>,
) -> io::Result<serde_json::Value> {
    pair.validate_with_resource_profile(Some(
        crate::attestation::ResourceProfile::ExperimentalStreamingTreeV2,
    ))?;
    if std::env::var("COMPUTERNAME").ok().as_deref() != Some("N2R-WIN11")
        || pair.source.disk_number != 1
        || pair.shadow.disk_number != 3
        || pair
            .source
            .identity
            .disk_guid
            .trim_matches(['{', '}'])
            .to_ascii_lowercase()
            != "1b191872-c372-41ee-a416-e18863996f54"
        || pair
            .shadow
            .identity
            .disk_guid
            .trim_matches(['{', '}'])
            .to_ascii_lowercase()
            != "c0f2cd39-ad3d-484e-9990-0e6eba74485f"
        || input.is_empty()
        || input.len() > 32
        || !guid_payload(payload)
    {
        return Err(invalid("enrolled small-cache refresh scope differs"));
    }
    let mut names = BTreeSet::new();
    for item in input {
        if item.components.len() > 16
            || item
                .components
                .iter()
                .any(|s| !crate::shadow_names::valid_unicode_component(s))
            || !names.insert(item.components.to_vec())
            || item.times.iter().any(|v| *v == 0 || *v >= i64::MAX as u64)
            || item.attributes & !0x2037 != 0
            || (item.attributes & 16 != 0) != item.directory
        {
            return Err(invalid("invalid bounded cache-refresh input"));
        }
        descriptor(item.security)?;
    }
    if !input[0].components.is_empty() || !input[0].directory {
        return Err(invalid("root expectation required"));
    }
    let wanted: Vec<_> = input
        .iter()
        .filter(|i| {
            i.components.len() == 2
                && i.components[0] == "System Volume Information"
                && i.components[1] == "IndexerVolumeGuid"
        })
        .collect();
    if wanted.len() != 1
        || wanted[0].directory
        || wanted[0].logical_length() != 76
        || wanted[0].logical_sha256() != hex::encode(Sha256::digest(payload))
    {
        return Err(invalid(
            "source indexer cache bytes do not match expectation",
        ));
    }
    let cache = wanted[0];
    let mut events = Vec::new();
    let source_before =
        native::observe_general_disk_state_readonly(pair.source.clone(), &mut events)?;
    let target = native::GeneralPartitionReader::open(pair.shadow.clone(), &mut events)?;
    if source_before.disk_attributes != 3
        || native::mounted_filesystem_general(pair.shadow.clone(), &mut events)? != "ReFS"
    {
        return Err(invalid("excluded source and writable ReFS shadow required"));
    }
    let mut privileges = Privileges::enable_for(&[
        "SeBackupPrivilege",
        "SeRestorePrivilege",
        "SeSecurityPrivilege",
        "SeManageVolumePrivilege",
    ])?;
    let root = format!("{}\\", pair.shadow.volume_path()?);
    let volume = File::options()
        .read(true)
        .write(true)
        .share_mode(3)
        .open(pair.shadow.volume_path()?)?;
    pair.shadow
        .validate_volume_extent(&ctl(&volume, 0x00560000, &[], 1024)?)?;
    let mut cache_exists = false;
    let mut identities: BTreeMap<Vec<String>, Vec<u8>> = BTreeMap::new();
    // Complete directory preflight: no unknown names and no missing entries
    // except the one exact cache this routine is permitted to create.
    for directory in input.iter().filter(|i| i.directory) {
        let handle = open(
            &format!("{}{}", root, directory.components.join("\\")),
            true,
            true,
        )?;
        let directory_id = query_bytes(&snapshot(&handle), 18, 24)?[8..24].to_vec();
        if identities
            .get(directory.components)
            .is_some_and(|id| id != &directory_id)
        {
            return Err(invalid("directory identity changed during cache preflight"));
        }
        identities.insert(directory.components.to_vec(), directory_id);
        let actual = enumerate(&handle)?;
        let mut seen = BTreeSet::new();
        for entry in actual {
            let name = String::from_utf16(&entry.name_utf16)
                .map_err(|_| invalid("invalid target namespace UTF-16"))?;
            if name == "." || name == ".." {
                continue;
            }
            let mut path = directory.components.to_vec();
            path.push(name);
            let expected = input
                .iter()
                .find(|i| i.components == path)
                .ok_or_else(|| invalid("unexpected existing-shadow entry"))?;
            if (entry.attributes & 16 != 0) != expected.directory
                || entry.attributes & 0x400 != 0
                || !seen.insert(path.clone())
            {
                return Err(invalid("target namespace type or identity ambiguity"));
            }
            if path == cache.components {
                cache_exists = true;
            }
            if identities
                .get(&path)
                .is_some_and(|id| id.as_slice() != entry.file_id.as_slice())
            {
                return Err(invalid("entry identity changed during cache preflight"));
            }
            identities.insert(path, entry.file_id.to_vec());
        }
        for child in input.iter().filter(|i| {
            i.components.len() == directory.components.len() + 1
                && i.components.starts_with(directory.components)
        }) {
            if !seen.contains(child.components) && child.components != cache.components {
                return Err(invalid("missing existing-shadow entry"));
            }
        }
    }
    let path = format!("{}{}", root, cache.components.join("\\"));
    let unique: BTreeSet<_> = identities.values().collect();
    if unique.len() != identities.len() {
        return Err(invalid("aliased shadow identities are unsupported"));
    }
    let mut payload_written = 0u64;
    if cache_exists {
        let mut file = open(&path, false, true)?;
        let state = snapshot(&file);
        if Some(query_bytes(&state, 18, 24)?[8..24].to_vec()).as_ref()
            != identities.get(cache.components)
        {
            return Err(invalid("indexer cache identity changed before refresh"));
        }
        let standard = query_bytes(&state, 1, 24)?;
        let stream_bytes = info(&file, 7, stream_layout::MAX_STREAM_BUFFER)?;
        let (streams, _) = stream_layout::parse_streams(&stream_bytes)?;
        if layout::u64_at(standard, 8)? != 76
            || u32::from_le_bytes(standard[16..20].try_into().unwrap()) != 1
            || standard[20] != 0
            || streams.len() != 1
            || !streams[0].name.is_empty()
            || streams[0].logical_size != 76
        {
            return Err(invalid("existing indexer cache shape differs"));
        }
        let mut old = [0; 76];
        file.read_exact(&mut old)?;
        if !guid_payload(&old) {
            return Err(invalid("existing indexer cache is not a GUID"));
        }
        if old != payload {
            file.seek(SeekFrom::Start(0))?;
            file.write_all(payload)?;
            file.sync_all()?;
            payload_written = 76;
        }
        file.seek(SeekFrom::Start(0))?;
        if hash_exact_stream(&mut file, 76)? != cache.logical_sha256()
            || Some(query_bytes(&snapshot(&file), 18, 24)?[8..24].to_vec()).as_ref()
                != identities.get(cache.components)
        {
            return Err(invalid(
                "indexer cache bytes or identity changed during refresh",
            ));
        }
    } else {
        let mut writer = |_: usize, file: &mut File| file.write_all(payload);
        create(&path, cache, 0, Some(&mut writer))?;
        payload_written = 76;
        let mut file = open(&path, false, false)?;
        if hash_exact_stream(&mut file, 76)? != cache.logical_sha256() {
            return Err(invalid("created source cache bytes differ"));
        }
        identities.insert(
            cache.components.to_vec(),
            query_bytes(&snapshot(&file), 18, 24)?[8..24].to_vec(),
        );
    }
    let mut metadata_updated = 0;
    for item in input.iter().rev() {
        let handle = open(
            &format!("{}{}", root, item.components.join("\\")),
            item.directory,
            true,
        )?;
        let before = snapshot(&handle);
        if Some(query_bytes(&before, 18, 24)?[8..24].to_vec()).as_ref()
            != identities.get(item.components)
        {
            return Err(invalid("shadow identity changed before metadata refresh"));
        }
        if !security_matches(item, &before, &same_security)? {
            backup_security(&handle, item.security)?;
            if !security_matches(item, &snapshot(&handle), &same_security)? {
                return Err(invalid("refreshed descriptor views differ"));
            }
        }
        basic(&handle, item)?;
        if !item.directory {
            handle.sync_all()?;
        }
        if query_bytes(&snapshot(&handle), 18, 24)?[8..24] != query_bytes(&before, 18, 24)?[8..24] {
            return Err(invalid("shadow identity changed during metadata refresh"));
        }
        metadata_updated += 1;
    }
    volume.sync_all()?;
    target.revalidate_route(&mut events)?;
    if native::observe_general_disk_state_readonly(pair.source.clone(), &mut events)?
        != source_before
    {
        return Err(invalid("cache refresh storage route changed"));
    }
    privileges.restore()?;
    Ok(
        serde_json::json!({"schema_version":1,"kind":"reused-shadow-small-cache-refresh",
        "cache_created":!cache_exists,"cache_payload_bytes_written":payload_written,
        "unchanged_user_payload_bytes_written":0,"metadata_objects_updated":metadata_updated,
        "source_payload_writes":0,"source_before":source_before,"events":events,
        "privileges":privileges.audit(),"requires_fresh_conversion_admission":true,"conversion_qualified":false}),
    )
}
