//! Deliberately fragmented, newly created NTFS laboratory files. Allocation is
//! changed only by NTFS through FSCTL_MOVE_FILE; no volume WriteFile is issued.
//! This module is not part of conversion admission or recovery authority.
use crate::{
    attestation_native::Privileges, discovery, file_storage, layout, stream_layout, stream_native,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    os::windows::{
        fs::{MetadataExt, OpenOptionsExt},
        io::AsRawHandle,
    },
    path::{Path, PathBuf},
};
use windows_sys::Win32::Storage::FileSystem::GetFileInformationByHandleEx;

const CLUSTER: u64 = 4096;
const STREAM_BYTES: u64 = 2 * 1024 * 1024;
const CLUSTERS: u64 = STREAM_BYTES / CLUSTER;
const WINDOW_START: u64 = 12 * 1024 * 1024 * 1024 / CLUSTER;
const WINDOW_CLUSTERS: u64 = 64 * 1024 * 1024 / CLUSTER;
const BITMAP_CAPACITY: usize = 16 + 8192;
const PARTITION_BYTES: u64 = 52 * 1024 * 1024 * 1024;

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}
fn require(condition: bool, message: &str) -> io::Result<()> {
    if condition {
        Ok(())
    } else {
        Err(invalid(message))
    }
}
fn u64_at(bytes: &[u8], offset: usize) -> io::Result<u64> {
    Ok(u64::from_le_bytes(
        bytes
            .get(offset..offset + 8)
            .ok_or_else(|| invalid("short native u64"))?
            .try_into()
            .unwrap(),
    ))
}
fn u32_at(bytes: &[u8], offset: usize) -> io::Result<u32> {
    Ok(u32::from_le_bytes(
        bytes
            .get(offset..offset + 4)
            .ok_or_else(|| invalid("short native u32"))?
            .try_into()
            .unwrap(),
    ))
}
fn source() -> io::Result<discovery::VolumeDiscovery> {
    let source = discovery::discover(r"H:\", discovery::Role::Source)?;
    require(
        source.binding.disk_number == 6
            && layout::guid_bytes(&source.binding.identity.disk_guid)?
                == layout::guid_bytes("f95141cb-fe7e-439a-a82b-c2b3f55965d2")?
            && layout::guid_bytes(&source.binding.identity.partition_guid)?
                == layout::guid_bytes("f77d3d8f-9a87-464d-a7de-e1b77604da7b")?
            && source.binding.identity.partition_number == 2
            && source.binding.identity.partition_offset == 32 * 1024 * 1024
            && source.binding.identity.partition_bytes == PARTITION_BYTES
            && source.binding.identity.disk_bytes == 56 * 1024 * 1024 * 1024
            && !source.disk_is_windows_disk
            && !source.read_only
            && source.filesystem == "NTFS"
            && source.label == "n2r-links-source"
            && source.bytes_per_sector == 512
            && source.sectors_per_cluster == 8,
        "exact writable enrolled disk-6 NTFS H: fixture required",
    )?;
    Ok(source)
}
fn control(volume: &File, code: u32, input: &[u8], capacity: usize) -> io::Result<Vec<u8>> {
    let query = stream_native::ioctl(volume, code, input, capacity);
    if let Some(error) = query.native_error {
        return Err(io::Error::from_raw_os_error(error));
    }
    Ok(query.bytes)
}
fn verify_volume(volume: &File, expected: Option<(u64, u64)>) -> io::Result<(u64, u64)> {
    let extents = control(volume, 0x0056_0000, &[], 32)?;
    let ntfs = control(volume, 0x0009_0064, &[], 128)?;
    require(
        extents.len() == 32
            && u32_at(&extents, 0)? == 1
            && u32_at(&extents, 8)? == 6
            && u64_at(&extents, 16)? == 32 * 1024 * 1024
            && u64_at(&extents, 24)? == PARTITION_BYTES
            && ntfs.len() >= 96
            && u32_at(&ntfs, 40)? == 512
            && u32_at(&ntfs, 44)? == CLUSTER as u32
            && u32_at(&ntfs, 48)? == 1024,
        "held volume route or NTFS record/cluster geometry changed",
    )?;
    let actual = u64_at(&ntfs, 0)?;
    let clusters = u64_at(&ntfs, 16)?;
    require(
        clusters > WINDOW_START + WINDOW_CLUSTERS && clusters <= PARTITION_BYTES / CLUSTER,
        "NTFS total cluster count outside partition",
    )?;
    require(
        expected.is_none_or(|expected| expected == (actual, clusters)),
        "held NTFS serial or total cluster count changed",
    )?;
    Ok((actual, clusters))
}
fn identity(file: &File, serial: u64) -> io::Result<String> {
    let id = file_storage::file_id_info(file)?;
    let bytes = hex::decode(&id).map_err(|_| invalid("invalid file identity"))?;
    require(
        bytes.len() == 24 && u64_at(&bytes, 0)? == serial && bytes[16..].iter().all(|b| *b == 0),
        "file identity is not on held NTFS volume",
    )?;
    Ok(id)
}
fn same_identity(file: &File, serial: u64, expected: &str) -> io::Result<()> {
    require(
        identity(file, serial)? == expected,
        "held fixture file identity changed",
    )
}
fn standard(file: &File) -> io::Result<Value> {
    let mut info = [0u64; 3];
    // SAFETY: live borrowed file, aligned initialized 24-byte FILE_STANDARD_INFO.
    if unsafe {
        GetFileInformationByHandleEx(file.as_raw_handle(), 1, info.as_mut_ptr().cast(), 24)
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    require(
        info[0] <= i64::MAX as u64 && info[1] <= i64::MAX as u64 && (info[2] >> 32) & 0xffff == 0,
        "invalid/deleting/directory fixture standard info",
    )?;
    Ok(json!({"allocation_size":info[0],"end_of_file":info[1],
        "number_of_links":info[2] as u32,"delete_pending":false,"directory":false}))
}
fn ordinary_directory(path: &Path) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    require(
        metadata.is_dir() && metadata.file_attributes() & 0x400 == 0,
        "ordinary non-reparse fixture parent required",
    )
}
fn new_stream(
    path: &Path,
    serial: u64,
    seed: u64,
    length: u64,
    created: &mut Vec<Value>,
) -> io::Result<(File, String)> {
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .share_mode(3)
        .custom_flags(0x0020_0000)
        .open(path)?;
    created.push(json!({"path":path,"created":true,"initialized":false}));
    let id = identity(&file, serial)?;
    created.last_mut().unwrap()["file_id_info"] = json!(id);
    require(
        file.metadata()?.is_file() && file.metadata()?.file_attributes() & 0x4e00 == 0,
        "ordinary uncompressed, unencrypted, nonsparse file required",
    )?;
    let mut buffer = vec![0u8; 65536];
    let mut at = 0u64;
    while at < length {
        let count = (length - at).min(buffer.len() as u64) as usize;
        for (index, byte) in buffer[..count].iter_mut().enumerate() {
            *byte = ((at + index as u64).wrapping_mul(31).wrapping_add(seed) % 251) as u8;
        }
        file.write_all(&buffer[..count])?;
        at += count as u64;
    }
    file.sync_all()?;
    same_identity(&file, serial, &id)?;
    require(
        file.metadata()?.len() == length,
        "initialized stream length differs",
    )?;
    *created.last_mut().unwrap() = json!({"path":path,"created":true,"initialized":true,
        "length":length,"file_id_info":id});
    Ok((file, id))
}
fn hashes(file: &mut File, length: u64) -> io::Result<Value> {
    require(
        length <= STREAM_BYTES && file.metadata()?.len() == length,
        "bounded stream EOF differs",
    )?;
    file.seek(SeekFrom::Start(0))?;
    let mut sha = Sha256::new();
    let mut content = crate::content_digest::Hasher::new();
    let mut buffer = vec![0u8; 65536];
    let mut remaining = length;
    while remaining != 0 {
        let count = remaining.min(buffer.len() as u64) as usize;
        file.read_exact(&mut buffer[..count])?;
        sha.update(&buffer[..count]);
        content.update(&buffer[..count]);
        remaining -= count as u64;
    }
    let mut extra = [0u8; 1];
    require(
        file.read(&mut extra)? == 0,
        "unexpected bytes after stream EOF",
    )?;
    Ok(json!({"length":length,"sha256":hex::encode(sha.finalize()),
        "content_digest":content.finish(),"content_digest_algorithm":"xxh3-128"}))
}
fn lcn_at(runs: &[stream_layout::Run], vcn: u64) -> io::Result<u64> {
    let index = runs.partition_point(|run| run.vcn + run.clusters <= vcn);
    let run = runs
        .get(index)
        .ok_or_else(|| invalid("missing fixture VCN"))?;
    require(run.vcn <= vcn, "gapped fixture retrieval mapping")?;
    run.lcn
        .and_then(|lcn| lcn.checked_add(vcn - run.vcn))
        .ok_or_else(|| invalid("sparse or overflowing fixture mapping"))
}
fn mapping(file: &File) -> io::Result<crate::retrieval_paging::Capture> {
    let capture = stream_native::retrieval_capture(file)?;
    require(
        capture.runs.first().is_some_and(|r| r.vcn == 0)
            && capture
                .runs
                .last()
                .is_some_and(|r| r.vcn + r.clusters == CLUSTERS)
            && capture.runs.iter().all(|r| r.lcn.is_some()),
        "fixture mapping does not cover initialized 2 MiB",
    )?;
    for vcn in 0..CLUSTERS {
        require(
            lcn_at(&capture.runs, vcn)? < PARTITION_BYTES / CLUSTER,
            "fixture extent outside partition",
        )?;
    }
    Ok(capture)
}
fn map_json(capture: &crate::retrieval_paging::Capture) -> Value {
    json!({"canonical_sha256":hex::encode(Sha256::digest(&capture.canonical)),
        "page_proof":capture.proof,
        "extents":capture.runs.iter().map(|run| json!({"vcn":run.vcn,"lcn":run.lcn,
            "clusters":run.clusters})).collect::<Vec<_>>()})
}
struct Bitmap {
    start: u64,
    bits: u64,
    bytes: Vec<u8>,
    sha256: String,
}
impl Bitmap {
    fn free(&self, lcn: u64) -> io::Result<bool> {
        let bit = lcn
            .checked_sub(self.start)
            .filter(|v| *v < self.bits)
            .ok_or_else(|| invalid("requested cluster outside returned bitmap"))?;
        Ok(self.bytes[16 + bit as usize / 8] & (1 << (bit % 8)) == 0)
    }
}
fn bitmap(volume: &File, start: u64, total_clusters: u64) -> io::Result<Bitmap> {
    let query = stream_native::ioctl(
        volume,
        stream_layout::GET_BITMAP,
        &start.to_le_bytes(),
        BITMAP_CAPACITY,
    );
    if let Some(error) = query.native_error.filter(|e| *e != 234) {
        return Err(io::Error::from_raw_os_error(error));
    }
    require(query.bytes.len() > 16, "empty fixture bitmap")?;
    let first = u64_at(&query.bytes, 0)?;
    let declared = u64_at(&query.bytes, 8)?;
    require(
        first <= start && first < total_clusters && declared == total_clusters - first,
        "fixture bitmap domain differs",
    )?;
    let bits = declared.min((query.bytes.len() - 16) as u64 * 8);
    let sha256 = hex::encode(Sha256::digest(&query.bytes));
    Ok(Bitmap {
        start: first,
        bits,
        bytes: query.bytes,
        sha256,
    })
}
fn find_window(volume: &File, total_clusters: u64) -> io::Result<(u64, Value)> {
    let map = bitmap(volume, WINDOW_START, total_clusters)?;
    let end = WINDOW_START + WINDOW_CLUSTERS;
    let mut run = 0u64;
    for lcn in WINDOW_START..end {
        run = if map.free(lcn)? { run + 1 } else { 0 };
        if run == 4 * CLUSTERS {
            let start = lcn + 1 - run;
            return Ok((
                start,
                json!({"search_start_lcn":WINDOW_START,
                "search_clusters":WINDOW_CLUSTERS,"selected_start_lcn":start,
                "selected_clusters":run,"bitmap_sha256":map.sha256,
                "bitmap_start_lcn":map.start,"bitmap_returned_bits":map.bits}),
            ));
        }
    }
    Err(invalid(
        "no bounded free fragmentation window near 12 GiB; no relocation attempted",
    ))
}
fn scatter(
    volume: &File,
    serial: u64,
    total_clusters: u64,
    file: &File,
    id: &str,
    name: &str,
    first_lcn: u64,
    moves: &mut Vec<Value>,
) -> io::Result<()> {
    for vcn in 0..CLUSTERS {
        require(
            moves.len() < (2 * CLUSTERS) as usize,
            "fixture move budget exhausted",
        )?;
        verify_volume(volume, Some((serial, total_clusters)))?;
        same_identity(file, serial, id)?;
        require(
            file.metadata()?.len() == STREAM_BYTES,
            "fixture EOF changed before move",
        )?;
        let before = mapping(file)?;
        let destination = first_lcn + 4 * vcn;
        let free = bitmap(volume, destination, total_clusters)?;
        require(
            free.free(destination)?,
            "destination became allocated; refusing without retry",
        )?;
        let mut input = [0u8; 32];
        // MOVE_FILE_DATA for the supported 64-bit Windows guest. NTFS performs
        // all allocation and data relocation; this is not raw volume writing.
        require(
            std::mem::size_of::<usize>() == 8,
            "64-bit fixture helper required",
        )?;
        input[..8].copy_from_slice(&(file.as_raw_handle() as usize as u64).to_le_bytes());
        input[8..16].copy_from_slice(&vcn.to_le_bytes());
        input[16..24].copy_from_slice(&destination.to_le_bytes());
        input[24..28].copy_from_slice(&1u32.to_le_bytes());
        let query = stream_native::ioctl(volume, 0x0009_0074, &input, 0);
        let mut observation = json!({"stream":name,"vcn":vcn,"clusters":1,
            "prior_lcn":lcn_at(&before.runs,vcn)?,"destination_lcn":destination,
            "free_bitmap_sha256":free.sha256,"file_id_info":id,
            "before_mapping_sha256":hex::encode(Sha256::digest(&before.canonical)),
            "submitted":true,"native_error":query.native_error,"verified":false});
        // Even a failed move may have changed allocation. Observe it once;
        // never automatically retry, unwind, delete or manually edit metadata.
        let after = mapping(file);
        if let Ok(after) = &after {
            observation["after_mapping_sha256"] =
                json!(hex::encode(Sha256::digest(&after.canonical)));
            observation["actual_lcn"] = json!(lcn_at(&after.runs, vcn)?);
        }
        moves.push(observation);
        if let Some(error) = query.native_error {
            return Err(io::Error::from_raw_os_error(error));
        }
        let after = after?;
        for other in 0..CLUSTERS {
            let expected = if other == vcn {
                destination
            } else {
                lcn_at(&before.runs, other)?
            };
            require(
                lcn_at(&after.runs, other)? == expected,
                "NTFS move changed an unexpected fixture mapping",
            )?;
        }
        same_identity(file, serial, id)?;
        moves.last_mut().unwrap()["verified"] = json!(true);
    }
    file.sync_all()?;
    let final_map = mapping(file)?;
    require(
        final_map.runs.len() == CLUSTERS as usize,
        "fragmentation did not produce 512 distinct extents",
    )?;
    Ok(())
}

/// Observe the base FILE record through the documented read-only NTFS FSCTL.
/// Validate its USA and local attribute bounds, but do not interpret or write
/// extension records. Conversion's independent raw parser must do that later.
fn base_record(volume: &File, id: &str) -> io::Result<Value> {
    let id_bytes = hex::decode(id).map_err(|_| invalid("invalid NTFS identity"))?;
    let reference = u64_at(&id_bytes, 8)?;
    let ordinal = reference & 0x0000_ffff_ffff_ffff;
    let response = control(volume, 0x0009_0068, &ordinal.to_le_bytes(), 65536)?;
    let returned_reference = u64_at(&response, 0)?;
    let length = u32_at(&response, 8)? as usize;
    require(
        length == 1024
            && response.len() >= 12 + length
            && returned_reference & 0x0000_ffff_ffff_ffff == reference & 0x0000_ffff_ffff_ffff,
        "NTFS FILE record query returned another record or geometry",
    )?;
    let raw = &response[12..12 + length];
    require(&raw[..4] == b"FILE", "queried NTFS record is not FILE")?;
    let short = |bytes: &[u8], at: usize| -> io::Result<u16> {
        Ok(u16::from_le_bytes(
            bytes
                .get(at..at + 2)
                .ok_or_else(|| invalid("short FILE u16"))?
                .try_into()
                .unwrap(),
        ))
    };
    require(
        u64::from(short(raw, 16)?) == reference >> 48
            && short(raw, 22)? & 1 != 0
            && u64_at(raw, 32)? == 0,
        "queried FILE sequence/in-use/base identity differs",
    )?;
    let usa = short(raw, 4)? as usize;
    let usa_count = short(raw, 6)? as usize;
    require(
        usa_count == 3 && usa >= 8 && usa + usa_count * 2 <= length,
        "FILE update-sequence bounds differ",
    )?;
    let mut fixed = raw.to_vec();
    let encoded = (1..usa_count).all(|sector| {
        let at = sector * 512 - 2;
        raw[at..at + 2] == raw[usa..usa + 2]
    });
    let restored = (1..usa_count).all(|sector| {
        let at = sector * 512 - 2;
        raw[at..at + 2] == raw[usa + sector * 2..usa + sector * 2 + 2]
    });
    require(encoded || restored, "FILE update-sequence mismatch")?;
    for sector in 1..usa_count {
        let at = sector * 512 - 2;
        fixed[at..at + 2].copy_from_slice(&raw[usa + sector * 2..usa + sector * 2 + 2]);
    }
    let used = u32_at(&fixed, 24)? as usize;
    let mut at = short(&fixed, 20)? as usize;
    require(
        at >= 48 && at.is_multiple_of(8) && used <= length && at < used,
        "FILE attribute area differs",
    )?;
    let mut attrs = Vec::new();
    let mut found_list = false;
    loop {
        require(
            attrs.len() <= 64 && at + 4 <= used,
            "unterminated FILE attributes",
        )?;
        let kind = u32_at(&fixed, at)?;
        if kind == u32::MAX {
            break;
        }
        let size = u32_at(&fixed, at + 4)? as usize;
        require(
            size >= 24 && size.is_multiple_of(8) && at + size <= used,
            "invalid FILE attribute bounds",
        )?;
        let named = fixed[at + 9] as usize;
        let name_at = short(&fixed, at + 10)? as usize;
        require(
            named == 0 || (name_at >= 16 && name_at + 2 * named <= size),
            "invalid FILE attribute name",
        )?;
        let name: Vec<u16> = if named == 0 {
            vec![]
        } else {
            fixed[at + name_at..at + name_at + 2 * named]
                .chunks_exact(2)
                .map(|b| u16::from_le_bytes([b[0], b[1]]))
                .collect()
        };
        found_list |= kind == 0x20;
        attrs.push(json!({"type":kind,"length":size,"nonresident":fixed[at+8],
            "name_utf16":name,"instance":short(&fixed,at+14)?}));
        at += size;
    }
    Ok(
        json!({"file_reference":reference,"returned_file_reference":returned_reference,
        "record_length":length,"raw_sha256":hex::encode(Sha256::digest(raw)),
        "raw_hex":hex::encode(raw),"usa_verified":true,
        "usa_representation":if encoded {"sector_tails_encoded"} else {"already_restored_by_native_query"},
        "attributes":attrs,
        "attribute_list_present":found_list,"extension_records_decoded":false}),
    )
}

/// Creates only fresh probe-named files on the exact enrolled volume. Every
/// attempted move is retained in the returned report, including failure paths.
/// The caller must persist this report even when `success` is false.
pub fn create(probe_id: &str) -> Value {
    let mut report = json!({"schema_version":1,"kind":"ntfs-attribute-list-fixture",
        "probe_id":probe_id,"success":false,"automatic_retry":false,
        "formats_performed":0,"raw_volume_write_calls":0,"deletions_performed":0,
        "conversion_authorized":false,"planned_move_count":2*CLUSTERS,
        "cluster_bytes":CLUSTER,"default_stream_bytes":STREAM_BYTES,
        "named_stream_bytes":STREAM_BYTES});
    let mut created = Vec::new();
    let mut moves = Vec::new();
    let attempt = (|| -> io::Result<()> {
        require(
            probe_id.len() == 32
                && probe_id
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "lowercase 32-character probe ID required",
        )?;
        require(
            std::env::var("COMPUTERNAME").as_deref() == Ok("N2R-WIN11"),
            "owning enrolled Windows guest required",
        )?;
        let before = source()?;
        ordinary_directory(Path::new(r"H:\"))?;
        ordinary_directory(Path::new(r"H:\nested"))?;
        let base = PathBuf::from(format!(r"H:\attribute-list-{probe_id}.bin"));
        let segments = PathBuf::from(format!("{}:Segments:$DATA", base.display()));
        let note = PathBuf::from(format!("{}:Note:$DATA", base.display()));
        let aliases = [
            PathBuf::from(format!(r"H:\attribute-list-{probe_id}-alias.bin")),
            PathBuf::from(format!(r"H:\nested\attribute-list-{probe_id}-nested.bin")),
        ];
        for path in [&base, &segments, &note, &aliases[0], &aliases[1]] {
            require(
                !path.try_exists()?,
                "a fixture path already exists; no overwrite permitted",
            )?;
        }
        let mut privileges = Privileges::enable_for(&["SeManageVolumePrivilege"])?;
        let volume = OpenOptions::new()
            .read(true)
            .write(true)
            .share_mode(7)
            .open(before.volume_guid_path.trim_end_matches('\\'))?;
        let (serial, total_clusters) = verify_volume(&volume, None)?;
        report["source"] = serde_json::to_value(&before).map_err(io::Error::other)?;
        report["ntfs_serial"] = json!(serial);
        report["ntfs_total_clusters"] = json!(total_clusters);
        let (mut default, id) = new_stream(&base, serial, 17, STREAM_BYTES, &mut created)?;
        let (mut named, named_id) = new_stream(&segments, serial, 73, STREAM_BYTES, &mut created)?;
        let (mut note_file, note_id) = new_stream(&note, serial, 129, 64, &mut created)?;
        require(
            id == named_id && id == note_id,
            "new ADS identities differ from new base file",
        )?;
        let mut held_aliases = Vec::new();
        for path in &aliases {
            fs::hard_link(&base, path)?;
            created.push(json!({"path":path,"hard_link_created":true,"file_id_info":id}));
            let alias = OpenOptions::new()
                .read(true)
                .share_mode(3)
                .custom_flags(0x0020_0000)
                .open(path)?;
            same_identity(&alias, serial, &id)?;
            held_aliases.push(alias);
        }
        let default_before = hashes(&mut default, STREAM_BYTES)?;
        let named_before = hashes(&mut named, STREAM_BYTES)?;
        let note_before = hashes(&mut note_file, 64)?;
        let note_standard = standard(&note_file)?;
        require(
            note_standard["allocation_size"] == 0 && note_standard["end_of_file"] == 64,
            "small Note ADS is not resident",
        )?;
        report["initial_streams"] = json!([
            {"path":base,"name_utf16":[],"file_id_info":id,"hashes":default_before,"mapping":map_json(&mapping(&default)?)},
            {"path":segments,"name_utf16":"Segments".encode_utf16().collect::<Vec<_>>(),"file_id_info":id,"hashes":named_before,"mapping":map_json(&mapping(&named)?)},
            {"path":note,"name_utf16":"Note".encode_utf16().collect::<Vec<_>>(),"file_id_info":id,"hashes":note_before,"standard_info":note_standard}
        ]);
        let (window, window_report) = find_window(&volume, total_clusters)?;
        report["free_window"] = window_report;
        scatter(
            &volume,
            serial,
            total_clusters,
            &default,
            &id,
            "",
            window,
            &mut moves,
        )?;
        scatter(
            &volume,
            serial,
            total_clusters,
            &named,
            &id,
            "Segments",
            window + 2,
            &mut moves,
        )?;
        let default_after = hashes(&mut default, STREAM_BYTES)?;
        let named_after = hashes(&mut named, STREAM_BYTES)?;
        let note_after = hashes(&mut note_file, 64)?;
        require(
            default_before == default_after
                && named_before == named_after
                && note_before == note_after,
            "logical fixture bytes changed during NTFS relocation",
        )?;
        for file in [&default, &named, &note_file]
            .into_iter()
            .chain(held_aliases.iter())
        {
            same_identity(file, serial, &id)?;
            require(
                standard(file)?["number_of_links"] == 3,
                "fixture hard-link count differs",
            )?;
        }
        let note_standard_after = standard(&note_file)?;
        require(
            note_standard_after["allocation_size"] == 0 && note_standard_after["end_of_file"] == 64,
            "small Note ADS ceased to be resident",
        )?;
        let record = base_record(&volume, &id)?;
        report["base_file_record"] = record;
        report["final_streams"] = json!([
            {"path":base,"name_utf16":[],"file_id_info":id,"hashes":default_after,"mapping":map_json(&mapping(&default)?)},
            {"path":segments,"name_utf16":"Segments".encode_utf16().collect::<Vec<_>>(),"file_id_info":id,"hashes":named_after,"mapping":map_json(&mapping(&named)?)},
            {"path":note,"name_utf16":"Note".encode_utf16().collect::<Vec<_>>(),"file_id_info":id,"hashes":note_after,"standard_info":note_standard_after}
        ]);
        report["hard_links"] = json!(
            aliases
                .iter()
                .map(|p| json!({"path":p,"file_id_info":id}))
                .collect::<Vec<_>>()
        );
        verify_volume(&volume, Some((serial, total_clusters)))?;
        let after = source()?;
        require(
            before.binding == after.binding && before.volume_guid_path == after.volume_guid_path,
            "source binding changed around fixture creation",
        )?;
        report["source_after"] = serde_json::to_value(after).map_err(io::Error::other)?;
        require(
            report["base_file_record"]["attribute_list_present"] == true,
            "512 extents observed but no base ATTRIBUTE_LIST; retain fixture for inspection",
        )?;
        privileges.restore()?;
        report["privileges_restored"] = json!(true);
        report["payload_bytes_initialized"] = json!(2 * STREAM_BYTES + 64);
        report["logical_bytes_hashed"] = json!(4 * STREAM_BYTES + 128);
        report["verified_move_count"] = json!(moves.len());
        report["success"] = json!(true);
        Ok(())
    })();
    if let Err(error) = attempt {
        report["error"] = json!(error.to_string());
        report["native_error"] = json!(error.raw_os_error());
    }
    report["created_paths"] = json!(created);
    report["moves"] = json!(moves);
    report
}
