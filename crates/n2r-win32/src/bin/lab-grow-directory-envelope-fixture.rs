//! Create-new directory-only growth of the pinned disposable F: fixture.
//! This laboratory binary grants no converter admission or recovery authority.
#[cfg(not(windows))]
fn main() {
    eprintln!("this fixture helper requires Windows");
    std::process::exit(1);
}

#[cfg(windows)]
fn main() {
    if let Err(error) = windows::run() {
        eprintln!("directory-envelope fixture: {error}");
        std::process::exit(1);
    }
}

#[cfg(windows)]
mod windows {
    use n2r_win32::{attestation::IoctlQuery, discovery, layout, retrieval_paging, stream_layout};
    use serde::{Deserialize, Serialize};
    use serde_json::{Value, json};
    use sha2::{Digest, Sha256};
    use std::{
        collections::{BTreeMap, BTreeSet},
        fs::{self, File, OpenOptions},
        io::{self, Read, Write},
        os::windows::{fs::OpenOptionsExt, io::AsRawHandle},
        path::{Path, PathBuf},
        ptr,
    };
    use windows_sys::Win32::{
        Storage::FileSystem::{
            FILE_INFO_BY_HANDLE_CLASS, FileAttributeTagInfo, FileBasicInfo, FileIdInfo,
            FileStandardInfo, FileStreamInfo, GetFileInformationByHandleEx,
        },
        System::IO::DeviceIoControl,
    };

    const ROOT: &str = r"F:\";
    const PARENT: &str = "6fe2d6b6-a2fb-447e-802b-7b3ff0d9f16e";
    const MANIFEST_SHA: &str = "7810754f1853490d399f87bf1b24f509a8c32716cee84d38babc7c385a487f66";
    const CLUSTER: u64 = 65536;
    const PARTITION_BYTES: u64 = 52 << 30;
    const ANCHOR: &str = "N2RV3";
    const MAX_RECEIPT: usize = 16 << 20;

    fn invalid(message: impl Into<String>) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidData, message.into())
    }
    fn need(condition: bool, message: &str) -> io::Result<()> {
        if condition {
            Ok(())
        } else {
            Err(invalid(message))
        }
    }
    fn sha(bytes: &[u8]) -> String {
        hex::encode(Sha256::digest(bytes))
    }
    fn u32_at(bytes: &[u8], offset: usize) -> io::Result<u32> {
        layout::u32_at(bytes, offset)
    }
    fn u64_at(bytes: &[u8], offset: usize) -> io::Result<u64> {
        layout::u64_at(bytes, offset)
    }
    fn component(text: &str) -> bool {
        !text.is_empty()
            && !matches!(text, "." | "..")
            && !text.ends_with([' ', '.'])
            && !text
                .chars()
                .any(|c| c.is_control() || "\\/:*?\"<>|".contains(c))
    }
    fn ordinary_path(path: &Path, drive: &str) -> io::Result<Vec<String>> {
        let text = path.to_str().ok_or_else(|| invalid("non-Unicode path"))?;
        let tail = text
            .strip_prefix(drive)
            .ok_or_else(|| invalid("wrong path drive"))?;
        need(
            text.len() < 2048 && !tail.is_empty(),
            "bounded non-root path required",
        )?;
        let parts: Vec<_> = tail.split('\\').map(String::from).collect();
        need(
            parts.iter().all(|s| component(s)),
            "ordinary path components required",
        )?;
        Ok(parts)
    }
    fn open_metadata(path: &Path, directory: bool, exclude_writes: bool) -> io::Result<File> {
        let file = OpenOptions::new()
            .access_mode(0x80) // FILE_READ_ATTRIBUTES; never FILE_READ_DATA.
            .share_mode(if exclude_writes { 1 } else { 3 })
            .custom_flags(0x0220_0000) // BACKUP_SEMANTICS | OPEN_REPARSE_POINT.
            .open(path)?;
        let observed = metadata(&file)?;
        need(
            observed.directory == directory,
            "native object type differs",
        )?;
        Ok(file)
    }

    // Keep ancestors open without delete sharing, including all staged C: paths.
    fn guard_ancestors(path: &Path, drive: &str) -> io::Result<Vec<File>> {
        let parts = ordinary_path(path, drive)?;
        let mut guards = vec![open_metadata(Path::new(drive), true, false)?];
        let mut current = PathBuf::from(drive);
        for part in &parts[..parts.len() - 1] {
            current.push(part);
            guards.push(open_metadata(&current, true, false)?);
        }
        Ok(guards)
    }

    #[repr(C, align(8))]
    struct InfoBuffer([u8; 65536]);
    fn info(file: &File, class: FILE_INFO_BY_HANDLE_CLASS, bytes: usize) -> io::Result<Vec<u8>> {
        need(bytes <= 65536, "native metadata bound exceeded")?;
        let mut buffer = InfoBuffer([0; 65536]);
        // SAFETY: synchronous metadata-only query into an aligned initialized
        // allocation of the advertised size; the borrowed handle remains live.
        if unsafe {
            GetFileInformationByHandleEx(
                file.as_raw_handle(),
                class,
                buffer.0.as_mut_ptr().cast(),
                bytes as u32,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(buffer.0[..bytes].to_vec())
    }

    #[derive(Clone, Debug, Serialize, PartialEq, Eq)]
    struct Metadata {
        native_file_id: String,
        creation_time: u64,
        last_access_time: u64,
        last_write_time: u64,
        change_time: u64,
        file_attributes: u32,
        allocation_bytes: u64,
        logical_length: u64,
        hard_links: u32,
        directory: bool,
    }
    fn metadata(file: &File) -> io::Result<Metadata> {
        let basic = info(file, FileBasicInfo, 40)?;
        let standard = info(file, FileStandardInfo, 24)?;
        let tag = info(file, FileAttributeTagInfo, 8)?;
        let id = info(file, FileIdInfo, 24)?;
        let attributes = u32_at(&basic, 32)?;
        need(
            u32_at(&tag, 0)? == attributes
                && u32_at(&tag, 4)? == 0
                && attributes & (0x40 | 0x200 | 0x400 | 0x800 | 0x1000 | 0x4000) == 0
                && standard[20] == 0
                && standard[21] <= 1
                && (attributes & 0x10 != 0) == (standard[21] == 1)
                && id.iter().any(|b| *b != 0),
            "ordinary initialized non-reparse metadata required",
        )?;
        Ok(Metadata {
            native_file_id: hex::encode(id),
            creation_time: u64_at(&basic, 0)?,
            last_access_time: u64_at(&basic, 8)?,
            last_write_time: u64_at(&basic, 16)?,
            change_time: u64_at(&basic, 24)?,
            file_attributes: attributes,
            allocation_bytes: u64_at(&standard, 0)?,
            logical_length: u64_at(&standard, 8)?,
            hard_links: u32_at(&standard, 16)?,
            directory: standard[21] == 1,
        })
    }
    fn on_volume(meta: &Metadata, serial: u64) -> io::Result<()> {
        let id = hex::decode(&meta.native_file_id).map_err(|_| invalid("invalid file ID"))?;
        need(
            id.len() == 24
                && serial != 0
                && u64_at(&id, 0)? == serial
                && u64_at(&id, 8)? != 0
                && id[16..] == [0; 8],
            "NTFS file ID belongs to another volume",
        )
    }
    fn ioctl(file: &File, code: u32, input: &[u8], capacity: usize) -> io::Result<IoctlQuery> {
        need(
            capacity <= 65536 && input.len() <= 8,
            "IOCTL bound exceeded",
        )?;
        let mut buffer = vec![0u64; capacity.div_ceil(8)];
        let mut returned = 0u32;
        // SAFETY: synchronous query-only control; bounded initialized buffers
        // remain live, and no disk/volume setter or payload write is dispatched.
        let ok = unsafe {
            DeviceIoControl(
                file.as_raw_handle(),
                code,
                if input.is_empty() {
                    ptr::null()
                } else {
                    input.as_ptr().cast()
                },
                input.len() as u32,
                buffer.as_mut_ptr().cast(),
                capacity as u32,
                &mut returned,
                ptr::null_mut(),
            )
        };
        let error = (ok == 0).then(|| io::Error::last_os_error().raw_os_error().unwrap_or(-1));
        need(
            returned as usize <= capacity,
            "native query exceeded buffer",
        )?;
        // SAFETY: returned is checked against the initialized allocation above.
        let bytes =
            unsafe { std::slice::from_raw_parts(buffer.as_ptr().cast::<u8>(), returned as usize) }
                .to_vec();
        Ok(IoctlQuery {
            code,
            input: input.to_vec(),
            bytes,
            native_error: error,
        })
    }
    fn control(file: &File, code: u32, capacity: usize) -> io::Result<Vec<u8>> {
        let q = ioctl(file, code, &[], capacity)?;
        if let Some(error) = q.native_error {
            return Err(io::Error::from_raw_os_error(error));
        }
        Ok(q.bytes)
    }
    fn source() -> io::Result<discovery::VolumeDiscovery> {
        let s = discovery::discover(ROOT, discovery::Role::Source)?;
        let p = &s.binding.identity;
        need(
            s.binding.disk_number == 1
                && p.partition_number == 2
                && layout::guid_bytes(&p.disk_guid)?
                    == layout::guid_bytes("1b191872-c372-41ee-a416-e18863996f54")?
                && layout::guid_bytes(&p.partition_guid)?
                    == layout::guid_bytes("f06075a8-67a2-46b9-8fac-4af4da809617")?
                && p.disk_bytes == 64 << 30
                && p.partition_offset == 16 << 20
                && p.partition_bytes == PARTITION_BYTES
                && p.logical_sector_bytes == 512
                && p.physical_sector_bytes == 4096
                && !s.disk_is_windows_disk
                && s.windows_disk_number == 0
                && s.read_only
                && s.source_write_requests == 0
                && s.observed_twice_unchanged
                && u64_at(&s.evidence.disk_attributes, 8)? == 0
                && s.filesystem == "NTFS"
                && s.label == "n2r-stream-source"
                && s.bytes_per_sector == 512
                && s.sectors_per_cluster == 128,
            "exact online writable disposable disk-1 NTFS F: fixture required",
        )?;
        // Discovery excludes the current OS disk and validates GPT BASIC_DATA.
        // Also refuse any EFI-system partition on the enrolled physical disk.
        let gpt = &s.evidence.gpt_layout;
        for entry in gpt[48..].chunks_exact(144) {
            need(
                entry[32..48] != layout::guid_bytes("c12a7328-f81f-11d2-ba4b-00a0c93ec93b")?,
                "EFI/system partition on source disk",
            )?;
        }
        Ok(s)
    }
    fn volume(
        file: &File,
        binding: &n2r_win32::general_layout::GeneralDiskBinding,
    ) -> io::Result<Value> {
        let extents = control(file, 0x0056_0000, 32)?;
        binding.validate_volume_extent(&extents)?;
        let ntfs = control(file, 0x0009_0064, 128)?;
        need(
            ntfs.len() >= 96
                && u32_at(&ntfs, 40)? == 512
                && u32_at(&ntfs, 44)? == CLUSTER as u32
                && u32_at(&ntfs, 48)? == 1024
                && u64_at(&ntfs, 16)? > 0
                && u64_at(&ntfs, 16)? <= PARTITION_BYTES / CLUSTER,
            "held NTFS volume geometry differs",
        )?;
        Ok(
            json!({"ntfs_volume_data":hex::encode(&ntfs), "serial":u64_at(&ntfs,0)?,
            "total_clusters":u64_at(&ntfs,16)?, "volume_extents":hex::encode(extents)}),
        )
    }

    #[derive(Clone, Debug, Serialize, PartialEq, Eq)]
    struct Stream {
        name_utf16: Vec<u16>,
        logical_length: u64,
        allocation_bytes: u64,
    }
    fn streams(file: &File) -> io::Result<Vec<Stream>> {
        let buffer = info(file, FileStreamInfo, 65536)?;
        let mut at = 0usize;
        let mut result = BTreeMap::new();
        loop {
            need(
                at <= buffer.len() - 24,
                "stream metadata offset exceeds bound",
            )?;
            let next = u32_at(&buffer, at)? as usize;
            let name_bytes = u32_at(&buffer, at + 4)? as usize;
            let end = at
                .checked_add(24 + name_bytes)
                .ok_or_else(|| invalid("stream name overflow"))?;
            need(
                name_bytes >= 14
                    && name_bytes.is_multiple_of(2)
                    && end <= buffer.len()
                    && (next == 0
                        || (next.is_multiple_of(8)
                            && next >= 24 + name_bytes
                            && at + next <= buffer.len() - 24)),
                "invalid complete native stream list",
            )?;
            let native_name: Vec<u16> = buffer[at + 24..end]
                .chunks_exact(2)
                .map(|b| u16::from_le_bytes(b.try_into().unwrap()))
                .collect();
            let text = String::from_utf16(&native_name)
                .map_err(|_| invalid("invalid native stream UTF16"))?;
            let name = text
                .strip_prefix(':')
                .and_then(|s| s.strip_suffix(":$DATA"))
                .ok_or_else(|| invalid("unexpected native stream type"))?;
            need(
                name.is_empty() || component(name),
                "ordinary named data stream required",
            )?;
            let stream = Stream {
                name_utf16: name.encode_utf16().collect(),
                logical_length: u64_at(&buffer, at + 8)?,
                allocation_bytes: u64_at(&buffer, at + 16)?,
            };
            need(
                result.insert(stream.name_utf16.clone(), stream).is_none(),
                "duplicate native stream identity",
            )?;
            if next == 0 {
                break;
            }
            at += next;
        }
        need(
            result.contains_key(&Vec::new()) && result.len() <= 16,
            "default stream or bounded stream inventory missing",
        )?;
        Ok(result.into_values().collect())
    }
    fn retrieval(file: &File, stream: &Stream) -> io::Result<Value> {
        let mut assembler = retrieval_paging::Assembler::default();
        for _ in 0..retrieval_paging::MAX_PAGES {
            let query = ioctl(
                file,
                stream_layout::GET_RETRIEVAL,
                &assembler.next_vcn().to_le_bytes(),
                assembler.response_capacity(),
            )?;
            if assembler.next_vcn() == 0 && query.native_error == Some(38) && query.bytes.is_empty()
            {
                need(
                    stream.allocation_bytes < CLUSTER && stream.logical_length < CLUSTER,
                    "unmapped nonresident stream",
                )?;
                return Ok(
                    json!({"scope":"resident-or-empty-no-cluster-map", "native_error":38, "runs":[], "canonical_hex":""}),
                );
            }
            if assembler.push(&query)? {
                let capture = assembler.finish()?;
                let mut runs = vec![];
                for run in &capture.runs {
                    let lcn = run.lcn.ok_or_else(|| invalid("sparse original stream"))?;
                    need(
                        lcn.checked_add(run.clusters)
                            .is_some_and(|end| end <= PARTITION_BYTES / CLUSTER),
                        "original mapping exceeds source partition",
                    )?;
                    runs.push(json!({"vcn":run.vcn,"lcn":lcn,"clusters":run.clusters}));
                }
                need(
                    capture
                        .proof
                        .virtual_clusters
                        .checked_mul(CLUSTER)
                        .is_some_and(|n| {
                            n >= stream.logical_length && n == stream.allocation_bytes
                        }),
                    "complete stream map coverage differs from EOF/allocation",
                )?;
                return Ok(
                    json!({"scope":"complete-zero-vcn-map", "canonical_hex":hex::encode(capture.canonical), "runs":runs, "paging":capture.proof}),
                );
            }
        }
        Err(invalid("complete original mapping exceeded page budget"))
    }

    #[derive(Deserialize)]
    struct Manifest {
        files: usize,
        filesystem: String,
        label: String,
        cluster: u64,
        manifest: Vec<ManifestFile>,
    }
    #[derive(Deserialize)]
    struct ManifestFile {
        path: String,
        length: u64,
        sha256: String,
    }
    struct Original {
        path: PathBuf,
        parts: Vec<String>,
        expected: ManifestFile,
        file: File,
        stream_files: Vec<(Stream, File)>,
        before: Value,
    }
    fn observe(original: &Original, serial: u64) -> io::Result<Value> {
        let meta = metadata(&original.file)?;
        on_volume(&meta, serial)?;
        need(
            !meta.directory
                && meta.logical_length == original.expected.length
                && meta.hard_links == 1,
            "original file identity/EOF/type differs",
        )?;
        let actual_streams = streams(&original.file)?;
        need(
            actual_streams
                == original
                    .stream_files
                    .iter()
                    .map(|(s, _)| s.clone())
                    .collect::<Vec<_>>(),
            "original native stream inventory changed",
        )?;
        let mut observations = vec![];
        for (stream, file) in &original.stream_files {
            let stream_meta = metadata(file)?;
            on_volume(&stream_meta, serial)?;
            need(
                stream_meta.native_file_id == meta.native_file_id
                    && stream_meta.logical_length == stream.logical_length
                    && stream_meta.allocation_bytes == stream.allocation_bytes,
                "same-handle native stream identity/length differs",
            )?;
            observations.push(
                json!({"stream":stream,"metadata":stream_meta,"retrieval":retrieval(file,stream)?}),
            );
        }
        Ok(
            json!({"path":original.parts,"metadata":meta,"streams":observations,
            "historical_expected_default_sha256":original.expected.sha256,"fresh_payload_hash_observed":false}),
        )
    }
    fn same_observation(before: &Value, after: &Value) -> bool {
        // Paging segmentation is incidental; compare the complete canonical map.
        let mut a = before.clone();
        let mut b = after.clone();
        for object in [&mut a, &mut b] {
            for stream in object["streams"].as_array_mut().unwrap() {
                stream["retrieval"]
                    .as_object_mut()
                    .unwrap()
                    .remove("paging");
            }
        }
        a == b
    }

    struct Args {
        fixture_id: String,
        manifest: PathBuf,
        output: PathBuf,
    }
    fn args() -> io::Result<Args> {
        let mut values = BTreeMap::new();
        let mut ack = false;
        let mut args = std::env::args().skip(1);
        while let Some(arg) = args.next() {
            if arg == "--acknowledge-disposable-data-volume" {
                need(!ack, "duplicate acknowledgement")?;
                ack = true;
            } else {
                need(
                    matches!(
                        arg.as_str(),
                        "--fixture-id"
                            | "--original-manifest"
                            | "--original-manifest-sha256"
                            | "--output"
                    ),
                    "unknown fixture argument",
                )?;
                let value = args
                    .next()
                    .ok_or_else(|| invalid("missing fixture argument value"))?;
                need(
                    values.insert(arg, value).is_none(),
                    "duplicate fixture argument",
                )?;
            }
        }
        let mut take = |key| {
            values
                .remove(key)
                .ok_or_else(|| invalid(format!("missing {key}")))
        };
        let fixture_id = take("--fixture-id")?;
        let manifest = PathBuf::from(take("--original-manifest")?);
        let expected_sha = take("--original-manifest-sha256")?;
        let output = PathBuf::from(take("--output")?);
        need(
            ack && fixture_id.len() == 32
                && fixture_id
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                && expected_sha == MANIFEST_SHA
                && std::env::var("COMPUTERNAME").is_ok_and(|v| v.eq_ignore_ascii_case("N2R-WIN11")),
            "explicit enrolled fixture acknowledgement, ID, manifest pin and VM required",
        )?;
        ordinary_path(&manifest, r"C:\")?;
        ordinary_path(&output, r"C:\")?;
        need(
            manifest != output && output.extension().is_some_and(|v| v == "json"),
            "distinct fresh C: JSON output required",
        )?;
        Ok(Args {
            fixture_id,
            manifest,
            output,
        })
    }
    pub fn run() -> io::Result<()> {
        let args = args()?;
        let _manifest_ancestors = guard_ancestors(&args.manifest, r"C:\")?;
        let _output_ancestors = guard_ancestors(&args.output, r"C:\")?;
        let mut manifest_file = OpenOptions::new()
            .read(true)
            .share_mode(1)
            .custom_flags(0x0020_0000)
            .open(&args.manifest)?;
        need(
            !metadata(&manifest_file)?.directory && manifest_file.metadata()?.len() <= 4 << 20,
            "ordinary bounded pinned manifest required",
        )?;
        let mut manifest_bytes = Vec::new();
        manifest_file.read_to_end(&mut manifest_bytes)?;
        need(
            sha(&manifest_bytes) == MANIFEST_SHA,
            "original fixture manifest SHA differs",
        )?;
        let manifest: Manifest = serde_json::from_slice(&manifest_bytes)?;
        need(
            manifest.files == 808
                && manifest.manifest.len() == 808
                && manifest.cluster == CLUSTER
                && manifest.filesystem == "NTFS"
                && manifest.label == "n2r-stream-source",
            "original mixed fixture manifest identity differs",
        )?;
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .share_mode(1)
            .custom_flags(0x0020_0000)
            .open(&args.output)?;
        let anchor = ANCHOR.to_owned();
        let mut created_paths = vec![vec![anchor.clone()]];
        for index in 0..150 {
            created_paths.push(vec![anchor.clone(), format!("D{index:03}")]);
        }
        let created_paths_utf16: Vec<Vec<Vec<u16>>> = created_paths
            .iter()
            .map(|parts| {
                parts
                    .iter()
                    .map(|part| part.encode_utf16().collect())
                    .collect()
            })
            .collect();
        let mut report = json!({"schema_version":1,"kind":"ntfs-directory-object-envelope-fixture","success":false,
            "fixture_id":args.fixture_id,"source_parent_checkpoint":PARENT,
            "source_parent_checkpoint_scope":"controller-supplied historical provenance; guest does not attest Hyper-V state",
            "original_fixture_manifest_sha256":MANIFEST_SHA,"anchor":anchor,"created_paths":created_paths,
            "created_paths_utf16":created_paths_utf16,
            "created_directories":0,"created_payload_files":0,"originals_verified":0,
            "original_payload_writes":0,"original_payload_bytes_read":0,"extent_moves":0,
            "fresh_content_equality_verified":false,"root_time_scope":"native FileBasicInfo observations; persisted SI belongs to the subsequent frozen raw baseline",
            "original_content_scope":"historical manifest expectations only; fresh full baseline and independent observer verify payload separately"});
        let result = grow(&manifest, &created_paths, &mut report);
        if let Err(error) = &result {
            report["error"] = json!(error.to_string());
        }
        let bytes = serde_json::to_vec_pretty(&report)?;
        need(bytes.len() <= MAX_RECEIPT, "fixture receipt exceeded bound")?;
        output.write_all(&bytes)?;
        output.write_all(b"\n")?;
        output.sync_all()?;
        result
    }
    fn grow(manifest: &Manifest, paths: &[Vec<String>], report: &mut Value) -> io::Result<()> {
        let before_source = source()?;
        let volume_file = OpenOptions::new()
            .read(true)
            .write(true)
            .share_mode(3)
            .open(before_source.volume_guid_path.trim_end_matches('\\'))?;
        let volume_before = volume(&volume_file, &before_source.binding)?;
        let serial = volume_before["serial"]
            .as_u64()
            .ok_or_else(|| invalid("missing volume serial"))?;
        let root = open_metadata(Path::new(ROOT), true, false)?;
        let root_before = metadata(&root)?;
        on_volume(&root_before, serial)?;
        report["source"] = serde_json::to_value(&before_source)?;
        report["before"] = json!({"root":root_before,"volume":volume_before});
        for entry in fs::read_dir(ROOT)? {
            let entry = entry?;
            need(
                !entry
                    .file_name()
                    .to_string_lossy()
                    .eq_ignore_ascii_case(ANCHOR),
                "fixture namespace already exists; no retry/overwrite allowed",
            )?;
        }
        let mut ancestors: BTreeMap<PathBuf, File> = BTreeMap::new();
        let mut originals = Vec::with_capacity(808);
        let mut identities = BTreeSet::new();
        let mut names = BTreeSet::new();
        let mut original_streams = 0usize;
        let mut total_bytes = 0u64;
        for expected in &manifest.manifest {
            let path = PathBuf::from(&expected.path);
            let parts = ordinary_path(&path, ROOT)?;
            need(
                names.insert(expected.path.to_ascii_uppercase())
                    && expected.sha256.len() == 64
                    && expected.sha256.bytes().all(|b| b.is_ascii_hexdigit()),
                "duplicate original path or invalid historical digest",
            )?;
            let mut parent = PathBuf::from(ROOT);
            for part in &parts[..parts.len() - 1] {
                parent.push(part);
                if !ancestors.contains_key(&parent) {
                    let directory = open_metadata(&parent, true, false)?;
                    on_volume(&metadata(&directory)?, serial)?;
                    ancestors.insert(parent.clone(), directory);
                }
            }
            let file = open_metadata(&path, false, true)?;
            let base_meta = metadata(&file)?;
            on_volume(&base_meta, serial)?;
            need(
                identities.insert(base_meta.native_file_id.clone()),
                "duplicate original file identity",
            )?;
            let mut stream_files = vec![];
            for stream in streams(&file)? {
                let stream_file = if stream.name_utf16.is_empty() {
                    file.try_clone()?
                } else {
                    let name = String::from_utf16(&stream.name_utf16)
                        .map_err(|_| invalid("invalid stream name"))?;
                    open_metadata(
                        Path::new(&format!("{}:{name}:$DATA", expected.path)),
                        false,
                        true,
                    )?
                };
                stream_files.push((stream, stream_file));
            }
            original_streams += stream_files.len();
            total_bytes = total_bytes
                .checked_add(expected.length)
                .ok_or_else(|| invalid("original size overflow"))?;
            let mut original = Original {
                path,
                parts,
                expected: ManifestFile {
                    path: expected.path.clone(),
                    length: expected.length,
                    sha256: expected.sha256.clone(),
                },
                file,
                stream_files,
                before: Value::Null,
            };
            original.before = observe(&original, serial)?;
            originals.push(original);
        }
        need(
            original_streams == 808 && total_bytes == 9_885_781_381,
            "original complete stream count/bytes differs",
        )?;
        let before: Vec<_> = originals.iter().map(|o| o.before.clone()).collect();
        report["before"]["original_files"] = serde_json::to_value(&before)?;
        report["before"]["original_metadata_sha256"] = json!(sha(&serde_json::to_vec(&before)?));
        let mut created = Vec::with_capacity(151);
        let mut directories = Vec::with_capacity(151);
        for parts in paths {
            let mut path = PathBuf::from(ROOT);
            for part in parts {
                path.push(part);
            }
            fs::create_dir(&path)?; // Create-new only. Never remove partial output.
            report["created_directories"] = json!(created.len() + 1);
            let file = open_metadata(&path, true, false)?;
            on_volume(&metadata(&file)?, serial)?;
            created.push(path);
            directories.push(file);
        }
        // Owning-volume FlushFileBuffers persists directory metadata through NTFS;
        // no original file/stream data or raw volume WriteFile is requested.
        volume_file.sync_all()?;
        report["owning_volume_flush_completed"] = json!(true);
        let anchor_entries: Vec<_> = fs::read_dir(&created[0])?.collect::<io::Result<Vec<_>>>()?;
        need(
            anchor_entries.len() == 150,
            "new anchor child count differs",
        )?;
        let expected_names: BTreeSet<_> = paths[1..].iter().map(|p| p[1].clone()).collect();
        let actual_names: BTreeSet<_> = anchor_entries
            .iter()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        need(
            actual_names == expected_names,
            "new anchor namespace differs",
        )?;
        let mut actual_created = vec![];
        for (index, (path, file)) in created.iter().zip(&directories).enumerate() {
            if index > 0 {
                need(
                    fs::read_dir(path)?.next().is_none(),
                    "new child directory is not empty",
                )?;
            }
            let meta = metadata(file)?;
            on_volume(&meta, serial)?;
            let path_utf16: Vec<Vec<u16>> = paths[index]
                .iter()
                .map(|part| part.encode_utf16().collect())
                .collect();
            actual_created
                .push(json!({"path":paths[index],"path_utf16":path_utf16,"metadata":meta}));
        }
        let mut after = vec![];
        for original in &originals {
            let observation = observe(original, serial)?;
            need(
                same_observation(&original.before, &observation),
                &format!("original metadata/map changed: {}", original.path.display()),
            )?;
            after.push(observation);
        }
        let after_source = source()?;
        need(
            before_source.binding == after_source.binding
                && before_source.evidence == after_source.evidence,
            "source routing/storage attributes changed",
        )?;
        let volume_after = volume(&volume_file, &before_source.binding)?;
        need(
            volume_before["serial"] == volume_after["serial"]
                && volume_before["total_clusters"] == volume_after["total_clusters"],
            "source NTFS identity/cluster count changed",
        )?;
        let root_after = metadata(&root)?;
        need(
            root_before.native_file_id == root_after.native_file_id
                && root_before.creation_time == root_after.creation_time
                && root_before.file_attributes == root_after.file_attributes
                && root_after.directory,
            "source root identity/type changed",
        )?;
        report["after"] = json!({"root":root_after,"volume":volume_after,"source":after_source,"original_files":after,
            "original_metadata_sha256":sha(&serde_json::to_vec(&after)?),"created":actual_created});
        report["originals_verified"] = json!(808);
        report["original_streams_verified"] = json!(808);
        report["original_logical_bytes_metadata_verified"] = json!(total_bytes);
        report["full_retrieval_maps_unchanged"] = json!(true);
        report["all_original_file_identities_unchanged"] = json!(true);
        report["held_original_handles"] = json!({"access":"FILE_READ_ATTRIBUTES","share_read":true,"share_write":false,"share_delete":false});
        report["created_directories"] = json!(151);
        report["success"] = json!(true);
        Ok(())
    }
}
