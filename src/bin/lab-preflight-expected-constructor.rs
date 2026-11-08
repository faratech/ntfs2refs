//! Constructor input preflight from CLOSED authenticated expected pages.
//! Opens ordinary metadata files only; no source volume/device or setters.
#![recursion_limit = "256"]
#[cfg(windows)]
mod windows {
    use anyhow::{Context, Result, ensure};
    use clap::Parser;
    use n2r_win32::{
        metadata_pages::Reader, reference_file::ReferenceFileSnapshot,
        tree_resources::SourceResourceAdmission,
    };
    use ntfs2refs::{
        refs_security_descriptor,
        shadow_tree::{ExpectedTreePageHeader, Object},
    };
    use serde::{Deserialize, Serialize};
    use sha2::{Digest, Sha256};
    use std::{
        cell::{Cell, RefCell},
        collections::BTreeMap,
        fs::{self, File, OpenOptions},
        io::{Read, Seek, SeekFrom, Write},
        os::windows::fs::{MetadataExt, OpenOptionsExt},
        path::{Component, Path, PathBuf},
        sync::{
            Arc,
            atomic::{AtomicU64, Ordering},
        },
        time::SystemTime,
    };
    const PURPOSE: [u8; 8] = *b"N2REXP01";
    const MAX_SD: u64 = 65_536;
    const METADATA_CAP: u64 = 1 << 20;

    #[derive(Parser)]
    #[command(
        about = "Run actual pure constructor checks on closed expected.pages; metadata files only"
    )]
    struct Args {
        #[arg(long)]
        expected_pages: PathBuf,
        #[arg(long)]
        expected_sha256: String,
        #[arg(long)]
        source_assessment: PathBuf,
        #[arg(long)]
        source_assessment_sha256: String,
        /// Independent working/control filesystem GUID, never source0's volume.
        #[arg(long)]
        metadata_volume_guid: String,
        #[arg(long, default_value_t = 536_870_912)]
        max_file_bytes: u64,
        #[arg(long, default_value_t = 134_217_728)]
        max_row_bytes: u64,
        #[arg(long, default_value_t = 16_384)]
        max_unique_descriptors: usize,
        #[arg(long, default_value_t = 1_048_576)]
        max_output_bytes: usize,
        #[arg(long)]
        ram_bytes: u64,
        #[arg(long)]
        output: PathBuf,
    }
    #[derive(Deserialize)]
    struct Assessment {
        binding: n2r_win32::general_layout::GeneralDiskBinding,
        resource_admission: SourceResourceAdmission,
    }
    struct Held {
        file: File,
        snapshot: ReferenceFileSnapshot,
        modified: SystemTime,
        sha256: [u8; 32],
    }
    fn digest(value: &str) -> Result<[u8; 32]> {
        ensure!(
            value.len() == 64
                && value
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "canonical lowercase SHA-256 required"
        );
        hex::decode(value)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("SHA width differs"))
    }
    fn ordinary_path(path: &Path) -> Result<()> {
        ensure!(
            path.is_absolute()
                && !path
                    .components()
                    .any(|c| matches!(c, Component::CurDir | Component::ParentDir)),
            "absolute ordinary metadata path required"
        );
        for parent in path.parent().context("metadata parent absent")?.ancestors() {
            if parent.as_os_str().is_empty() {
                continue;
            }
            let m = fs::symlink_metadata(parent)?;
            ensure!(
                m.is_dir() && m.file_attributes() & 0x400 == 0,
                "metadata ancestry is not ordinary"
            );
        }
        Ok(())
    }
    fn on_volume(path: &str, guid: &str) -> Result<bool> {
        n2r_win32::layout::guid_bytes(guid)?;
        let prefix = format!("\\\\?\\Volume{{{}}}\\", guid.trim_matches(['{', '}']));
        Ok(path
            .get(..prefix.len())
            .is_some_and(|p| p.eq_ignore_ascii_case(&prefix)))
    }
    impl Held {
        fn open(path: &Path, hash: &str, maximum: u64, volume: &str) -> Result<Self> {
            ordinary_path(path)?;
            let mut file = OpenOptions::new()
                .read(true)
                .share_mode(1)
                .custom_flags(0x0020_0000)
                .open(path)?;
            n2r_win32::file_storage::require_readonly_access(&file)?;
            let snapshot = n2r_win32::reference_file::observe_reference_file_handle_with_limit(
                &file, maximum,
            )?;
            ensure!(
                snapshot.number_of_links == 1
                    && snapshot.file_bytes > 0
                    && on_volume(&snapshot.final_path, volume)?,
                "metadata must be on the explicit independent working filesystem"
            );
            let modified = file.metadata()?.modified()?;
            let sha256 = digest(hash)?;
            ensure!(
                n2r_win32::sha256_native::hash_range(&mut file, 0, snapshot.file_bytes)? == sha256,
                "closed metadata does not match its independent full SHA-256"
            );
            let held = Self {
                file,
                snapshot,
                modified,
                sha256,
            };
            held.revalidate(maximum)?;
            Ok(held)
        }
        fn revalidate(&self, maximum: u64) -> Result<()> {
            ensure!(
                n2r_win32::reference_file::observe_reference_file_handle_with_limit(
                    &self.file, maximum
                )? == self.snapshot
                    && self.file.metadata()?.modified()? == self.modified,
                "held metadata identity changed"
            );
            let mut file = self.file.try_clone()?;
            ensure!(
                n2r_win32::sha256_native::hash_range(&mut file, 0, self.snapshot.file_bytes)?
                    == self.sha256,
                "held metadata bytes changed"
            );
            Ok(())
        }
    }
    fn decode_chunk(payload: &[u8], maximum: usize) -> Result<Vec<u8>> {
        // Same canonical chunk format as shadow_tree/pages.rs; this diagnostic
        // cannot call its private decoder or infer semantic/write authority.
        let text: &str = serde_json::from_slice(payload)?;
        let input = text.as_bytes();
        ensure!(
            input.len().is_multiple_of(4),
            "expected chunk base64 width differs"
        );
        let padding = input.iter().rev().take_while(|b| **b == b'=').count();
        ensure!(padding <= 2, "expected chunk padding differs");
        let length = input
            .len()
            .checked_div(4)
            .and_then(|n| n.checked_mul(3))
            .and_then(|n| n.checked_sub(padding))
            .context("expected chunk length overflow")?;
        ensure!(
            length > 0 && length <= maximum,
            "expected chunk exceeds admitted size"
        );
        let digit = |b: u8| -> Result<u8> {
            Ok(match b {
                b'A'..=b'Z' => b - b'A',
                b'a'..=b'z' => b - b'a' + 26,
                b'0'..=b'9' => b - b'0' + 52,
                b'+' => 62,
                b'/' => 63,
                _ => anyhow::bail!("noncanonical expected base64 alphabet"),
            })
        };
        let mut result = Vec::new();
        result.try_reserve_exact(length)?;
        for (index, c) in input.chunks_exact(4).enumerate() {
            let last = index + 1 == input.len() / 4;
            let a = digit(c[0])?;
            let b = digit(c[1])?;
            result.push((a << 2) | (b >> 4));
            if c[2] == b'=' {
                ensure!(
                    last && c[3] == b'=' && b & 15 == 0,
                    "noncanonical expected padding bits"
                );
            } else {
                let d = digit(c[2])?;
                result.push((b << 4) | (d >> 2));
                if c[3] == b'=' {
                    ensure!(last && d & 3 == 0, "noncanonical expected padding bits");
                } else {
                    result.push((d << 6) | digit(c[3])?);
                }
            }
        }
        ensure!(
            result.len() == length,
            "expected decoded chunk width differs"
        );
        Ok(result)
    }

    use n2r_win32::shadow_native::{
        input_domain::{InputDomain, ObjectInput},
        report_memory::{ReportMemoryAccountant, ReportMemoryLease},
    };
    struct Ledger {
        limit: u64,
        used: AtomicU64,
        peak: AtomicU64,
    }
    #[derive(Clone)]
    struct Payer(Arc<Ledger>);
    struct Lease {
        ledger: Arc<Ledger>,
        bytes: u64,
    }
    impl Drop for Lease {
        fn drop(&mut self) {
            self.ledger.used.fetch_sub(self.bytes, Ordering::SeqCst);
        }
    }
    impl ReportMemoryLease for Lease {
        fn shrink_to(&mut self, bytes: u64) -> std::io::Result<()> {
            if bytes > self.bytes {
                return Err(std::io::Error::other("preflight lease cannot grow"));
            }
            self.ledger
                .used
                .fetch_sub(self.bytes - bytes, Ordering::SeqCst);
            self.bytes = bytes;
            Ok(())
        }
    }
    impl ReportMemoryAccountant for Payer {
        fn reserve(&self, bytes: u64) -> std::io::Result<Box<dyn ReportMemoryLease>> {
            let mut old = self.0.used.load(Ordering::SeqCst);
            loop {
                let next = old
                    .checked_add(bytes)
                    .filter(|n| *n <= self.0.limit)
                    .ok_or_else(|| {
                        std::io::Error::other(format!(
                            "preflight RAM refusal: leased {old} + requested {bytes} > limit {}",
                            self.0.limit
                        ))
                    })?;
                match self
                    .0
                    .used
                    .compare_exchange(old, next, Ordering::SeqCst, Ordering::SeqCst)
                {
                    Ok(_) => {
                        self.0.peak.fetch_max(next, Ordering::SeqCst);
                        break;
                    }
                    Err(current) => old = current,
                }
            }
            Ok(Box::new(Lease {
                ledger: self.0.clone(),
                bytes,
            }))
        }
        fn lease_heap_bytes(&self) -> u64 {
            std::mem::size_of::<Lease>() as u64
        }
    }
    #[derive(Clone, Copy)]
    struct Row {
        start: u64,
        chunks: u64,
        bytes: u64,
    }
    struct PaidObject {
        object: Object,
        _memory: Box<dyn ReportMemoryLease>,
    }
    impl ObjectInput for PaidObject {
        fn input(&self) -> n2r_win32::shadow_native::Input<'_> {
            self.object.input()
        }
    }
    struct Domain {
        reader: RefCell<Reader>,
        rows: Vec<Row>,
        admission: SourceResourceAdmission,
        header: ExpectedTreePageHeader,
        maximum_chunk: usize,
        payer: Payer,
        counts_checked: Cell<bool>,
        _reader_memory: Box<dyn ReportMemoryLease>,
        _index_memory: Box<dyn ReportMemoryLease>,
        _header_memory: Box<dyn ReportMemoryLease>,
    }
    impl Domain {
        fn open(expected: &Held, admission: SourceResourceAdmission, payer: Payer) -> Result<Self> {
            let budget = admission.expected_page_budget()?;
            let reader_memory = payer.reserve(u64::from(budget.max_page_bytes) * 3 + 131_072)?;
            let index_bytes = admission
                .objects()?
                .checked_mul(48)
                .and_then(|n| n.checked_add(4096))
                .context("preflight index RAM overflow")?;
            let index_memory = payer.reserve(index_bytes)?;
            let mut reader = Reader::open_held(
                expected.file.try_clone()?,
                &hex::encode(expected.sha256),
                PURPOSE,
                budget,
            )?;
            let first = reader.get(0)?;
            ensure!(first.key.is_empty(), "expected header key differs");
            let header_memory = payer.reserve(
                (first.payload.len() as u64)
                    .checked_mul(32)
                    .and_then(|n| {
                        n.checked_add(std::mem::size_of::<ExpectedTreePageHeader>() as u64)
                    })
                    .context("preflight header RAM overflow")?,
            )?;
            let header: ExpectedTreePageHeader = serde_json::from_slice(&first.payload)?;
            ensure!(
                header.schema_version == 3
                    && header.resource_admission == Some(admission)
                    && header.total_objects == admission.objects()?,
                "expected/source admission mismatch"
            );
            drop(first);
            let maximum_chunk =
                usize::try_from(((budget.max_page_bytes - 90) / 4 * 3).min(768 * 1024))?;
            let mut rows = Vec::new();
            rows.try_reserve_exact(usize::try_from(header.total_objects)?)?;
            ensure!(
                (rows.capacity() as u64) * std::mem::size_of::<Row>() as u64 <= index_bytes,
                "preflight actual index capacity exceeds payment"
            );
            let mut cursor = 1u64;
            let mut compact = 0u64;
            let _chunk_memory = payer.reserve(u64::from(budget.max_page_bytes) * 4)?;
            for ordinal in 0..header.total_objects {
                let start = cursor;
                let (mut chunks, mut bytes, mut previous) = (0u64, 0u64, maximum_chunk);
                while cursor < reader.len() {
                    let item = reader.get(cursor)?;
                    ensure!(item.key.len() == 16, "expected object key width differs");
                    let object = u64::from_be_bytes(item.key[..8].try_into()?);
                    if object != ordinal {
                        ensure!(
                            chunks > 0 && object == ordinal + 1,
                            "expected object sequence differs"
                        );
                        break;
                    }
                    ensure!(
                        u64::from_be_bytes(item.key[8..].try_into()?) == chunks
                            && previous == maximum_chunk,
                        "expected chunk order/nonfinal size differs"
                    );
                    let raw = decode_chunk(&item.payload, maximum_chunk)?;
                    previous = raw.len();
                    bytes = bytes
                        .checked_add(raw.len() as u64)
                        .filter(|n| *n <= admission.budget.max_row_bytes)
                        .context("expected object exceeds admitted row")?;
                    chunks += 1;
                    cursor += 1;
                }
                ensure!(chunks > 0, "expected object has no complete chunks");
                compact = compact
                    .checked_add(bytes)
                    .filter(|n| *n <= admission.semantic_byte_budget())
                    .context("expected compact domain exceeds semantic budget")?;
                rows.push(Row {
                    start,
                    chunks,
                    bytes,
                });
            }
            ensure!(
                cursor == reader.len(),
                "unaccounted expected objects/chunks"
            );
            reader.revalidate()?;
            Ok(Self {
                reader: RefCell::new(reader),
                rows,
                admission,
                header,
                maximum_chunk,
                payer,
                counts_checked: Cell::new(false),
                _reader_memory: reader_memory,
                _index_memory: index_memory,
                _header_memory: header_memory,
            })
        }
    }
    impl InputDomain for Domain {
        type Object = PaidObject;
        fn len(&self) -> usize {
            self.rows.len()
        }
        fn object(&self, index: usize) -> std::io::Result<PaidObject> {
            (|| -> Result<PaidObject> {
                let row = self
                    .rows
                    .get(index)
                    .context("preflight expected ordinal absent")?;
                let memory = self.payer.reserve(
                    self.admission
                        .budget
                        .max_row_bytes
                        .checked_mul(8)
                        .and_then(|n| {
                            n.checked_add(u64::from(self.admission.budget.page_bytes) * 4)
                        })
                        .context("preflight row RAM overflow")?,
                )?;
                let mut bytes = Vec::new();
                bytes.try_reserve_exact(usize::try_from(row.bytes)?)?;
                let mut reader = self.reader.borrow_mut();
                for chunk in 0..row.chunks {
                    let item = reader.get(row.start + chunk)?;
                    ensure!(
                        item.key.len() == 16
                            && u64::from_be_bytes(item.key[..8].try_into()?) == index as u64
                            && u64::from_be_bytes(item.key[8..].try_into()?) == chunk,
                        "held expected chunk identity differs"
                    );
                    let raw = decode_chunk(&item.payload, self.maximum_chunk)?;
                    ensure!(
                        bytes
                            .len()
                            .checked_add(raw.len())
                            .is_some_and(|n| n as u64 <= row.bytes),
                        "held expected row grew"
                    );
                    bytes.extend_from_slice(&raw);
                }
                ensure!(
                    bytes.len() as u64 == row.bytes,
                    "held expected row length differs"
                );
                let object: Object = serde_json::from_slice(&bytes)?;
                Ok(PaidObject {
                    object,
                    _memory: memory,
                })
            })()
            .map_err(std::io::Error::other)
        }
        fn require_resource_metadata(
            &self,
            admission: SourceResourceAdmission,
        ) -> std::io::Result<()> {
            (|| -> Result<()> {
                ensure!(
                    self.counts_checked.get()
                        && self.admission == admission
                        && self.header.resource_admission == Some(admission)
                        && self.rows.len() as u64 == admission.objects()?,
                    "preflight resource domain is not completely checked"
                );
                self.reader.borrow_mut().revalidate()?;
                Ok(())
            })()
            .map_err(std::io::Error::other)
        }
    }
    #[derive(Serialize)]
    struct InputError {
        check: &'static str,
        source_record: u64,
        source_sequence: u16,
        path: Vec<String>,
        message: String,
    }
    #[derive(Default, Serialize)]
    struct SviCounts {
        objects: u64,
        canonical_objects: u64,
        namespace_paths: u64,
        directories: u64,
        nested_directories: u64,
        files: u64,
        streams: u64,
        logical_stream_bytes: u64,
    }
    #[derive(Serialize)]
    struct SviStreamDiagnostic {
        name_utf16: Vec<u16>,
        length: u64,
        content_digest: Option<String>,
        source_evidence: Option<ntfs2refs::shadow_tree::SourceStreamEvidence>,
        source_offset: Option<u64>,
        source_extent_count: usize,
        sparse: bool,
    }
    #[derive(Serialize)]
    struct SviObjectDiagnostic {
        object_ordinal: usize,
        source_record: u64,
        source_sequence: u16,
        path: Vec<String>,
        svi_namespace_paths: Vec<Vec<String>>,
        canonical_root_matches_sdk_exactly: bool,
        object_type: &'static str,
        attributes: u32,
        reparse_tag: Option<u32>,
        additional_names: usize,
        default_data_length: u64,
        default_data_digest: Option<String>,
        named_streams: usize,
        streams: Vec<SviStreamDiagnostic>,
        stored_security_sha256: String,
        api_security_sha256: Option<String>,
    }
    struct Count {
        bytes: usize,
        maximum: usize,
    }
    impl Write for Count {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.bytes = self
                .bytes
                .checked_add(bytes.len())
                .filter(|n| *n <= self.maximum)
                .ok_or_else(|| std::io::Error::other("preflight report exceeds output cap"))?;
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    fn svi_path(path: &[String]) -> bool {
        path.first()
            .is_some_and(|root| root.eq_ignore_ascii_case("System Volume Information"))
    }
    fn record_svi(
        ordinal: usize,
        object: &Object,
        payer: &Payer,
        counts: &mut SviCounts,
        records: &mut Vec<SviObjectDiagnostic>,
        payments: &mut Vec<Box<dyn ReportMemoryLease>>,
        retained_bytes: &mut usize,
        maximum_bytes: usize,
    ) -> Result<()> {
        let canonical = svi_path(&object.path);
        let paths = std::iter::once(&object.path)
            .chain(object.additional_names.iter())
            .filter(|path| svi_path(path));
        let path_count = paths.clone().count();
        if path_count == 0 {
            return Ok(());
        }
        counts.objects += 1;
        counts.canonical_objects += u64::from(canonical);
        counts.namespace_paths += path_count as u64;
        counts.directories += u64::from(object.directory);
        counts.nested_directories +=
            u64::from(object.directory && paths.clone().any(|path| path.len() > 1));
        counts.files += u64::from(!object.directory);
        for stream in object.data_streams() {
            counts.streams += 1;
            counts.logical_stream_bytes = counts
                .logical_stream_bytes
                .checked_add(stream.length)
                .context("SVI diagnostic logical-byte count overflow")?;
        }
        // Always count the entire authenticated source namespace. Retained
        // diagnostics have a separate, explicit RAM/output bound; truncation
        // never turns the actual SDK refusal into constructor eligibility.
        if records.len() >= 4096 {
            return Ok(());
        }
        let mut memory_bytes = 8192u64;
        for path in std::iter::once(&object.path).chain(paths.clone()) {
            for part in path {
                memory_bytes = memory_bytes
                    .checked_add((part.len() as u64) * 4 + 128)
                    .context("SVI path diagnostic RAM overflow")?;
            }
        }
        for stream in object.data_streams() {
            memory_bytes = memory_bytes
                .checked_add(
                    (stream.name_utf16.len() as u64) * 8
                        + (stream.sha256.map_or(0, str::len) as u64) * 4
                        + 1024,
                )
                .context("SVI stream diagnostic RAM overflow")?;
        }
        memory_bytes = memory_bytes
            .checked_add((object.sha256.as_ref().map_or(0, String::len) as u64) * 4)
            .context("SVI default digest diagnostic RAM overflow")?;
        let payment = payer.reserve(memory_bytes)?;
        let diagnostic = SviObjectDiagnostic {
            object_ordinal: ordinal,
            source_record: object.record_number,
            source_sequence: object.sequence_number,
            path: object.path.clone(),
            svi_namespace_paths: paths.cloned().collect(),
            canonical_root_matches_sdk_exactly: object
                .path
                .first()
                .is_some_and(|root| root == "System Volume Information"),
            object_type: if object.directory {
                "directory"
            } else {
                "file"
            },
            attributes: object.attributes,
            reparse_tag: object.reparse.as_ref().map(|point| point.tag()),
            additional_names: object.additional_names.len(),
            default_data_length: object.length,
            default_data_digest: object.sha256.clone(),
            named_streams: object.named_streams.len(),
            streams: object
                .data_streams()
                .map(|stream| SviStreamDiagnostic {
                    name_utf16: stream.name_utf16.to_vec(),
                    length: stream.length,
                    content_digest: stream.sha256.map(str::to_owned),
                    source_evidence: stream.source_evidence,
                    source_offset: stream.source_offset,
                    source_extent_count: stream.source_extents.len(),
                    sparse: stream.sparse.is_some(),
                })
                .collect(),
            stored_security_sha256: hex::encode(Sha256::digest(&object.security)),
            api_security_sha256: object
                .api_security
                .as_ref()
                .map(|bytes| hex::encode(Sha256::digest(bytes))),
        };
        let mut count = Count {
            bytes: 0,
            maximum: maximum_bytes.saturating_sub(*retained_bytes),
        };
        if serde_json::to_writer_pretty(&mut count, &diagnostic).is_ok() {
            *retained_bytes += count.bytes;
            records.push(diagnostic);
            payments.push(payment);
        }
        Ok(())
    }
    fn record_error(
        object: &Object,
        check: &'static str,
        message: String,
        payer: &Payer,
        errors: &mut Vec<InputError>,
        payments: &mut Vec<Box<dyn ReportMemoryLease>>,
        counts: &mut BTreeMap<&'static str, u64>,
        retained_bytes: &mut usize,
        maximum_bytes: usize,
    ) -> Result<()> {
        *counts.entry(check).or_default() += 1;
        if errors.len() >= 128 {
            return Ok(());
        }
        let bytes =
            object
                .path
                .iter()
                .try_fold(4096u64 + (message.len() as u64) * 4, |n, part| {
                    n.checked_add((part.len() as u64) * 4 + 96)
                        .context("preflight error RAM overflow")
                })?;
        let payment = payer.reserve(bytes)?;
        let error = InputError {
            check,
            source_record: object.record_number,
            source_sequence: object.sequence_number,
            path: object.path.clone(),
            message,
        };
        let mut count = Count {
            bytes: 0,
            maximum: maximum_bytes.saturating_sub(*retained_bytes),
        };
        if serde_json::to_writer_pretty(&mut count, &error).is_ok() {
            *retained_bytes += count.bytes;
            errors.push(error);
            payments.push(payment);
        }
        Ok(())
    }
    pub fn run() -> Result<()> {
        let args = Args::parse();
        ensure!(
            (1..=16_384).contains(&args.max_unique_descriptors)
                && (4096..=1_048_576).contains(&args.max_output_bytes)
                && args.max_file_bytes > 192
                && args.max_row_bytes > 0
                && (64 << 20..=16u64 << 30).contains(&args.ram_bytes),
            "explicit preflight limits differ"
        );
        n2r_win32::layout::guid_bytes(&args.metadata_volume_guid)?;
        let payer = Payer(Arc::new(Ledger {
            limit: args.ram_bytes,
            used: AtomicU64::new(0),
            peak: AtomicU64::new(0),
        }));
        let _scalar_memory =
            payer.reserve(METADATA_CAP * 32 + (args.max_output_bytes as u64) * 32 + 1_048_576)?;
        let mut assessment = Held::open(
            &args.source_assessment,
            &args.source_assessment_sha256,
            METADATA_CAP,
            &args.metadata_volume_guid,
        )?;
        assessment.file.seek(SeekFrom::Start(0))?;
        let data: Assessment =
            serde_json::from_reader((&mut assessment.file).take(assessment.snapshot.file_bytes))?;
        let admission = data.resource_admission;
        admission.validate()?;
        data.binding.validate()?;
        ensure!(
            data.binding.disk_number == 0
                && data.binding.layout_profile
                    == n2r_win32::general_layout::GeneralDiskLayoutProfile::OfflineWindows
                && n2r_win32::layout::guid_bytes(&data.binding.volume_guid)?
                    != n2r_win32::layout::guid_bytes(&args.metadata_volume_guid)?,
            "metadata filesystem must be independent of original source0"
        );
        ensure!(
            args.ram_bytes <= admission.budget.ram_bytes
                && admission.budget.max_row_bytes <= args.max_row_bytes,
            "explicit preflight cap exceeds original RAM or cannot decode admitted rows"
        );
        let expected = Held::open(
            &args.expected_pages,
            &args.expected_sha256,
            args.max_file_bytes,
            &args.metadata_volume_guid,
        )?;
        let domain = Domain::open(&expected, admission, payer.clone())?;
        let _security_working =
            payer.reserve(refs_security_descriptor::constructor_working_bytes(MAX_SD)?)?;
        let mut seen = BTreeMap::<[u8; 32], bool>::new();
        let mut input_errors = Vec::new();
        let mut error_payments = Vec::new();
        let mut error_counts = BTreeMap::new();
        let mut retained_error_bytes = 0usize;
        let mut security_payments = Vec::new();
        let mut svi_counts = SviCounts::default();
        let mut svi_records = Vec::new();
        let mut svi_payments = Vec::new();
        let mut retained_svi_bytes = 0usize;
        let (mut files, mut directories, mut streams, mut trust_objects, mut api_views) =
            (0u64, 0u64, 0u64, 0u64, 0u64);
        let (
            mut reparses,
            mut ea_objects,
            mut namespace_names,
            mut source_ranges,
            mut sparse_streams,
        ) = (0u64, 0u64, 0u64, 0u64, 0u64);
        let (mut maximum_path_depth, mut maximum_security_bytes) = (0usize, 0usize);
        for index in 0..domain.len() {
            let row = domain.object(index)?;
            let object = &row.object;
            files += u64::from(!object.directory);
            directories += u64::from(object.directory);
            streams += object.data_streams().count() as u64;
            api_views += u64::from(object.api_security.is_some());
            reparses += u64::from(object.reparse.is_some());
            ea_objects += u64::from(object.extended_attributes.is_some());
            namespace_names += 1 + object.additional_names.len() as u64;
            maximum_path_depth = maximum_path_depth.max(object.path.len());
            maximum_security_bytes = maximum_security_bytes.max(object.security.len());
            record_svi(
                index,
                object,
                &payer,
                &mut svi_counts,
                &mut svi_records,
                &mut svi_payments,
                &mut retained_svi_bytes,
                args.max_output_bytes / 3,
            )?;
            for stream in object.data_streams() {
                source_ranges +=
                    stream.source_extents.len() as u64 + u64::from(stream.source_offset.is_some());
                sparse_streams += u64::from(stream.sparse.is_some());
            }
            // These are the exact existing setter's source-side predicates.
            // Target freshness, native support and readback remain deferred.
            let mut check = |name, result: std::io::Result<()>| -> Result<()> {
                if let Err(error) = result {
                    record_error(
                        object,
                        name,
                        error.to_string(),
                        &payer,
                        &mut input_errors,
                        &mut error_payments,
                        &mut error_counts,
                        &mut retained_error_bytes,
                        args.max_output_bytes / 2,
                    )?;
                }
                Ok(())
            };
            if let Some(eas) = object.extended_attributes.as_ref() {
                check("extended_attributes_validate", eas.validate())?;
            }
            if let Some(point) = object.reparse.as_ref() {
                check("reparse_point_validate", point.validate())?;
                check(
                    "reparse_mount_directory",
                    if point.tag() == n2r_win32::reparse_layout::IO_REPARSE_TAG_MOUNT_POINT
                        && !object.directory
                    {
                        Err(std::io::Error::other(
                            "mount-point reparse target must be a directory",
                        ))
                    } else {
                        Ok(())
                    },
                )?;
                check(
                    "reparse_file_empty",
                    if !object.directory && object.length != 0 {
                        Err(std::io::Error::other(
                            "reparse restoration requires a fresh owned empty file",
                        ))
                    } else {
                        Ok(())
                    },
                )?;
            }
            let mut key = Sha256::new();
            key.update((object.security.len() as u64).to_le_bytes());
            key.update(&object.security);
            key.update([u8::from(object.api_security.is_some())]);
            if let Some(api) = object.api_security.as_ref() {
                key.update((api.len() as u64).to_le_bytes());
                key.update(api);
            }
            let key: [u8; 32] = key.finalize().into();
            // Validate every context (API pair included); deduplicate only the retained diagnostics.
            let prepared = refs_security_descriptor::ConstructorSecurityViews::prepare(
                &object.security,
                object.api_security.as_deref(),
                admission.budget.max_row_bytes.min(MAX_SD),
            );
            if prepared.as_ref().is_ok_and(|p| p.is_some()) {
                trust_objects += 1;
            }
            if !seen.contains_key(&key) {
                ensure!(
                    seen.len() < args.max_unique_descriptors,
                    "unique security contexts exceed explicit diagnostic cap"
                );
                let payment = payer.reserve(4096)?;
                let valid = prepared.is_ok();
                if let Err(error) = prepared {
                    record_error(
                        object,
                        "constructor_security_views",
                        error.to_string(),
                        &payer,
                        &mut input_errors,
                        &mut error_payments,
                        &mut error_counts,
                        &mut retained_error_bytes,
                        args.max_output_bytes / 2,
                    )?;
                }
                seen.insert(key, valid);
                security_payments.push(payment);
            }
        }
        admission.validate_tree(files, directories, streams)?;
        domain.counts_checked.set(true);
        let volume_root = format!(
            "\\\\?\\Volume{{{}}}\\",
            args.metadata_volume_guid.trim_matches(['{', '}'])
        );
        let system_result =
            n2r_win32::shadow_native::private_tree::preflight_system_payload_input_domain(&domain);
        let result = n2r_win32::shadow_native::private_tree::preflight_resource_input_domain(
            &domain,
            admission,
            data.binding.identity.partition_bytes,
            &volume_root,
            &payer,
        );
        domain.reader.borrow_mut().revalidate()?;
        expected.revalidate(args.max_file_bytes)?;
        assessment.revalidate(METADATA_CAP)?;
        let (summary, constructor_error) = match result {
            Ok(summary) => (Some(summary), None),
            Err(error) => (None, Some(error.to_string())),
        };
        let (system_summary, system_error) = match system_result {
            Ok(value) => (Some(value), None),
            Err(error) => (None, Some(error.to_string())),
        };
        let eligible =
            constructor_error.is_none() && system_error.is_none() && error_counts.is_empty();
        let total_input_errors: u64 = error_counts.values().sum();
        let diagnostics_truncated = total_input_errors > input_errors.len() as u64;
        let constructor_completed = summary.is_some();
        let svi_diagnostics_complete = svi_counts.objects == svi_records.len() as u64;
        let report = serde_json::json!({"schema_version":1,"kind":"closed-expected-constructor-preflight-v1",
            "expected_file":expected.snapshot,"expected_sha256":args.expected_sha256,
            "source_assessment_sha256":args.source_assessment_sha256,
            "source_inspection_sha256":hex::encode(admission.source_inspection_sha256),
            "source_binding_expectation":data.binding,"objects":domain.len(),"files":files,"directories":directories,
            "streams":streams,"namespace_names":namespace_names,"source_ranges":source_ranges,"sparse_streams":sparse_streams,
            "reparse_objects":reparses,"ea_observed_objects":ea_objects,"api_view_objects":api_views,
            "maximum_path_depth":maximum_path_depth,"maximum_stored_security_bytes":maximum_security_bytes,
            "unique_security_contexts":seen.len(),"trust_objects":trust_objects,
            "input_error_counts":error_counts,"input_errors_total":total_input_errors,"input_errors":input_errors,
            "input_error_diagnostics_truncated":diagnostics_truncated,
            "system_volume_information_counts":svi_counts,
            "system_volume_information_objects":svi_records,
            "system_volume_information_diagnostics_complete":svi_diagnostics_complete,
            "system_volume_information_diagnostics_maximum_objects":4096,
            "system_volume_information_diagnostics_maximum_bytes":args.max_output_bytes/3,
            "system_volume_information_digest_algorithm":"XXH3-128 content digest (historical Object.sha256 field); security digests are SHA-256",
            "system_volume_information_identity_scope":"record/sequence and namespace from authenticated expected metadata; not a current filesystem observation or write authority",
            "system_payload_summary":system_summary,"system_payload_error":system_error,
            "constructor_summary":summary,"constructor_error":constructor_error,"pure_input_eligible":eligible,
            "explicit_ram_cap":args.ram_bytes,"measured_paid_ram_peak":payer.0.peak.load(Ordering::SeqCst),
            "constructor_pure_checks_completed":constructor_completed,
            "native_memory_stored_descriptor_validation_completed":constructor_completed,
            "all_source_security_contexts_checked":true,"all_source_shape_records_checked":true,
            "path_root_identity_used_as_authority":false,
            "source_device_opens":0,"source_volume_opens":0,"setter_calls":0,"metadata_only":true,
            "deferred_native_checks":["fresh shadow identity/profile/allocator and formatter collisions",
                "native namespace, EA/reparse/attributes/time/security inheritance and paired API projection",
                "actual ReFS 0x530 canonical packing/hash carry and graph page/change bounds",
                "placement/move success, target readback, source proof, publication/AP/HND/finalizer/restart"],
            "source_admission_issued":false,"native_preservation_qualified":false,"execution_authorized":false});
        let mut count = Count {
            bytes: 0,
            maximum: args.max_output_bytes - 1,
        };
        serde_json::to_writer_pretty(&mut count, &report)?;
        ordinary_path(&args.output)?;
        ensure!(!args.output.exists(), "fresh preflight output required");
        let parent = OpenOptions::new()
            .access_mode(0x80)
            .share_mode(1)
            .custom_flags(0x0220_0000)
            .open(args.output.parent().context("output parent absent")?)?;
        let route = n2r_win32::file_storage::final_path_guid(&parent)?;
        ensure!(
            on_volume(&route, &args.metadata_volume_guid)?
                || route.trim_end_matches('\\').eq_ignore_ascii_case(&format!(
                    "\\\\?\\Volume{{{}}}",
                    args.metadata_volume_guid.trim_matches(['{', '}'])
                )),
            "output must remain on explicit metadata filesystem"
        );
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .share_mode(0)
            .custom_flags(0x0020_0000)
            .open(&args.output)?;
        serde_json::to_writer_pretty(&mut output, &report)?;
        output.write_all(b"\n")?;
        output.sync_all()?;
        println!(
            "{}",
            serde_json::to_string(
                &serde_json::json!({"output":args.output,"bytes":count.bytes+1,
            "pure_input_eligible":eligible,"objects":domain.len(),"source_device_opens":0,"setter_calls":0})
            )?
        );
        ensure!(
            eligible,
            "constructor input preflight refused; see closed output report"
        );
        Ok(())
    }
}
#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    windows::run()
}
#[cfg(not(windows))]
fn main() {
    eprintln!("Closed expected constructor preflight requires Windows.");
    std::process::exit(2);
}
