//! Read-only readiness of one actual private ordinary stream prefix. This is
//! not evidence of the scratch payload's contents or source/write authority.
use super::*;
use crate::shadow_native::report_memory::{ReportMemoryAccountant, ReportMemoryLease};

struct Evidence {
    metadata: Snapshot,
    private_security: Vec<u8>,
    retrieval: Vec<u8>,
    storage: initialized_regions::Proof,
    integrity: Vec<u8>,
    digest: String,
}
/// One same-file readonly native owner, with actual allocator and storage
/// observations. There is no Clone, Deserialize or raw handle accessor.
pub struct RoutedPrefixReady {
    file: File,
    expected_path: String,
    logical_length: u64,
    prefix: u64,
    partition: u64,
    row_bytes: usize,
    evidence: Evidence,
    payer: Arc<dyn ReportMemoryAccountant>,
    _memory: Box<dyn ReportMemoryLease>,
}
fn bad(message: &str) -> io::Error {
    invalid(message)
}
fn add(a: u64, b: u64) -> io::Result<u64> {
    a.checked_add(b)
        .ok_or_else(|| bad("routed prefix RAM overflow"))
}
fn peak(row: usize, path: usize) -> io::Result<u64> {
    add(
        add(
            (row as u64)
                .checked_mul(4)
                .ok_or_else(|| bad("routed prefix RAM overflow"))?,
            4 * 1024 * 1024,
        )?,
        (path as u64)
            .checked_mul(16)
            .ok_or_else(|| bad("routed prefix RAM overflow"))?,
    )
}
pub(super) fn security(file: &File) -> io::Result<Vec<u8>> {
    // Owner/group/DACL only: the private constructor's original data handle
    // has READ_CONTROL; final source SACL preservation is a separate phase.
    const INFORMATION: u32 = 7;
    let mut required = 0u32;
    let ok = unsafe {
        windows_sys::Win32::Security::GetKernelObjectSecurity(
            file.as_raw_handle(),
            INFORMATION,
            ptr::null_mut(),
            0,
            &mut required,
        )
    };
    if ok == 0 && io::Error::last_os_error().raw_os_error() != Some(122) {
        return Err(io::Error::last_os_error());
    }
    if !(20..=crate::attestation::MAX_SECURITY_BYTES as u32).contains(&required) {
        return Err(bad(
            "private routed prefix security exceeds its constructor profile",
        ));
    }
    let mut words = vec![0u64; (required as usize).div_ceil(8)];
    let mut used = 0u32;
    if unsafe {
        windows_sys::Win32::Security::GetKernelObjectSecurity(
            file.as_raw_handle(),
            INFORMATION,
            words.as_mut_ptr().cast(),
            required,
            &mut used,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    if used < 20 || used > required {
        return Err(bad("private routed prefix security query length differs"));
    }
    let bytes =
        unsafe { std::slice::from_raw_parts(words.as_ptr().cast::<u8>(), used as usize) }.to_vec();
    crate::security_descriptor::validate(&bytes)?;
    Ok(bytes)
}
fn capture(
    file: &File,
    path: &str,
    logical: u64,
    prefix: u64,
    partition: u64,
    row: usize,
) -> io::Result<Evidence> {
    let before = snapshot(file);
    for (class, length) in [(0, 40), (1, 24), (18, 24), (9, 8)] {
        query_bytes(&before, class, length)?;
    }
    let standard = query_bytes(&before, 1, 24)?;
    let id = query_bytes(&before, 18, 24)?;
    let attrs = layout::u32_at(query_bytes(&before, 9, 8)?, 0)?;
    if layout::u64_at(standard, 8)? != logical
        || layout::u64_at(standard, 0)? < prefix
        || layout::u32_at(standard, 16)? != 1
        || standard[20] != 0
        || standard[21] != 0
        || id[8..24] == [0; 16]
        || attrs & (0x10 | 0x200 | 0x400 | 0x800 | 0x4000) != 0
        || !crate::file_storage::held_at_guid_path(file, path)?
    {
        return Err(bad(
            "private routed prefix native identity/EOF/type differs",
        ));
    }
    let sd = security(file)?;
    let (first, continuation) = crate::stream_native::retrieval_queries_resource(file, row)?;
    let mapping = crate::retrieval_paging::assemble_queries_with_limits(
        &first,
        &continuation,
        crate::retrieval_paging::Limits::for_resource_bytes(row)?,
    )?;
    let mut digest = Sha256::new();
    digest.update(b"n2r-private-routed-prefix-readiness-v1\0");
    digest.update(id);
    digest.update(logical.to_le_bytes());
    digest.update(prefix.to_le_bytes());
    digest.update((sd.len() as u64).to_le_bytes());
    digest.update(&sd);
    let mut covered = 0u64;
    let cluster = crate::target_cluster::bytes();
    for run in &mapping.runs {
        let offset = run
            .vcn
            .checked_mul(cluster)
            .ok_or_else(|| bad("routed prefix VCN overflow"))?;
        // The complete retrieval transcript can include an unallocated final
        // partial-cluster suffix. It is not part of this initialized-prefix
        // proof; its real bytes remain on the materialization path. The full
        // transcript is still captured and compared again below.
        if offset >= prefix {
            break;
        }
        let length = run
            .clusters
            .checked_mul(cluster)
            .ok_or_else(|| bad("routed prefix mapping overflow"))?;
        if length == 0 || offset != covered {
            return Err(bad("private routed prefix logical coverage differs"));
        }
        let lcn = run.lcn.ok_or_else(|| {
            bad(&format!(
                "private routed prefix contains an in-prefix hole: vcn={}, clusters={}, prefix_bytes={}, logical_bytes={}, stream={path:?}",
                run.vcn, run.clusters, prefix, logical
            ))
        })?;
        let physical = lcn
            .checked_mul(cluster)
            .ok_or_else(|| bad("routed prefix physical mapping overflow"))?;
        if physical.checked_add(length).is_none_or(|n| n > partition) {
            return Err(bad(
                "private routed prefix map is incomplete or escapes volume",
            ));
        }
        let n = length.min(prefix - offset);
        digest.update(offset.to_le_bytes());
        digest.update(physical.to_le_bytes());
        digest.update(n.to_le_bytes());
        covered = covered
            .checked_add(n)
            .ok_or_else(|| bad("routed prefix coverage overflow"))?;
        if covered == prefix {
            break;
        }
    }
    if covered != prefix {
        return Err(bad("private routed prefix complete mapping absent"));
    }
    let storage = initialized_regions::capture_initialized(file, prefix, 2, row).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("routed prefix first initialized-region observation {path:?}: {e}"),
        )
    })?;
    let integrity = ctl(file, 0x9027c, &[], 16)?;
    if integrity.len() != 16
        || integrity[..8] != [0; 8]
        || layout::u32_at(&integrity, 12)? != crate::target_cluster::bytes_u32()
    {
        return Err(bad("routed prefix integrity must remain disabled"));
    }
    let after = snapshot(file);
    let after_sd = security(file)?;
    let (first, continuation) = crate::stream_native::retrieval_queries_resource(file, row)?;
    let after_mapping = crate::retrieval_paging::assemble_queries_with_limits(
        &first,
        &continuation,
        crate::retrieval_paging::Limits::for_resource_bytes(row)?,
    )?;
    let after_storage =
        initialized_regions::capture_initialized(file, prefix, 2, row).map_err(|e| {
            io::Error::new(
                e.kind(),
                format!("routed prefix second initialized-region observation {path:?}: {e}"),
            )
        })?;
    if before != after
        || sd != after_sd
        || mapping.canonical != after_mapping.canonical
        || !storage.same_transcript(&after_storage)
        || !crate::file_storage::held_at_guid_path(file, path)?
    {
        return Err(bad(
            "private routed prefix metadata/security/mapping/validity changed during observation",
        ));
    }
    // Noncached validity is normalized after exact before/after query checks.
    // Cached-valid bits/row segmentation and mutable tail times do not enter
    // the cross-phase prefix fingerprint.
    digest.update(2u32.to_le_bytes());
    digest.update(&integrity);
    Ok(Evidence {
        metadata: before,
        private_security: sd,
        retrieval: mapping.canonical,
        storage,
        integrity,
        digest: hex::encode(digest.finalize()),
    })
}
fn retained_bytes(e: &Evidence, path: &String) -> io::Result<u64> {
    let mut n = add(
        path.capacity() as u64,
        std::mem::size_of::<RoutedPrefixReady>() as u64,
    )?;
    n = add(
        n,
        (e.metadata.queries.capacity() * std::mem::size_of::<crate::attestation::Query>()) as u64,
    )?;
    for q in &e.metadata.queries {
        n = add(n, q.bytes.capacity() as u64)?;
    }
    n = add(n, e.metadata.security.capacity() as u64)?;
    if let Some(q) = &e.metadata.kernel_security {
        n = add(n, q.bytes.capacity() as u64)?;
    }
    if e.metadata.extended_attributes.is_some()
        || e.metadata.extended_attributes_error.is_some()
        || e.metadata.reparse.is_some()
        || e.metadata.directory_case_sensitivity.is_some()
    {
        return Err(bad("unexpected feature scope in private prefix snapshot"));
    }
    for b in [&e.private_security, &e.retrieval, &e.integrity] {
        n = add(n, b.capacity() as u64)?;
    }
    n = add(n, e.storage.retained_bytes()?)?;
    add(n, e.digest.capacity() as u64)
}
impl RoutedPrefixReady {
    pub fn prefix_bytes(&self) -> u64 {
        self.prefix
    }
    pub fn logical_length(&self) -> u64 {
        self.logical_length
    }
    pub fn evidence_sha256(&self) -> &str {
        &self.evidence.digest
    }
    pub fn revalidate(&self) -> io::Result<()> {
        let _work = self
            .payer
            .reserve(peak(self.row_bytes, self.expected_path.len())?)?;
        let current = capture(
            &self.file,
            &self.expected_path,
            self.logical_length,
            self.prefix,
            self.partition,
            self.row_bytes,
        )?;
        if current.digest != self.evidence.digest {
            return Err(bad(
                "private routed prefix identity/mapping/storage proof changed",
            ));
        }
        Ok(())
    }
}
pub(super) fn observe(
    tree: &PrivateTree,
    index: usize,
    name: &[u16],
    components: &[String],
    logical: u64,
    prefix: u64,
) -> io::Result<RoutedPrefixReady> {
    let memory = tree.memory.as_ref().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::Unsupported,
            "routed prefix requires the actual retained private-tree allocator",
        )
    })?;
    let admission = tree
        .metadata_resource_admission
        .ok_or_else(|| bad("routed prefix resource admission absent"))?;
    let row = usize::try_from(admission.budget.max_row_bytes).map_err(io::Error::other)?;
    let payer = memory.payer();
    let mut work = payer.reserve(peak(row, 32768)?)?;
    if prefix == 0
        || !crate::target_cluster::aligned(prefix)
        || prefix != crate::target_cluster::floor(logical)
    {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "routed prefix requires the complete ordinary full-cluster prefix",
        ));
    }
    let key = StreamKey::named(index, name);
    if tree.sparse_targets.contains_key(&key) {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "sparse/carrier routing retains its existing supply path",
        ));
    }
    tree.validate_stream_shape_named(index, name, components, logical)?;
    let file = tree
        .files
        .get(&key)
        .ok_or_else(|| bad("private routed prefix file absent"))?;
    if !tree.placement_complete || file.valid_prefix() < prefix {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "private prefix has not completed storage preparation",
        ));
    }
    let path = streams::path(&tree.pair.shadow.volume_path()?, components, name)?;
    let duplicate = crate::file_storage::duplicate_readonly(file.metadata_handle())?;
    crate::file_storage::require_readonly_access(&duplicate)?;
    let evidence = capture(
        &duplicate,
        &path,
        logical,
        prefix,
        tree.pair.shadow.identity.partition_bytes,
        row,
    )?;
    tree.require_source_excluded()?;
    work.shrink_to(retained_bytes(&evidence, &path)?)?;
    Ok(RoutedPrefixReady {
        file: duplicate,
        expected_path: path,
        logical_length: logical,
        prefix,
        partition: tree.pair.shadow.identity.partition_bytes,
        row_bytes: row,
        evidence,
        payer,
        _memory: work,
    })
}
