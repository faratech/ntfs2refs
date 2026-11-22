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
    // `None` where a helper thread of a batch made the observation: it made
    // the revalidation too, on the same duplicate, and closed it.
    file: Option<File>,
    // That revalidation, taken by the one `revalidate` the owner makes.
    seen_revalidation: std::cell::Cell<Option<io::Result<()>>>,
    // Whether the capture this owner holds was just made on its duplicate
    // and nothing has been asked of the file since: in a run that verifies
    // each thing once, the `revalidate` that follows it at once is that
    // capture (see `Plan::observe`).
    just_captured: std::cell::Cell<bool>,
    expected_path: String,
    logical_length: u64,
    prefix: u64,
    partition: u64,
    row_bytes: usize,
    evidence: Evidence,
    payer: Arc<dyn ReportMemoryAccountant>,
    _memory: Box<dyn ReportMemoryLease>,
}

/// What `observe` asks Windows about one prefix, settled from this
/// process's own records before a helper thread of a batch is started.
pub(super) struct Plan<'tree> {
    file: &'tree unwritten::PrivatePlaceholder,
    // Whether the prefix's storage is prepared. Where it is not, `observe`
    // compares the file's mapping and then stops, with nothing observed.
    prepared: bool,
    path: String,
    logical: u64,
    prefix: u64,
    partition: u64,
    row: usize,
    // The shadow's root the tree holds, where the run verifies each thing
    // once ([`PrivateTree::shadow_root`]); `None` opens it for every query.
    root: Option<&'tree crate::file_storage::HeldVolumeRoot>,
}
/// What a helper thread saw for one `observe` of a prefix and the
/// `revalidate` that follows it, in their order.
pub(super) struct PrefixSeen {
    /// The comparison of the file's complete mapping with its tracked
    /// pieces, which `observe` makes before it looks at the prefix.
    placements: io::Result<()>,
    /// The observation and then its revalidation, where the helper came to
    /// them: the mapping held and the prefix's storage is prepared.
    observed: Option<io::Result<(Evidence, io::Result<()>)>>,
}
impl PrefixSeen {
    /// Whether the helper saw everything of the prefix, without a failure.
    pub(super) fn held(&self) -> bool {
        self.placements.is_ok() && matches!(self.observed, Some(Ok((_, Ok(())))))
    }
}
/// One `observe` and its `revalidate` as a batch made them ready: what its
/// helper saw, and the workspace of `observe`, which the batch reserved.
pub(super) struct PrepaidPrefix {
    pub(super) seen: PrefixSeen,
    pub(super) work: Box<dyn ReportMemoryLease>,
}
fn bad(message: &str) -> io::Error {
    invalid(message)
}
fn add(a: u64, b: u64) -> io::Result<u64> {
    a.checked_add(b)
        .ok_or_else(|| bad("routed prefix RAM overflow"))
}
/// Of the row a file's queries are limited to, what a file of `logical`
/// bytes can take: its mapping and its validity regions have no more
/// entries than it has clusters. The observation's workspace was four of
/// the row itself, a sixteenth of the run's memory for every prefix.
fn row_for(row: usize, logical: u64) -> usize {
    row.min(crate::retrieval_paging::returned_bytes_for_stream(logical).saturating_mul(4))
}
fn peak(row: usize, path: usize) -> io::Result<u64> {
    add(
        add(
            (row as u64)
                .checked_mul(4)
                .ok_or_else(|| bad("routed prefix RAM overflow"))?,
            512 * 1024,
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
/// Whether `file` is the object `path` names: through the shadow's held
/// root where one is given, otherwise by opening the root for the query.
fn held_at(
    file: &File,
    path: &str,
    root: Option<&crate::file_storage::HeldVolumeRoot>,
) -> io::Result<bool> {
    match root {
        Some(root) => root.held_at_guid_path(file, path),
        None => crate::file_storage::held_at_guid_path(file, path),
    }
}
impl PrivateTree {
    /// The shadow's root, opened once and held with the tree's files: an
    /// observation of a routed prefix asked for it on every capture, opening
    /// and closing it each time (`file_storage::held_at_guid_path`).
    pub(super) fn shadow_root(&self) -> io::Result<&crate::file_storage::HeldVolumeRoot> {
        if let Some(root) = self.shadow_root.get() {
            return Ok(root);
        }
        let root = crate::file_storage::HeldVolumeRoot::open(&format!(
            "{}\\",
            self.pair.shadow.volume_path()?
        ))?;
        // Where two threads opened it at once, one of the two is kept.
        Ok(self.shadow_root.get_or_init(|| root))
    }
    /// The shadow's held root for a run that verifies each thing once; a
    /// thorough run opens the root for every query, as before.
    fn shadow_root_once(&self) -> Option<&crate::file_storage::HeldVolumeRoot> {
        crate::verify_policy::verifies_once()
            .then(|| self.shadow_root().ok())
            .flatten()
    }
}
fn capture(
    file: &File,
    path: &str,
    logical: u64,
    prefix: u64,
    partition: u64,
    row: usize,
    root: Option<&crate::file_storage::HeldVolumeRoot>,
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
        || !held_at(file, path, root)?
    {
        return Err(bad(
            "private routed prefix native identity/EOF/type differs",
        ));
    }
    let sd = security(file)?;
    let mapping = crate::stream_native::retrieval_capture_resource(file, row)?;
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
    if !crate::verify_policy::verifies_once() {
        let after = snapshot(file);
        let after_sd = security(file)?;
        let after_mapping = crate::stream_native::retrieval_capture_resource(file, row)?;
        let after_storage = initialized_regions::capture_initialized(file, prefix, 2, row)
            .map_err(|e| {
                io::Error::new(
                    e.kind(),
                    format!("routed prefix second initialized-region observation {path:?}: {e}"),
                )
            })?;
        if before != after
            || sd != after_sd
            || mapping.canonical != after_mapping.canonical
            || !storage.same_transcript(&after_storage)
            || !held_at(file, path, root)?
        {
            return Err(bad(
                "private routed prefix metadata/security/mapping/validity changed during observation",
            ));
        }
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
        if let Some(seen) = self.seen_revalidation.take() {
            return seen;
        }
        if self.just_captured.replace(false) && crate::verify_policy::verifies_once() {
            return Ok(());
        }
        let file = self.file.as_ref().ok_or_else(|| {
            bad("a routed prefix that a helper thread observed is revalidated once, by that thread")
        })?;
        let _work = self.payer.reserve(peak(
            row_for(self.row_bytes, self.logical_length),
            self.expected_path.len(),
        )?)?;
        revalidate(
            file,
            &self.expected_path,
            self.logical_length,
            self.prefix,
            self.partition,
            self.row_bytes,
            &self.evidence.digest,
            None,
        )
    }
}
/// The observation made again, held to the digest of the first.
#[allow(clippy::too_many_arguments)]
fn revalidate(
    file: &File,
    path: &str,
    logical: u64,
    prefix: u64,
    partition: u64,
    row: usize,
    digest: &str,
    root: Option<&crate::file_storage::HeldVolumeRoot>,
) -> io::Result<()> {
    let current = capture(file, path, logical, prefix, partition, row, root)?;
    if current.digest != digest {
        return Err(bad(
            "private routed prefix identity/mapping/storage proof changed",
        ));
    }
    Ok(())
}
/// What [`observe`] will ask Windows about this prefix, for a batch whose
/// helper thread asks it. `None` where `observe` does not come to ask: it
/// then says why itself, as it does for every stream taken by itself.
pub(super) fn plan<'tree>(
    tree: &'tree PrivateTree,
    index: usize,
    name: &[u16],
    components: &[String],
    logical: u64,
    prefix: u64,
) -> Option<Plan<'tree>> {
    tree.memory.as_ref()?;
    let admission = tree.metadata_resource_admission?;
    let row = usize::try_from(admission.budget.max_row_bytes).ok()?;
    if prefix == 0
        || !crate::target_cluster::aligned(prefix)
        || prefix != crate::target_cluster::floor(logical)
    {
        return None;
    }
    let key = StreamKey::named(index, name);
    if tree.sparse_targets.contains_key(&key) {
        return None;
    }
    let file = tree.files.get(&key)?;
    let path = streams::path(&tree.pair.shadow.volume_path().ok()?, components, name).ok()?;
    Some(Plan {
        file,
        prepared: tree.placement_complete && file.valid_prefix() >= prefix,
        path,
        logical,
        prefix,
        partition: tree.pair.shadow.identity.partition_bytes,
        row,
        root: tree.shadow_root_once(),
    })
}
impl Plan<'_> {
    /// The workspace [`observe`] reserves for this prefix.
    pub(super) fn observation_bytes(&self) -> io::Result<u64> {
        peak(row_for(self.row, self.logical), 32768)
    }
    /// The workspace [`RoutedPrefixReady::revalidate`] reserves for it.
    pub(super) fn revalidation_bytes(&self) -> io::Result<u64> {
        peak(row_for(self.row, self.logical), self.path.len())
    }
    /// The Windows calls of one [`observe`] and of the `revalidate` after
    /// it, on a helper thread: the same calls in the same order, on one
    /// duplicate that is closed before this returns. Every workspace is the
    /// caller's ([`Self::observation_bytes`], [`Self::revalidation_bytes`]
    /// and the file's mapping workspace).
    ///
    /// In a run that verifies each thing once the `revalidate` is not made:
    /// it was the same capture again on the same duplicate, at once, with
    /// nothing asked of the file between the two. The file is held by this
    /// process and nothing else writes to the shadow; the planning pass
    /// keeps the capture's digest in its plan, the mapping of every stream
    /// is compared with its tracked pieces when the capture begins, and the
    /// walk of the frozen shadow captures every stream's mapping, initialized
    /// regions and integrity again. A thorough run makes it as before.
    pub(super) fn observe(&self) -> PrefixSeen {
        let placements = self.file.check_placements_prepaid();
        if placements.is_err() || !self.prepared {
            return PrefixSeen {
                placements,
                observed: None,
            };
        }
        let observed = (|| {
            let duplicate = crate::file_storage::duplicate_readonly(self.file.metadata_handle())?;
            crate::file_storage::require_readonly_access(&duplicate)?;
            let evidence = capture(
                &duplicate,
                &self.path,
                self.logical,
                self.prefix,
                self.partition,
                self.row,
                self.root,
            )?;
            let revalidated = if crate::verify_policy::verifies_once() {
                Ok(())
            } else {
                revalidate(
                    &duplicate,
                    &self.path,
                    self.logical,
                    self.prefix,
                    self.partition,
                    self.row,
                    &evidence.digest,
                    self.root,
                )
            };
            Ok((evidence, revalidated))
        })();
        PrefixSeen {
            placements,
            observed: Some(observed),
        }
    }
}
/// `prepaid` is this observation as a batch made it ready ([`Plan`]): the
/// comparison of the file's mapping, the observation of the prefix and its
/// revalidation are then what the batch's helper thread returned for them,
/// taken where this function and `revalidate` make them, and the workspace
/// is the one the batch reserved. Everything else is done here, in the same
/// order, whoever observed the file.
pub(super) fn observe(
    tree: &PrivateTree,
    index: usize,
    name: &[u16],
    components: &[String],
    logical: u64,
    prefix: u64,
    prepaid: Option<PrepaidPrefix>,
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
    let (seen_placements, seen_observed, prepaid_work) = match prepaid {
        Some(batch) => (
            Some(batch.seen.placements),
            batch.seen.observed,
            Some(batch.work),
        ),
        None => (None, None, None),
    };
    let mut work = match prepaid_work {
        Some(lease) => lease,
        None => payer.reserve(peak(row_for(row, logical), 32768)?)?,
    };
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
    tree.validate_stream_shape_observed(index, name, components, logical, seen_placements)?;
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
    let (duplicate, evidence, seen_revalidation) = match seen_observed {
        Some(observed) => {
            let (evidence, revalidated) = observed?;
            (None, evidence, Some(revalidated))
        }
        None => {
            let duplicate = crate::file_storage::duplicate_readonly(file.metadata_handle())?;
            crate::file_storage::require_readonly_access(&duplicate)?;
            let evidence = capture(
                &duplicate,
                &path,
                logical,
                prefix,
                tree.pair.shadow.identity.partition_bytes,
                row,
                tree.shadow_root_once(),
            )?;
            (Some(duplicate), evidence, None)
        }
    };
    tree.require_source_excluded()?;
    work.shrink_to(retained_bytes(&evidence, &path)?)?;
    Ok(RoutedPrefixReady {
        just_captured: std::cell::Cell::new(duplicate.is_some()),
        file: duplicate,
        seen_revalidation: std::cell::Cell::new(seen_revalidation),
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

#[cfg(test)]
mod workspace_tests {
    use super::*;

    #[test]
    fn a_prefixs_observation_reserves_for_the_file_not_for_the_largest_row() {
        const MIB: u64 = 1024 * 1024;
        // A machine with 16 GB free limits a row to 141 MiB: four of those
        // were reserved to observe the prefix of any file. A file of a
        // megabyte takes under 5 MiB, the same on every machine,
        let small = peak(row_for(141 << 20, 1 << 20), 32768).unwrap();
        assert!(small < 5 * MIB + MIB / 2, "{small}");
        assert_eq!(small, peak(row_for(600 << 20, 1 << 20), 32768).unwrap());
        // a longer file more, and none more than the row allowed before.
        let long = peak(row_for(141 << 20, 1 << 40), 32768).unwrap();
        assert!(long > small && long <= peak(141 << 20, 32768).unwrap());
        assert_eq!(row_for(4096, 1 << 40), 4096);
    }
}
