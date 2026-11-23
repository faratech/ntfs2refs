//! One read-only stream batch. Live immutable tree ownership and actual
//! same-FileObject duplicates scope the cached summary/ranges to this callback.
//! No snapshot can cross a tree write, serialize authority, or expose handles.
use super::*;

#[derive(PartialEq, Eq)]
struct Metadata {
    basic: [u8; 40],
    standard: [u8; 24],
    identity: [u8; 24],
    tag: [u8; 8],
    security: Vec<u8>,
}
impl Metadata {
    fn capture(file: &File) -> io::Result<Self> {
        validate_open_type(file, false)?;
        let value = Self {
            basic: info(file, 0, 40)?
                .try_into()
                .map_err(|_| invalid("supply basic size differs"))?,
            standard: info(file, 1, 24)?
                .try_into()
                .map_err(|_| invalid("supply standard size differs"))?,
            identity: info(file, 18, 24)?
                .try_into()
                .map_err(|_| invalid("supply identity size differs"))?,
            tag: info(file, 9, 8)?
                .try_into()
                .map_err(|_| invalid("supply tag size differs"))?,
            security: super::routed_prefix::security(file)?,
        };
        if value.standard[20] != 0
            || value.standard[21] != 0
            || u32::from_le_bytes(value.standard[16..20].try_into().unwrap()) != 1
        {
            return Err(invalid(
                "supply snapshot file link/type/delete state differs",
            ));
        }
        Ok(value)
    }
}
struct NativeFile {
    file: File,
    metadata: Metadata,
    mapping: Option<[u8; 32]>,
}
impl NativeFile {
    /// `prepaid`: the workspace of the mapping query is held by the caller
    /// already (a helper thread of a batch); otherwise it is reserved here.
    fn capture(
        file: &File,
        placeholder: Option<&unwritten::PrivatePlaceholder>,
        prepaid: bool,
    ) -> io::Result<Self> {
        let duplicate = crate::file_storage::duplicate_readonly(file)?;
        crate::file_storage::require_readonly_access(&duplicate)?;
        let metadata = Metadata::capture(&duplicate)?;
        let mapping = placeholder
            .map(|p| p.readonly_supply_mapping_fingerprint(&duplicate, prepaid))
            .transpose()?
            .flatten();
        if !crate::verify_policy::verifies_once() && Metadata::capture(&duplicate)? != metadata {
            return Err(invalid(
                "supply snapshot metadata changed during map capture",
            ));
        }
        Ok(Self {
            file: duplicate,
            metadata,
            mapping,
        })
    }
    fn revalidate(
        &self,
        placeholder: Option<&unwritten::PrivatePlaceholder>,
        prepaid: bool,
    ) -> io::Result<()> {
        let before = Metadata::capture(&self.file)?;
        let mapping = placeholder
            .map(|p| p.readonly_supply_mapping_fingerprint(&self.file, prepaid))
            .transpose()?
            .flatten();
        let after = Metadata::capture(&self.file)?;
        if before != self.metadata || after != self.metadata || mapping != self.mapping {
            return Err(invalid(
                "readonly supply snapshot metadata/security/complete map changed",
            ));
        }
        Ok(())
    }
}

/// What a helper thread of a batch saw of one stream's snapshot: the two
/// observations [`with_snapshot`] makes of the stream's files, in its order.
pub(super) struct SnapshotSeen {
    /// The capture of the stream's own file and then of its sparse target.
    captured: io::Result<()>,
    /// Their revalidation, made where both captures held. A snapshot whose
    /// capture failed never comes to it.
    revalidated: io::Result<()>,
}
/// The capture and the revalidation of [`with_snapshot`] for one stream, on
/// a helper thread: the same queries of the same duplicates, one after the
/// other with nothing between them, where the calling thread derives the
/// stream's ranges between the two. The duplicates are closed before this
/// returns. The mapping query's workspace is the caller's.
pub(super) fn observe_prepaid(
    primary: Option<&unwritten::PrivatePlaceholder>,
    sparse: Option<&File>,
) -> SnapshotSeen {
    let captured = (|| {
        let primary = primary
            .map(|file| NativeFile::capture(file.metadata_handle(), Some(file), true))
            .transpose()?;
        let sparse = sparse
            .map(|file| NativeFile::capture(file, None, true))
            .transpose()?;
        Ok::<_, io::Error>((primary, sparse))
    })();
    match captured {
        Err(error) => SnapshotSeen {
            captured: Err(error),
            revalidated: Ok(()),
        },
        Ok((native, native_sparse)) => SnapshotSeen {
            captured: Ok(()),
            revalidated: if crate::verify_policy::verifies_once() {
                Ok(())
            } else {
                (|| {
                    if let Some(file) = &native {
                        file.revalidate(primary, true)?;
                    }
                    if let Some(file) = &native_sparse {
                        file.revalidate(None, true)?;
                    }
                    Ok(())
                })()
            },
        },
    }
}
impl SnapshotSeen {
    /// Whether the pass goes on beyond this snapshot.
    pub(super) fn held(&self) -> bool {
        self.captured.is_ok() && self.revalidated.is_ok()
    }
}
/// A stream's snapshot as a batch made it ready: what its helper saw, and
/// the two reservations of [`with_snapshot`], which the batch made before
/// the helper started.
pub(super) struct PrepaidSnapshot {
    pub(super) seen: SnapshotSeen,
    pub(super) memory: Box<dyn report_memory::ReportMemoryLease>,
    pub(super) ranges_memory: Box<dyn report_memory::ReportMemoryLease>,
}

/// Issued only inside with_readonly_supply_stream_snapshot. The immutable
/// borrow prevents any safe PrivateTree write while this native batch exists.
pub struct NativeReadOnlySupplyStreamSnapshot<'tree> {
    tree: &'tree PrivateTree,
    key: StreamKey,
    primary: Option<NativeFile>,
    sparse: Option<NativeFile>,
    // The revalidation as a helper thread of a batch made it, which then
    // made the captures too and closed its duplicates: no file is held
    // above. Taken by the one revalidation every snapshot ends with.
    seen_revalidation: std::cell::Cell<Option<io::Result<()>>>,
    summary: StreamSupplySummary,
    ranges: Vec<(SupplyKind, SupplyRange)>,
    // The actual shared payer stays live until every native handle, key,
    // descriptor, summary and range above has dropped.
    _memory: Box<dyn report_memory::ReportMemoryLease>,
    _ranges_memory: Box<dyn report_memory::ReportMemoryLease>,
}
impl NativeReadOnlySupplyStreamSnapshot<'_> {
    pub fn summary(&self) -> &StreamSupplySummary {
        &self.summary
    }
    pub fn ranges(&self) -> &[(SupplyKind, SupplyRange)] {
        &self.ranges
    }
    pub(super) fn tree(&self) -> &PrivateTree {
        self.tree
    }
    pub(super) fn key(&self) -> &StreamKey {
        &self.key
    }
    fn revalidate(&self) -> io::Result<()> {
        if let Some(seen) = self.seen_revalidation.take() {
            return seen;
        }
        if let Some(file) = &self.primary {
            file.revalidate(self.tree.files.get(&self.key), false)?;
        }
        if let Some(file) = &self.sparse {
            file.revalidate(None, false)?;
        }
        Ok(())
    }
}
/// The handles this tree holds, with the eight its fences count for the
/// volume, the privilege leases and temporary control opens, and the
/// shadow's root where the tree holds it open (`PrivateTree::shadow_root`).
fn owned_handles(tree: &PrivateTree) -> Option<u64> {
    (tree.files.len() as u64)
        .checked_add(tree.sparse_targets.len() as u64)
        .and_then(|n| n.checked_add(tree.metadata_targets.len() as u64))
        .and_then(|n| n.checked_add(u64::from(tree.carrier_directory.is_some())))
        .and_then(|n| n.checked_add(u64::from(tree.dedicated_source.is_some())))
        .and_then(|n| n.checked_add(u64::from(tree.shadow_root.get().is_some())))
        .and_then(|n| n.checked_add(8))
}
/// Whether the tree's handle slots have room for a batch's helper threads:
/// each holds at most a stream's two duplicates and the volume root a path
/// comparison opens, where one stream at a time holds two.
pub(super) fn handles_admit_helpers(tree: &PrivateTree, threads: usize) -> bool {
    let Some(admission) = tree.metadata_resource_admission else {
        return false;
    };
    owned_handles(tree)
        .and_then(|held| held.checked_add((threads as u64).checked_mul(3)?))
        .is_some_and(|handles| handles <= admission.budget.handle_slots)
}
/// The most ranges a stream's snapshot can have and what holding them
/// takes. The dense interval partition contributes at most two pieces per
/// retained reference. Each sparse island boundary adds one split and each
/// declared logical hole one range; no row maximum is leased for an
/// ordinary one-range stream.
pub(super) fn range_bound(
    tree: &PrivateTree,
    key: &StreamKey,
    name: &[u16],
    maximum: u64,
) -> io::Result<(usize, u64)> {
    let sparse = tree.sparse_targets.get(key);
    let references = tree.original_coordinates.get(key).map_or(0, Vec::len);
    let maximum_ranges = references
        .checked_mul(2)
        .and_then(|n| n.checked_add(sparse.map_or(0, |t| t.islands.len())))
        .and_then(|n| n.checked_add(sparse.map_or(0, |t| t.layout.holes.len())))
        .and_then(|n| n.checked_add(4))
        .ok_or_else(|| invalid("supply snapshot range count overflow"))?;
    let per_range = (std::mem::size_of::<(SupplyKind, SupplyRange)>() as u64)
        .checked_add(
            (name.len() as u64)
                .checked_mul(2)
                .ok_or_else(|| invalid("supply name RAM overflow"))?,
        )
        .ok_or_else(|| invalid("supply range RAM overflow"))?;
    let range_memory = (maximum_ranges as u64)
        .checked_mul(per_range)
        .and_then(|n| n.checked_mul(2))
        .and_then(|n| n.checked_add(4096))
        .ok_or_else(|| invalid("supply snapshot range RAM overflow"))?;
    if range_memory > maximum {
        return Err(invalid(
            "readonly supply interval bounds exceed actual row budget",
        ));
    }
    Ok((maximum_ranges, range_memory))
}
/// The most a stream's ranges may take: the caller's window, and no more
/// than eight of the rows the admission allows.
pub(super) fn range_window(
    admission: &crate::tree_resources::SourceResourceAdmission,
    maximum_range_bytes: u64,
) -> io::Result<u64> {
    Ok(maximum_range_bytes.min(
        admission
            .budget
            .max_row_bytes
            .checked_mul(8)
            .ok_or_else(|| invalid("supply snapshot row overflow"))?,
    ))
}
/// The ranges of one stream as its snapshot gathers them: counted against
/// the window and against the bound they were paid for by.
pub(super) struct RangeSink {
    ranges: Vec<(SupplyKind, SupplyRange)>,
    bytes: u64,
    maximum: u64,
    maximum_ranges: usize,
}
impl RangeSink {
    pub(super) fn new(maximum: u64, maximum_ranges: usize) -> io::Result<Self> {
        let mut ranges = Vec::new();
        ranges
            .try_reserve_exact(maximum_ranges)
            .map_err(io::Error::other)?;
        if ranges.capacity() > maximum_ranges.saturating_mul(2) {
            return Err(invalid("snapshot range vector exceeds paid capacity"));
        }
        Ok(Self {
            ranges,
            bytes: 0,
            maximum,
            maximum_ranges,
        })
    }
    pub(super) fn push(&mut self, kind: SupplyKind, range: &SupplyRange) -> io::Result<()> {
        let next = (std::mem::size_of::<(SupplyKind, SupplyRange)>() as u64)
            .checked_add(
                (range.stream_name_utf16.len() as u64)
                    .checked_mul(2)
                    .ok_or_else(|| invalid("snapshot stream name overflow"))?,
            )
            .ok_or_else(|| invalid("snapshot range size overflow"))?;
        self.bytes = self
            .bytes
            .checked_add(next)
            .ok_or_else(|| invalid("snapshot range total overflow"))?;
        if self.bytes > self.maximum {
            return Err(invalid("readonly supply ranges exceed actual row budget"));
        }
        if self.ranges.len() == self.maximum_ranges {
            return Err(invalid(
                "snapshot range count exceeds actual interval bound",
            ));
        }
        self.ranges.push((kind, range.clone()));
        Ok(())
    }
    pub(super) fn ranges(&self) -> &[(SupplyKind, SupplyRange)] {
        &self.ranges
    }
    fn into_ranges(self) -> Vec<(SupplyKind, SupplyRange)> {
        self.ranges
    }
}
pub(super) fn close_result<T>(
    result: io::Result<T>,
    closing: io::Result<()>,
    label: &str,
) -> io::Result<T> {
    match (result, closing) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Err(close)) => Err(io::Error::new(
            error.kind(),
            format!("{error}; {label} also failed: {close}"),
        )),
        (Err(error), _) => Err(error),
        (_, Err(error)) => Err(io::Error::new(error.kind(), format!("{label}: {error}"))),
    }
}
pub(super) fn with_snapshot<T>(
    tree: &PrivateTree,
    index: usize,
    name: &[u16],
    components: &[String],
    logical: u64,
    maximum_range_bytes: u64,
    prepaid: Option<PrepaidSnapshot>,
    consume: impl FnOnce(&NativeReadOnlySupplyStreamSnapshot<'_>) -> io::Result<T>,
) -> io::Result<T> {
    // Native full source/shadow fences are PER STREAM, never cached across a
    // write or callback. Even creation/callback failures execute the closing.
    //
    // `prepaid` is this stream as a batch made it ready: the capture and the
    // revalidation of its files are then what the batch's helper thread
    // returned for them, taken where this function makes them, and its two
    // reservations are the ones the batch made. Everything else is done
    // here, in the same order, whoever observed the files.
    let opening = tree.require_source_excluded();
    let result = (|| {
        opening?;
        if !tree.placement_complete {
            return Err(invalid(
                "readonly supply snapshot requires complete live placement",
            ));
        }
        let admission = tree
            .metadata_resource_admission
            .ok_or_else(|| invalid("readonly supply snapshot requires V4 admission"))?;
        let payer = tree
            .memory
            .as_ref()
            .ok_or_else(|| invalid("readonly supply snapshot payer absent"))?
            .payer();
        let maximum = range_window(&admission, maximum_range_bytes)?;
        let (seen, prepaid_memory, prepaid_ranges) = match prepaid {
            Some(batch) => (
                Some(batch.seen),
                Some(batch.memory),
                Some(batch.ranges_memory),
            ),
            None => (None, None, None),
        };
        let work = tree
            .supply_stream_workspace_bytes(index, name)?
            .checked_add(1024 * 1024)
            .ok_or_else(|| invalid("supply snapshot RAM overflow"))?;
        // Pay before the first owned key, metadata buffer, or native duplicate.
        let memory = match prepaid_memory {
            Some(lease) => lease,
            None => payer.reserve(work)?,
        };
        let key = tree.validate_stream_shape_metadata(index, name, components, logical)?;
        let primary = tree.files.get(&key);
        let sparse = tree.sparse_targets.get(&key);
        let (maximum_ranges, range_memory) = range_bound(tree, &key, name, maximum)?;
        let range_lease = match prepaid_ranges {
            Some(lease) => lease,
            None => payer.reserve(range_memory)?,
        };
        let extra = usize::from(primary.is_some()) + usize::from(sparse.is_some());
        let handles = owned_handles(tree)
            .and_then(|n| n.checked_add(extra as u64))
            .ok_or_else(|| invalid("supply snapshot handle count overflow"))?;
        if handles > admission.budget.handle_slots {
            return Err(invalid(
                "supply snapshot duplicates exceed actual handle slots",
            ));
        }
        let (primary, sparse, seen_revalidation) = match seen {
            None => (
                primary
                    .map(|file| NativeFile::capture(file.metadata_handle(), Some(file), false))
                    .transpose()?,
                sparse
                    .map(|target| NativeFile::capture(&target.file, None, false))
                    .transpose()?,
                None,
            ),
            Some(seen) => {
                seen.captured?;
                (None, None, Some(seen.revalidated))
            }
        };
        let mut snapshot = NativeReadOnlySupplyStreamSnapshot {
            tree,
            key,
            primary,
            sparse,
            seen_revalidation: std::cell::Cell::new(seen_revalidation),
            summary: StreamSupplySummary {
                logical_bytes: 0,
                materialize_bytes: 0,
                source_reference_bytes: 0,
                hole_bytes: 0,
                ranges: 0,
                ordered_range_sha256: String::new(),
            },
            ranges: Vec::new(),
            _memory: memory,
            _ranges_memory: range_lease,
        };
        let mut ranges = RangeSink::new(maximum, maximum_ranges)?;
        let built = supply::stream_in_snapshot(&snapshot, |kind, range| ranges.push(kind, range));
        let result = match built {
            Ok(summary) => {
                if summary.logical_bytes != logical {
                    return close_result(
                        Err(invalid("snapshot canonical logical length differs")),
                        snapshot.revalidate(),
                        "supply snapshot native closing",
                    );
                }
                snapshot.summary = summary;
                snapshot.ranges = ranges.into_ranges();
                // The callback may reserve/clone bounded app output, but no
                // mutable tree API can run under this immutable borrow.
                consume(&snapshot)
            }
            Err(error) => Err(error),
        };
        close_result(
            result,
            snapshot.revalidate(),
            "supply snapshot native closing",
        )
    })();
    close_result(
        result,
        tree.require_source_excluded(),
        "supply snapshot full source/shadow closing fence",
    )
}
