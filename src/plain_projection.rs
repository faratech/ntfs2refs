//! Which objects of a source a conversion makes into plain files, and what
//! it does to each.
//!
//! An object is converted to plain only on a data volume, only after the
//! user agreed to a list that names it (`plain_consent`), and only by a
//! transform this module names. A [`PlainTransform`] says exactly what is
//! taken off the object; everything else is carried over as for any other
//! object, and the run's own verification holds the new volume to it.
//!
//! What this build converts:
//!
//! - [`PlainKind::AttributesCleared`], the TEMPORARY and OFFLINE attributes
//!   of a file or directory that has no reparse point. ReFS keeps neither as
//!   NTFS does (OFFLINE without a reparse point means nothing to any program
//!   but a hierarchical storage manager, and TEMPORARY is a caching hint),
//!   so the object is carried over with both cleared and its contents
//!   unchanged. An OFFLINE file with a reparse point belongs to such a
//!   manager and is still refused.
//! - [`PlainKind::WofExpanded`], a file WOF's file provider keeps
//!   compressed. Its plain bytes are copied through WOF on the frozen source
//!   (`n2r_win32::plain_copy`) and the new file is made from that copy,
//!   without the reparse point, the WofCompressedData stream and the sparse
//!   and reparse attributes; everything else is carried over.
//! - [`PlainKind::CloudPlaceholderPlain`], a cloud provider's placeholder
//!   (Cloud Files API, OneDrive and others) whose data is wholly on the
//!   volume once the volume is frozen. What was not is downloaded before
//!   the freeze (`drive_plain_prefreeze`), with the user's agreement. The
//!   raw source has to hold every byte of its unnamed stream (no hole below
//!   its length); the new file is then made from a copy read through the
//!   Cloud Files filter recalling nothing, as a WOF file is (the copy holds
//!   the bytes without the sparse layout a placeholder keeps them in),
//!   without the reparse point and the provider's pin, recall, OFFLINE and
//!   sparse marks. A directory placeholder loses its point and marks only.
use crate::{
    ntfs_admission,
    ntfs_inspect::{FileInventory, RootFileDomain},
};
use anyhow::{Context, Result};
pub(crate) use n2r_win32::plain_ledger::{
    CLEARABLE_ATTRIBUTES, ENCRYPTED, LedgerRow, LedgerState, PlainEntry, PlainKind, PlainList,
};

/// What a conversion does to one object to make it a plain file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PlainTransform {
    pub kind: PlainKind,
    /// The Win32 file attributes taken off the object; never anything
    /// outside [`CLEARABLE_ATTRIBUTES`].
    pub cleared_attributes: u32,
}

impl PlainTransform {
    /// The attributes the new object is made with.
    pub(crate) fn target_attributes(self, source_attributes: u32) -> u32 {
        source_attributes & !self.target_cleared()
    }

    /// Every attribute the new object is made without: the cleared ones,
    /// and for a WOF file its reparse point and the sparse unnamed stream
    /// WOF leaves on the source.
    pub(crate) fn target_cleared(self) -> u32 {
        match self.kind {
            PlainKind::WofExpanded => {
                n2r_win32::plain_ledger::REPARSE_POINT | n2r_win32::plain_ledger::SPARSE_FILE
            }
            PlainKind::EfsDecrypted => ENCRYPTED,
            // Its reparse point, the provider's pin and recall marks, and
            // the OFFLINE and sparse marks a placeholder has.
            PlainKind::CloudPlaceholderPlain => CLOUD_CLEARED,
            _ => self.cleared_attributes,
        }
    }
}

/// What a cloud placeholder made plain is made without: what the content
/// verdict takes off its record before (`volume_manifest::declared_after`).
pub(crate) const CLOUD_CLEARED: u32 = n2r_win32::plain_ledger::REPARSE_POINT
    | n2r_win32::plain_ledger::SPARSE_FILE
    | n2r_win32::plain_ledger::CLOUD_ATTRIBUTES
    | n2r_win32::plain_ledger::OFFLINE;

/// The transform an object with these source attributes takes, if any.
///
/// Pure: from the attributes NTFS keeps for the object and whether it has a
/// reparse point. An object with a reparse point takes none (an OFFLINE
/// file with one is a hierarchical storage manager's, and is refused), nor
/// does an EFS-encrypted one, which is refused by name.
pub(crate) fn transform_for(source_attributes: u32, reparse_point: bool) -> Option<PlainTransform> {
    let cleared = source_attributes & CLEARABLE_ATTRIBUTES;
    (cleared != 0 && !reparse_point && source_attributes & ENCRYPTED == 0).then_some(
        PlainTransform {
            kind: PlainKind::AttributesCleared,
            cleared_attributes: cleared,
        },
    )
}

/// A file WOF's file provider keeps compressed, as the raw source shows it:
/// its reparse point of tag 0x80000017 read exactly, an unnamed stream of
/// the file's plain length, and the `WofCompressedData` stream that holds
/// the compressed data. Nothing else.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct WofFile {
    pub algorithm: u32,
    /// The file's length as a program reads it.
    pub plain_bytes: u64,
    /// What `WofCompressedData` takes on the source, freed when the file is
    /// made plain.
    pub compressed_allocated: u64,
}

/// The WOF file `file` is, if it is one.
pub(crate) fn wof_file(file: &FileInventory) -> Result<Option<WofFile>> {
    let Some(point) = crate::ntfs_reparse::file_point(file)? else {
        return Ok(None);
    };
    let Some(algorithm) = n2r_win32::reparse_layout::wof_file_algorithm(&point.buffer) else {
        return Ok(None);
    };
    let compressed: Vec<u16> = n2r_win32::reparse_layout::WOF_COMPRESSED_DATA
        .encode_utf16()
        .collect();
    let unnamed = file.streams.iter().filter(|s| s.name_utf16.is_empty());
    let data = file.streams.iter().filter(|s| s.name_utf16 == compressed);
    let (unnamed, data): (Vec<_>, Vec<_>) = (unnamed.collect(), data.collect());
    anyhow::ensure!(
        !file.is_directory && file.streams.len() == 2 && unnamed.len() == 1 && data.len() == 1,
        "MFT record {}: a WOF reparse point without exactly its unnamed stream and {}",
        file.record_number,
        n2r_win32::reparse_layout::WOF_COMPRESSED_DATA
    );
    Ok(Some(WofFile {
        algorithm,
        plain_bytes: unnamed[0].logical_size,
        compressed_allocated: data[0].allocated_size,
    }))
}

/// What making `files` plain does to the volume: the bytes it grows by
/// (each plain length, rounded up to the target's cluster) and the bytes it
/// frees (each `WofCompressedData` allocation).
pub(crate) fn wof_growth(files: &[WofFile], target_cluster: u64) -> (u64, u64) {
    files.iter().fold((0u64, 0u64), |(grows, frees), file| {
        (
            grows.saturating_add(file.plain_bytes.div_ceil(target_cluster) * target_cluster),
            frees.saturating_add(file.compressed_allocated),
        )
    })
}

/// Refuses, with the numbers, a volume whose WOF files made plain would not
/// fit in its free space.
pub(crate) fn require_wof_room(files: &[WofFile], target_cluster: u64, free: u64) -> Result<()> {
    let (grows, frees) = wof_growth(files, target_cluster);
    let needed = grows.saturating_sub(frees);
    anyhow::ensure!(
        needed <= free,
        "the {} file(s) WOF keeps compressed take {grows} bytes made plain (in {target_cluster}-byte clusters), {frees} bytes of their compressed data are freed, so the volume needs {needed} more bytes, and {free} are free. Free {} bytes, or expand some of the files with `compact /u /exe <file>` and convert then. Nothing was changed",
        files.len(),
        needed - free
    );
    Ok(())
}

/// What a check says of the files WOF keeps compressed: what making them
/// plain takes, and whether it fits.
pub(crate) fn wof_note(files: &[WofFile], target_cluster: u64, free: u64) -> String {
    let (grows, frees) = wof_growth(files, target_cluster);
    format!(
        "{} file(s) are kept compressed by WOF. Made plain they would take {grows} bytes and free {frees}: {}.",
        files.len(),
        match require_wof_room(files, target_cluster, free) {
            Ok(()) => format!(
                "{} more bytes, and {free} are free",
                grows.saturating_sub(frees)
            ),
            Err(_) => format!(
                "{} more bytes, and only {free} are free",
                grows.saturating_sub(frees)
            ),
        }
    )
}

/// Whether `stream` is WOF's WofCompressedData.
pub(crate) fn is_wof_compressed_data(stream: &crate::ntfs_inspect::StreamInventory) -> bool {
    stream
        .name_utf16
        .iter()
        .copied()
        .eq(n2r_win32::reparse_layout::WOF_COMPRESSED_DATA.encode_utf16())
}

/// The plain copy key of a WOF file's unnamed stream.
pub(crate) fn copy_key(file: &FileInventory) -> n2r_win32::plain_copy::PlainCopyKey {
    n2r_win32::plain_copy::PlainCopyKey {
        record_number: file.record_number,
        sequence_number: file.sequence_number,
        stream_name_utf16: Vec::new(),
    }
}

/// Whether this run makes `file` a plain file from its WOF copy (where
/// `wof_expanded` is enabled, `PlainKind::implemented`). The stream it
/// leaves off is declared by the ledger (`DeclaredDrops`), and every count
/// of the new tree against the source's admission expects it so.
pub(crate) fn wof_taken(file: &FileInventory) -> bool {
    PlainKind::WofExpanded.implemented()
        && crate::plain_consent::takes_plain()
        && wof_file(file).ok().flatten().is_some()
}

/// The name of the logged utility stream in which EFS keeps a file's keys.
const EFS_ATTRIBUTE_NAME: &str = "$EFS";
/// Said wherever a run cannot read an EFS-encrypted file it would make plain.
pub(crate) const EFS_KEY_REMEDY: &str = "this account holds no EFS key for it. Run the conversion as the user who encrypted the file, import that user's EFS certificate and key (certmgr.msc, or cipher /x on the machine it came from), or run it as the volume's data recovery agent; or decrypt it first with `cipher /d <file>`";

/// What EFS has made of an object, as the raw source shows it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum EfsObject {
    /// A directory marked encrypted: new files in it are encrypted. Only
    /// the mark is taken off.
    Directory,
    /// An encrypted file: exactly one, unnamed, encrypted DATA stream and
    /// its `$EFS` attribute.
    File(EfsFile),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct EfsFile {
    /// The plain text's length, as the owner reads it.
    pub plain_bytes: u64,
    /// The raw `$EFS` attribute: its resident digest, or a SHA-256 of where
    /// it lies.
    pub efs_attribute_digest: String,
    /// A SHA-256 of where the ciphertext lies (its extents and sizes).
    pub ciphertext_extents_sha256: String,
}

fn is_efs_attribute(attribute: &crate::ntfs_inspect::AttributeInventory) -> bool {
    attribute.type_code == 0x100
        && attribute
            .name_utf16
            .iter()
            .copied()
            .eq(EFS_ATTRIBUTE_NAME.encode_utf16())
}

/// Whether `attribute` is one an EFS object made plain leaves behind or
/// has decrypted: its `$EFS` attribute, or its encrypted DATA.
pub(crate) fn efs_attribute(attribute: &crate::ntfs_inspect::AttributeInventory) -> bool {
    is_efs_attribute(attribute) || (attribute.type_code == 0x80 && attribute.flags == 0x4000)
}

fn sha256_json(value: &impl serde::Serialize) -> Result<String> {
    use sha2::Digest;
    Ok(hex::encode(sha2::Sha256::digest(serde_json::to_vec(
        value,
    )?)))
}

/// The EFS object `file` is, if it is one this build makes plain. An
/// encrypted file of another shape (named streams, compressed or sparse
/// and encrypted, a reparse point) is none, and is refused by name.
pub(crate) fn efs_object(file: &FileInventory) -> Result<Option<EfsObject>> {
    let attributes = crate::ntfs_file_attributes::project_user(file)?.source_attributes;
    if attributes & ENCRYPTED == 0 || crate::ntfs_reparse::file_point(file)?.is_some() {
        return Ok(None);
    }
    let efs: Vec<_> = file
        .attributes
        .iter()
        .filter(|a| is_efs_attribute(a))
        .collect();
    if file.is_directory {
        return Ok((efs.len() <= 1 && file.streams.is_empty()).then_some(EfsObject::Directory));
    }
    let [stream] = file.streams.as_slice() else {
        return Ok(None);
    };
    let [efs] = efs.as_slice() else {
        return Ok(None);
    };
    if !stream.name_utf16.is_empty() || stream.flags != 0x4000 || stream.resident {
        return Ok(None);
    }
    Ok(Some(EfsObject::File(EfsFile {
        plain_bytes: stream.logical_size,
        efs_attribute_digest: match &efs.resident_sha256 {
            Some(digest) if efs.resident => digest.clone(),
            _ => sha256_json(&(&efs.extents, efs.logical_size, efs.allocated_size))?,
        },
        ciphertext_extents_sha256: sha256_json(&(
            &stream.extents,
            stream.logical_size,
            stream.initialized_size,
            stream.allocated_size,
        ))?,
    })))
}

pub(crate) use crate::ntfs_inspect::efs_blocker;

/// Whether this run makes `file` a plain object from EFS (where
/// `efs_decrypted` is enabled, `PlainKind::implemented`).
pub(crate) fn efs_taken(file: &FileInventory) -> bool {
    PlainKind::EfsDecrypted.implemented()
        && crate::plain_consent::takes_plain()
        && efs_object(file).ok().flatten().is_some()
}

/// Said wherever a cloud placeholder is refused because its data is not on
/// the volume.
pub(crate) const CLOUD_REMEDY: &str = "start its cloud provider (OneDrive, say) so that the conversion can download it before the volume is frozen, or make it always available on this device; or agree to leave it out, which keeps it in the cloud and not on the new volume";

/// What the Cloud Files API's placeholders become, said with the question.
/// OneDrive and the Cloud Files API do not run on ReFS.
pub(crate) const CLOUD_WARNING: &str = "OneDrive and other Cloud Files API providers do not run on ReFS: after the conversion the folders they synced stop syncing, and their files are ordinary files that are not uploaded or updated any more. Move the provider's folder to an NTFS volume first to keep it syncing";

/// A cloud provider's placeholder (Cloud Files API, reparse tags
/// 0x9000x01A), as the raw source shows it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CloudPlaceholder {
    pub tag: u32,
    pub directory: bool,
    /// The file's length as a program reads it (0 for a directory).
    pub plain_bytes: u64,
    /// The bytes of its unnamed stream the raw source holds no clusters
    /// for (holes), below its length: what is not on the volume.
    pub raw_missing_bytes: u64,
}

/// The bytes of `stream` below its length that no allocated cluster holds.
pub(crate) fn raw_missing_bytes(stream: &crate::ntfs_inspect::StreamInventory) -> u64 {
    if stream.resident {
        return 0;
    }
    let present: Vec<n2r_win32::cloud_native::FileRange> = stream
        .extents
        .iter()
        .filter(|extent| extent.physical_offset.is_some())
        .map(|extent| n2r_win32::cloud_native::FileRange {
            offset: extent.logical_offset,
            length: extent.length,
        })
        .collect();
    stream.logical_size - n2r_win32::cloud_native::present_bytes(stream.logical_size, &present)
}

/// The cloud placeholder `file` is, if it is one of a shape this build
/// makes plain: a directory with no data stream, or a file whose unnamed
/// stream is neither compressed nor encrypted. Anything else with a cloud
/// tag is refused by admission, by name.
pub(crate) fn cloud_placeholder(file: &FileInventory) -> Result<Option<CloudPlaceholder>> {
    let Some(point) = crate::ntfs_reparse::file_point(file)? else {
        return Ok(None);
    };
    if !n2r_win32::reparse_layout::is_cloud_tag(point.tag()) {
        return Ok(None);
    }
    if file.is_directory {
        return Ok(file.streams.is_empty().then_some(CloudPlaceholder {
            tag: point.tag(),
            directory: true,
            plain_bytes: 0,
            raw_missing_bytes: 0,
        }));
    }
    let unnamed: Vec<_> = file
        .streams
        .iter()
        .filter(|s| s.name_utf16.is_empty())
        .collect();
    let [stream] = unnamed.as_slice() else {
        return Ok(None);
    };
    if !matches!(stream.flags, 0 | 0x8000) {
        return Ok(None);
    }
    Ok(Some(CloudPlaceholder {
        tag: point.tag(),
        directory: false,
        plain_bytes: stream.logical_size,
        raw_missing_bytes: raw_missing_bytes(stream),
    }))
}

/// Whether this run makes `file`, a cloud placeholder, plain (where
/// `cloud_placeholder_plain` is enabled). Whether its data is on the volume
/// is held at the freeze ([`census`]), not here: before the freeze a run
/// downloads what is not.
pub(crate) fn cloud_taken(file: &FileInventory) -> bool {
    PlainKind::CloudPlaceholderPlain.implemented()
        && crate::plain_consent::takes_plain()
        && cloud_placeholder(file).ok().flatten().is_some()
}

/// The plain copy `file`'s new unnamed stream is made from: a WOF file's,
/// read through WOF, an EFS file's, decrypted, or a cloud placeholder's,
/// read through the Cloud Files filter recalling nothing. It has to have
/// been taken.
pub(crate) fn plain_copy_pin(
    file: &FileInventory,
) -> Result<Option<n2r_win32::plain_copy::PlainCopyPin>> {
    let copied = wof_taken(file)
        || (efs_taken(file) && matches!(efs_object(file)?, Some(EfsObject::File(_))))
        || (cloud_taken(file) && !file.is_directory);
    if !copied {
        return Ok(None);
    }
    n2r_win32::plain_copy::taken_pin(&copy_key(file))
        .map(Some)
        .with_context(|| {
            format!(
                "MFT record {} is made plain from its copy, which was not taken",
                file.record_number
            )
        })
}

/// The object a native observation of `file` is compared with, where this
/// run makes it plain from its copy: the raw source as the filter that owns
/// it shows it to Windows, and nothing else changed.
///
/// - WOF hides its reparse point, the REPARSE_POINT and SPARSE_FILE
///   attributes and its WofCompressedData stream (the lab's listing of a
///   `compact /exe` file shows attributes 0x20, one stream, the full length).
/// - Either way the unnamed stream's contents are what the filter reads,
///   which the plain copy holds: Windows' read of it is held to the copy's
///   content digest, and never left unread as a plain stream would be.
///
/// `None` for every other object, which is compared as it is.
pub(crate) fn observed_view(file: &FileInventory) -> Result<Option<FileInventory>> {
    let Some(pin) = plain_copy_pin(file)? else {
        return Ok(None);
    };
    filter_view(file, wof_taken(file), &pin.content_digest).map(Some)
}

/// [`observed_view`] of a file whose copy has `content_digest`; `wof`
/// where WOF owns it.
fn filter_view(file: &FileInventory, wof: bool, content_digest: &str) -> Result<FileInventory> {
    let mut view = file.clone();
    if wof {
        view.reparse = None;
        view.attributes.retain(|attribute| {
            attribute.type_code != 0xc0
                && !(attribute.type_code == 0x80
                    && attribute
                        .name_utf16
                        .iter()
                        .copied()
                        .eq(n2r_win32::reparse_layout::WOF_COMPRESSED_DATA.encode_utf16()))
        });
        view.streams
            .retain(|stream| !is_wof_compressed_data(stream));
        if let Some(information) = view.standard_information.as_mut() {
            information.file_attributes &=
                !(n2r_win32::plain_ledger::REPARSE_POINT | n2r_win32::plain_ledger::SPARSE_FILE);
        }
    }
    let unnamed = view
        .streams
        .iter_mut()
        .find(|stream| stream.name_utf16.is_empty())
        .with_context(|| format!("MFT record {} has no unnamed stream", file.record_number))?;
    // EFS: Windows reads the encrypted stream decrypted, as an ordinary one.
    unnamed.flags &= !0x4000;
    // WOF: Windows shows the stream as an ordinary one, not sparse (the lab:
    // attributes 0x20 where the raw record gives 0x220).
    if wof {
        unnamed.flags &= !0x8000;
    }
    unnamed.logical_sha256 = Some(content_digest.to_owned());
    unnamed.logical_hash_status = crate::ntfs_inspect::LogicalHashStatus::Complete;
    for attribute in view
        .attributes
        .iter_mut()
        .filter(|attribute| attribute.type_code == 0x80 && attribute.name_utf16.is_empty())
    {
        attribute.flags &= !0x4000;
        if wof {
            attribute.flags &= !0x8000;
        }
    }
    Ok(view)
}

/// Whether a stream's allocation, as Windows reports it, is held by its
/// plain copy rather than by the raw record: the unnamed stream of an object
/// this run makes plain from a copy. WOF reports the allocation of its
/// compressed data for it, which no raw extent of the stream accounts for;
/// the stream's contents are held to the copy's digest instead.
pub(crate) fn allocation_held_by_copy(
    record_number: u64,
    sequence_number: u16,
    stream_name_utf16: &[u16],
) -> bool {
    stream_name_utf16.is_empty()
        && n2r_win32::plain_copy::taken_pin(&n2r_win32::plain_copy::PlainCopyKey {
            record_number,
            sequence_number,
            stream_name_utf16: Vec::new(),
        })
        .is_some()
}

/// The transform of one file or directory, from its raw record.
pub(crate) fn of_file(file: &FileInventory) -> Result<Option<PlainTransform>> {
    // An EFS object of another shape is refused by admission, by name.
    if PlainKind::EfsDecrypted.implemented() && efs_object(file).ok().flatten().is_some() {
        return Ok(Some(PlainTransform {
            kind: PlainKind::EfsDecrypted,
            cleared_attributes: 0,
        }));
    }
    // A cloud placeholder of another shape is refused by admission, by name.
    if PlainKind::CloudPlaceholderPlain.implemented()
        && cloud_placeholder(file).ok().flatten().is_some()
    {
        return Ok(Some(PlainTransform {
            kind: PlainKind::CloudPlaceholderPlain,
            cleared_attributes: 0,
        }));
    }
    // A WOF point of another shape is refused by admission, by name, and
    // every WOF file while `wof_expanded` is not enabled.
    if PlainKind::WofExpanded.implemented() && wof_file(file).ok().flatten().is_some() {
        return Ok(Some(PlainTransform {
            kind: PlainKind::WofExpanded,
            cleared_attributes: 0,
        }));
    }
    let projected = crate::ntfs_file_attributes::project_user(file)?;
    let reparse = crate::ntfs_reparse::file_point(file)?.is_some();
    Ok(transform_for(projected.source_attributes, reparse))
}

/// The attributes admission accepts on an object because a conversion to
/// plain takes them off: none unless this run takes objects to plain.
pub(crate) fn admitted_attributes(reparse_point: bool) -> u32 {
    if crate::plain_consent::takes_plain() && !reparse_point {
        CLEARABLE_ATTRIBUTES
    } else {
        0
    }
}

/// The attributes the new object is made without, for this run.
pub(crate) fn cleared_on_target(file: &FileInventory) -> Result<u32> {
    if !crate::plain_consent::takes_plain() {
        return Ok(0);
    }
    Ok(of_file(file)?.map_or(0, PlainTransform::target_cleared))
}

/// A path as a listing names it: `\` and the components.
pub(crate) fn listing_path(components: &[String]) -> String {
    format!("\\{}", components.join("\\"))
}

/// The list entry for one object.
pub(crate) fn entry(path: String, file: &FileInventory, transform: PlainTransform) -> PlainEntry {
    let wof = wof_file(file).ok().flatten();
    // An EFS file's plain text, kept in the working storage until the run
    // ends; on the new volume it takes what its ciphertext took.
    if let Some(efs) = (transform.kind == PlainKind::EfsDecrypted)
        .then(|| efs_object(file).ok().flatten())
        .flatten()
    {
        let plain = match efs {
            EfsObject::File(file) => file.plain_bytes,
            EfsObject::Directory => 0,
        };
        return PlainEntry {
            kind: transform.kind,
            path,
            cleared_attributes: transform.cleared_attributes,
            bytes: plain,
            volume_extra_bytes: 0,
            working_extra_bytes: plain,
            download_bytes: 0,
        };
    }
    // A cloud placeholder's plain copy, kept in the working storage; what
    // the raw source does not hold of it is downloaded before the freeze
    // (the check replaces this with what the Cloud Files API reports).
    if let Some(cloud) = (transform.kind == PlainKind::CloudPlaceholderPlain)
        .then(|| cloud_placeholder(file).ok().flatten())
        .flatten()
    {
        return PlainEntry {
            kind: transform.kind,
            path,
            cleared_attributes: transform.cleared_attributes,
            bytes: cloud.plain_bytes,
            volume_extra_bytes: 0,
            working_extra_bytes: cloud.plain_bytes,
            download_bytes: cloud.raw_missing_bytes,
        };
    }
    let cluster = n2r_win32::target_cluster::bytes();
    PlainEntry {
        kind: transform.kind,
        path,
        cleared_attributes: transform.cleared_attributes,
        bytes: match wof {
            // As a program reads it; the compressed data is not carried.
            Some(wof) => wof.plain_bytes,
            None => file
                .streams
                .iter()
                .fold(0u64, |sum, stream| sum.saturating_add(stream.logical_size)),
        },
        // Clearing an attribute takes no room anywhere. A WOF file takes its
        // plain length on the new volume, less what its compressed data took
        // on the source, and its copy in the working storage.
        volume_extra_bytes: wof.map_or(0, |wof| {
            wof_growth(&[wof], cluster)
                .0
                .saturating_sub(wof.compressed_allocated)
        }),
        working_extra_bytes: wof.map_or(0, |wof| wof.plain_bytes),
        download_bytes: 0,
    }
}

/// What the frozen source makes plain: the agreed list's subset, the
/// ledger's rows, the copies to take and the WOF files among them.
pub(crate) struct Census {
    pub list: PlainList,
    pub rows: Vec<LedgerRow>,
    pub copies: Vec<n2r_win32::plain_copy::PlainCopyRequest>,
    pub wof: Vec<WofFile>,
}

/// Fills each row of a file made plain from a copy with that copy's
/// digests: the ledger ties what the new file holds to what was read.
pub(crate) fn attach_copies(rows: &mut [LedgerRow]) -> Result<()> {
    for row in rows.iter_mut().filter(|row| {
        row.kind == PlainKind::WofExpanded
            || (row.kind == PlainKind::EfsDecrypted && row.efs.is_some())
            || (row.kind == PlainKind::CloudPlaceholderPlain
                && row.cloud.as_ref().is_some_and(|cloud| !cloud.directory))
    }) {
        let pin = n2r_win32::plain_copy::taken_pin(&n2r_win32::plain_copy::PlainCopyKey {
            record_number: row.record_number,
            sequence_number: row.sequence_number,
            stream_name_utf16: Vec::new(),
        })
        .with_context(|| {
            format!(
                "MFT record {} is made plain from its WOF copy, which was not taken",
                row.record_number
            )
        })?;
        row.plain_copy = Some(n2r_win32::plain_ledger::LedgerCopy {
            bytes: pin.bytes,
            sha256: pin.sha256,
            content_digest: pin.content_digest,
        });
    }
    Ok(())
}

/// Whether `path` (as a listing names it) is `left` or below it.
pub(crate) fn within(path: &str, left: &str) -> bool {
    path == left
        || (path.len() > left.len()
            && path.starts_with(left)
            && path.as_bytes()[left.len()] == b'\\')
}

/// Whether an object with these names is left out: every name within a
/// path agreed to be left out, or none. An object some of whose names are
/// left out and some not (a hard link out of a folder left out) cannot be
/// half made, and is refused by name.
pub(crate) fn left_out_by(
    paths: &[String],
    left_out: &std::collections::BTreeSet<String>,
) -> std::result::Result<bool, String> {
    let inside = paths
        .iter()
        .filter(|path| left_out.iter().any(|left| within(path, left)))
        .count();
    match inside {
        0 => Ok(false),
        n if n == paths.len() => Ok(true),
        _ => Err(format!(
            "{} has names both in a cloud folder left out and outside it ({}): it cannot be left out in part. Nothing was changed: remove the hard links that leave the folder, or do not leave the folder out",
            paths[0],
            paths.join(", ")
        )),
    }
}

/// The list entry and the ledger row of an object left out of the
/// conversion (`cloud_left_out`): what the admission counted of it (the
/// object, a file's data streams and their bytes), which the new tree does
/// not hold.
fn left_out_row(file: &FileInventory, paths: Vec<String>) -> Result<(PlainEntry, LedgerRow)> {
    let first = paths
        .first()
        .cloned()
        .with_context(|| format!("MFT record {} has no name", file.record_number))?;
    let bytes = if file.is_directory {
        0
    } else {
        file.streams
            .iter()
            .fold(0u64, |sum, stream| sum.saturating_add(stream.logical_size))
    };
    let before = crate::ntfs_file_attributes::project_user(file)?.win32_attributes;
    let placeholder = cloud_placeholder(file)?;
    Ok((
        PlainEntry {
            kind: PlainKind::CloudLeftOut,
            path: first,
            cleared_attributes: 0,
            bytes,
            volume_extra_bytes: 0,
            working_extra_bytes: 0,
            download_bytes: 0,
        },
        LedgerRow {
            kind: PlainKind::CloudLeftOut,
            paths,
            record_number: file.record_number,
            sequence_number: file.sequence_number,
            before: LedgerState {
                attributes: before,
                reparse_tag: placeholder.map(|placeholder| placeholder.tag),
            },
            after: LedgerState::default(),
            witness: format!(
                "MFT record {} on the frozen source, {}; left out as agreed, it stays in the cloud",
                file.record_number,
                if placeholder.is_some() {
                    "a cloud placeholder"
                } else {
                    "below a cloud folder left out"
                }
            ),
            plain_copy: None,
            efs: None,
            cloud: placeholder.map(|placeholder| n2r_win32::plain_ledger::LedgerCloud {
                tag: placeholder.tag,
                directory: placeholder.directory,
                plain_bytes: placeholder.plain_bytes,
                raw_missing_bytes: placeholder.raw_missing_bytes,
            }),
            left_out: Some(n2r_win32::plain_ledger::LedgerLeftOut {
                directory: file.is_directory,
                streams: if file.is_directory {
                    0
                } else {
                    file.streams.len() as u64
                },
                bytes,
            }),
        },
    ))
}

/// The objects of a frozen source that are converted to plain: the list,
/// and the ledger's rows with every name of each object. NTFS-internal
/// objects are never converted.
pub(crate) fn census(files: &impl RootFileDomain) -> Result<Census> {
    let (mut entries, mut rows, mut copies, mut wofs) =
        (Vec::new(), Vec::new(), Vec::new(), Vec::new());
    let mut not_present: Vec<String> = Vec::new();
    // What the user agreed to leave out: those paths, and everything below
    // a folder among them. Each object is found and declared by its own
    // row; nothing is left out by inference afterwards.
    let left_out = crate::plain_consent::left_out_paths();
    for ordinal in 0..files.file_count() {
        let file = files.file(ordinal)?;
        if ntfs_admission::paged::internal_role(files, &file)?.is_some() {
            continue;
        }
        if !left_out.is_empty() {
            let paths: Vec<String> = ntfs_admission::paged::user_paths(files, &file)
                .with_context(|| {
                    format!(
                        "the names of MFT record {}, which may be left out",
                        file.record_number
                    )
                })?
                .iter()
                .map(|path| listing_path(path))
                .collect();
            if left_out_by(&paths, &left_out).map_err(anyhow::Error::msg)? {
                let (entry, row) = left_out_row(&file, paths)?;
                entries.push(entry);
                rows.push(row);
                continue;
            }
        }
        let Some(transform) = of_file(&file)? else {
            continue;
        };
        let paths: Vec<String> = ntfs_admission::paged::user_paths(files, &file)
            .with_context(|| {
                format!(
                    "the names of MFT record {}, which is converted to plain",
                    file.record_number
                )
            })?
            .iter()
            .map(|path| listing_path(path))
            .collect();
        let first = paths
            .first()
            .cloned()
            .with_context(|| format!("MFT record {} has no name", file.record_number))?;
        let before = crate::ntfs_file_attributes::project_user(&file)?.win32_attributes;
        let wof = (transform.kind == PlainKind::WofExpanded)
            .then(|| wof_file(&file))
            .transpose()?
            .flatten();
        if let Some(wof) = wof {
            copies.push(n2r_win32::plain_copy::PlainCopyRequest {
                key: copy_key(&file),
                bytes: wof.plain_bytes,
                through: n2r_win32::plain_copy::PlainRead::Filter,
            });
            wofs.push(wof);
        }
        let efs = (transform.kind == PlainKind::EfsDecrypted)
            .then(|| efs_object(&file))
            .transpose()?
            .flatten();
        if let Some(EfsObject::File(encrypted)) = &efs {
            copies.push(n2r_win32::plain_copy::PlainCopyRequest {
                key: copy_key(&file),
                bytes: encrypted.plain_bytes,
                through: n2r_win32::plain_copy::PlainRead::Decrypted,
            });
        }
        let cloud = (transform.kind == PlainKind::CloudPlaceholderPlain)
            .then(|| cloud_placeholder(&file))
            .transpose()?
            .flatten();
        if let Some(placeholder) = cloud {
            // What the Cloud Files API said was on the volume has to be
            // what the frozen source holds: the whole file, no hole below
            // its length. A placeholder that is not was neither downloaded
            // before the freeze nor agreed to be left out.
            if placeholder.raw_missing_bytes != 0 {
                not_present.push(format!(
                    "{first} ({} of its {} bytes)",
                    placeholder.raw_missing_bytes, placeholder.plain_bytes
                ));
                continue;
            }
            if !placeholder.directory {
                copies.push(n2r_win32::plain_copy::PlainCopyRequest {
                    key: copy_key(&file),
                    bytes: placeholder.plain_bytes,
                    through: n2r_win32::plain_copy::PlainRead::Filter,
                });
            }
        }
        entries.push(entry(first, &file, transform));
        rows.push(LedgerRow {
            kind: transform.kind,
            paths,
            record_number: file.record_number,
            sequence_number: file.sequence_number,
            before: LedgerState {
                attributes: before,
                reparse_tag: wof
                    .map(|_| n2r_win32::reparse_layout::IO_REPARSE_TAG_WOF)
                    .or(cloud.map(|placeholder| placeholder.tag)),
            },
            after: LedgerState {
                attributes: transform.target_attributes(before),
                reparse_tag: None,
            },
            witness: format!(
                "$STANDARD_INFORMATION of MFT record {} on the frozen source{}",
                file.record_number,
                if wof.is_some() {
                    ", its WOF reparse point and streams, and its plain copy read through WOF"
                } else if cloud.is_some_and(|placeholder| !placeholder.directory) {
                    ", its cloud reparse point, the clusters of its whole unnamed stream, and its plain copy read through the Cloud Files filter recalling nothing"
                } else if cloud.is_some() {
                    ", its cloud reparse point"
                } else {
                    ""
                }
            ),
            plain_copy: None,
            efs: match efs {
                Some(EfsObject::File(encrypted)) => Some(n2r_win32::plain_ledger::LedgerEfs {
                    efs_attribute_digest: encrypted.efs_attribute_digest,
                    ciphertext_extents_sha256: encrypted.ciphertext_extents_sha256,
                }),
                _ => None,
            },
            cloud: cloud.map(|placeholder| n2r_win32::plain_ledger::LedgerCloud {
                tag: placeholder.tag,
                directory: placeholder.directory,
                plain_bytes: placeholder.plain_bytes,
                raw_missing_bytes: placeholder.raw_missing_bytes,
            }),
            left_out: None,
        });
    }
    if let Some(first) = not_present.first() {
        anyhow::bail!(
            "{} cloud placeholder(s) of the frozen source are not wholly on this device, for example {first}: nothing was downloaded for them before the volume was frozen, and leaving them out was not agreed. Nothing was changed: {CLOUD_REMEDY}",
            not_present.len()
        );
    }
    let list = PlainList::new(entries).map_err(anyhow::Error::msg)?;
    rows.sort_by(|a, b| a.paths.cmp(&b.paths));
    Ok(Census {
        list,
        rows,
        copies,
        wof: wofs,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use n2r_win32::plain_ledger::{OFFLINE, TEMPORARY};

    #[test]
    fn temporary_and_offline_are_cleared_and_nothing_else() {
        let archive = 0x20;
        let t = transform_for(TEMPORARY | archive, false).unwrap();
        assert_eq!(t.kind, PlainKind::AttributesCleared);
        assert_eq!(t.cleared_attributes, TEMPORARY);
        assert_eq!(t.target_attributes(TEMPORARY | archive | 1), archive | 1);
        let both = transform_for(TEMPORARY | OFFLINE, false).unwrap();
        assert_eq!(both.cleared_attributes, TEMPORARY | OFFLINE);
        assert_eq!(both.target_attributes(TEMPORARY | OFFLINE), 0);
        // Nothing to take off.
        assert_eq!(transform_for(archive | 0x2000, false), None);
    }

    #[test]
    fn a_reparse_point_or_encryption_is_never_made_plain_by_clearing() {
        // OFFLINE with a reparse point is a storage manager's file.
        assert_eq!(transform_for(OFFLINE | 0x400, true), None);
        assert_eq!(transform_for(TEMPORARY, true), None);
        // EFS is refused by name; clearing TEMPORARY would hide that.
        assert_eq!(transform_for(TEMPORARY | ENCRYPTED, false), None);
    }

    #[test]
    fn wof_files_made_plain_are_held_to_the_free_space() {
        let file = |plain_bytes, compressed_allocated| WofFile {
            algorithm: 1,
            plain_bytes,
            compressed_allocated,
        };
        // Rounded up to the target's cluster; the compressed data freed.
        let files = [file(5000, 4096), file(1, 0)];
        assert_eq!(wof_growth(&files, 4096), (8192 + 4096, 4096));
        assert_eq!(wof_growth(&files, 65536), (2 * 65536, 4096));
        assert!(require_wof_room(&files, 4096, 8192).is_ok());
        let refused = require_wof_room(&files, 4096, 8191)
            .unwrap_err()
            .to_string();
        assert!(
            refused.contains("needs 8192 more bytes, and 8191 are free")
                && refused.contains("Free 1 bytes")
                && refused.contains("compact /u /exe"),
            "{refused}"
        );
        let note = wof_note(&files, 4096, 8191);
        assert!(
            note.starts_with("2 file(s) are kept compressed by WOF")
                && note.contains("8192 more bytes, and only 8191 are free"),
            "{note}"
        );
        // Freed more than it grows: nothing needed.
        assert!(require_wof_room(&[file(10, 1 << 20)], 4096, 0).is_ok());
        assert!(require_wof_room(&[], 4096, 0).is_ok());
    }

    fn stream(name: &str, flags: u16) -> crate::ntfs_inspect::StreamInventory {
        crate::ntfs_inspect::StreamInventory {
            name: name.to_owned(),
            name_utf16: name.encode_utf16().collect(),
            resident: false,
            flags,
            logical_size: 721_234,
            initialized_size: 721_234,
            allocated_size: 0,
            extents: vec![],
            resident_sha256: None,
            logical_sha256: Some("00".repeat(16)),
            logical_hash_status: crate::ntfs_inspect::LogicalHashStatus::Complete,
        }
    }

    fn attribute(
        type_code: u32,
        name: &str,
        flags: u16,
    ) -> crate::ntfs_inspect::AttributeInventory {
        serde_json::from_value(serde_json::json!({
            "type_code": type_code, "instance": 0,
            "name_utf16": name.encode_utf16().collect::<Vec<u16>>(),
            "flags": flags, "resident": false, "logical_size": 0, "initialized_size": 0,
            "allocated_size": 0, "lowest_vcn": 0, "compression_unit": 0,
            "extents": [],
        }))
        .unwrap()
    }

    fn cloud_stream(
        resident: bool,
        logical: u64,
        extents: serde_json::Value,
    ) -> crate::ntfs_inspect::StreamInventory {
        serde_json::from_value(serde_json::json!({
            "name": "", "name_utf16": [], "resident": resident, "flags": 0x8000,
            "logical_size": logical, "initialized_size": logical,
            "allocated_size": logical.next_multiple_of(4096),
            "extents": extents, "resident_sha256": null,
        }))
        .unwrap()
    }

    fn wof_file() -> FileInventory {
        FileInventory {
            record_number: 41,
            sequence_number: 1,
            hard_link_count: 1,
            is_directory: false,
            is_metadata: false,
            metadata_role: crate::ntfs_inspect::MetadataRole::OutsideExtendCandidate,
            metadata_role_issue: None,
            base_file_reference: 0,
            names: vec![],
            standard_information: Some(crate::ntfs_inspect::StandardInformation {
                creation_time: 1,
                modification_time: 2,
                mft_change_time: 3,
                access_time: 4,
                file_attributes: 0x620,
                security_id: None,
            }),
            streams: vec![stream("", 0x8000), stream("WofCompressedData", 0)],
            attributes: vec![
                attribute(0x80, "", 0x8000),
                attribute(0x80, "WofCompressedData", 0),
                attribute(0xc0, "", 0),
            ],
            extended_attributes: None,
            reparse: Some(n2r_win32::reparse_layout::Point {
                buffer: vec![0; 24],
            }),
        }
    }

    #[test]
    fn windows_is_held_to_the_view_the_filter_gives_and_nothing_more() {
        let copy = "ab".repeat(16);
        let raw = wof_file();
        let view = filter_view(&raw, true, &copy).unwrap();
        // WOF's view: no reparse point, no WofCompressedData, no REPARSE_POINT
        // or SPARSE_FILE; everything else as the raw source holds it.
        assert!(view.reparse.is_none());
        assert_eq!(view.streams.len(), 1);
        assert!(view.attributes.iter().all(|a| a.type_code != 0xc0));
        assert_eq!(view.attributes.len(), 1);
        assert_eq!(
            view.standard_information.as_ref().unwrap().file_attributes,
            0x20
        );
        assert_eq!(view.streams[0].logical_size, raw.streams[0].logical_size);
        // Not sparse, as Windows shows it (0x20, not 0x220).
        assert_eq!(view.streams[0].flags, 0);
        assert_eq!(view.attributes[0].flags, 0);
        assert_eq!(view.names.len(), raw.names.len());
        // Its contents are the copy's, read by Windows and held to them.
        assert_eq!(
            view.streams[0].logical_sha256.as_deref(),
            Some(copy.as_str())
        );
        // Not WOF's: nothing hidden; an encrypted stream read decrypted.
        let mut encrypted = wof_file();
        encrypted.reparse = None;
        encrypted.attributes = vec![attribute(0x80, "", 0x4000)];
        encrypted.streams = vec![stream("", 0x4000)];
        let view = filter_view(&encrypted, false, &copy).unwrap();
        assert_eq!(view.streams[0].flags, 0);
        assert_eq!(view.attributes[0].flags, 0);
        assert_eq!(
            view.standard_information.as_ref().unwrap().file_attributes,
            0x620
        );
        // A file with no unnamed stream has no view.
        let mut none = wof_file();
        none.streams.retain(|s| !s.name_utf16.is_empty());
        assert!(filter_view(&none, false, &copy).is_err());
    }

    #[test]
    fn only_a_copied_streams_allocation_is_held_by_its_copy() {
        // An identity no other test of this process takes a copy of.
        let (record, sequence) = (0xfeed_0000_0041u64, 9u16);
        assert!(!allocation_held_by_copy(record, sequence, &[]));
        let run = tempfile::tempdir().unwrap();
        n2r_win32::plain_copy::arm(
            &run.path().join(n2r_win32::plain_copy::DIRECTORY),
            vec![n2r_win32::plain_copy::PlainCopyRequest {
                key: n2r_win32::plain_copy::PlainCopyKey {
                    record_number: record,
                    sequence_number: sequence,
                    stream_name_utf16: Vec::new(),
                },
                bytes: 4,
                through: n2r_win32::plain_copy::PlainRead::Filter,
            }],
        )
        .unwrap();
        n2r_win32::plain_copy::take_armed_with(|_| Ok(&b"wof!"[..])).unwrap();
        let held = allocation_held_by_copy(record, sequence, &[]);
        // Another sequence of the record, a named stream: their own allocation.
        let other_sequence = allocation_held_by_copy(record, sequence + 1, &[]);
        let named = allocation_held_by_copy(record, sequence, &[0x61]);
        n2r_win32::plain_copy::remove(run.path()).unwrap();
        assert!(held && !other_sequence && !named);
        assert!(!allocation_held_by_copy(record, sequence, &[]));
    }

    #[test]
    fn a_placeholder_is_on_the_volume_only_where_clusters_hold_it() {
        // Wholly allocated: nothing is missing.
        let full = cloud_stream(
            false,
            10_000,
            serde_json::json!([{"logical_offset": 0, "physical_offset": 40960, "length": 12288}]),
        );
        assert_eq!(raw_missing_bytes(&full), 0);
        // A hole in the middle, and an unallocated tail past the last run.
        let partial = cloud_stream(
            false,
            10_000,
            serde_json::json!([
                {"logical_offset": 0, "physical_offset": 40960, "length": 4096},
                {"logical_offset": 4096, "physical_offset": null, "length": 4096},
            ]),
        );
        assert_eq!(raw_missing_bytes(&partial), 10_000 - 4096);
        // Nothing allocated: the whole file is in the cloud.
        let none = cloud_stream(
            false,
            10_000,
            serde_json::json!([{"logical_offset": 0, "physical_offset": null, "length": 12288}]),
        );
        assert_eq!(raw_missing_bytes(&none), 10_000);
        // A resident stream is in its record.
        assert_eq!(
            raw_missing_bytes(&cloud_stream(true, 20, serde_json::json!([]))),
            0
        );
    }

    #[test]
    fn a_cloud_placeholder_made_plain_loses_its_point_and_marks_only() {
        let transform = PlainTransform {
            kind: PlainKind::CloudPlaceholderPlain,
            cleared_attributes: 0,
        };
        // ARCHIVE | READONLY stay; REPARSE_POINT, SPARSE_FILE, OFFLINE,
        // PINNED and RECALL_ON_DATA_ACCESS go.
        let before = 0x20 | 0x1 | 0x400 | 0x200 | 0x1000 | 0x8_0000 | 0x40_0000;
        assert_eq!(transform.target_attributes(before), 0x21);
        // The list agrees to the object, not to the attributes taken off,
        // which only TEMPORARY and OFFLINE may be.
        assert!(
            PlainList::new(vec![PlainEntry {
                kind: PlainKind::CloudPlaceholderPlain,
                path: "\\OneDrive\\a.txt".into(),
                cleared_attributes: 0,
                bytes: 10,
                volume_extra_bytes: 0,
                working_extra_bytes: 10,
                download_bytes: 10,
            }])
            .is_ok()
        );
        assert!(CLOUD_WARNING.contains("do not run on ReFS"));
        assert!(CLOUD_REMEDY.contains("leave it out"));
    }

    #[test]
    fn what_is_left_out_is_each_object_within_a_path_agreed() {
        let left: std::collections::BTreeSet<String> =
            ["\\c\\folder".to_owned(), "\\c\\a.bin".to_owned()].into();
        let paths = |names: &[&str]| names.iter().map(|n| (*n).to_owned()).collect::<Vec<_>>();
        assert_eq!(left_out_by(&paths(&["\\c\\a.bin"]), &left), Ok(true));
        assert_eq!(left_out_by(&paths(&["\\c\\folder"]), &left), Ok(true));
        assert_eq!(
            left_out_by(&paths(&["\\c\\folder\\deep\\x.txt"]), &left),
            Ok(true)
        );
        // A sibling whose name only begins the same is not below it.
        assert_eq!(left_out_by(&paths(&["\\c\\folder2\\x"]), &left), Ok(false));
        assert_eq!(left_out_by(&paths(&["\\c\\a.bin2"]), &left), Ok(false));
        // A file with a name inside and one outside cannot be half made.
        let split = left_out_by(&paths(&["\\c\\folder\\x", "\\d\\x"]), &left).unwrap_err();
        assert!(split.contains("cannot be left out in part"), "{split}");
        assert!(within("\\c", "\\c") && !within("\\c", "\\c\\d"));
    }

    #[test]
    fn a_path_is_written_as_a_listing_writes_it() {
        assert_eq!(listing_path(&[]), "\\");
        assert_eq!(
            listing_path(&["a".into(), "temporary.tmp".into()]),
            "\\a\\temporary.tmp"
        );
    }
}
