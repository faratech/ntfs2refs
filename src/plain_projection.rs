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
            PlainKind::WofExpanded | PlainKind::SisExpanded => {
                n2r_win32::plain_ledger::REPARSE_POINT | n2r_win32::plain_ledger::SPARSE_FILE
            }
            PlainKind::EfsDecrypted => ENCRYPTED,
            // Its reparse point, the provider's pin and recall marks, and
            // the OFFLINE and sparse marks a placeholder has.
            PlainKind::CloudPlaceholderPlain
            | PlainKind::ProjfsPlaceholderPlain
            | PlainKind::HsmRecalled => PLACEHOLDER_CLEARED,
            PlainKind::DedupRehydrated => {
                n2r_win32::plain_ledger::REPARSE_POINT | n2r_win32::plain_ledger::SPARSE_FILE
            }
            _ => self.cleared_attributes,
        }
    }
}

/// What a cloud placeholder made plain is made without: what the content
/// verdict takes off its record before (`volume_manifest::declared_after`).
pub(crate) const PLACEHOLDER_CLEARED: u32 = n2r_win32::plain_ledger::REPARSE_POINT
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
        "the {} file(s) WOF keeps compressed or Data Deduplication optimized take {grows} bytes made plain (in {target_cluster}-byte clusters), {frees} bytes of their compressed data are freed, so the volume needs {needed} more bytes, and {free} are free. Free {} bytes, or expand some of the files first (`compact /u /exe <file>`; `Start-DedupJob -Type Unoptimization -Volume <drive>:`) and convert then. Nothing was changed",
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

/// A Single Instance Storage link, as the raw source shows it: its reparse
/// point read exactly (`reparse_layout::sis_link`), and one unnamed stream
/// of the file's length that holds no data of its own (every byte below its
/// length a hole). A link written to since SIS linked it (part of its data
/// its own) is none, and is refused by name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SisFile {
    pub link: n2r_win32::reparse_layout::SisLink,
    /// The file's length as a program reads it: its common store file's.
    pub plain_bytes: u64,
}

/// The SIS link `file` is, if it is one of the shape this build expands.
pub(crate) fn sis_file(file: &FileInventory) -> Result<Option<SisFile>> {
    let Some(point) = crate::ntfs_reparse::file_point(file)? else {
        return Ok(None);
    };
    if point.tag() != n2r_win32::reparse_layout::IO_REPARSE_TAG_SIS || file.is_directory {
        return Ok(None);
    }
    let Some(link) = n2r_win32::reparse_layout::sis_link(&point.buffer) else {
        return Ok(None);
    };
    let [stream] = file.streams.as_slice() else {
        return Ok(None);
    };
    if !stream.name_utf16.is_empty()
        || !matches!(stream.flags, 0 | 0x8000)
        || (stream.resident && stream.logical_size != 0)
        || raw_missing_bytes(stream) != stream.logical_size
    {
        return Ok(None);
    }
    Ok(Some(SisFile {
        link,
        plain_bytes: stream.logical_size,
    }))
}

/// Whether this run makes `file`, a SIS link, a plain file from its common
/// store file (where `sis_expanded` is enabled).
pub(crate) fn sis_taken(file: &FileInventory) -> bool {
    PlainKind::SisExpanded.implemented()
        && crate::plain_consent::takes_plain()
        && sis_file(file).ok().flatten().is_some()
}

/// Pure: the common store file a SIS link's data is read from, held to
/// what the link's reparse point says of it. `common` is the frozen
/// source's record of the reference the point names (`None` where no
/// record of that number and sequence number is in use) and `paths` its
/// names, as a listing names them. It has to be an ordinary file named
/// `\SIS Common Store\{CSID}.sis`, with an unnamed stream of the link's
/// length; anything else refuses the run, by name.
pub(crate) fn resolve_sis(
    link_path: &str,
    sis: &SisFile,
    common: Option<&FileInventory>,
    paths: &[String],
) -> std::result::Result<n2r_win32::plain_ledger::LedgerSis, String> {
    let expected = format!(
        "\\{}\\{}",
        n2r_win32::reparse_layout::SIS_COMMON_STORE,
        sis.link.common_store_name()
    );
    let refuse = |why: String| {
        Err(format!(
            "{link_path} is a Single Instance Storage link whose data is the common store file {expected} (MFT record {}, sequence {}), and {why}. Nothing was changed: the link cannot be made a plain file",
            sis.link.common_store_record, sis.link.common_store_sequence
        ))
    };
    let Some(common) = common else {
        return refuse("no such record is in use on the volume".into());
    };
    if common.is_directory
        || crate::ntfs_reparse::file_point(common)
            .ok()
            .flatten()
            .is_some()
    {
        return refuse("that record is a directory or has a reparse point of its own".into());
    }
    let Some(named) = paths
        .iter()
        .find(|path| path.eq_ignore_ascii_case(&expected))
    else {
        return refuse(format!("that record is named {}", paths.join(", ")));
    };
    let Some(unnamed) = common.streams.iter().find(|s| s.name_utf16.is_empty()) else {
        return refuse("that file has no unnamed stream".into());
    };
    if unnamed.logical_size != sis.plain_bytes || unnamed.flags & 0x4000 != 0 {
        return refuse(format!(
            "its unnamed stream is {} bytes long{}, the link {}",
            unnamed.logical_size,
            if unnamed.flags & 0x4000 != 0 {
                " and encrypted"
            } else {
                ""
            },
            sis.plain_bytes
        ));
    }
    Ok(n2r_win32::plain_ledger::LedgerSis {
        common_store_path: named.clone(),
        common_store_record: common.record_number,
        common_store_sequence: common.sequence_number,
        bytes: unnamed.logical_size,
    })
}

/// What expanding `links` takes on the new volume: each link's length,
/// rounded up to the target's cluster (a link takes no cluster on the
/// source).
pub(crate) fn sis_growth(links: &[SisFile], target_cluster: u64) -> u64 {
    links.iter().fold(0u64, |grows, link| {
        grows.saturating_add(link.plain_bytes.div_ceil(target_cluster) * target_cluster)
    })
}

/// Refuses, with the numbers, a volume whose SIS links expanded would not
/// fit in `free` (its free space, less what WOF files made plain take).
pub(crate) fn require_sis_room(links: &[SisFile], target_cluster: u64, free: u64) -> Result<()> {
    let grows = sis_growth(links, target_cluster);
    anyhow::ensure!(
        grows <= free,
        "the {} Single Instance Storage link(s) take {grows} bytes made plain (in {target_cluster}-byte clusters) and {free} bytes are free for them. Free {} bytes, or copy some of the files elsewhere and convert then. Nothing was changed",
        links.len(),
        grows - free
    );
    Ok(())
}

/// Said wherever a cloud placeholder is refused because its data is not on
/// the volume.
pub(crate) const CLOUD_REMEDY: &str = "start its cloud provider (OneDrive, say) so that the conversion can download it before the volume is frozen, and run the conversion as the user the provider runs for (a Cloud Files provider serves only the account that runs it); or make it always available on this device; or agree to leave it out, which keeps it in the cloud and not on the new volume";

/// What the Cloud Files API's placeholders become, said with the question.
/// OneDrive and the Cloud Files API do not run on ReFS.
pub(crate) const CLOUD_WARNING: &str = "OneDrive and other Cloud Files API providers do not run on ReFS: after the conversion the folders they synced stop syncing, and their files are ordinary files that are not uploaded or updated any more. Move the provider's folder to an NTFS volume first to keep it syncing";

pub(crate) use n2r_win32::plain_ledger::PlaceholderFamily;

/// A placeholder whose data a provider keeps (the Cloud Files API's,
/// reparse tags 0x9000x01A; ProjFS's, 0x9000001C), as the raw source shows
/// it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Placeholder {
    pub family: PlaceholderFamily,
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

/// The placeholder `file` is, if it is one of a shape this build makes
/// plain: a directory with no data stream (a cloud sync root's folder may
/// hold the Cloud Files API's own stream; ProjFS's virtualization root is a
/// placeholder folder too, its marker the reparse point), or a file whose
/// unnamed stream is neither compressed nor encrypted. Anything else with
/// such a tag is refused by admission, by name. Only the families this
/// build converts ([`PlainKind::implemented`]) are recognised.
pub(crate) fn placeholder_of(file: &FileInventory) -> Result<Option<Placeholder>> {
    let Some(point) = crate::ntfs_reparse::file_point(file)? else {
        return Ok(None);
    };
    let Some(family) =
        PlaceholderFamily::of_tag(point.tag()).filter(|family| family.plain_kind().implemented())
    else {
        return Ok(None);
    };
    if file.is_directory {
        // A sync root's folder holds the Cloud Files API's own stream
        // (`${3D0CE612-...}.SyncRootIdentity`), which is left off it; any
        // other named stream on a placeholder folder is refused by
        // admission.
        return Ok(file
            .streams
            .iter()
            .all(|stream| family == PlaceholderFamily::Cloud && sync_root_stream(stream))
            .then_some(Placeholder {
                family,
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
    Ok(Some(Placeholder {
        family,
        tag: point.tag(),
        directory: false,
        plain_bytes: stream.logical_size,
        raw_missing_bytes: raw_missing_bytes(stream),
    }))
}

/// Whether this run makes `file`, a cloud placeholder file, plain from a
/// copy: one taken plain and not left out (`cloud_left_out`, as the run's
/// ledger declares it once the volume is frozen). A left-out placeholder
/// has no copy: it is not made at all, and Windows' view of it at the
/// freeze is compared as the raw record holds it.
pub(crate) fn placeholder_copied(file: &FileInventory) -> bool {
    placeholder_taken(file)
        && !file.is_directory
        && !n2r_win32::plain_ledger::declared()
            .is_left_out(file.record_number, file.sequence_number)
}

/// Whether `stream` is the Cloud Files API's own on a sync root's folder.
pub(crate) fn sync_root_stream(stream: &crate::ntfs_inspect::StreamInventory) -> bool {
    String::from_utf16(&stream.name_utf16)
        .is_ok_and(|name| n2r_win32::plain_ledger::is_cloud_private_stream(&name))
}

/// Whether `stream` of `file` is one a cloud folder made plain is made
/// without (`sync_root_stream`, on a folder this run makes plain).
pub(crate) fn cloud_dropped_stream(
    file: &FileInventory,
    stream: &crate::ntfs_inspect::StreamInventory,
) -> bool {
    file.is_directory && sync_root_stream(stream) && placeholder_taken(file)
}

/// Whether this run makes `file`, a cloud placeholder, plain (where
/// `cloud_placeholder_plain` is enabled). Whether its data is on the volume
/// is held at the freeze ([`census`]), not here: before the freeze a run
/// downloads what is not.
pub(crate) fn placeholder_taken(file: &FileInventory) -> bool {
    crate::plain_consent::takes_plain() && placeholder_of(file).ok().flatten().is_some()
}

/// The plain copy `file`'s new unnamed stream is made from: a WOF file's,
/// read through WOF, an EFS file's, decrypted, or a cloud placeholder's,
/// read through the Cloud Files filter recalling nothing. It has to have
/// been taken.
pub(crate) fn plain_copy_pin(
    file: &FileInventory,
) -> Result<Option<n2r_win32::plain_copy::PlainCopyPin>> {
    let copied = wof_taken(file)
        || dedup_taken(file)
        || (efs_taken(file) && matches!(efs_object(file)?, Some(EfsObject::File(_))))
        || placeholder_copied(file)
        || sis_taken(file);
    if !copied {
        return Ok(None);
    }
    n2r_win32::plain_copy::taken_pin(&copy_key(file))
        .map(Some)
        .with_context(|| {
            format!(
                "MFT record {} is made plain from its copy, and no copy of it was taken at the freeze: the census of the frozen source requested none for it",
                file.record_number
            )
        })
}

/// The object a native observation of `file` is compared with, where this
/// run makes it plain from its copy: the raw source as the filter that owns
/// it shows it to Windows, and nothing else changed.
///
/// - The dedup filter hides nothing of the file: its reparse point and
///   attributes are compared as the raw record holds them.
/// - WOF hides its reparse point, the REPARSE_POINT and SPARSE_FILE
///   attributes and its WofCompressedData stream (the lab's listing of a
///   `compact /exe` file shows attributes 0x20, one stream, the full length).
/// - A cloud placeholder (`cloud_placeholder_plain`) hides nothing from an
///   observer that opens it as its reparse point, as Windows' observation
///   of the source does: its point, its cloud tag and its pinned, recall,
///   OFFLINE and sparse attributes are what the raw record holds, and the
///   whole of its data is on the volume (the census holds it to that). Its
///   unnamed stream's allocation is the raw record's too.
/// - Either way the unnamed stream's contents are what the filter reads,
///   which the plain copy holds: Windows' read of it is held to the copy's
///   content digest, and never left unread as a plain stream would be.
///
/// `None` for every other object, which is compared as it is.
pub(crate) fn observed_view(file: &FileInventory) -> Result<Option<FileInventory>> {
    // A sync root's folder: the Cloud Files filter hides the API's own
    // stream from Windows (the lab: its stream enumeration ends at once,
    // ERROR_HANDLE_EOF), so Windows is held to the folder without it.
    if file.is_directory && placeholder_taken(file) && file.streams.iter().any(sync_root_stream) {
        return Ok(Some(sync_root_view(file)));
    }
    // A SIS link: no filter of this Windows reads it (SIS's ran on Windows
    // Storage Server only), so Windows' view of it is the link as the raw
    // record holds it, every byte a hole. Its copy is its common store
    // file's, which the new file is made from and the ledger names.
    if sis_taken(file) {
        return Ok(None);
    }
    let Some(pin) = plain_copy_pin(file)? else {
        return Ok(None);
    };
    filter_view(file, wof_taken(file), &pin.content_digest).map(Some)
}

/// A sync root's folder as Windows sees it: without the Cloud Files API's
/// own streams and their DATA attributes.
fn sync_root_view(file: &FileInventory) -> FileInventory {
    let mut view = file.clone();
    view.streams.retain(|stream| !sync_root_stream(stream));
    view.attributes.retain(|attribute| {
        !(attribute.type_code == 0x80
            && String::from_utf16(&attribute.name_utf16)
                .is_ok_and(|name| n2r_win32::plain_ledger::is_cloud_private_stream(&name)))
    });
    view
}

/// Whether `stream` of `file`, made plain from its copy, is that copy
/// exactly as the raw record holds it: the unnamed stream of a cloud
/// placeholder wholly on the volume, whose copy read through the filter has
/// the raw reading's own content digest. Windows' view of it is then the
/// raw stream's, which a run that verifies once need not read again; any
/// other copied stream (WOF's, EFS's) is read by Windows and held to its
/// copy.
pub(crate) fn copy_is_the_raw_stream(
    file: &FileInventory,
    stream: &crate::ntfs_inspect::StreamInventory,
) -> bool {
    if !stream.name_utf16.is_empty() || !placeholder_copied(file) {
        return false;
    }
    let Some(raw) = file.streams.iter().find(|s| s.name_utf16.is_empty()) else {
        return false;
    };
    n2r_win32::plain_copy::taken_pin(&copy_key(file)).is_some_and(|pin| {
        raw.logical_hash_status == crate::ntfs_inspect::LogicalHashStatus::Complete
            && raw.logical_sha256.as_deref() == Some(pin.content_digest.as_str())
            && raw.logical_size == pin.bytes
    })
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

/// Held by a test that takes plain copies: the process holds one set of
/// them at a time.
#[cfg(test)]
pub(crate) static COPY_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// A file Data Deduplication has optimized, as the raw source shows it: its
/// dedup reparse point and exactly one, unnamed, stream of the file's plain
/// length, whose data is in the chunk store.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DedupFile {
    pub plain_bytes: u64,
    /// What the stream itself takes on the source (the ranges not yet
    /// optimized), freed when the file is made plain.
    pub allocated: u64,
}

impl DedupFile {
    /// As the capacity gate counts it: its plain length on the new volume,
    /// less what its own stream took.
    pub(crate) fn growing(self) -> WofFile {
        WofFile {
            algorithm: 0,
            plain_bytes: self.plain_bytes,
            compressed_allocated: self.allocated,
        }
    }
}

/// The deduplicated file `file` is, if it is one this build makes plain.
pub(crate) fn dedup_file(file: &FileInventory) -> Result<Option<DedupFile>> {
    let Some(point) = crate::ntfs_reparse::file_point(file)? else {
        return Ok(None);
    };
    if !n2r_win32::reparse_layout::is_dedup_point(&point.buffer) || file.is_directory {
        return Ok(None);
    }
    let [stream] = file.streams.as_slice() else {
        return Ok(None);
    };
    Ok(
        (stream.name_utf16.is_empty() && stream.flags & !0x8000 == 0).then_some(DedupFile {
            plain_bytes: stream.logical_size,
            allocated: stream.allocated_size,
        }),
    )
}

/// Said where a deduplicated file cannot be read through this Windows.
pub(crate) const DEDUP_FILTER_REMEDY: &str = "this Windows has no Data Deduplication filter to read it through: convert the volume from a Windows Server with the Data Deduplication feature, or rehydrate its files first with `Start-DedupJob -Type Unoptimization -Volume <drive>:`";

/// Whether this Windows reads deduplicated files through its filter.
pub(crate) fn dedup_readable() -> bool {
    #[cfg(windows)]
    {
        static PRESENT: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
        *PRESENT.get_or_init(n2r_win32::plain_copy::dedup_filter_present)
    }
    #[cfg(not(windows))]
    {
        false
    }
}

/// Whether this run makes `file` a plain file from what the dedup filter
/// reads (where `dedup_rehydrated` is enabled and this Windows has the
/// filter).
pub(crate) fn dedup_taken(file: &FileInventory) -> bool {
    PlainKind::DedupRehydrated.implemented()
        && crate::plain_consent::takes_plain()
        && dedup_file(file).ok().flatten().is_some()
        && dedup_readable()
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
    // A SIS link of another shape is refused by admission, by name.
    if PlainKind::SisExpanded.implemented() && sis_file(file).ok().flatten().is_some() {
        return Ok(Some(PlainTransform {
            kind: PlainKind::SisExpanded,
            cleared_attributes: 0,
        }));
    }
    // A placeholder of another shape is refused by admission, by name.
    if let Some(placeholder) = placeholder_of(file).ok().flatten() {
        return Ok(Some(PlainTransform {
            kind: placeholder.family.plain_kind(),
            cleared_attributes: 0,
        }));
    }
    // A deduplicated file; one this Windows cannot read through its filter
    // is refused by admission, by name, with the remedy.
    if PlainKind::DedupRehydrated.implemented() && dedup_file(file).ok().flatten().is_some() {
        return Ok(Some(PlainTransform {
            kind: PlainKind::DedupRehydrated,
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
    let wof = wof_file(file)
        .ok()
        .flatten()
        .or_else(|| dedup_file(file).ok().flatten().map(DedupFile::growing));
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
    if let Some(cloud) = transform
        .kind
        .family()
        .and_then(|_| placeholder_of(file).ok().flatten())
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
    // A SIS link takes its whole length on the new volume (it took no
    // cluster on the source), and its copy in the working storage.
    if let Some(sis) = (transform.kind == PlainKind::SisExpanded)
        .then(|| sis_file(file).ok().flatten())
        .flatten()
    {
        return PlainEntry {
            kind: transform.kind,
            path,
            cleared_attributes: transform.cleared_attributes,
            bytes: sis.plain_bytes,
            volume_extra_bytes: sis_growth(&[sis], cluster),
            working_extra_bytes: sis.plain_bytes,
            download_bytes: 0,
        };
    }
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
    /// What the objects of System Volume Information not carried over take
    /// on the source: room the new volume does not have to give them.
    pub not_carried_allocated: u64,
    /// The SIS links expanded, which grow the volume as WOF files do.
    pub sis: Vec<SisFile>,
}

/// Where a directory of a source is, from System Volume Information.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SystemDepth {
    /// The volume's root.
    Root,
    /// Not in System Volume Information.
    Outside,
    /// System Volume Information itself.
    Folder,
    /// A folder directly in it.
    Immediate,
    /// Below one of those.
    Below,
}

/// Finds the objects of a source below System Volume Information's
/// immediate folders (what a data volume's conversion does not carry over,
/// `system_volume_information_not_carried`) without deriving each object's
/// path: each directory's place is found once, walking up to the first
/// directory already placed.
pub(crate) struct SystemFolders<'a, D: RootFileDomain> {
    files: &'a D,
    known: std::collections::HashMap<u64, SystemDepth>,
}

impl<'a, D: RootFileDomain> SystemFolders<'a, D> {
    pub(crate) fn new(files: &'a D) -> Self {
        Self {
            files,
            known: Default::default(),
        }
    }

    /// The place of the directory `reference` (its record number, with its
    /// sequence number in the top 16 bits). A directory that cannot be
    /// found is outside: the admission refuses an object whose path it
    /// cannot derive, whatever this says.
    fn depth(&mut self, reference: u64) -> Result<SystemDepth> {
        let mut chain: Vec<(u64, bool)> = Vec::new();
        let mut current = reference;
        let mut depth = loop {
            if current & 0x0000_ffff_ffff_ffff == 5 {
                break SystemDepth::Root;
            }
            if let Some(&known) = self.known.get(&current) {
                break known;
            }
            anyhow::ensure!(
                chain.len() < 4096,
                "the directories above MFT record {} do not reach the root",
                reference & 0x0000_ffff_ffff_ffff
            );
            let Some(directory) = self.files.find_record(
                current & 0x0000_ffff_ffff_ffff,
                Some((current >> 48) as u16),
            )?
            else {
                break SystemDepth::Outside;
            };
            let Some(name) = directory.names.iter().find(|name| name.namespace != 2) else {
                break SystemDepth::Outside;
            };
            chain.push((
                current,
                String::from_utf16_lossy(&name.name_utf16)
                    .eq_ignore_ascii_case(n2r_win32::plain_ledger::SYSTEM_VOLUME_INFORMATION),
            ));
            current = name.parent_record_number | (u64::from(name.parent_sequence_number) << 48);
        };
        for (directory, system_name) in chain.into_iter().rev() {
            depth = match depth {
                SystemDepth::Root if system_name => SystemDepth::Folder,
                SystemDepth::Root | SystemDepth::Outside => SystemDepth::Outside,
                SystemDepth::Folder => SystemDepth::Immediate,
                SystemDepth::Immediate | SystemDepth::Below => SystemDepth::Below,
            };
            self.known.insert(directory, depth);
        }
        Ok(depth)
    }

    /// Whether `file` may be below System Volume Information's immediate
    /// folders: one of its names is. Whether it is not carried over is
    /// [`ntfs_admission::system_not_carried`] of its paths.
    pub(crate) fn may_be_below(&mut self, file: &FileInventory) -> Result<bool> {
        for name in file.names.iter().filter(|name| name.namespace != 2) {
            let parent = name.parent_record_number | (u64::from(name.parent_sequence_number) << 48);
            if matches!(
                self.depth(parent)?,
                SystemDepth::Immediate | SystemDepth::Below
            ) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// The paths of `file`, where it is below System Volume Information's
    /// immediate folders and so not carried over. An object with names
    /// there and elsewhere is refused by name.
    pub(crate) fn not_carried(&mut self, file: &FileInventory) -> Result<Option<Vec<Vec<String>>>> {
        if !self.may_be_below(file)? {
            return Ok(None);
        }
        let paths = ntfs_admission::paged::user_paths(self.files, file).with_context(|| {
            format!(
                "the names of MFT record {}, below the folders of System Volume Information",
                file.record_number
            )
        })?;
        Ok(ntfs_admission::system_not_carried(&paths, file)
            .map_err(anyhow::Error::msg)?
            .then_some(paths))
    }
}

/// What an object of System Volume Information not carried over takes on
/// the source: its streams' clusters.
pub(crate) fn allocated(file: &FileInventory) -> u64 {
    file.streams
        .iter()
        .filter(|stream| !stream.resident)
        .fold(0u64, |sum, stream| {
            sum.saturating_add(stream.allocated_size)
        })
}

/// The ledger row of an object of System Volume Information not carried
/// over (`system_volume_information_not_carried`): its names, what the
/// admission counted of it, and each of its data streams' length and, where
/// the inspection read it, SHA-256.
fn not_carried_row(file: &FileInventory, paths: Vec<String>) -> LedgerRow {
    let (streams, bytes) = counted_streams(file);
    LedgerRow {
        kind: PlainKind::SystemVolumeInformationNotCarried,
        paths,
        record_number: file.record_number,
        sequence_number: file.sequence_number,
        before: LedgerState {
            attributes: file
                .standard_information
                .as_ref()
                .map_or(0, |information| information.file_attributes),
            reparse_tag: file.reparse.as_ref().map(|point| point.tag()),
        },
        after: LedgerState::default(),
        witness: format!(
            "MFT record {} on the frozen source, below the folders of System Volume Information: Windows' own, not carried over",
            file.record_number
        ),
        plain_copy: None,
        efs: None,
        cloud: None,
        left_out: Some(n2r_win32::plain_ledger::LedgerLeftOut {
            directory: file.is_directory,
            streams,
            bytes,
        }),
        sis: None,
        dropped_streams: Vec::new(),
        recorded_streams: file
            .streams
            .iter()
            .map(|stream| n2r_win32::plain_ledger::LedgerRecordedStream {
                name: String::from_utf16_lossy(&stream.name_utf16),
                bytes: stream.logical_size,
                sha256: stream
                    .logical_sha256
                    .clone()
                    .or_else(|| stream.resident_sha256.clone()),
            })
            .collect(),
    }
}

/// Fills each row of a file made plain from a copy with that copy's
/// digests: the ledger ties what the new file holds to what was read.
pub(crate) fn attach_copies(rows: &mut [LedgerRow]) -> Result<()> {
    for row in rows.iter_mut().filter(|row| {
        row.kind == PlainKind::WofExpanded
            || row.kind == PlainKind::SisExpanded
            || (row.kind == PlainKind::EfsDecrypted && row.efs.is_some())
            || (row.kind.family().is_some()
                && !row.kind.is_left_out()
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
            "{} has names both in a placeholder folder left out and outside it ({}): it cannot be left out in part. Nothing was changed: remove the hard links that leave the folder, or do not leave the folder out",
            paths[0],
            paths.join(", ")
        )),
    }
}

/// The list entry and the ledger row of an object left out of the
/// conversion (`cloud_left_out`, `projfs_left_out`, `hsm_left_out`): what
/// the admission counted of it (the object, its data streams and their
/// bytes), which the new tree does not hold. A placeholder takes its own
/// family's kind; an object below a folder left out, `below`'s.
fn left_out_row(
    file: &FileInventory,
    paths: Vec<String>,
    below: PlainKind,
) -> Result<(PlainEntry, LedgerRow)> {
    let first = paths
        .first()
        .cloned()
        .with_context(|| format!("MFT record {} has no name", file.record_number))?;
    let (streams, bytes) = counted_streams(file);
    let before = crate::ntfs_file_attributes::project_user(file)?.win32_attributes;
    let placeholder = placeholder_of(file)?;
    let kind = placeholder.map_or(below, |placeholder| placeholder.family.left_out_kind());
    let family = kind.family().unwrap_or(PlaceholderFamily::Cloud);
    Ok((
        PlainEntry {
            kind,
            path: first,
            cleared_attributes: 0,
            bytes,
            volume_extra_bytes: 0,
            working_extra_bytes: 0,
            download_bytes: 0,
        },
        LedgerRow {
            kind,
            paths,
            record_number: file.record_number,
            sequence_number: file.sequence_number,
            before: LedgerState {
                attributes: before,
                reparse_tag: placeholder.map(|placeholder| placeholder.tag),
            },
            after: LedgerState::default(),
            witness: format!(
                "MFT record {} on the frozen source, {}; left out as agreed, it stays with its {}",
                file.record_number,
                if placeholder.is_some() {
                    "a placeholder"
                } else {
                    "below a placeholder folder left out"
                },
                family.provider()
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
                streams,
                bytes,
            }),
            sis: None,
            dropped_streams: Vec::new(),
            recorded_streams: Vec::new(),
        },
    ))
}

/// The data streams the source's admission counts of an object, and their
/// bytes: every stream of a file or a directory (a directory's named
/// streams are counted, as they are carried).
fn counted_streams(file: &FileInventory) -> (u64, u64) {
    (
        file.streams.len() as u64,
        file.streams
            .iter()
            .fold(0u64, |sum, stream| sum.saturating_add(stream.logical_size)),
    )
}

/// The objects of a frozen data volume that are converted to plain: the
/// list, and the ledger's rows with every name of each object; and those of
/// System Volume Information not carried over, each with a row of its own
/// and on no list. NTFS-internal objects are never converted. A run that
/// does not take objects to plain converts none, and still leaves out what
/// System Volume Information does not carry.
pub(crate) fn census(files: &impl RootFileDomain) -> Result<Census> {
    let (mut entries, mut rows, mut copies, mut wofs, mut sis_links) =
        (Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new());
    let takes_plain = crate::plain_consent::takes_plain();
    let mut system = SystemFolders::new(files);
    let mut not_carried_allocated = 0u64;
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
        if let Some(paths) = system.not_carried(&file)? {
            not_carried_allocated = not_carried_allocated.saturating_add(allocated(&file));
            rows.push(not_carried_row(
                &file,
                paths.iter().map(|path| listing_path(path)).collect(),
            ));
            continue;
        }
        if !takes_plain {
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
            let keys: std::collections::BTreeSet<String> = left_out.keys().cloned().collect();
            if left_out_by(&paths, &keys).map_err(anyhow::Error::msg)? {
                let below = left_out
                    .iter()
                    .find(|(left, _)| paths.iter().any(|path| within(path, left)))
                    .map_or(PlainKind::CloudLeftOut, |(_, kind)| *kind);
                let (entry, row) = left_out_row(&file, paths, below)?;
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
        let dedup = (transform.kind == PlainKind::DedupRehydrated)
            .then(|| dedup_file(&file))
            .transpose()?
            .flatten();
        if let Some(dedup) = dedup {
            copies.push(n2r_win32::plain_copy::PlainCopyRequest {
                key: copy_key(&file),
                bytes: dedup.plain_bytes,
                through: n2r_win32::plain_copy::PlainRead::Filter,
            });
            wofs.push(dedup.growing());
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
        // A SIS link: its data is its common store file's, which has to be
        // the one its reparse point names; the copy is read from that file.
        let sis = match (transform.kind == PlainKind::SisExpanded)
            .then(|| sis_file(&file))
            .transpose()?
            .flatten()
        {
            Some(link) => {
                let common = files.find_record(
                    link.link.common_store_record,
                    Some(link.link.common_store_sequence),
                )?;
                let common_paths: Vec<String> = match &common {
                    Some(common) => ntfs_admission::paged::user_paths(files, common)
                        .with_context(|| {
                            format!(
                                "the names of MFT record {}, the common store file of {first}",
                                common.record_number
                            )
                        })?
                        .iter()
                        .map(|path| listing_path(path))
                        .collect(),
                    None => Vec::new(),
                };
                let resolved = resolve_sis(&first, &link, common.as_ref(), &common_paths)
                    .map_err(anyhow::Error::msg)?;
                copies.push(n2r_win32::plain_copy::PlainCopyRequest {
                    key: copy_key(&file),
                    bytes: link.plain_bytes,
                    through: n2r_win32::plain_copy::PlainRead::CommonStore {
                        record_number: resolved.common_store_record,
                        sequence_number: resolved.common_store_sequence,
                    },
                });
                sis_links.push(link);
                Some(resolved)
            }
            None => None,
        };
        let cloud = transform
            .kind
            .family()
            .map(|_| placeholder_of(&file))
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
                    .or(cloud.map(|placeholder| placeholder.tag))
                    .or(dedup.map(|_| n2r_win32::reparse_layout::IO_REPARSE_TAG_DEDUP))
                    .or(sis
                        .as_ref()
                        .map(|_| n2r_win32::reparse_layout::IO_REPARSE_TAG_SIS)),
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
                    ", its placeholder's reparse point, the clusters of its whole unnamed stream, and its plain copy read through its provider's filter recalling nothing"
                } else if cloud.is_some() {
                    ", its placeholder's reparse point"
                } else if sis.is_some() {
                    ", its Single Instance Storage reparse point and hole-only unnamed stream, the common store file it names, and its plain copy read from that file"
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
            sis,
            // A sync root's folder: the Cloud Files API's own stream on it.
            dropped_streams: if cloud.is_some_and(|placeholder| placeholder.directory) {
                file.streams
                    .iter()
                    .filter(|stream| sync_root_stream(stream))
                    .map(|stream| n2r_win32::plain_ledger::LedgerStream {
                        name: String::from_utf16_lossy(&stream.name_utf16),
                        bytes: stream.logical_size,
                    })
                    .collect()
            } else {
                Vec::new()
            },
            recorded_streams: Vec::new(),
        });
    }
    if let Some(first) = not_present.first() {
        anyhow::bail!(
            "{} placeholder(s) of the frozen source are not wholly on this device, for example {first}: nothing brought them onto it before the volume was frozen, and leaving them out was not agreed. Nothing was changed: {CLOUD_REMEDY}",
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
        not_carried_allocated,
        sis: sis_links,
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

    /// A SIS link's reparse point as SI_REPARSE_BUFFER version 5 has it,
    /// naming the common store file `{0D0C0B0A-0F0E-1110-1213-141516171819}.sis`
    /// at MFT record 70, sequence 3.
    fn sis_point() -> Vec<u8> {
        let mut point = n2r_win32::reparse_layout::IO_REPARSE_TAG_SIS
            .to_le_bytes()
            .to_vec();
        point.extend_from_slice(&64u16.to_le_bytes());
        point.extend_from_slice(&0u16.to_le_bytes());
        point.extend_from_slice(&5u32.to_le_bytes());
        point.extend_from_slice(&0u32.to_le_bytes());
        point.extend((0x0au8..0x1a).collect::<Vec<u8>>());
        point.extend_from_slice(&1u64.to_le_bytes());
        point.extend_from_slice(&(41u64 | 1 << 48).to_le_bytes());
        point.extend_from_slice(&(70u64 | 3 << 48).to_le_bytes());
        point.extend_from_slice(&0x1111u64.to_le_bytes());
        point.extend_from_slice(&0x2222u64.to_le_bytes());
        point
    }

    /// `file` with the reparse point `point`, as the raw source holds one:
    /// its resident $REPARSE_POINT attribute and the point read from it.
    fn with_point(mut file: FileInventory, point: Vec<u8>) -> FileInventory {
        file.attributes
            .retain(|attribute| attribute.type_code != 0xc0);
        file.attributes
            .push(crate::ntfs_inspect::AttributeInventory {
                type_code: 0xc0,
                instance: 0,
                name_utf16: Vec::new(),
                flags: 0,
                resident: true,
                logical_size: point.len() as u64,
                initialized_size: point.len() as u64,
                allocated_size: point.len().next_multiple_of(8) as u64,
                lowest_vcn: 0,
                compression_unit: 0,
                total_allocated_size: None,
                extents: vec![],
                resident_sha256: Some(n2r_win32::content_digest::of(&point)),
                resident_metadata_hex: Some(hex::encode(&point)),
            });
        file.reparse = Some(n2r_win32::reparse_layout::Point { buffer: point });
        file
    }

    /// A SIS link of 10 000 bytes, every one a hole.
    fn sis_link_file() -> FileInventory {
        let mut link = wof_file();
        link.streams = vec![cloud_stream(
            false,
            10_000,
            serde_json::json!([{"logical_offset": 0, "physical_offset": null, "length": 12288}]),
        )];
        link.attributes = vec![attribute(0x80, "", 0x8000)];
        with_point(link, sis_point())
    }

    /// Its common store file: an ordinary file of the link's length.
    fn common_store_file() -> FileInventory {
        let mut common = wof_file();
        common.record_number = 70;
        common.sequence_number = 3;
        common.reparse = None;
        common.streams = vec![cloud_stream(
            false,
            10_000,
            serde_json::json!([{"logical_offset": 0, "physical_offset": 40960, "length": 12288}]),
        )];
        common.streams[0].flags = 0;
        common.attributes = vec![attribute(0x80, "", 0)];
        common
    }

    #[test]
    fn a_sis_link_is_read_exactly_and_only_while_it_holds_no_data_of_its_own() {
        let sis = sis_file(&sis_link_file()).unwrap().unwrap();
        assert_eq!(sis.plain_bytes, 10_000);
        assert_eq!(sis.link.common_store_record, 70);
        assert_eq!(sis.link.common_store_sequence, 3);
        assert_eq!(
            sis.link.common_store_name(),
            "{0D0C0B0A-0F0E-1110-1213-141516171819}.sis"
        );
        // Written to since it was linked: part of its data its own.
        let mut written = sis_link_file();
        written.streams[0] = cloud_stream(
            false,
            10_000,
            serde_json::json!([
                {"logical_offset": 0, "physical_offset": 40960, "length": 4096},
                {"logical_offset": 4096, "physical_offset": null, "length": 8192},
            ]),
        );
        assert_eq!(sis_file(&written).unwrap(), None);
        // A named stream beside it, or a directory: not a link this build reads.
        let mut named = sis_link_file();
        named.streams.push(stream("extra", 0));
        assert_eq!(sis_file(&named).unwrap(), None);
        let mut folder = sis_link_file();
        folder.is_directory = true;
        assert_eq!(sis_file(&folder).unwrap(), None);
        // Expanded, it is made without its reparse point and sparse mark.
        let t = PlainTransform {
            kind: PlainKind::SisExpanded,
            cleared_attributes: 0,
        };
        assert_eq!(t.target_attributes(0x620), 0x20);
    }

    #[test]
    fn a_sis_links_common_store_file_has_to_be_the_one_its_point_names() {
        let sis = sis_file(&sis_link_file()).unwrap().unwrap();
        let named =
            vec!["\\SIS Common Store\\{0d0c0b0a-0f0e-1110-1213-141516171819}.sis".to_owned()];
        let common = common_store_file();
        let resolved = resolve_sis("\\a.bin", &sis, Some(&common), &named).unwrap();
        assert_eq!(resolved.common_store_path, named[0]);
        assert_eq!(
            (
                resolved.common_store_record,
                resolved.common_store_sequence,
                resolved.bytes
            ),
            (70, 3, 10_000)
        );
        let refused = |common: Option<&FileInventory>, paths: &[String]| {
            resolve_sis("\\a.bin", &sis, common, paths).unwrap_err()
        };
        assert!(refused(None, &[]).contains("no such record is in use"));
        let elsewhere = vec!["\\other\\x.sis".to_owned()];
        assert!(refused(Some(&common), &elsewhere).contains("that record is named \\other\\x.sis"));
        let mut shorter = common_store_file();
        shorter.streams[0].logical_size = 9_999;
        assert!(refused(Some(&shorter), &named).contains("9999 bytes long"));
        let pointed = with_point(common_store_file(), sis_point());
        assert!(refused(Some(&pointed), &named).contains("reparse point of its own"));
        let mut encrypted = common_store_file();
        encrypted.streams[0].flags = 0x4000;
        assert!(refused(Some(&encrypted), &named).contains("encrypted"));
        // Every refusal names the link and the file it needs.
        assert!(refused(None, &[]).starts_with(
            "\\a.bin is a Single Instance Storage link whose data is the common store file \\SIS Common Store\\{0D0C0B0A-0F0E-1110-1213-141516171819}.sis (MFT record 70, sequence 3)"
        ));
    }

    #[test]
    fn sis_links_expanded_are_held_to_the_free_space() {
        let link = sis_file(&sis_link_file()).unwrap().unwrap();
        assert_eq!(sis_growth(&[link, link], 4096), 24_576);
        assert!(require_sis_room(&[link, link], 4096, 24_576).is_ok());
        let refused = require_sis_room(&[link, link], 4096, 24_575)
            .unwrap_err()
            .to_string();
        assert!(
            refused.starts_with("the 2 Single Instance Storage link(s) take 24576 bytes made plain (in 4096-byte clusters) and 24575 bytes are free for them. Free 1 bytes"),
            "{refused}"
        );
        assert!(require_sis_room(&[], 4096, 0).is_ok());
    }

    #[test]
    fn a_sync_roots_folder_shows_windows_no_stream_of_the_apis() {
        let mut folder = wof_file();
        folder.is_directory = true;
        let identity = "${3D0CE612-FDEE-43f7-8ACA-957BEC0CCBA0}.SyncRootIdentity";
        folder.streams = vec![stream(identity, 0)];
        folder.attributes = vec![attribute(0x80, identity, 0), attribute(0xc0, "", 0)];
        let view = sync_root_view(&folder);
        assert!(view.streams.is_empty());
        assert_eq!(view.attributes.len(), 1);
        assert!(view.reparse.is_some());
    }

    #[test]
    fn a_cloud_placeholder_shows_windows_what_its_raw_record_holds() {
        let copy = "cd".repeat(16);
        let mut raw = wof_file();
        raw.streams.retain(|s| s.name_utf16.is_empty());
        raw.attributes = vec![attribute(0x80, "", 0x8000), attribute(0xc0, "", 0)];
        raw.standard_information.as_mut().unwrap().file_attributes = 0x8_0620;
        let view = filter_view(&raw, false, &copy).unwrap();
        // Its point, its attributes (pinned, sparse, reparse) and its sparse
        // stream are as the raw record holds them.
        assert!(view.reparse.is_some());
        assert_eq!(view.attributes.len(), 2);
        assert_eq!(
            view.standard_information.as_ref().unwrap().file_attributes,
            0x8_0620
        );
        assert_eq!(view.streams[0].flags, 0x8000);
        // Its contents are held to the copy read through the filter.
        assert_eq!(
            view.streams[0].logical_sha256.as_deref(),
            Some(copy.as_str())
        );
    }

    #[test]
    fn only_a_copied_streams_allocation_is_held_by_its_copy() {
        // An identity no other test of this process takes a copy of.
        let _held = COPY_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
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
    fn only_the_cloud_files_apis_own_stream_is_a_sync_roots() {
        let named = |name: &str| {
            let mut stream = cloud_stream(true, 120, serde_json::json!([]));
            stream.name = name.into();
            stream.name_utf16 = name.encode_utf16().collect();
            stream.flags = 0;
            stream
        };
        assert!(sync_root_stream(&named(
            "${3D0CE612-FDEE-43f7-8ACA-957BEC0CCBA0}.SyncRootIdentity"
        )));
        assert!(!sync_root_stream(&named("Zone.Identifier")));
        assert!(!sync_root_stream(&named("")));
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
    fn a_deduplicated_file_grows_the_volume_by_its_plain_length() {
        let file = DedupFile {
            plain_bytes: 5000,
            allocated: 4096,
        };
        // Counted as a WOF file is: its plain length rounded to the target
        // cluster, less what its own stream took.
        assert_eq!(wof_growth(&[file.growing()], 4096), (8192, 4096));
        let refused = require_wof_room(&[file.growing()], 4096, 0)
            .unwrap_err()
            .to_string();
        assert!(
            refused.contains("Start-DedupJob -Type Unoptimization"),
            "{refused}"
        );
        assert!(DEDUP_FILTER_REMEDY.contains("Windows Server"));
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
