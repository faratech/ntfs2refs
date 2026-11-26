//! The supported user-object projection from raw NTFS SI to Win32 attributes.
//! Internal index flags are not FILE_BASIC_INFO flags or target capabilities.
use crate::{ntfs_inspect::FileInventory, ntfs_namespace};
use anyhow::{Context, Result, ensure};

const NTFS_DIRECTORY: u32 = 0x1000_0000;
const OTHER_HIGH_FLAGS: u32 = 0xe000_0000;
const WIN32_DIRECTORY: u32 = 0x10;

pub(crate) struct Projection {
    /// Existing source-policy bits, with only the evidenced NTFS directory
    /// marker removed. In particular NORMAL and low DIRECTORY policy are not
    /// broadened here.
    pub source_attributes: u32,
    pub win32_attributes: u32,
}

pub(crate) fn project_user(file: &FileInventory) -> Result<Projection> {
    let raw = file
        .standard_information
        .as_ref()
        .context("missing raw standard information")?
        .file_attributes;
    ensure!(
        raw & OTHER_HIGH_FLAGS == 0,
        "unsupported user SI index/view/reserved flags"
    );
    if raw & NTFS_DIRECTORY != 0 {
        ensure!(
            file.is_directory
                && file.base_file_reference == 0
                && file
                    .streams
                    .iter()
                    .all(|stream| !stream.name_utf16.is_empty()),
            "NTFS directory marker requires a complete ordinary directory"
        );
        let mut roots = file.attributes.iter().filter(|attribute| {
            attribute.type_code == 0x90 && ntfs_namespace::is_i30(&attribute.name_utf16)
        });
        let root = roots
            .next()
            .context("NTFS directory marker lacks its I30 index root")?;
        ensure!(
            roots.next().is_none()
                && root.resident
                && (48..=4096).contains(&root.logical_size)
                && root.initialized_size == root.logical_size
                && root.allocated_size == root.logical_size
                && root.lowest_vcn == 0
                && root.extents.is_empty()
                && root.compression_unit == 0
                && root.total_allocated_size.is_none()
                && (root.flags == 0 || (root.flags == 1 && raw & 0x800 != 0))
                && root
                    .resident_sha256
                    .as_deref()
                    .is_some_and(n2r_win32::content_digest::is_hex),
            "NTFS directory marker requires one coherent resident I30 root"
        );
        // The frozen raw namespace walker and native source observer still
        // independently validate actual root contents, membership and type.
    }
    let source_attributes = raw & !NTFS_DIRECTORY;
    Ok(Projection {
        source_attributes,
        win32_attributes: source_attributes
            | if file.is_directory {
                WIN32_DIRECTORY
            } else {
                0
            },
    })
}
