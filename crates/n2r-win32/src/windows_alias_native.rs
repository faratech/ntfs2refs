//! Held-handle construction of derived Windows aliases on an owned ReFS shadow.
//! No path open, source mutation, privilege enabling or admission authority.
//! The caller retains constructor ownership, namespace exclusion and the real
//! source/shadow binding. A serialized observation cannot supply those owners.
use crate::{file_storage, reparse_layout::Point, reparse_native, shadow_names};
use serde::Serialize;
use std::{fs::File, io, os::windows::io::AsRawHandle};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_TYPE_DISK, GetFileInformationByHandleEx, GetFileType, GetVolumeInformationByHandleW,
};

/// Conservative caller-paid workspace for bounded native names and reparse
/// queries. This is not a process-memory observation or an independent lease.
pub const WORKSPACE_BYTES: u64 = 1024 * 1024;

#[derive(Clone, Debug, Serialize)]
pub struct Observation {
    pub parent_file_id_info: [u8; 24],
    pub canonical_file_id_info: [u8; 24],
    pub alias_file_id_info: [u8; 24],
    pub directory: bool,
    pub alias_component: Vec<u16>,
    pub relative_target_component: Vec<u16>,
    pub point: Point,
    pub same_volume_and_parent_verified: bool,
    pub canonical_identity_and_shape_unchanged: bool,
    pub grants_admission_or_source_authority: bool,
}

#[derive(PartialEq, Eq)]
struct Snapshot {
    id: [u8; 24],
    standard: [u8; 24],
    tag: [u8; 8],
    path: String,
}
fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
fn information<const N: usize>(file: &File, class: i32) -> io::Result<[u8; N]> {
    if N > 24 { return Err(invalid("alias native information exceeds fixed buffer")); }
    let mut words = [0u64; 3];
    // SAFETY: borrowed live handle, aligned initialized fixed output, exact
    // readonly information class; neither the handle nor pointer escapes.
    if unsafe { GetFileInformationByHandleEx(file.as_raw_handle(), class,
        words.as_mut_ptr().cast(), N as u32) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: all N initialized bytes belong to the live aligned allocation.
    Ok(unsafe { std::slice::from_raw_parts(words.as_ptr().cast::<u8>(), N) }
        .try_into().map_err(|_| invalid("alias information width differs"))?)
}
fn require_refs(file: &File) -> io::Result<()> {
    let mut label = [0u16; 261];
    let mut filesystem = [0u16; 32];
    let (mut serial, mut maximum, mut flags) = (0u32, 0u32, 0u32);
    // SAFETY: actual caller-held file/directory handle, initialized bounded
    // metadata outputs; no volume/path is opened or filesystem state changed.
    if unsafe { GetVolumeInformationByHandleW(file.as_raw_handle(), label.as_mut_ptr(),
        label.len() as u32, &mut serial, &mut maximum, &mut flags,
        filesystem.as_mut_ptr(), filesystem.len() as u32) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if filesystem[..5] != [82, 101, 70, 83, 0] {
        return Err(invalid("derived alias operations require actual ReFS handles, never an NTFS source"));
    }
    Ok(())
}
fn snapshot(file: &File, directory: bool) -> io::Result<Snapshot> {
    // SAFETY: GetFileType only examines the borrowed live handle.
    if unsafe { GetFileType(file.as_raw_handle()) } != FILE_TYPE_DISK {
        return Err(invalid("derived alias requires an actual filesystem file/directory"));
    }
    require_refs(file)?;
    let id = information::<24>(file, 18)?;
    let standard = information::<24>(file, 1)?;
    let mut tag = information::<8>(file, 9)?;
    let attributes = u32::from_le_bytes(tag[..4].try_into().unwrap());
    // ReparseTag is defined only when FILE_ATTRIBUTE_REPARSE_POINT is set.
    // Actual point presence/bytes are independently queried on the same handle.
    if attributes & 0x400 == 0 { tag[4..].fill(0); }
    if id[..8] == [0; 8] || id[8..] == [0; 16]
        || standard[20] != 0 || standard[21] != u8::from(directory)
        || u32::from_le_bytes(standard[16..20].try_into().unwrap()) == 0
        || (attributes & 0x10 != 0) != directory {
        return Err(invalid("alias native identity/delete/type/link information is invalid"));
    }
    Ok(Snapshot { id, standard, tag, path: file_storage::final_path_guid(file)? })
}
fn direct_child<'a>(parent: &Snapshot, child: &'a Snapshot) -> io::Result<&'a str> {
    let (actual_parent, component) = child.path.rsplit_once('\\')
        .ok_or_else(|| invalid("held derived alias child has no native parent"))?;
    if !actual_parent.eq_ignore_ascii_case(parent.path.trim_end_matches('\\'))
        || !shadow_names::valid_unicode_component(component) {
        return Err(invalid("held alias/canonical object is not a direct child of the held parent"));
    }
    Ok(component)
}
fn validate_pair(parent: &Snapshot, canonical: &Snapshot, alias: &Snapshot,
    relative: &[u16]) -> io::Result<Vec<u16>> {
    if parent.id[..8] != canonical.id[..8] || canonical.id[..8] != alias.id[..8]
        || parent.id == canonical.id || parent.id == alias.id || canonical.id == alias.id
        || u32::from_le_bytes(parent.tag[..4].try_into().unwrap()) & 0x400 != 0
        || parent.tag[4..] != [0; 4]
        || u32::from_le_bytes(alias.standard[16..20].try_into().unwrap()) != 1 {
        return Err(invalid("derived alias needs distinct same-volume objects and an ordinary held parent"));
    }
    let target = direct_child(parent, canonical)?;
    if target.encode_utf16().ne(relative.iter().copied()) {
        return Err(invalid("relative alias target does not name the actual held canonical sibling"));
    }
    Ok(direct_child(parent, alias)?.encode_utf16().collect())
}
fn same_parent(parent: &Snapshot, actual: &Snapshot) -> bool {
    // Child metadata changes may alter a directory's allocation or timestamps.
    // Its actual identity/type/name must remain the original held parent.
    parent.id == actual.id && parent.path == actual.path && parent.tag == actual.tag
}

/// Install ONLY on a caller-held constructor-owned fresh empty alias. All
/// handles must be synchronous/no-follow and exclude outside namespace writers.
/// The parent is natively checked as the direct same-volume parent of both
/// handles. The caller additionally proves shadow ownership, the alias leaf's
/// mapping to its source DOS name, case/collision policy and reserved workspace.
/// Required SET privileges must already belong to the caller; none are enabled.
/// On error retain the constructor state: no delete, retry or repair occurs.
pub fn install_fresh_owned(parent: &File, canonical: &File, alias: &File,
    directory: bool, relative_target_component: &[u16]) -> io::Result<Observation> {
    let expected = Point::relative_component_alias(relative_target_component)?;
    let parent_before = snapshot(parent, true)?;
    let canonical_before = snapshot(canonical, directory)?;
    let alias_before = snapshot(alias, directory)?;
    validate_pair(&parent_before, &canonical_before, &alias_before, relative_target_component)?;
    let canonical_point = reparse_native::capture(canonical)?;
    if reparse_native::capture(parent)?.is_some() || reparse_native::capture(alias)?.is_some()
        || (!directory && u64::from_le_bytes(alias_before.standard[8..16].try_into().unwrap()) != 0) {
        return Err(invalid("derived alias must start fresh empty and non-reparse beneath an ordinary parent"));
    }
    // Existing primitive also proves no DATA runs for an empty file, complete
    // empty-directory enumeration, same native ID and exact SET/GET bytes.
    let installed = reparse_native::restore_fresh_owned(alias, &expected)?;
    if installed != expected { return Err(invalid("derived alias install readback differs")); }
    let result = verify_owned(parent, canonical, alias, directory, relative_target_component)?;
    if result.parent_file_id_info != parent_before.id
        || result.canonical_file_id_info != canonical_before.id
        || result.alias_file_id_info != alias_before.id
        || snapshot(canonical, directory)? != canonical_before
        || reparse_native::capture(canonical)? != canonical_point
        || !same_parent(&parent_before, &snapshot(parent, true)?) {
        return Err(invalid("held canonical target or parent changed during derived alias installation"));
    }
    Ok(result)
}

/// Read-only no-follow verification on the same caller-owned alias/target/parent
/// handles. This does not follow the link, open its target or issue authority.
/// Canonical target reparse bytes, when present, remain exact and unchanged.
pub fn verify_owned(parent: &File, canonical: &File, alias: &File,
    directory: bool, relative_target_component: &[u16]) -> io::Result<Observation> {
    let expected = Point::relative_component_alias(relative_target_component)?;
    let parent_before = snapshot(parent, true)?;
    let canonical_before = snapshot(canonical, directory)?;
    let alias_before = snapshot(alias, directory)?;
    let alias_component = validate_pair(&parent_before, &canonical_before, &alias_before,
        relative_target_component)?;
    let canonical_point = reparse_native::capture(canonical)?;
    if reparse_native::capture(parent)?.is_some()
        || reparse_native::capture(alias)?.as_ref() != Some(&expected)
        || u32::from_le_bytes(alias_before.tag[..4].try_into().unwrap()) & 0x400 == 0
        || u32::from_le_bytes(alias_before.tag[4..].try_into().unwrap()) != expected.tag()
        || (!directory && u64::from_le_bytes(alias_before.standard[8..16].try_into().unwrap()) != 0) {
        return Err(invalid("held derived alias has different native reparse bytes or type"));
    }
    if snapshot(canonical, directory)? != canonical_before
        || reparse_native::capture(canonical)? != canonical_point
        || snapshot(alias, directory)? != alias_before
        || !same_parent(&parent_before, &snapshot(parent, true)?) {
        return Err(invalid("derived alias verification lost stable actual target/alias/parent identity"));
    }
    Ok(Observation { parent_file_id_info: parent_before.id,
        canonical_file_id_info: canonical_before.id, alias_file_id_info: alias_before.id,
        directory, alias_component, relative_target_component: relative_target_component.to_vec(),
        point: expected, same_volume_and_parent_verified: true,
        canonical_identity_and_shape_unchanged: true, grants_admission_or_source_authority: false })
}
