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

/// A link check involves three held objects: the directory the link is in,
/// the object it points at, and the link itself. This says which one a
/// failure belongs to.
fn of(role: &'static str, error: io::Error) -> io::Error {
    io::Error::new(error.kind(), format!("{role}: {error}"))
}
const PARENT: &str = "the link's parent directory";
const CANONICAL: &str = "the object the link points at";
const ALIAS: &str = "the link itself";
fn information<const N: usize>(file: &File, class: i32) -> io::Result<[u8; N]> {
    if N > 24 {
        return Err(invalid("alias native information exceeds fixed buffer"));
    }
    let mut words = [0u64; 3];
    // SAFETY: borrowed live handle, aligned initialized fixed output, exact
    // readonly information class; neither the handle nor pointer escapes.
    if unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle(),
            class,
            words.as_mut_ptr().cast(),
            N as u32,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: all N initialized bytes belong to the live aligned allocation.
    Ok(
        unsafe { std::slice::from_raw_parts(words.as_ptr().cast::<u8>(), N) }
            .try_into()
            .map_err(|_| invalid("alias information width differs"))?,
    )
}
fn require_refs(file: &File) -> io::Result<()> {
    let mut label = [0u16; 261];
    let mut filesystem = [0u16; 32];
    let (mut serial, mut maximum, mut flags) = (0u32, 0u32, 0u32);
    // SAFETY: actual caller-held file/directory handle, initialized bounded
    // metadata outputs; no volume/path is opened or filesystem state changed.
    if unsafe {
        GetVolumeInformationByHandleW(
            file.as_raw_handle(),
            label.as_mut_ptr(),
            label.len() as u32,
            &mut serial,
            &mut maximum,
            &mut flags,
            filesystem.as_mut_ptr(),
            filesystem.len() as u32,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    if filesystem[..5] != [82, 101, 70, 83, 0] {
        return Err(invalid(
            "derived alias operations require actual ReFS handles, never an NTFS source",
        ));
    }
    Ok(())
}
fn snapshot(file: &File, directory: bool) -> io::Result<Snapshot> {
    // SAFETY: GetFileType only examines the borrowed live handle.
    if unsafe { GetFileType(file.as_raw_handle()) } != FILE_TYPE_DISK {
        return Err(invalid(
            "derived alias requires an actual filesystem file/directory",
        ));
    }
    require_refs(file)?;
    let id = information::<24>(file, 18)?;
    let standard = information::<24>(file, 1)?;
    let mut tag = information::<8>(file, 9)?;
    let attributes = u32::from_le_bytes(tag[..4].try_into().unwrap());
    // ReparseTag is defined only when FILE_ATTRIBUTE_REPARSE_POINT is set.
    // Actual point presence/bytes are independently queried on the same handle.
    if attributes & 0x400 == 0 {
        tag[4..].fill(0);
    }
    if id[..8] == [0; 8]
        || id[8..] == [0; 16]
        || standard[20] != 0
        || standard[21] != u8::from(directory)
        || u32::from_le_bytes(standard[16..20].try_into().unwrap()) == 0
        || (attributes & 0x10 != 0) != directory
    {
        return Err(invalid(
            "alias native identity/delete/type/link information is invalid",
        ));
    }
    // `direct_child` needs each handle's path on its volume, and one volume
    // for all three: the device path gives both.
    Ok(Snapshot {
        id,
        standard,
        tag,
        path: file_storage::final_path_device(file)?,
    })
}
fn direct_child<'a>(parent: &Snapshot, child: &'a Snapshot) -> io::Result<&'a str> {
    let (actual_parent, component) = child
        .path
        .rsplit_once('\\')
        .ok_or_else(|| invalid("held derived alias child has no native parent"))?;
    if !actual_parent.eq_ignore_ascii_case(parent.path.trim_end_matches('\\'))
        || !shadow_names::valid_unicode_component(component)
    {
        return Err(invalid(
            "held alias/canonical object is not a direct child of the held parent",
        ));
    }
    Ok(component)
}
fn validate_pair(
    parent: &Snapshot,
    canonical: &Snapshot,
    alias: &Snapshot,
    relative: &[u16],
) -> io::Result<Vec<u16>> {
    if parent.id[..8] != canonical.id[..8]
        || canonical.id[..8] != alias.id[..8]
        || parent.id == canonical.id
        || parent.id == alias.id
        || canonical.id == alias.id
        || u32::from_le_bytes(parent.tag[..4].try_into().unwrap()) & 0x400 != 0
        || parent.tag[4..] != [0; 4]
        || u32::from_le_bytes(alias.standard[16..20].try_into().unwrap()) != 1
    {
        return Err(invalid(
            "derived alias needs distinct same-volume objects and an ordinary held parent",
        ));
    }
    let target = direct_child(parent, canonical)?;
    if target.encode_utf16().ne(relative.iter().copied()) {
        return Err(invalid(
            "relative alias target does not name the actual held canonical sibling",
        ));
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
pub fn install_fresh_owned(
    parent: &File,
    canonical: &File,
    alias: &File,
    directory: bool,
    relative_target_component: &[u16],
) -> io::Result<Observation> {
    install_fresh_owned_under(
        parent,
        None,
        canonical,
        alias,
        directory,
        relative_target_component,
    )
}

/// [`install_fresh_owned`] beneath a parent that the caller examined
/// ([`examine_parent`]) through this same held handle, once for the links of
/// a batch that lie in it: installing a link's point changes the link, never
/// its parent's identity, path, type or reparse point, which is what the
/// examination holds. Only under the check-once policy; otherwise each
/// installation examines the parent itself, as before.
pub fn install_fresh_owned_in(
    parent: &File,
    examined: &ExaminedParent,
    canonical: &File,
    alias: &File,
    directory: bool,
    relative_target_component: &[u16],
) -> io::Result<Observation> {
    install_fresh_owned_under(
        parent,
        Some(examined),
        canonical,
        alias,
        directory,
        relative_target_component,
    )
}

fn install_fresh_owned_under(
    parent: &File,
    examined: Option<&ExaminedParent>,
    canonical: &File,
    alias: &File,
    directory: bool,
    relative_target_component: &[u16],
) -> io::Result<Observation> {
    let expected = Point::relative_component_alias(relative_target_component)?;
    // Under the check-once policy what this call has read through one of
    // its held handles is not asked of that handle again while nothing has
    // changed the object: the parent (examined by the caller or here) and
    // the target are not looked at again by the verification that follows
    // the installation, and the link's point is the one the installation
    // read back. Every distinct check is still made once. Otherwise each is
    // asked again, as before.
    let reuse = crate::verify_policy::checks_once();
    let examined_here;
    let parent_before = match examined.filter(|_| reuse) {
        Some(examined) => &examined.before,
        None => {
            examined_here = snapshot(parent, true).map_err(|e| of(PARENT, e))?;
            &examined_here
        }
    };
    let canonical_before = snapshot(canonical, directory).map_err(|e| of(CANONICAL, e))?;
    let alias_before = snapshot(alias, directory).map_err(|e| of(ALIAS, e))?;
    validate_pair(
        parent_before,
        &canonical_before,
        &alias_before,
        relative_target_component,
    )?;
    let canonical_point = reparse_native::capture(canonical)?;
    // The examination of the parent found it without a reparse point; the
    // installation below finds the fresh link without one before it sets it.
    if (!(reuse && examined.is_some()) && reparse_native::capture(parent)?.is_some())
        || (!reuse && reparse_native::capture(alias)?.is_some())
        || (!directory && u64::from_le_bytes(alias_before.standard[8..16].try_into().unwrap()) != 0)
    {
        return Err(invalid(
            "derived alias must start fresh empty and non-reparse beneath an ordinary parent",
        ));
    }
    // Existing primitive also proves no DATA runs for an empty file, complete
    // empty-directory enumeration, same native ID and exact SET/GET bytes.
    let installed = reparse_native::restore_fresh_owned(alias, &expected)?;
    if installed != expected {
        return Err(invalid("derived alias install readback differs"));
    }
    let result = if reuse {
        verify_held(
            parent,
            parent_before,
            canonical,
            alias,
            directory,
            relative_target_component,
            Some(Seen {
                canonical: &canonical_before,
                alias_point: &installed,
            }),
        )?
    } else {
        verify_owned(
            parent,
            canonical,
            alias,
            directory,
            relative_target_component,
        )?
    };
    if result.parent_file_id_info != parent_before.id
        || result.canonical_file_id_info != canonical_before.id
        || result.alias_file_id_info != alias_before.id
    {
        return Err(invalid(
            "held canonical target or parent changed during derived alias installation",
        ));
    }
    // The verification just made took fresh snapshots of all three objects
    // after the link was installed and its identities equal the ones taken
    // before. Looking at the target and the parent yet again (two more
    // snapshots of five queries each, for every one of 112,000 links) is
    // left out under the check-once policy.
    if !reuse
        && (snapshot(canonical, directory)? != canonical_before
            || reparse_native::capture(canonical)? != canonical_point
            || !same_parent(parent_before, &snapshot(parent, true)?))
    {
        return Err(invalid(
            "held canonical target or parent changed during derived alias installation",
        ));
    }
    Ok(result)
}

/// What [`install_fresh_owned`] read through its held handles in the same
/// call, for the verification that follows the installation: the target,
/// which nothing has changed since, and the link's point as the
/// installation read it back, after which nothing has changed the link.
struct Seen<'a> {
    canonical: &'a Snapshot,
    alias_point: &'a Point,
}

/// Read-only no-follow verification on the same caller-owned alias/target/parent
/// handles. This does not follow the link, open its target or issue authority.
/// Canonical target reparse bytes, when present, remain exact and unchanged.
pub fn verify_owned(
    parent: &File,
    canonical: &File,
    alias: &File,
    directory: bool,
    relative_target_component: &[u16],
) -> io::Result<Observation> {
    let examined = examine_parent(parent)?;
    verify_owned_in(
        parent,
        &examined,
        canonical,
        alias,
        directory,
        relative_target_component,
    )
}

/// A held parent directory as a link's verification finds it: its identity,
/// its path on its volume, that it is an ordinary directory and that it has
/// no reparse point. A directory holds many links, and a caller that verifies
/// them through one held handle examines the parent once for all of them
/// ([`verify_owned_in`]) instead of once for each: on the full Windows volume
/// that was a third of the opens, questions and closes of 112,609 links, in
/// each of three passes.
pub struct ExaminedParent {
    before: Snapshot,
}

/// Examines `parent` as [`verify_owned`] does first of all. What it finds
/// holds for as long as the caller holds this handle.
pub fn examine_parent(parent: &File) -> io::Result<ExaminedParent> {
    let before = snapshot(parent, true).map_err(|e| of(PARENT, e))?;
    if reparse_native::capture(parent)?.is_some() {
        return Err(invalid(
            "held derived alias has different native reparse bytes or type",
        ));
    }
    Ok(ExaminedParent { before })
}

/// [`verify_owned`] with a parent that was examined through this same held
/// handle. Every check is the one `verify_owned` makes; the parent's own are
/// in `examined`.
pub fn verify_owned_in(
    parent: &File,
    examined: &ExaminedParent,
    canonical: &File,
    alias: &File,
    directory: bool,
    relative_target_component: &[u16],
) -> io::Result<Observation> {
    verify_held(
        parent,
        &examined.before,
        canonical,
        alias,
        directory,
        relative_target_component,
        None,
    )
}

/// [`verify_owned_in`], where `seen` is what the installation made in the
/// same call has just read of the target and of the link's point.
fn verify_held(
    parent: &File,
    parent_before: &Snapshot,
    canonical: &File,
    alias: &File,
    directory: bool,
    relative_target_component: &[u16],
    seen: Option<Seen<'_>>,
) -> io::Result<Observation> {
    let expected = Point::relative_component_alias(relative_target_component)?;
    let read_canonical;
    let canonical_before = match &seen {
        Some(seen) => seen.canonical,
        None => {
            read_canonical = snapshot(canonical, directory).map_err(|e| of(CANONICAL, e))?;
            &read_canonical
        }
    };
    let alias_before = snapshot(alias, directory).map_err(|e| of(ALIAS, e))?;
    let alias_component = validate_pair(
        parent_before,
        canonical_before,
        &alias_before,
        relative_target_component,
    )?;
    // The target's point is compared only by the second look below; the
    // installation already read it in this call.
    let canonical_point = match &seen {
        Some(_) => None,
        None => reparse_native::capture(canonical)?,
    };
    let alias_point = match &seen {
        Some(seen) => Some(seen.alias_point.clone()),
        None => reparse_native::capture(alias)?,
    };
    if alias_point.as_ref() != Some(&expected)
        || u32::from_le_bytes(alias_before.tag[..4].try_into().unwrap()) & 0x400 == 0
        || u32::from_le_bytes(alias_before.tag[4..].try_into().unwrap()) != expected.tag()
        || (!directory && u64::from_le_bytes(alias_before.standard[8..16].try_into().unwrap()) != 0)
    {
        return Err(invalid(
            "held derived alias has different native reparse bytes or type",
        ));
    }
    // A read-only verification of three objects this process holds: each was
    // snapshotted a second time at the end only to see that nothing changed
    // in the microseconds it took. Left out under the check-once policy.
    if !crate::verify_policy::checks_once()
        && (snapshot(canonical, directory)? != *canonical_before
            || reparse_native::capture(canonical)? != canonical_point
            || snapshot(alias, directory)? != alias_before
            || !same_parent(parent_before, &snapshot(parent, true)?))
    {
        return Err(invalid(
            "derived alias verification lost stable actual target/alias/parent identity",
        ));
    }
    Ok(Observation {
        parent_file_id_info: parent_before.id,
        canonical_file_id_info: canonical_before.id,
        alias_file_id_info: alias_before.id,
        directory,
        alias_component,
        relative_target_component: relative_target_component.to_vec(),
        point: expected,
        same_volume_and_parent_verified: true,
        canonical_identity_and_shape_unchanged: true,
        grants_admission_or_source_authority: false,
    })
}

#[cfg(test)]
mod role_tests {
    use super::*;

    #[test]
    fn a_link_check_failure_says_which_of_its_three_objects_failed() {
        let reason = "alias native identity/delete/type/link information is invalid";
        for role in [PARENT, CANONICAL, ALIAS] {
            let error = of(role, invalid(reason));
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
            assert_eq!(error.to_string(), format!("{role}: {reason}"));
        }
        assert_ne!(PARENT, CANONICAL);
        assert_ne!(CANONICAL, ALIAS);
    }
}
