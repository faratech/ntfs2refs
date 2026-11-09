//! Hard-link namespaces over one canonical native file. Link creation uses
//! only the constructor-owned file and destination-directory handles.
use super::input_domain::{InputDomain, ObjectInput, SliceInputs};
use super::*;
use std::collections::{BTreeMap, BTreeSet};
use windows_sys::Win32::{Foundation::HANDLE, System::IO::IO_STATUS_BLOCK};

pub(super) const MAX_NAMES: usize = 16_384;

#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtSetInformationFile(
        handle: HANDLE,
        status: *mut IO_STATUS_BLOCK,
        information: *const core::ffi::c_void,
        length: u32,
        class: i32,
    ) -> i32;
    fn RtlNtStatusToDosError(status: i32) -> u32;
}

pub(super) fn paths<'a>(item: &'a Input<'_>) -> impl Iterator<Item = &'a [String]> {
    std::iter::once(item.components).chain(item.additional_names.iter().map(Vec::as_slice))
}

pub(super) fn count(item: &Input<'_>) -> io::Result<u32> {
    if item.directory && !item.additional_names.is_empty() {
        return Err(invalid("directory hard links are not supported"));
    }
    u32::try_from(item.additional_names.len())
        .ok()
        .and_then(|n| n.checked_add(1))
        .ok_or_else(|| invalid("hard-link count overflow"))
}

pub(super) fn validate(
    input: &[Input<'_>],
    maximum_names: usize,
    valid_component: impl Fn(&str) -> bool,
) -> io::Result<()> {
    validate_domain(&SliceInputs(input), maximum_names, valid_component)
}

pub(super) fn validate_domain(
    input: &impl InputDomain,
    maximum_names: usize,
    valid_component: impl Fn(&str) -> bool,
) -> io::Result<()> {
    validate_domain_inner(input, maximum_names, None, valid_component)
}
pub(super) fn resource_path_valid(root: &str, path: &[String]) -> bool {
    path.iter()
        .try_fold(root.encode_utf16().count(), |n, part| {
            n.checked_add(part.encode_utf16().count())
                .and_then(|n| n.checked_add(1))
        })
        .is_some_and(|n| n.saturating_sub(usize::from(!path.is_empty())) < 32767)
}
pub(super) fn validate_resource_domain(
    input: &impl InputDomain,
    maximum_names: usize,
    root: &str,
    valid_component: impl Fn(&str) -> bool,
) -> io::Result<()> {
    validate_domain_inner(input, maximum_names, Some(root), valid_component)
}
fn validate_domain_inner(
    input: &impl InputDomain,
    maximum_names: usize,
    root: Option<&str>,
    valid_component: impl Fn(&str) -> bool,
) -> io::Result<()> {
    if !input.any(|i| !i.additional_names.is_empty())? {
        return Ok(());
    }
    let mut directories = BTreeSet::new();
    input.for_each(|_, item| {
        if item.directory {
            directories.insert(crate::shadow_names::conservative_path_key(item.components));
        }
        Ok(())
    })?;
    let mut names = BTreeSet::new();
    for index in 0..input.len() {
        let owned = input.object(index)?;
        let view = owned.input();
        let item = &view;
        count(item)?;
        if !item.additional_names.is_empty()
            && item
                .components
                .first()
                .is_some_and(|n| n == "System Volume Information")
        {
            return Err(invalid(
                "filesystem-managed objects cannot carry user hard links",
            ));
        }
        for path in paths(item) {
            if root.map_or(path.len() > 16, |root| !resource_path_valid(root, path))
                || path.iter().any(|p| !valid_component(p))
                || !names.insert(crate::shadow_names::conservative_path_key(path))
                || names.len() > maximum_names
                || (!path.is_empty()
                    && !directories.contains(&crate::shadow_names::conservative_path_key(
                        &path[..path.len() - 1],
                    )))
                || (!item.additional_names.is_empty()
                    && path
                        .first()
                        .is_some_and(|n| n == "System Volume Information"))
            {
                return Err(invalid(
                    "hard-link namespace path, parent or capacity differs",
                ));
            }
        }
    }
    Ok(())
}

pub(super) fn find<'a, 'b>(
    input: &'a [Input<'b>],
    path: &[String],
) -> Option<(usize, &'a Input<'b>)> {
    input
        .iter()
        .enumerate()
        .find(|(_, item)| paths(item).any(|p| p == path))
}

#[derive(Debug, Serialize)]
pub struct Observation {
    pub components: Vec<String>,
    pub before: Snapshot,
    pub after: Snapshot,
    pub same_file_id: bool,
    pub expected_link_count: u32,
    pub link_count_matches: bool,
}

pub(super) fn observe(
    root: &str,
    item: &Input<'_>,
    canonical: &Snapshot,
    protected: bool,
) -> io::Result<Vec<Observation>> {
    let expected = count(item)?;
    let canonical_id = query_bytes(canonical, 18, 24)?;
    let mut result = Vec::with_capacity(item.additional_names.len());
    for path in item.additional_names {
        let name = format!("{root}{}", path.join("\\"));
        let file = open_input(&name, item, protected)?;
        let before = repeat_snapshot(&file, canonical);
        let after = repeat_snapshot(&file, canonical);
        let same_file_id = query_bytes(&before, 18, 24)? == canonical_id
            && query_bytes(&after, 18, 24)? == canonical_id;
        let link_count_matches = layout::u32_at(query_bytes(&before, 1, 24)?, 16)? == expected
            && layout::u32_at(query_bytes(&after, 1, 24)?, 16)? == expected;
        if before != after || before != *canonical || !same_file_id || !link_count_matches {
            return Err(invalid(
                "hard-link alias identity, metadata or link count differs",
            ));
        }
        result.push(Observation {
            components: path.clone(),
            before,
            after,
            same_file_id,
            expected_link_count: expected,
            link_count_matches,
        });
    }
    Ok(result)
}

pub(super) fn verify(
    item: &Input<'_>,
    canonical: &Snapshot,
    aliases: &[Observation],
) -> io::Result<()> {
    if aliases.len() != item.additional_names.len() {
        return Err(invalid("hard-link observation coverage differs"));
    }
    let expected = count(item)?;
    for (path, alias) in item.additional_names.iter().zip(aliases) {
        if alias.components != *path
            || alias.before != *canonical
            || alias.after != alias.before
            || !alias.same_file_id
            || !alias.link_count_matches
            || alias.expected_link_count != expected
        {
            return Err(invalid(
                "hard-link observation does not bind the canonical file",
            ));
        }
    }
    Ok(())
}

/// FILE_LINK_INFORMATION: ReplaceIfExists=false, native parent handle,
/// relative single component, byte length (no terminator). WDK documents no
/// additional source-handle access requirement for FileLinkInformation.
fn create_link(source: &File, parent: &File, name: &str) -> io::Result<()> {
    if std::mem::size_of::<HANDLE>() != 8 {
        return Err(invalid(
            "hard-link native layout currently requires 64-bit Windows",
        ));
    }
    let name: Vec<u16> = name.encode_utf16().collect();
    let length = (20usize + 2 * name.len()).max(24);
    let mut storage = vec![0u64; length.div_ceil(8)];
    // SAFETY: 8-byte-aligned zeroed FILE_LINK_INFORMATION backing on x64;
    // pointer fields refer to live owning handles for the synchronous call.
    let bytes = unsafe {
        std::slice::from_raw_parts_mut(storage.as_mut_ptr().cast::<u8>(), storage.len() * 8)
    };
    bytes[8..16].copy_from_slice(&(parent.as_raw_handle() as usize as u64).to_le_bytes());
    bytes[16..20].copy_from_slice(
        &u32::try_from(name.len() * 2)
            .map_err(|_| invalid("link name length overflow"))?
            .to_le_bytes(),
    );
    for (i, unit) in name.iter().enumerate() {
        bytes[20 + i * 2..22 + i * 2].copy_from_slice(&unit.to_le_bytes());
    }
    let mut iosb = IO_STATUS_BLOCK::default();
    // SAFETY: initialized bounded native structure; neither path nor handle
    // escapes the call. Class11 is FILE_INFORMATION_CLASS FileLinkInformation.
    let status = unsafe {
        NtSetInformationFile(
            source.as_raw_handle(),
            &mut iosb,
            storage.as_ptr().cast(),
            length as u32,
            11,
        )
    };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(
            unsafe { RtlNtStatusToDosError(status) } as i32,
        ));
    }
    // SAFETY: the successful synchronous call initialized IO_STATUS_BLOCK.
    let completion = unsafe { iosb.Anonymous.Status };
    if completion != 0 {
        return Err(io::Error::from_raw_os_error(
            unsafe { RtlNtStatusToDosError(completion) } as i32,
        ));
    }
    Ok(())
}

pub(super) fn create_owned(
    input: &[Input<'_>],
    handles: &BTreeMap<usize, File>,
) -> io::Result<Vec<serde_json::Value>> {
    create_owned_domain(&SliceInputs(input), handles)
}

pub(super) fn create_owned_domain(
    input: &impl InputDomain,
    handles: &BTreeMap<usize, File>,
) -> io::Result<Vec<serde_json::Value>> {
    create_owned_domain_inner(input, handles, None)
}
pub(super) fn create_owned_resource_domain(
    input: &impl InputDomain,
    handles: &BTreeMap<usize, File>,
    maximum_names: usize,
    root: &str,
    payer: &dyn report_memory::ReportMemoryAccountant,
) -> io::Result<Vec<serde_json::Value>> {
    create_owned_domain_inner(input, handles, Some((maximum_names, root, payer)))
}
fn create_owned_domain_inner(
    input: &impl InputDomain,
    handles: &BTreeMap<usize, File>,
    resources: Option<(usize, &str, &dyn report_memory::ReportMemoryAccountant)>,
) -> io::Result<Vec<serde_json::Value>> {
    if !input.any(|i| !i.additional_names.is_empty())? {
        return Ok(Vec::new());
    }
    if let Some((maximum_names, root, _)) = resources {
        validate_resource_domain(
            input,
            maximum_names,
            root,
            crate::shadow_names::valid_unicode_component,
        )?;
    } else {
        validate_domain(
            input,
            MAX_NAMES,
            crate::shadow_names::valid_unicode_component,
        )?;
    }
    let mut directories = BTreeMap::new();
    input.for_each(|index, item| {
        if item.directory
            && directories
                .insert(item.components.to_vec(), (index, 0usize))
                .is_some()
        {
            return Err(invalid("duplicate canonical hard-link parent"));
        }
        Ok(())
    })?;
    if resources.is_some() {
        input.for_each(|_, item| {
            for path in paths(item).filter(|path| !path.is_empty()) {
                let (_, count) = directories.get_mut(&path[..path.len() - 1])
                    .ok_or_else(|| invalid("resource hard-link child has no owned parent"))?;
                *count = count.checked_add(1)
                    .ok_or_else(|| invalid("resource hard-link child count overflow"))?;
            }
            Ok(())
        })?;
    }
    let mut created = Vec::new();
    for index in 0..input.len() {
        let owned = input.object(index)?;
        let view = owned.input();
        let item = &view;
        if item.additional_names.is_empty() {
            continue;
        }
        let file = handles
            .get(&index)
            .ok_or_else(|| invalid("owned canonical link handle missing"))?;
        validate_open_type(file, false)?;
        let identity = info(file, 18, 24)?;
        if layout::u32_at(&info(file, 1, 24)?, 16)? != 1 {
            return Err(invalid("fresh canonical file already has additional links"));
        }
        for (number, path) in item.additional_names.iter().enumerate() {
            let parent_path = &path[..path.len() - 1];
            let &(parent_index, parent_children) = directories
                .get(parent_path)
                .ok_or_else(|| invalid("hard-link parent is not a canonical owned directory"))?;
            let parent = handles
                .get(&parent_index)
                .ok_or_else(|| invalid("hard-link parent handle missing"))?;
            validate_open_type(parent, true)?;
            let parent_id = info(parent, 18, 24)?;
            let name = path.last().ok_or_else(|| invalid("empty hard-link name"))?;
            // Final canonical/additional-name count bounds the parent at
            // every intermediate link step. The same real tree payer owns
            // both complete enumeration passes before either native query.
            let (enumeration_budget, _enumeration_memory) = if let Some((maximum_names, _, payer)) = resources {
                if parent_children > maximum_names {
                    return Err(invalid("resource hard-link parent exceeds admitted namespace"));
                }
                let evidence = parent_children.checked_add(2).and_then(|n| n.checked_mul(4096))
                    .and_then(|n| n.checked_add(namespace_layout::CAPACITY * 4))
                    .ok_or_else(|| invalid("resource hard-link enumeration overflow"))?;
                let memory = payer.reserve((evidence as u64).checked_mul(2)
                    .ok_or_else(|| invalid("resource hard-link enumeration RAM overflow"))?)?;
                (Some(evidence), Some(memory))
            } else { (None, None) };
            if parent_id[..8] != identity[..8]
                || enumerate_with_resource_budget(parent, enumeration_budget)?
                    .iter()
                    .any(|e| e.name_utf16 == name.encode_utf16().collect::<Vec<_>>())
            {
                return Err(invalid(
                    "hard-link destination exists or is on a different volume",
                ));
            }
            create_link(file, parent, name)?;
            let expected =
                u32::try_from(number + 2).map_err(|_| invalid("hard-link count overflow"))?;
            if info(file, 18, 24)? != identity
                || info(parent, 18, 24)? != parent_id
                || layout::u32_at(&info(file, 1, 24)?, 16)? != expected
            {
                return Err(invalid("hard-link identity or incremented count differs"));
            }
            let entries: Vec<_> = enumerate_with_resource_budget(parent, enumeration_budget)?
                .into_iter()
                .filter(|e| e.name_utf16 == name.encode_utf16().collect::<Vec<_>>())
                .collect();
            if entries.len() != 1
                || entries[0].file_id != identity[8..24]
                || entries[0].attributes & (16 | 0x400) != 0
            {
                return Err(invalid(
                    "created hard-link namespace does not refer to its canonical file",
                ));
            }
            created.push(
                serde_json::json!({"components":path,"canonical_components":item.components,
                "file_id":&identity[8..24],"link_count":expected,"replace_if_exists":false}),
            );
        }
    }
    Ok(created)
}
