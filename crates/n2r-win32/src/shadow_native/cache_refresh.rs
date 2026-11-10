//! Small-cache and metadata synchronization on an existing disposable shadow.
//! User payloads are never rewritten; complete conversion admission follows.
use super::input_domain::{InputDomain, ObjectInput, SliceInputs};
use super::*;
use std::collections::{BTreeMap, BTreeSet};

/// Names the object a per-object metadata pass failed on. The path is read
/// only on the error path, so the passes cost what they did before.
pub(super) fn at_object(input: &impl InputDomain, pass: &str, index: usize, error: io::Error) -> io::Error {
    let path = input
        .object(index)
        .map(|owned| owned.input().components.join("\\"))
        .unwrap_or_else(|_| "<path unavailable>".to_owned());
    io::Error::new(
        error.kind(),
        format!("{pass}: object {index} \\{path}: {error}"),
    )
}

/// Both sides of a descriptor comparison, so a mismatch can be diagnosed from
/// the message alone.
pub(super) fn security_difference(item: &Input<'_>, actual: &Snapshot) -> String {
    format!(
        "expected_stored={} expected_api={} actual_api={} actual_kernel={}",
        hex::encode(item.security),
        item.expected_api_security
            .map_or_else(|| "same-as-stored".to_owned(), hex::encode),
        hex::encode(&actual.security),
        actual
            .kernel_security
            .as_ref()
            .map_or_else(|| "absent".to_owned(), |query| hex::encode(&query.bytes)),
    )
}

#[derive(Clone, Copy, Default)]
pub(super) struct ProtectionRestore {
    dacl: bool,
    sacl: bool,
}

fn restore_acl_protection(file: &File, item: &Input<'_>) -> io::Result<ProtectionRestore> {
    restore_acl_protection_with_limit(file, item, None)
}
pub(super) fn restore_acl_protection_with_limit(
    file: &File,
    item: &Input<'_>,
    maximum: Option<u64>,
) -> io::Result<ProtectionRestore> {
    use crate::security_descriptor::{self, Presence};
    use windows_sys::Win32::Security::{
        Authorization::{SE_FILE_OBJECT, SetSecurityInfo},
        DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
        PROTECTED_SACL_SECURITY_INFORMATION, SACL_SECURITY_INFORMATION,
        UNPROTECTED_DACL_SECURITY_INFORMATION, UNPROTECTED_SACL_SECURITY_INFORMATION,
    };
    let actual = security_snapshot_with_limit(file, maximum);
    let kernel = actual
        .kernel_security
        .as_ref()
        .ok_or_else(|| invalid("kernel descriptor absent during protection restore"))?;
    if kernel.native_error.is_some() || kernel.bytes.len() < 20 {
        return Err(invalid("kernel protection query failed"));
    }
    let source = if let Some(maximum) = maximum {
        security_descriptor::validate_with_limit(item.security, maximum)?
    } else {
        security_descriptor::validate(item.security)?
    };
    let observed = if let Some(maximum) = maximum {
        security_descriptor::validate_with_limit(&kernel.bytes, maximum)?
    } else {
        security_descriptor::validate(&kernel.bytes)?
    };
    let changed = ProtectionRestore {
        dacl: source.dacl_protected() != observed.dacl_protected(),
        sacl: source.sacl_protected() != observed.sacl_protected(),
    };
    if !changed.dacl && !changed.sacl {
        return Ok(changed);
    }
    // Change this object only. SetSecurityInfo, used below as the fallback,
    // also propagates inheritance to every existing descendant and marks their
    // ACLs auto-inherited. Called on the root of a Windows volume, whose SACL
    // protection differs from the formatter's, it stamped SACL flags on the
    // whole shadow tree that no later descriptor restore removes. The kernel
    // object interface takes the protection and auto-inherited flags from the
    // descriptor's own control word and touches nothing else.
    {
        use windows_sys::Win32::Security::SetKernelObjectSecurity;
        let mut information = 0;
        let mut expressible = true;
        if changed.dacl {
            if source.dacl.presence != Presence::Absent {
                information |= DACL_SECURITY_INFORMATION;
            } else {
                expressible = false;
            }
        }
        if changed.sacl {
            if source.sacl.presence != Presence::Absent {
                information |= SACL_SECURITY_INFORMATION;
            } else {
                expressible = false;
            }
        }
        if expressible && information != 0 {
            if let Some(maximum) = maximum {
                descriptor_with_limit(item.security, maximum)?;
            } else {
                descriptor(item.security)?;
            }
            let mut request = item.security.to_vec();
            let control = u16::from_le_bytes([request[2], request[3]])
                | SE_DACL_AUTO_INHERIT_REQ
                | SE_SACL_AUTO_INHERIT_REQ;
            request[2..4].copy_from_slice(&control.to_le_bytes());
            // SAFETY: live authorized metadata handle; `request` is the validated
            // self-relative source descriptor with only its control word changed.
            check(unsafe {
                SetKernelObjectSecurity(file.as_raw_handle(), information, request.as_mut_ptr().cast())
            })?;
            return Ok(changed);
        }
    }
    let mut sd = if let Some(maximum) = maximum {
        descriptor_with_limit(item.security, maximum)?
    } else {
        descriptor(item.security)?
    };
    let mut flags = 0;
    if changed.dacl {
        flags |= if source.dacl_protected() {
            PROTECTED_DACL_SECURITY_INFORMATION
        } else {
            UNPROTECTED_DACL_SECURITY_INFORMATION
        };
        if source.dacl.presence != Presence::Absent {
            flags |= DACL_SECURITY_INFORMATION;
        }
    }
    if changed.sacl {
        flags |= if source.sacl_protected() {
            PROTECTED_SACL_SECURITY_INFORMATION
        } else {
            UNPROTECTED_SACL_SECURITY_INFORMATION
        };
        if source.sacl.presence != Presence::Absent {
            flags |= SACL_SECURITY_INFORMATION;
        }
    }
    // Every nonzero ACL offset is checked by the portable descriptor parser
    // and the native descriptor validator. A null ACL is passed as NULL only
    // when that is the source state. In particular, offset zero is never an
    // ACL pointer into the descriptor header.
    let base = sd.as_mut_ptr().cast::<u8>();
    let dacl = if changed.dacl && source.dacl.presence == Presence::Present {
        let offset = source
            .dacl
            .offset
            .ok_or_else(|| invalid("source DACL offset absent"))?;
        // SAFETY: validated aligned ACL range inside the live descriptor.
        unsafe { base.add(offset).cast() }
    } else {
        ptr::null_mut()
    };
    let sacl = if changed.sacl && source.sacl.presence == Presence::Present {
        let offset = source
            .sacl
            .offset
            .ok_or_else(|| invalid("source SACL offset absent"))?;
        // SAFETY: validated aligned ACL range inside the live descriptor.
        unsafe { base.add(offset).cast() }
    } else {
        ptr::null_mut()
    };
    // For an absent ACL, omit the ACL_SECURITY_INFORMATION bit. SetSecurityInfo
    // then receives a protection-only request, not a request to install a null
    // ACL. If this combination is unsupported, propagate that failure while
    // still constructing the disposable shadow; never normalize absence away.
    // Directory inheritance is completed parent-first below. BackupWrite then
    // restores the full stored descriptor, including exact ACL presence and ACE
    // order; the caller's kernel/API semantic comparison remains mandatory.
    // SAFETY: live authorized metadata handle, validated aligned ACL buffers,
    // and enabled security privilege for any SACL protection operation.
    let result = unsafe {
        SetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            flags,
            ptr::null_mut(),
            ptr::null_mut(),
            dacl,
            sacl,
        )
    };
    if result != 0 {
        return Err(io::Error::from_raw_os_error(result as i32));
    }
    Ok(changed)
}

const SE_DACL_PRESENT: u16 = 0x0004;
const SE_DACL_AUTO_INHERIT_REQ: u16 = 0x0100;
const SE_SACL_AUTO_INHERIT_REQ: u16 = 0x0200;
const SE_DACL_AUTO_INHERITED: u16 = 0x0400;
const SE_SACL_AUTO_INHERITED: u16 = 0x0800;

/// Which ACLs of a directory carry an auto-inherited flag, as
/// SECURITY_INFORMATION bits; zero when none does.
pub(super) fn auto_inherited_acls(descriptor: &[u8]) -> u32 {
    use windows_sys::Win32::Security::{DACL_SECURITY_INFORMATION, SACL_SECURITY_INFORMATION};
    if descriptor.len() < 20 {
        return 0;
    }
    let control = u16::from_le_bytes([descriptor[2], descriptor[3]]);
    let mut information = 0;
    if control & SE_SACL_AUTO_INHERITED != 0 {
        information |= SACL_SECURITY_INFORMATION;
    }
    if control & SE_DACL_AUTO_INHERITED != 0 && control & SE_DACL_PRESENT != 0 {
        information |= DACL_SECURITY_INFORMATION;
    }
    information
}

/// Clear the auto-inherited flags on a directory the ReFS formatter created,
/// before anything is created beneath it.
///
/// On ReFS a new object takes those flags from its parent, and the formatter's
/// root and System Volume Information both carry "SACL auto-inherited". Every
/// object then created in the shadow is born with ACL control flags that its
/// NTFS source does not have, and no later descriptor restore removes them.
/// Re-setting the directory's own ACLs through the kernel object interface
/// with the auto-inherit request bits, and without the auto-inherited bits,
/// clears them; children created afterwards are clean. Returns whether
/// anything was changed.
pub(super) fn clear_acl_auto_inheritance(directory: &File) -> io::Result<bool> {
    use windows_sys::Win32::Security::SetKernelObjectSecurity;
    let snapshot = security_snapshot_with_limit(directory, None);
    let kernel = snapshot
        .kernel_security
        .as_ref()
        .filter(|query| query.native_error.is_none())
        .ok_or_else(|| invalid("kernel descriptor absent before auto-inheritance reset"))?;
    let information = auto_inherited_acls(&kernel.bytes);
    if information == 0 {
        return Ok(false);
    }
    let mut request = kernel.bytes.clone();
    let control = (u16::from_le_bytes([request[2], request[3]])
        & !(SE_DACL_AUTO_INHERITED | SE_SACL_AUTO_INHERITED))
        | SE_DACL_AUTO_INHERIT_REQ
        | SE_SACL_AUTO_INHERIT_REQ;
    request[2..4].copy_from_slice(&control.to_le_bytes());
    // SAFETY: live directory handle holding WRITE_DAC and ACCESS_SYSTEM_SECURITY;
    // `request` is the descriptor the kernel just returned with only its
    // control word changed, and outlives the call.
    check(unsafe {
        SetKernelObjectSecurity(directory.as_raw_handle(), information, request.as_mut_ptr().cast())
    })?;
    Ok(true)
}
fn guid_payload(bytes: &[u8]) -> bool {
    if bytes.len() != 76 {
        return false;
    }
    bytes.chunks_exact(2).enumerate().all(|(at, b)| {
        let c = u16::from_le_bytes([b[0], b[1]]);
        match at {
            0 => c == b'{' as u16,
            37 => c == b'}' as u16,
            9 | 14 | 19 | 24 => c == b'-' as u16,
            _ => c <= 127 && (c as u8).is_ascii_hexdigit(),
        }
    })
}

/// Internal implementation for a consuming PrivateTree owner. Unlike `run`,
/// this accepts no pathname-created targets: every object is an actual handle
/// retained by that constructor or transferred from its exclusive placeholder.
/// Only the parent module can call this; report/input JSON cannot create it.
pub(super) fn complete_owned_metadata(
    pair: &GeneralSourceShadowBinding,
    source_before: &native::GeneralDiskState,
    volume: &File,
    input: &[Input<'_>],
    handles: &BTreeMap<usize, File>,
    same_security: impl Fn(&[u8], &[u8]) -> io::Result<bool>,
) -> io::Result<serde_json::Value> {
    complete_owned_metadata_domain(
        pair,
        source_before,
        volume,
        &SliceInputs(input),
        handles,
        1280,
        None,
        same_security,
    )
}

pub(super) fn complete_owned_metadata_domain(
    pair: &GeneralSourceShadowBinding,
    source_before: &native::GeneralDiskState,
    volume: &File,
    input: &impl InputDomain,
    handles: &BTreeMap<usize, File>,
    maximum_objects: usize,
    resource_admission: Option<crate::tree_resources::SourceResourceAdmission>,
    same_security: impl Fn(&[u8], &[u8]) -> io::Result<bool>,
) -> io::Result<serde_json::Value> {
    if source_before.disk_attributes != 3 {
        return Err(invalid(
            "owning metadata requires original dedicated exclusion",
        ));
    }
    complete_owned_metadata_scoped_domain(
        pair,
        &private_tree::source_scope::ConstructionSourceState::Dedicated(source_before.clone()),
        None,
        volume,
        input,
        handles,
        maximum_objects,
        resource_admission,
        same_security,
    )
}

pub(super) fn complete_owned_metadata_scoped_domain(
    pair: &GeneralSourceShadowBinding,
    source_before: &private_tree::source_scope::ConstructionSourceState,
    partition_source: Option<&native::PartitionSourceMetadataWitness>,
    volume: &File,
    input: &impl InputDomain,
    handles: &BTreeMap<usize, File>,
    maximum_objects: usize,
    resource_admission: Option<crate::tree_resources::SourceResourceAdmission>,
    same_security: impl Fn(&[u8], &[u8]) -> io::Result<bool>,
) -> io::Result<serde_json::Value> {
    complete_owned_metadata_scoped_windows_aliases_domain(pair,source_before,partition_source,volume,input,handles,
        maximum_objects,resource_admission,None,None,same_security)
}

pub(super) fn complete_owned_metadata_scoped_windows_aliases_domain(
    pair: &GeneralSourceShadowBinding,
    source_before: &private_tree::source_scope::ConstructionSourceState,
    partition_source: Option<&native::PartitionSourceMetadataWitness>,
    volume: &File,
    input: &impl InputDomain,
    handles: &BTreeMap<usize, File>,
    maximum_objects: usize,
    resource_admission: Option<crate::tree_resources::SourceResourceAdmission>,
    aliases: Option<&mut super::windows_aliases::StagedWindowsAliases>,
    enumeration_payer: Option<&dyn report_memory::ReportMemoryAccountant>,
    same_security: impl Fn(&[u8], &[u8]) -> io::Result<bool>,
) -> io::Result<serde_json::Value> {
    complete_owned_metadata_scoped_windows_aliases_domain_inner(
        pair, source_before, partition_source, volume, input, handles,
        maximum_objects, resource_admission, aliases, enumeration_payer, false, false, same_security,
    )
}

/// Explicit provisional construction only. The original expectation domain is
/// unchanged and must qualify again after authenticated raw security repair.
pub(super) fn complete_owned_metadata_scoped_windows_aliases_domain_with_security_placeholders(
    pair: &GeneralSourceShadowBinding,
    source_before: &private_tree::source_scope::ConstructionSourceState,
    partition_source: Option<&native::PartitionSourceMetadataWitness>,
    volume: &File,
    input: &impl InputDomain,
    handles: &BTreeMap<usize, File>,
    maximum_objects: usize,
    resource_admission: Option<crate::tree_resources::SourceResourceAdmission>,
    aliases: Option<&mut super::windows_aliases::StagedWindowsAliases>,
    enumeration_payer: Option<&dyn report_memory::ReportMemoryAccountant>,
    same_security: impl Fn(&[u8], &[u8]) -> io::Result<bool>,
) -> io::Result<serde_json::Value> {
    if pair.source.layout_profile != crate::general_layout::GeneralDiskLayoutProfile::OfflineWindows
        || resource_admission.is_none()
    {
        return Err(invalid("security placeholders require the explicit resource-bound Windows constructor"));
    }
    complete_owned_metadata_scoped_windows_aliases_domain_inner(
        pair, source_before, partition_source, volume, input, handles,
        maximum_objects, resource_admission, aliases, enumeration_payer, true, false, same_security,
    )
}

pub(super) fn complete_recovered_metadata_scoped_windows_aliases_domain(
    pair:&GeneralSourceShadowBinding,source_before:&private_tree::source_scope::ConstructionSourceState,
    volume:&File,input:&impl InputDomain,handles:&BTreeMap<usize,File>,maximum_objects:usize,
    admission:crate::tree_resources::SourceResourceAdmission,aliases:&mut super::windows_aliases::StagedWindowsAliases,
    payer:&dyn report_memory::ReportMemoryAccountant,security_placeholders:bool,
    same_security:impl Fn(&[u8],&[u8])->io::Result<bool>,
)->io::Result<serde_json::Value>{
    if pair.source.layout_profile!=crate::general_layout::GeneralDiskLayoutProfile::OfflineWindows {
        return Err(invalid("metadata recovery requires the explicit Windows profile"));
    }
    complete_owned_metadata_scoped_windows_aliases_domain_inner(pair,source_before,None,volume,input,handles,
        maximum_objects,Some(admission),Some(aliases),Some(payer),security_placeholders,true,same_security)
}
fn complete_owned_metadata_scoped_windows_aliases_domain_inner(
    pair: &GeneralSourceShadowBinding,
    source_before: &private_tree::source_scope::ConstructionSourceState,
    partition_source: Option<&native::PartitionSourceMetadataWitness>,
    volume: &File,
    input: &impl InputDomain,
    handles: &BTreeMap<usize, File>,
    maximum_objects: usize,
    resource_admission: Option<crate::tree_resources::SourceResourceAdmission>,
    mut aliases: Option<&mut super::windows_aliases::StagedWindowsAliases>,
    enumeration_payer: Option<&dyn report_memory::ReportMemoryAccountant>,
    security_placeholders: bool,
    recovering:bool,
    same_security: impl Fn(&[u8], &[u8]) -> io::Result<bool>,
) -> io::Result<serde_json::Value> {
    input.require_mutation_binding(&pair.shadow)?;
    let resource_root = format!("{}\\", pair.shadow.volume_path()?);
    if resource_admission.is_some() != enumeration_payer.is_some() {
        return Err(invalid("resource metadata enumeration requires its actual constructor payer"));
    }
    if let Some(admission) = resource_admission {
        input.require_resource_metadata(admission)?;
        super::hard_links::validate_resource_domain(
            input,
            admission.maximum_namespace_names()?,
            &resource_root,
            crate::shadow_names::valid_unicode_component,
        )?;
    } else {
        super::hard_links::validate_domain(
            input,
            super::hard_links::MAX_NAMES,
            crate::shadow_names::valid_unicode_component,
        )?;
    }
    if input.is_empty()
        || maximum_objects == 0
        || input.len() > maximum_objects
        || handles.len() != input.len()
    {
        return Err(invalid("complete owning metadata capability required"));
    }
    let root_owned = input.object(0)?;
    let root_view = root_owned.input();
    if !root_view.directory || !root_view.components.is_empty() {
        return Err(invalid("complete owning metadata root is absent"));
    }
    drop(root_owned);
    pair.shadow
        .validate_volume_extent(&ctl(volume, 0x00560000, &[], 1024)?)?;
    let mut events = Vec::new();
    source_before.require(pair, partition_source, &mut events)?;
    let target = native::GeneralPartitionReader::open(pair.shadow.clone(), &mut events)?;
    source_before.require(pair, partition_source, &mut events)?;
    if native::observe_general_disk_state_readonly(pair.shadow.clone(), &mut events)?
        .disk_attributes
        != 0
        || native::mounted_filesystem_general(pair.shadow.clone(), &mut events)? != "ReFS"
    {
        return Err(invalid(
            "owning metadata source exclusion or target route differs",
        ));
    }
    let mut identities: BTreeMap<usize, Vec<u8>> = BTreeMap::new();
    let mut unique = BTreeSet::new();
    let mut mappings = BTreeMap::new();
    let mut paths = BTreeSet::new();
    // Only namespace scalars remain resident. Looking up a child must not
    // decode every paged object for every native directory entry.
    let mut namespace_index = BTreeMap::new();
    let mut expected_children: BTreeMap<Vec<String>, BTreeSet<Vec<String>>> = BTreeMap::new();
    let metadata_progress = |pass, completed| input.progress(crate::progress::Update::new(
        crate::progress::Phase::MetadataRestoration, crate::progress::Unit::Objects,
        completed, Some(input.len() as u64),
    ).with_pass(pass));
    for index in 0..input.len() {
        metadata_progress(0, index as u64);
        (|| -> io::Result<()> {
        let owned = input.object(index)?;
        let view = owned.input();
        let item = &view;
        if resource_admission.map_or(item.components.len() > 16, |_| {
            !super::hard_links::resource_path_valid(&resource_root, item.components)
        }) || item
            .components
            .iter()
            .any(|part| !crate::shadow_names::valid_unicode_component(part))
            || !paths.insert(crate::shadow_names::conservative_path_key(item.components))
            || !basic_input_allowed(item)
        {
            return Err(invalid(
                "owning metadata input outside bounded source profile",
            ));
        }
        if let Some(a) = resource_admission {
            descriptor_with_limit(item.security, a.budget.max_row_bytes)?;
        } else {
            descriptor(item.security)?;
        }
        if let Some(api) = item.expected_api_security {
            if let Some(a) = resource_admission {
                descriptor_with_limit(api, a.budget.max_row_bytes)?;
            } else {
                descriptor(api)?;
            }
        }
        for path in super::hard_links::paths(item) {
            if namespace_index
                .insert(
                    path.to_vec(),
                    (index, item.directory, item.reparse.is_some()),
                )
                .is_some()
            {
                return Err(invalid("duplicate owned metadata namespace path"));
            }
            if !path.is_empty() {
                expected_children
                    .entry(path[..path.len() - 1].to_vec())
                    .or_default()
                    .insert(path.to_vec());
            }
        }
        let handle = handles
            .get(&index)
            .ok_or_else(|| invalid("owned metadata handle absent"))?;
        if recovering&&crate::reparse_native::capture(handle)?.is_some(){validate_bound_type(handle,item)?;}
        else{validate_open_type(handle, item.directory)?;}
        let id = info(handle, 18, 24)?;
        if !unique.insert(id.clone()) {
            return Err(invalid("owned metadata identities alias"));
        }
        if let Some(root) = identities.get(&0usize) {
            if id[..8] != root[..8] {
                return Err(invalid("owned metadata objects escape bound volume"));
            }
        }
        identities.insert(index, id);
        if !item.directory {
            let standard = info(handle, 1, 24)?;
            let streams = info(handle, 7, stream_layout::MAX_STREAM_BUFFER)?;
            super::streams::exact_list(&streams, item)?;
            if layout::u64_at(&standard, 8)? != item.logical_length()
                || layout::u32_at(&standard, 16)? != super::hard_links::count(item)?
                || standard[20] != 0
                || standard[21] != 0
            {
                return Err(invalid("owned metadata stream shape differs"));
            }
            if item.logical_length() != 0 && layout::u64_at(&standard, 0)? >= 4096 {
                let canonical = crate::stream_native::retrieval_capture(handle)?.canonical;
                // Keep the full-query comparison, retaining only its exact
                // length and SHA-256 between metadata phases. A paged object
                // domain must not retain every variable-sized retrieval map.
                mappings.insert(index, (canonical.len(), Sha256::digest(&canonical)));
            }
        }
        Ok(())
        })()
        .map_err(|error| at_object(input, "metadata shape", index, error))?;
    }
    metadata_progress(0, input.len() as u64);
    if let Some(aliases)=aliases.as_deref(){
        for path in aliases.paths(){
            if namespace_index.contains_key(path){return Err(invalid("derived alias collides with a canonical source name"));}
            expected_children.entry(path[..path.len()-1].to_vec()).or_default().insert(path.to_vec());
        }
    }
    let namespace = |points_installed: bool, aliases: Option<&super::windows_aliases::StagedWindowsAliases>| -> io::Result<()> {
        for index in 0..input.len() {
            metadata_progress(if points_installed { 7 } else { 1 }, index as u64);
            let owned = input.object(index)?;
            let directory = owned.input();
            if !directory.directory {
                continue;
            }
            if (points_installed&&directory.reparse.is_some())
                ||(recovering&&crate::reparse_native::capture(&handles[&index])?.is_some()) {
                continue;
            }
            let handle = &handles[&index];
            let (enumeration_budget, _enumeration_memory) = if let Some(payer) = enumeration_payer {
                let count = expected_children.get(directory.components).map_or(0, BTreeSet::len);
                let evidence = count.checked_add(2).and_then(|n| n.checked_mul(4096))
                    .and_then(|n| n.checked_add(namespace_layout::CAPACITY * 4))
                    .ok_or_else(|| invalid("owned resource directory enumeration overflow"))?;
                let memory = payer.reserve((evidence as u64).checked_mul(2)
                    .ok_or_else(|| invalid("owned resource directory enumeration RAM overflow"))?)?;
                (Some(evidence), Some(memory))
            } else { (None, None) };
            let mut seen = BTreeSet::new();
            for entry in enumerate_with_resource_budget(handle, enumeration_budget)? {
                if entry.name_utf16 == [46] || entry.name_utf16 == [46, 46] {
                    continue;
                }
                let name = String::from_utf16(&entry.name_utf16)
                    .map_err(|_| invalid("owned metadata namespace UTF-16 differs"))?;
                let mut path = directory.components.to_vec();
                path.push(name);
                if let Some(alias)=aliases.and_then(|aliases|aliases.entry(&path)){
                    if !seen.insert(path.clone())||(entry.attributes&16!=0)!=alias.directory
                        ||(!(recovering&&!points_installed)&&(entry.attributes&0x400!=0)!=points_installed)
                        ||entry.file_id.as_slice()!=&alias.file_id_info[8..24]{
                        return Err(invalid("derived alias namespace identity/type differs"));
                    }
                    continue;
                }
                let &(child_index, child_directory, child_reparse) = namespace_index.get(&path)
                    .ok_or_else(|| invalid("unexpected owned metadata namespace entry"))?;
                if !seen.insert(path.clone())
                    || (entry.attributes & 16 != 0) != child_directory
                    || (if recovering&&!points_installed {(entry.attributes&0x400!=0)&&!child_reparse}
                        else{(entry.attributes&0x400!=0)!=(points_installed&&child_reparse)})
                    || entry.file_id.as_slice() != &identities[&child_index][8..24]
                {
                    return Err(invalid("owned metadata namespace identity or type differs"));
                }
            }
            let complete = match expected_children.get(directory.components) {
                Some(expected) => expected == &seen,
                None => seen.is_empty(),
            };
            if !complete {
                return Err(invalid("missing owned metadata namespace entry"));
            }
        }
        metadata_progress(if points_installed { 7 } else { 1 }, input.len() as u64);
        Ok(())
    };
    namespace(false,aliases.as_deref())?;
    const DIRECTORY: u8 = 1;
    const EXTENDED_ATTRIBUTES: u8 = 2;
    const REPARSE: u8 = 4;
    // Reuse the existing prepaid scalar slot; the feature flags add no index
    // allocation. The held InputDomain is immutable throughout completion.
    const _: () = assert!(
        std::mem::size_of::<(usize, usize, u8)>() == std::mem::size_of::<(usize, usize, bool)>()
    );
    let mut ordered = Vec::new();
    input.for_each(|index, item| {
        metadata_progress(2, index as u64);
        let flags = (u8::from(item.directory) * DIRECTORY)
            | (u8::from(item.extended_attributes.is_some()) * EXTENDED_ATTRIBUTES)
            | (u8::from(item.reparse.is_some()) * REPARSE);
        ordered.push((index, item.components.len(), flags));
        Ok(())
    })?;
    metadata_progress(2, input.len() as u64);
    ordered.sort_by_key(|(_, depth, _)| *depth);
    let mut dacl_protection_updates = 0usize;
    let mut sacl_protection_updates = 0usize;
    let mut provisional_security_objects = 0usize;
    // Finish every directory's inheritance propagation before restoring any
    // file. A shallow canonical file may also have a name under a deep parent.
    for (ordinal, &(index, _, _)) in ordered
        .iter()
        .filter(|(_, _, flags)| *flags & DIRECTORY != 0)
        .chain(
            ordered
                .iter()
                .filter(|(_, _, flags)| *flags & DIRECTORY == 0),
        ).enumerate()
    {
        metadata_progress(3, ordinal as u64);
        (|| -> io::Result<()> {
        let owned = input.object(index)?;
        let original_view = owned.input();
        let temporary = if security_placeholders {
            crate::refs_security_descriptor::ConstructorSecurityViews::prepare(
                original_view.security, original_view.expected_api_security,
                resource_admission.ok_or_else(|| invalid("constructor security row admission absent"))?.budget.max_row_bytes,
            )?
        } else { None };
        let mut view = original_view;
        if let Some(temporary) = temporary.as_ref() {
            view.security = &temporary.stored;
            view.expected_api_security = temporary.api.as_deref();
            provisional_security_objects += 1;
        }
        let item = &view;
        let handle = &handles[&index];
        if info(handle, 18, 24)? != identities[&index] {
            return Err(invalid(
                "owned identity changed before security restoration",
            ));
        }
        if !security_matches(
            item,
            &security_snapshot_with_limit(
                handle,
                resource_admission.map(|a| a.budget.max_row_bytes),
            ),
            &same_security,
        )? {
            input.before_mutation(item.security.len() as u64)?;
            let restored = restore_acl_protection_with_limit(
                handle,
                item,
                resource_admission.map(|a| a.budget.max_row_bytes),
            )?;
            dacl_protection_updates += usize::from(restored.dacl);
            sacl_protection_updates += usize::from(restored.sacl);
            input.before_mutation(item.security.len() as u64)?;
            backup_security_with_limit(
                handle,
                item.security,
                resource_admission.map(|a| a.budget.max_row_bytes),
            )?;
            let restored_view = security_snapshot_with_limit(
                handle,
                resource_admission.map(|a| a.budget.max_row_bytes),
            );

            if !security_matches(item, &restored_view, &same_security)? {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "owned source security views differ after restoration: {}",
                        security_difference(item, &restored_view)
                    ),
                ));
            }
        }
        Ok(())
        })()
        .or_else(|error| input.defer_failure(at_object(input, "security restoration", index, error)))?;
    }
    metadata_progress(3, ordered.len() as u64);
    // Only actual constructor-owned canonical handles reach this operation.
    // EAs belong to the file identity and are set once, not per DATA stream or
    // hard-link name. Native mutation precedes final timestamp restoration.
    let mut ea_objects = 0usize;
    let mut ea_entries = 0usize;
    for (ordinal, &(index, _, flags)) in ordered.iter().enumerate() {
        metadata_progress(4, ordinal as u64);
        if flags & EXTENDED_ATTRIBUTES == 0 {
            continue;
        }
        (|| -> io::Result<()> {
        let owned = input.object(index)?;
        let view = owned.input();
        let item = &view;
        if let Some(expected) = item.extended_attributes {
            let handle = &handles[&index];
            if info(handle, 18, 24)? != identities[&index] {
                return Err(invalid("owned identity changed before EA restoration"));
            }
            let current=if recovering{Some(crate::extended_attributes_native::capture(handle).map_err(io::Error::other)?)}else{None};
            if current.as_ref().is_none_or(|current|!expected.equivalent(current)){
                input.before_mutation(0)?;
                if recovering{crate::extended_attributes_native::reconcile_owned(handle,expected)}
                else{crate::extended_attributes_native::restore_fresh_owned(handle,expected)}.map_err(io::Error::other)?;
            }
            ea_objects += 1;
            ea_entries += expected.entries.len();
        }
        Ok(())
        })()
        .or_else(|error| input.defer_failure(at_object(input, "extended-attribute restoration", index, error)))?;
    }
    metadata_progress(4, ordered.len() as u64);
    // Security propagation and all children finish before basic metadata.
    // Install points only after all parent-first ACL propagation has finished;
    // no security operation may traverse a newly installed junction target.
    let mut reparse_objects = 0usize;
    for (ordinal, &(index, _, flags)) in ordered.iter().enumerate() {
        metadata_progress(5, ordinal as u64);
        if flags & REPARSE == 0 {
            continue;
        }
        (|| -> io::Result<()> {
        let owned = input.object(index)?;
        let view = owned.input();
        let item = &view;
        if let Some(point) = item.reparse {
            let handle = &handles[&index];
            if info(handle, 18, 24)? != identities[&index] {
                return Err(invalid(
                    "owned identity changed before reparse installation",
                ));
            }
            let current=if recovering{crate::reparse_native::capture(handle)?}else{None};
            if let Some(current)=current {
                if &current!=point{return Err(invalid("recovered canonical reparse point conflicts; preserve without overwrite"));}
            }else{
                input.before_mutation(0)?;
                crate::reparse_native::restore_fresh_owned(handle, point).map_err(|error| {
                io::Error::new(
                    error.kind(),
                    format!("reparse install {:?}: {error}", item.components),
                )
                })?;
            }
            reparse_objects += 1;
        }
        Ok(())
        })()
        .or_else(|error| input.defer_failure(at_object(input, "reparse installation", index, error)))?;
    }
    metadata_progress(5, ordered.len() as u64);
    let provisional_aliases = if let Some(aliases)=aliases.as_deref_mut(){
        if security_placeholders { aliases.restore_metadata_with_security_placeholders(input,handles,&same_security)? }
        else { aliases.restore_metadata(input,handles,&same_security)?; 0 }
    } else { 0 };
    // Reverse depth order finalizes root last, using the same held handles.
    for (ordinal, &(index, _, _)) in ordered.iter().rev().enumerate() {
        metadata_progress(6, ordinal as u64);
        (|| -> io::Result<()> {
        let owned = input.object(index)?;
        let view = owned.input();
        let item = &view;
        let handle = &handles[&index];
        if info(handle, 18, 24)? != identities[&index] {
            return Err(invalid("owned identity changed before basic restoration"));
        }
        if !recovering||!basic_matches(item,&info(handle,0,40)?){
            input.before_mutation(0)?;
            basic(handle, item)?;
        }
        if !item.directory {
            handle.sync_all()?;
        }
        Ok(())
        })()
        .map_err(|error| at_object(input, "basic metadata restoration", index, error))?;
    }
    metadata_progress(6, ordered.len() as u64);
    input.before_mutation(0)?;
    volume.sync_all()?;
    namespace(true,aliases.as_deref())?;
    for index in 0..input.len() {
        metadata_progress(8, index as u64);
        (|| -> io::Result<()> {
        let owned = input.object(index)?;
        let original_view = owned.input();
        let temporary = if security_placeholders {
            crate::refs_security_descriptor::ConstructorSecurityViews::prepare(
                original_view.security, original_view.expected_api_security,
                resource_admission.ok_or_else(|| invalid("constructor security row admission absent"))?.budget.max_row_bytes,
            )?
        } else { None };
        let mut view = original_view;
        if let Some(temporary) = temporary.as_ref() {
            view.security = &temporary.stored;
            view.expected_api_security = temporary.api.as_deref();
        }
        let item = &view;
        let handle = &handles[&index];
        let actual = metadata_snapshot_with_limit(
            handle,
            item,
            resource_admission.map(|a| a.budget.max_row_bytes),
        );
        // Report which facet differs; one combined refusal cannot be acted on.
        let identity_same = query_bytes(&actual, 18, 24)? == identities[&index];
        let basic_same = basic_matches(item, query_bytes(&actual, 0, 40)?);
        let security_same = security_matches(item, &actual, &same_security)?;
        let ea_same = extended_attributes_match(item, &actual)?;
        let reparse_same = reparse_matches(item, &actual)?;
        if !(identity_same && basic_same && security_same && ea_same && reparse_same) {
            let detail = if security_same {
                String::new()
            } else {
                format!(" {}", security_difference(item, &actual))
            };
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "final owned source metadata readback differs: identity_same={identity_same} \
                     basic_same={basic_same} security_same={security_same} ea_same={ea_same} \
                     reparse_same={reparse_same}{detail}"
                ),
            ));
        }
        if let Some(mapping) = mappings.get(&index) {
            let canonical = crate::stream_native::retrieval_capture(handle)?.canonical;
            if canonical.len() != mapping.0 || Sha256::digest(&canonical) != mapping.1 {
                return Err(invalid(
                    "payload mapping changed during owned metadata completion",
                ));
            }
        }
        if !item.directory {
            let standard = info(handle, 1, 24)?;
            let streams = info(handle, 7, stream_layout::MAX_STREAM_BUFFER)?;
            super::streams::exact_list(&streams, item)?;
            if layout::u64_at(&standard, 8)? != item.logical_length()
                || layout::u32_at(&standard, 16)? != super::hard_links::count(item)?
                || standard[20] != 0
                || standard[21] != 0
            {
                return Err(invalid("final owned metadata stream shape differs"));
            }
            super::hard_links::observe(
                &format!("{}\\", pair.shadow.volume_path()?),
                item,
                &actual,
                false,
            )?;
            super::streams::observe(
                &format!("{}\\", pair.shadow.volume_path()?),
                item,
                &actual,
                false,
                false,
                pair.shadow.identity.partition_bytes / 4096,
                resource_admission
                    .map(|a| usize::try_from(a.budget.max_row_bytes).map_err(io::Error::other))
                    .transpose()?,
            )?;
            if let Some(layout) = item.sparse {
                super::sparse_stream::observe(handle, layout, item.logical_length())?;
            }
        }
        Ok(())
        })()
        .or_else(|error| input.defer_failure(at_object(input, "final metadata readback", index, error)))?;
    }
    metadata_progress(8, input.len() as u64);
    target.revalidate_route(&mut events)?;
    pair.shadow
        .validate_volume_extent(&ctl(volume, 0x00560000, &[], 1024)?)?;
    source_before.require(pair, partition_source, &mut events)?;
    if native::observe_general_disk_state_readonly(pair.shadow.clone(), &mut events)?
        .disk_attributes
        != 0
    {
        return Err(invalid("owning metadata storage state changed"));
    }
    let mut report =
        serde_json::json!({"schema_version":1,"kind":"owning-private-tree-metadata-completion",
        "metadata_objects_updated":input.len(),"metadata_objects_verified":input.len(),
        "metadata_readback_verified":true,"dacl_protection_states_restored":dacl_protection_updates,
        "sacl_protection_states_restored":sacl_protection_updates,
        "ea_objects_verified":ea_objects,"ea_entries_restored":ea_entries,
        "reparse_objects_verified":reparse_objects,
        "source_payload_writes":0,"user_payload_bytes_read":0,"user_payload_bytes_written":0,
        "source_before":source_before,"events":events,"owner_consumed":true,
        "disposable_maintenance_scope":true,"source_prefix_contents_verified":false,
        "requires_fresh_conversion_admission":true,"conversion_qualified":false});
    if security_placeholders {
        report["kind"] = "provisional-Windows-constructor-metadata-completion".into();
        report["security_readback_scope"] = "temporary-constructor-placeholder-views".into();
        report["process_trust_labels_preserved"] = false.into();
        report["process_trust_label_raw_repair_required"] = true.into();
        report["provisional_security_objects"] = provisional_security_objects.into();
        report["provisional_security_aliases"] = provisional_aliases.into();
        report["original_source_security_expectations_unchanged"] = true.into();
        report["requires_original_security_readback_after_raw_repair"] = true.into();
    }
    Ok(report)
}

pub fn run(
    pair: &GeneralSourceShadowBinding,
    input: &[Input<'_>],
    payload: &[u8],
    same_security: impl Fn(&[u8], &[u8]) -> io::Result<bool>,
) -> io::Result<serde_json::Value> {
    super::hard_links::validate(
        input,
        super::hard_links::MAX_NAMES,
        crate::shadow_names::valid_unicode_component,
    )?;
    pair.validate_with_resource_profile(Some(
        crate::attestation::ResourceProfile::ExperimentalStreamingTreeV2,
    ))?;
    if std::env::var("COMPUTERNAME").ok().as_deref() != Some("N2R-WIN11")
        || pair.source.disk_number != 1
        || pair.shadow.disk_number != 3
        || pair
            .source
            .identity
            .disk_guid
            .trim_matches(['{', '}'])
            .to_ascii_lowercase()
            != "1b191872-c372-41ee-a416-e18863996f54"
        || pair
            .shadow
            .identity
            .disk_guid
            .trim_matches(['{', '}'])
            .to_ascii_lowercase()
            != "c0f2cd39-ad3d-484e-9990-0e6eba74485f"
        || input.is_empty()
        || input.len() > 32
        || !guid_payload(payload)
    {
        return Err(invalid("enrolled small-cache refresh scope differs"));
    }
    let mut names = BTreeSet::new();
    for item in input {
        if item.components.len() > 16
            || item
                .components
                .iter()
                .any(|s| !crate::shadow_names::valid_unicode_component(s))
            || !names.insert(item.components.to_vec())
            || !basic_input_allowed(item)
        {
            return Err(invalid("invalid bounded cache-refresh input"));
        }
        descriptor(item.security)?;
    }
    if !input[0].components.is_empty() || !input[0].directory {
        return Err(invalid("root expectation required"));
    }
    let wanted: Vec<_> = input
        .iter()
        .filter(|i| {
            i.components.len() == 2
                && i.components[0] == "System Volume Information"
                && i.components[1] == "IndexerVolumeGuid"
        })
        .collect();
    if wanted.len() != 1
        || wanted[0].directory
        || wanted[0].logical_length() != 76
        || wanted[0].logical_sha256() != Some(crate::content_digest::of(payload))
    {
        return Err(invalid(
            "source indexer cache bytes do not match expectation",
        ));
    }
    let cache = wanted[0];
    let mut events = Vec::new();
    let source_before =
        native::observe_general_disk_state_readonly(pair.source.clone(), &mut events)?;
    let target = native::GeneralPartitionReader::open(pair.shadow.clone(), &mut events)?;
    if source_before.disk_attributes != 3
        || native::mounted_filesystem_general(pair.shadow.clone(), &mut events)? != "ReFS"
    {
        return Err(invalid("excluded source and writable ReFS shadow required"));
    }
    let mut privileges = Privileges::enable_for(&[
        "SeBackupPrivilege",
        "SeRestorePrivilege",
        "SeSecurityPrivilege",
        "SeManageVolumePrivilege",
    ])?;
    let root = format!("{}\\", pair.shadow.volume_path()?);
    let volume = File::options()
        .read(true)
        .write(true)
        .share_mode(3)
        .open(pair.shadow.volume_path()?)?;
    pair.shadow
        .validate_volume_extent(&ctl(&volume, 0x00560000, &[], 1024)?)?;
    let mut cache_exists = false;
    let mut identities: BTreeMap<Vec<String>, Vec<u8>> = BTreeMap::new();
    // Complete directory preflight: no unknown names and no missing entries
    // except the one exact cache this routine is permitted to create.
    for directory in input.iter().filter(|i| i.directory) {
        let handle = open(
            &format!("{}{}", root, directory.components.join("\\")),
            true,
            true,
        )?;
        let directory_id = query_bytes(&snapshot(&handle), 18, 24)?[8..24].to_vec();
        if identities
            .get(directory.components)
            .is_some_and(|id| id != &directory_id)
        {
            return Err(invalid("directory identity changed during cache preflight"));
        }
        identities.insert(directory.components.to_vec(), directory_id);
        let actual = enumerate(&handle)?;
        let mut seen = BTreeSet::new();
        for entry in actual {
            let name = String::from_utf16(&entry.name_utf16)
                .map_err(|_| invalid("invalid target namespace UTF-16"))?;
            if name == "." || name == ".." {
                continue;
            }
            let mut path = directory.components.to_vec();
            path.push(name);
            let (_, expected) = super::hard_links::find(input, &path)
                .ok_or_else(|| invalid("unexpected existing-shadow entry"))?;
            if (entry.attributes & 16 != 0) != expected.directory
                || entry.attributes & 0x400 != 0
                || !seen.insert(path.clone())
            {
                return Err(invalid("target namespace type or identity ambiguity"));
            }
            if path == cache.components {
                cache_exists = true;
            }
            if identities
                .get(&path)
                .is_some_and(|id| id.as_slice() != entry.file_id.as_slice())
            {
                return Err(invalid("entry identity changed during cache preflight"));
            }
            identities.insert(path, entry.file_id.to_vec());
        }
        for child_path in input
            .iter()
            .flat_map(super::hard_links::paths)
            .filter(|path| {
                path.len() == directory.components.len() + 1
                    && path.starts_with(directory.components)
            })
        {
            if !seen.contains(child_path) && child_path != cache.components {
                return Err(invalid("missing existing-shadow entry"));
            }
        }
    }
    let path = format!("{}{}", root, cache.components.join("\\"));
    if input.iter().any(|i| !i.additional_names.is_empty()) {
        let mut logical_ids = BTreeSet::new();
        for item in input {
            if item.components == cache.components && !cache_exists {
                continue;
            }
            let canonical = identities
                .get(item.components)
                .ok_or_else(|| invalid("canonical cache-refresh identity missing"))?;
            if !logical_ids.insert(canonical) {
                return Err(invalid("unrelated logical files share a native identity"));
            }
            for name in super::hard_links::paths(item) {
                if identities.get(name) != Some(canonical) {
                    return Err(invalid("hard-link cache-refresh identity differs"));
                }
            }
        }
    } else {
        let unique: BTreeSet<_> = identities.values().collect();
        if unique.len() != identities.len() {
            return Err(invalid("aliased shadow identities are unsupported"));
        }
    }
    let mut payload_written = 0u64;
    if cache_exists {
        let mut file = open(&path, false, true)?;
        let state = snapshot(&file);
        if Some(query_bytes(&state, 18, 24)?[8..24].to_vec()).as_ref()
            != identities.get(cache.components)
        {
            return Err(invalid("indexer cache identity changed before refresh"));
        }
        let standard = query_bytes(&state, 1, 24)?;
        let stream_bytes = info(&file, 7, stream_layout::MAX_STREAM_BUFFER)?;
        let (streams, _) = stream_layout::parse_streams(&stream_bytes)?;
        if layout::u64_at(standard, 8)? != 76
            || u32::from_le_bytes(standard[16..20].try_into().unwrap()) != 1
            || standard[20] != 0
            || streams.len() != 1
            || !streams[0].name.is_empty()
            || streams[0].logical_size != 76
        {
            return Err(invalid("existing indexer cache shape differs"));
        }
        let mut old = [0; 76];
        file.read_exact(&mut old)?;
        if !guid_payload(&old) {
            return Err(invalid("existing indexer cache is not a GUID"));
        }
        if old != payload {
            file.seek(SeekFrom::Start(0))?;
            file.write_all(payload)?;
            file.sync_all()?;
            payload_written = 76;
        }
        file.seek(SeekFrom::Start(0))?;
        if Some(hash_exact_stream(&mut file, 76)?) != cache.logical_sha256()
            || Some(query_bytes(&snapshot(&file), 18, 24)?[8..24].to_vec()).as_ref()
                != identities.get(cache.components)
        {
            return Err(invalid(
                "indexer cache bytes or identity changed during refresh",
            ));
        }
    } else {
        let mut writer = |_: usize, file: &mut File| file.write_all(payload);
        create(&path, cache, 0, Some(&mut writer))?;
        payload_written = 76;
        let mut file = open(&path, false, false)?;
        if Some(hash_exact_stream(&mut file, 76)?) != cache.logical_sha256() {
            return Err(invalid("created source cache bytes differ"));
        }
        identities.insert(
            cache.components.to_vec(),
            query_bytes(&snapshot(&file), 18, 24)?[8..24].to_vec(),
        );
    }
    // Private staging starts with protected SYSTEM-only directories. Complete
    // all parent-first directory ACL propagation before restoring canonical
    // files, including files with aliases under deeper directories.
    let mut ordered: Vec<_> = input.iter().collect();
    ordered.sort_by_key(|i| i.components.len());
    let mut dacl_protection_updates = 0usize;
    let mut sacl_protection_updates = 0usize;
    for item in ordered
        .iter()
        .filter(|item| item.directory)
        .chain(ordered.iter().filter(|item| !item.directory))
    {
        let handle = open(
            &format!("{}{}", root, item.components.join("\\")),
            item.directory,
            true,
        )?;
        let before = snapshot(&handle);
        if Some(query_bytes(&before, 18, 24)?[8..24].to_vec()).as_ref()
            != identities.get(item.components)
        {
            return Err(invalid("shadow identity changed before metadata refresh"));
        }
        if !security_matches(item, &before, &same_security)? {
            let restored = restore_acl_protection(&handle, item)?;
            dacl_protection_updates += usize::from(restored.dacl);
            sacl_protection_updates += usize::from(restored.sacl);
            backup_security(&handle, item.security)?;
            if !security_matches(item, &snapshot(&handle), &same_security)? {
                return Err(io::Error::other(format!(
                    "refreshed descriptor views differ at {}",
                    item.components.join("\\")
                )));
            }
        }
    }
    let mut metadata_updated = 0;
    // All child creation/security propagation is finished before restoring
    // timestamps and attributes, with root/parents finalized last.
    for item in ordered.into_iter().rev() {
        let handle = open(
            &format!("{}{}", root, item.components.join("\\")),
            item.directory,
            true,
        )?;
        let before = snapshot(&handle);
        if Some(query_bytes(&before, 18, 24)?[8..24].to_vec()).as_ref()
            != identities.get(item.components)
        {
            return Err(invalid(
                "identity changed before basic metadata restoration",
            ));
        }
        basic(&handle, item)?;
        if !item.directory {
            handle.sync_all()?;
        }
        if query_bytes(&snapshot(&handle), 18, 24)?[8..24] != query_bytes(&before, 18, 24)?[8..24] {
            return Err(invalid("shadow identity changed during metadata refresh"));
        }
        metadata_updated += 1;
    }
    volume.sync_all()?;
    // Recheck every object after restoring parent/root metadata as well. This
    // catches late inheritance or timestamp changes without reading payload.
    let mut metadata_verified = 0;
    for item in input {
        let handle = open_input(
            &format!("{}{}", root, item.components.join("\\")),
            item,
            false,
        )?;
        let actual = metadata_snapshot(&handle, item);
        if Some(query_bytes(&actual, 18, 24)?[8..24].to_vec()).as_ref()
            != identities.get(item.components)
            || !basic_matches(item, query_bytes(&actual, 0, 40)?)
            || !security_matches(item, &actual, &same_security)?
            || !extended_attributes_match(item, &actual)?
            || !reparse_matches(item, &actual)?
        {
            return Err(invalid(
                "final shadow metadata readback differs from source",
            ));
        }
        if !item.directory {
            if layout::u32_at(query_bytes(&actual, 1, 24)?, 16)? != super::hard_links::count(item)?
            {
                return Err(invalid("refreshed hard-link count differs"));
            }
            super::hard_links::observe(&root, item, &actual, false)?;
            super::streams::observe(
                &root,
                item,
                &actual,
                false,
                false,
                pair.shadow.identity.partition_bytes / 4096,
                None,
            )?;
            if let Some(layout) = item.sparse {
                super::sparse_stream::observe(&handle, layout, item.logical_length())?;
            }
        }
        metadata_verified += 1;
    }
    target.revalidate_route(&mut events)?;
    if native::observe_general_disk_state_readonly(pair.source.clone(), &mut events)?
        != source_before
    {
        return Err(invalid("cache refresh storage route changed"));
    }
    privileges.restore()?;
    Ok(
        serde_json::json!({"schema_version":1,"kind":"reused-shadow-small-cache-refresh",
        "cache_created":!cache_exists,"cache_payload_bytes_written":payload_written,
        "unchanged_user_payload_bytes_written":0,"metadata_objects_updated":metadata_updated,
        "metadata_objects_verified":metadata_verified,"metadata_readback_verified":true,
        "dacl_protection_states_restored":dacl_protection_updates,
        "sacl_protection_states_restored":sacl_protection_updates,
        "source_payload_writes":0,"source_before":source_before,"events":events,
        "privileges":privileges.audit(),"requires_fresh_conversion_admission":true,"conversion_qualified":false}),
    )
}
