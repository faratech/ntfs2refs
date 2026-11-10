//! Native creation capacity, before a backing-file owner exists. The actual
//! parent ancestry stays held without deletion sharing. No allocation quota
//! or upper bound on opaque Windows formatter growth is implied.
use super::*;

#[derive(Debug, Serialize)]
pub struct NativeCreationObservation {
    pub kind: &'static str,
    pub actual_parent: String,
    pub actual_volume_root: String,
    pub available_bytes: u64,
    pub minimum_free_bytes: u64,
    pub configured_allocation_quantum_bytes: u64,
    pub pending_growth_bytes: u64,
    pub sampled_not_reserved: bool,
    pub native_formatter_growth_bound_bytes: Option<u64>,
    pub entire_virtual_size_reserved: bool,
    pub grants_format_or_source_authority: bool,
}

pub struct NativeCreationAdmission {
    parents: Vec<File>,
    parent_identity: String,
    parent_path: String,
    volume_root: String,
    leaf: String,
    minimum_free_bytes: u64,
}

pub fn admit_fresh_native_backing(path: &Path) -> io::Result<NativeCreationAdmission> {
    if !path.is_absolute() || path.exists()
        || path.components().any(|p| matches!(p, Component::ParentDir | Component::CurDir))
        || !matches!(path.components().next(), Some(Component::Prefix(p)) if matches!(p.kind(), Prefix::Disk(_))) {
        return Err(invalid("fresh local ordinary VHDX route required for creation admission"));
    }
    let leaf = path.file_name().and_then(|n| n.to_str())
        .filter(|name| !name.contains([':', '\0']) && !name.ends_with([' ', '.']))
        .ok_or_else(|| invalid("ordinary VHDX filename required for creation admission"))?;
    if path.extension().and_then(|v| v.to_str()).is_none_or(|v| !v.eq_ignore_ascii_case("vhdx")) {
        return Err(invalid("native VHDX extension required for creation admission"));
    }
    let parent = path.parent().ok_or_else(|| invalid("VHDX parent absent"))?;
    let mut parents = Vec::new();
    for ancestor in parent.ancestors().filter(|p| !p.as_os_str().is_empty()) {
        let file = OpenOptions::new().access_mode(0x80).share_mode(3)
            .custom_flags(0x0220_0000).open(ancestor)?;
        let metadata = file.metadata()?;
        if !metadata.is_dir() || metadata.file_attributes() & 0x400 != 0 {
            return Err(invalid("native creation ancestry must be ordinary held directories"));
        }
        parents.push(file);
    }
    let held = parents.first().ok_or_else(|| invalid("native creation parent owner absent"))?;
    let actual_parent = crate::file_storage::final_path_guid(held)?;
    let end = actual_parent.find("}\\").ok_or_else(|| invalid("native creation volume GUID absent"))?;
    let volume_root = actual_parent[..end + 2].to_owned();
    let parent_identity = crate::file_storage::file_id_info(held)?;
    let available = crate::resource_native::observe_available_resources(Path::new(&volume_root))?;
    let floor = (available.scratch_available_bytes / 4).min(16 << 30);
    let owner = NativeCreationAdmission { parents, parent_identity, parent_path: actual_parent,
        volume_root, leaf: leaf.into(), minimum_free_bytes: floor };
    owner.check()?;
    Ok(owner)
}
impl NativeCreationAdmission {
    pub fn observe(&self) -> io::Result<NativeCreationObservation> {
        let parent = self.parents.first().ok_or_else(|| invalid("native creation parent owner lost"))?;
        if crate::file_storage::file_id_info(parent)? != self.parent_identity
            || !crate::file_storage::final_path_guid(parent)?.eq_ignore_ascii_case(&self.parent_path) {
            return Err(invalid("held native creation parent identity changed"));
        }
        let available = crate::resource_native::observe_available_resources(Path::new(&self.volume_root))?;
        Ok(NativeCreationObservation { kind: "native-shadow-creation-admission-v1",
            actual_parent: self.parent_path.clone(), actual_volume_root: self.volume_root.clone(),
            available_bytes: available.scratch_available_bytes, minimum_free_bytes: self.minimum_free_bytes,
            configured_allocation_quantum_bytes: u64::from(NATIVE_VHDX_ALLOCATION_QUANTUM_BYTES),
            pending_growth_bytes: u64::from(NATIVE_VHDX_ALLOCATION_QUANTUM_BYTES),
            sampled_not_reserved: true, native_formatter_growth_bound_bytes: None,
            entire_virtual_size_reserved: false, grants_format_or_source_authority: false })
    }
    pub fn check(&self) -> io::Result<()> {
        let current = self.observe()?;
        let required = current.minimum_free_bytes.checked_add(current.pending_growth_bytes)
            .ok_or_else(|| invalid("native creation free-space allowance overflow"))?;
        if current.available_bytes < required {
            return Err(io::Error::other(format!(
                "native shadow creation refused before allocation: actual volume {}, available {}, required {}, floor {}, provider quantum {}; native formatter amplification is not bounded by this sample",
                current.actual_volume_root, current.available_bytes, required,
                current.minimum_free_bytes, current.pending_growth_bytes)));
        }
        Ok(())
    }
    pub(super) fn require_backing(&self, backing: &retirement::OwnedBacking) -> io::Result<()> {
        let actual = backing.observe()?;
        let expected = format!("{}\\{}", self.parent_path.trim_end_matches('\\'), self.leaf);
        if !actual.final_path.eq_ignore_ascii_case(&expected) {
            return Err(invalid("created native backing is not under its admitted held parent"));
        }
        Ok(())
    }
}
