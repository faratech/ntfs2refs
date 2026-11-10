//! Separate derived Windows path entries on a constructor-owned ReFS shadow.
//! They never add source identities, source streams, or source hard links.
use super::{
    input_domain::{InputDomain, ObjectInput},
    *,
};
use crate::tree_resources::SourceResourceAdmission;
use crate::progress::{Phase, Unit, Update};
use std::collections::{BTreeMap, BTreeSet};

pub struct WindowsAliasInputRef<'a> {
    pub canonical_object_index: usize,
    pub parent_object_index: usize,
    pub components: &'a [String],
    pub canonical_components: &'a [String],
}
pub trait WindowsAliasInput {
    fn input(&self) -> WindowsAliasInputRef<'_>;
}
/// Implemented by the actual source-bound immutable alias page owner.
/// A report or a source-normalization flag cannot provide this owner.
pub trait WindowsAliasInputDomain {
    type Alias: WindowsAliasInput;
    fn len(&self) -> usize;
    fn alias(&self, index: usize) -> io::Result<Self::Alias>;
    fn source_inspection_sha256(&self) -> [u8; 32];
    fn semantic_sha256(&self) -> io::Result<[u8; 32]>;
    fn require_resource_metadata(&self, admission: SourceResourceAdmission) -> io::Result<()>;
    fn revalidate(&self) -> io::Result<()>;
}
pub(super) struct NoWindowsAliases;
impl WindowsAliasInput for () {
    fn input(&self) -> WindowsAliasInputRef<'_> {
        unreachable!("empty alias domain has no rows")
    }
}
impl WindowsAliasInputDomain for NoWindowsAliases {
    type Alias = ();
    fn len(&self) -> usize {
        0
    }
    fn alias(&self, _: usize) -> io::Result<()> {
        Err(invalid("empty alias domain"))
    }
    fn source_inspection_sha256(&self) -> [u8; 32] {
        [0; 32]
    }
    fn semantic_sha256(&self) -> io::Result<[u8; 32]> {
        Err(invalid("empty alias domain has no source pin"))
    }
    fn require_resource_metadata(&self, _: SourceResourceAdmission) -> io::Result<()> {
        Err(invalid("empty alias domain has no authority"))
    }
    fn revalidate(&self) -> io::Result<()> {
        Ok(())
    }
}

pub(super) struct VerifiedAlias {
    pub(super) components: Vec<String>,
    pub(super) canonical_components: Vec<String>,
    pub(super) canonical_object_index: usize,
    pub(super) parent_object_index: usize,
    pub(super) directory: bool,
    pub(super) attributes: u32,
    pub(super) file_id_info: [u8; 24],
    pub(super) canonical_file_id_info: [u8; 24],
    pub(super) parent_file_id_info: [u8; 24],
    pub(super) point: crate::reparse_layout::Point,
}
/// Native-issued ledger from construction or a protected readonly recovery
/// observation, never deserializable source/write authority. Source counts
/// stay unchanged; every entry has its own actual ReFS identity.
pub struct VerifiedWindowsAliases {
    pub(super) entries: Vec<VerifiedAlias>,
    pair: GeneralSourceShadowBinding,
    source_pin: [u8; 32],
    input_digest: [u8; 32],
    plan_digest: [u8; 32],
    maximum_row_bytes: u64,
    retained_memory_bytes: u64,
    _memory: Box<dyn report_memory::ReportMemoryLease>,
}
impl VerifiedWindowsAliases {
    /// Recovered rows are expectations only. Issue a private native ledger
    /// after checking every row against the actual converted READ_ONLY ReFS
    /// lease. No source/write capability or saved constructor proof is rebuilt.
    /// The caller must still perform the complete canonical-plus-alias native
    /// namespace and content validation before returning an observation.
    pub(crate) fn from_recovered_expectations_readonly(
        pair: &GeneralSourceShadowBinding,
        input: &impl InputDomain,
        aliases: &impl WindowsAliasInputDomain,
        admission: SourceResourceAdmission,
        protected: &native::GeneralReadonlyRefsVolume<'_>,
        payer: &dyn report_memory::ReportMemoryAccountant,
        same: &impl Fn(&[u8], &[u8]) -> io::Result<bool>,
    ) -> io::Result<Self> {
        admission.validate()?;
        if pair.source.layout_profile
            != crate::general_layout::GeneralDiskLayoutProfile::OfflineWindows
            || protected.binding() != &pair.source
            || aliases.source_inspection_sha256() != admission.source_inspection_sha256
        {
            return Err(invalid("recovered aliases require the actual converted Windows lease"));
        }
        crate::file_storage::require_readonly_access(protected.volume())?;
        pair.source.validate_volume_extent(&ctl(protected.volume(), 0x00560000, &[], 1024)?)?;
        input.require_resource_metadata(admission)?;
        aliases.require_resource_metadata(admission)?;
        aliases.revalidate()?;
        let plan_digest = aliases.semantic_sha256()?;
        let input_digest = super::private_tree::metadata::input_digest_domain(input)?;
        let root = format!("{}\\", pair.source.volume_path()?);
        let workspace = admission.budget.max_row_bytes.checked_mul(8)
            .and_then(|n| n.checked_add(4 << 20))
            .ok_or_else(|| invalid("recovered alias workspace overflow"))?;
        let _working = payer.reserve(workspace)?;
        let count = aliases.len();
        let mut bytes = 4096u64;
        let mut preflight = Sha256::new();
        for index in 0..count {
            let owner = aliases.alias(index)?;
            let row = owner.input();
            validate_row(input, &row, &root)?;
            bytes = bytes.checked_add(row_memory(&row)?)
                .ok_or_else(|| invalid("recovered alias retained RAM overflow"))?;
            row_digest(&mut preflight, &row);
        }
        let mut memory = payer.reserve(bytes.checked_add(payer.lease_heap_bytes())
            .ok_or_else(|| invalid("recovered alias owner RAM overflow"))?)?;
        let mut entries = BTreeMap::new();
        let mut identities = BTreeSet::new();
        let mut actual = Sha256::new();
        let mut charged = 4096u64;
        let mut privileges = Privileges::enable_for(&["SeBackupPrivilege", "SeSecurityPrivilege"])?;
        let open_readonly = |components: &[String]| {
            File::options().access_mode(super::PROTECTED_READ_ACCESS).share_mode(3)
                .custom_flags(0x02200000)
                .open(format!("{root}{}", components.join("\\")))
        };
        let root_handle = open_readonly(&[])?;
        let root_id: [u8; 24] = super::info(&root_handle, 18, 24)?.try_into()
            .map_err(|_| invalid("recovered alias root native ID width differs"))?;
        let mut events = Vec::new();
        let before = native::observe_general_disk_state_readonly(pair.source.clone(), &mut events)?;
        if before.disk_attributes & 2 == 0 || root_id[..8] == [0; 8] {
            return Err(invalid("recovered aliases lack physical READ_ONLY ReFS identity"));
        }
        for index in 0..count {
            let owner = aliases.alias(index)?;
            let row = owner.input();
            let directory = validate_row(input, &row, &root)?;
            charged = charged.checked_add(row_memory(&row)?)
                .ok_or_else(|| invalid("recovered alias rows changed after prepayment"))?;
            if charged > bytes || row.canonical_object_index == row.parent_object_index {
                return Err(invalid("recovered alias row or identity domain changed"));
            }
            row_digest(&mut actual, &row);
            let canonical_owner = input.object(row.canonical_object_index)?;
            let canonical = canonical_owner.input();
            let parent = open_readonly(&row.components[..row.components.len() - 1])?;
            let target = open_readonly(row.canonical_components)?;
            super::validate_bound_type(&target, &canonical)?;
            let alias = open_readonly(row.components)?;
            let observed = crate::windows_alias_native::verify_owned(
                &parent, &target, &alias, directory,
                &row.canonical_components.last().unwrap().encode_utf16().collect::<Vec<_>>(),
            )?;
            if observed.alias_file_id_info[..8] != root_id[..8]
                || !identities.insert(observed.alias_file_id_info)
            {
                return Err(invalid("recovered aliases repeat or escape the actual ReFS volume"));
            }
            let point = crate::reparse_layout::Point::relative_component_alias(
                &row.canonical_components.last().unwrap().encode_utf16().collect::<Vec<_>>(),
            )?;
            let attributes = (canonical.attributes & 0x2027) | 0x400
                | if directory { 16 } else { 0 };
            let expected = Input {
                components: row.components, additional_names: &[], directory,
                times: canonical.times, attributes, security: canonical.security,
                expected_api_security: canonical.expected_api_security,
                extended_attributes: None, reparse: Some(&point), payload: &[],
                expected_length: Some(0), expected_sha256: None, source_offset: None,
                source_runs: Vec::new(), named_streams: Vec::new(), sparse: None,
            };
            let snapshot = super::metadata_snapshot_with_limit(
                &alias, &expected, Some(admission.budget.max_row_bytes),
            );
            let standard = super::query_bytes(&snapshot, 1, 24)?;
            if observed.point != point
                || super::query_bytes(&snapshot, 18, 24)? != observed.alias_file_id_info
                || !super::basic_matches(&expected, super::query_bytes(&snapshot, 0, 40)?)
                || !super::security_matches(&expected, &snapshot, same)?
                || !super::reparse_matches(&expected, &snapshot)?
                || layout::u32_at(standard, 16)? != 1
                || standard[20] != 0 || standard[21] != u8::from(directory)
                || (!directory && layout::u64_at(standard, 8)? != 0)
            {
                return Err(invalid("recovered alias native metadata or point differs"));
            }
            if !directory {
                super::streams::exact_list(
                    &info(&alias, 7, stream_layout::MAX_STREAM_BUFFER)?, &expected,
                )?;
            }
            let entry = VerifiedAlias {
                components: row.components.to_vec(),
                canonical_components: row.canonical_components.to_vec(),
                canonical_object_index: row.canonical_object_index,
                parent_object_index: row.parent_object_index,
                directory, attributes, file_id_info: observed.alias_file_id_info,
                canonical_file_id_info: observed.canonical_file_id_info,
                parent_file_id_info: observed.parent_file_id_info, point,
            };
            if entries.insert(row.components.to_vec(), entry).is_some() {
                return Err(invalid("duplicate recovered alias path"));
            }
        }
        if aliases.len() != count || preflight.finalize() != actual.finalize()
            || aliases.semantic_sha256()? != plan_digest
            || super::private_tree::metadata::input_digest_domain(input)? != input_digest
        {
            return Err(invalid("recovered alias or canonical expectation domain changed"));
        }
        aliases.revalidate()?;
        let after = native::observe_general_disk_state_readonly(pair.source.clone(), &mut events)?;
        if before != after {
            return Err(invalid("recovered alias readonly source identity changed"));
        }
        privileges.restore()?;
        drop(root_handle);
        drop(identities);
        let entries: Vec<_> = entries.into_values().collect();
        let path_bytes = |path: &Vec<String>| -> io::Result<u64> {
            path.iter().try_fold((path.capacity() as u64)
                .checked_mul(mem::size_of::<String>() as u64)
                .ok_or_else(|| invalid("recovered alias path RAM overflow"))?, |sum, part| {
                sum.checked_add(part.capacity() as u64)
                    .ok_or_else(|| invalid("recovered alias path RAM overflow"))
            })
        };
        let mut retained = (entries.capacity() as u64)
            .checked_mul(mem::size_of::<VerifiedAlias>() as u64)
            .and_then(|n| n.checked_add(4096))
            .ok_or_else(|| invalid("recovered alias ledger RAM overflow"))?;
        for entry in &entries {
            retained = retained.checked_add(path_bytes(&entry.components)?)
                .and_then(|n| n.checked_add(path_bytes(&entry.canonical_components).ok()?))
                .and_then(|n| n.checked_add(entry.point.buffer.capacity() as u64))
                .ok_or_else(|| invalid("recovered alias ledger RAM overflow"))?;
        }
        memory.shrink_to(retained)?;
        Ok(Self {
            entries, pair: pair.clone(), source_pin: admission.source_inspection_sha256,
            input_digest, plan_digest, maximum_row_bytes: admission.budget.max_row_bytes,
            retained_memory_bytes: retained, _memory: memory,
        })
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
    pub fn plan_digest(&self) -> [u8; 32] {
        self.plan_digest
    }
    pub fn require_canonical_input(&self,input:&impl InputDomain)->io::Result<()> { self.require_input(input) }
    /// Account the retained opaque ledger in a new finalization arena. Its
    /// original lease stays alive until all live references have dropped.
    pub fn reserve_external_retained_memory(&self,payer:&dyn report_memory::ReportMemoryAccountant)
        ->io::Result<Box<dyn report_memory::ReportMemoryLease>> {
        payer.reserve(self.retained_memory_bytes.checked_add(payer.lease_heap_bytes())
            .ok_or_else(||invalid("external alias ownership RAM overflow"))?)
    }
    pub fn require_scope(
        &self,
        pair: &GeneralSourceShadowBinding,
        source_pin: [u8; 32],
        plan_digest: [u8; 32],
    ) -> io::Result<()> {
        if serde_json::to_vec(pair).map_err(io::Error::other)?
            != serde_json::to_vec(&self.pair).map_err(io::Error::other)?
            || self.source_pin != source_pin
            || self.plan_digest != plan_digest
        {
            return Err(invalid(
                "derived alias observation belongs to a different source/shadow plan",
            ));
        }
        Ok(())
    }
    /// Refresh exact alias metadata/points while the actual shadow device is
    /// physically READ_ONLY. The outer native owner retains mount/exclusion
    /// control; this function cannot manufacture that owner or write anything.
    pub fn observe_readonly_volume(
        &self,
        input: &impl InputDomain,
        volume: &File,
        payer: &dyn report_memory::ReportMemoryAccountant,
        same: &impl Fn(&[u8], &[u8]) -> io::Result<bool>,
    ) -> io::Result<ObservedWindowsAliases> {
        self.observe_readonly_target(input, volume, payer, same, false)
    }
    pub fn observe_converted_readonly_volume(
        &self,
        input: &impl InputDomain,
        volume: &File,
        payer: &dyn report_memory::ReportMemoryAccountant,
        same: &impl Fn(&[u8], &[u8]) -> io::Result<bool>,
    ) -> io::Result<ObservedWindowsAliases> {
        self.observe_readonly_target(input, volume, payer, same, true)
    }
    fn observe_readonly_target(
        &self,
        input: &impl InputDomain,
        volume: &File,
        payer: &dyn report_memory::ReportMemoryAccountant,
        same: &impl Fn(&[u8], &[u8]) -> io::Result<bool>,
        converted: bool,
    ) -> io::Result<ObservedWindowsAliases> {
        self.require_input(input)?;
        let binding = if converted {
            &self.pair.source
        } else {
            &self.pair.shadow
        };
        crate::file_storage::require_readonly_access(volume)?;
        binding.validate_volume_extent(&ctl(volume, 0x00560000, &[], 1024)?)?;
        let physical = native::device_file(
            &format!("\\\\.\\PhysicalDrive{}", binding.disk_number),
            false,
            false,
        )?;
        match ctl(&physical, 0x00070024, &[], 0) {
            Err(error) if error.raw_os_error() == Some(19) => {}
            Err(error) => return Err(error),
            Ok(_) => {
                return Err(invalid(
                    "alias observation requires actual native write protection",
                ));
            }
        }
        let work = self
            .maximum_row_bytes
            .checked_mul(8)
            .and_then(|n| n.checked_add(4 << 20))
            .ok_or_else(|| invalid("alias readonly workspace overflow"))?;
        let _working = payer.reserve(work)?;
        let mut privileges = Privileges::enable_for(&["SeBackupPrivilege", "SeSecurityPrivilege"])?;
        let mut events = Vec::new();
        let before = native::observe_general_disk_state_readonly(binding.clone(), &mut events)?;
        if before.disk_attributes & 2 == 0 {
            return Err(invalid(
                "alias observation needs physical READ_ONLY storage",
            ));
        }
        let root = format!("{}\\", binding.volume_path()?);
        for entry in &self.entries {
            let owner = input.object(entry.canonical_object_index)?;
            let canonical = owner.input();
            let open_readonly = |components: &[String]| {
                File::options()
                    .access_mode(super::PROTECTED_READ_ACCESS)
                    .share_mode(3)
                    .custom_flags(0x02200000)
                    .open(format!("{root}{}", components.join("\\")))
            };
            let parent = open_readonly(&entry.components[..entry.components.len() - 1])?;
            let target = open_readonly(&entry.canonical_components)?;
            super::validate_bound_type(&target, &canonical)?;
            let alias = open_readonly(&entry.components)?;
            let observed = crate::windows_alias_native::verify_owned(
                &parent,
                &target,
                &alias,
                entry.directory,
                &entry
                    .canonical_components
                    .last()
                    .unwrap()
                    .encode_utf16()
                    .collect::<Vec<_>>(),
            )?;
            if observed.parent_file_id_info != entry.parent_file_id_info
                || observed.canonical_file_id_info != entry.canonical_file_id_info
            {
                return Err(invalid(
                    "readonly alias parent or canonical identity differs from its constructor owner",
                ));
            }
            let expected = Input {
                components: &entry.components,
                additional_names: &[],
                directory: entry.directory,
                times: canonical.times,
                attributes: entry.attributes,
                security: canonical.security,
                expected_api_security: canonical.expected_api_security,
                extended_attributes: None,
                reparse: Some(&entry.point),
                payload: &[],
                expected_length: Some(0),
                expected_sha256: None,
                source_offset: None,
                source_runs: Vec::new(),
                named_streams: Vec::new(),
                sparse: None,
            };
            let snapshot = super::metadata_snapshot_with_limit(
                &alias,
                &expected,
                Some(self.maximum_row_bytes),
            );
            let standard = super::query_bytes(&snapshot, 1, 24)?;
            if super::query_bytes(&snapshot, 18, 24)? != entry.file_id_info
                || !super::basic_matches(&expected, super::query_bytes(&snapshot, 0, 40)?)
                || !super::security_matches(&expected, &snapshot, same)?
                || !super::reparse_matches(&expected, &snapshot)?
                || layout::u32_at(standard, 16)? != 1
                || standard[20] != 0
                || standard[21] != u8::from(entry.directory)
                || (!entry.directory && layout::u64_at(standard, 8)? != 0)
            {
                return Err(invalid("readonly derived alias metadata differs"));
            }
            if !entry.directory {
                super::streams::exact_list(
                    &info(&alias, 7, stream_layout::MAX_STREAM_BUFFER)?,
                    &expected,
                )?;
            }
        }
        let after = native::observe_general_disk_state_readonly(binding.clone(), &mut events)?;
        if before != after {
            return Err(invalid("alias readonly device state changed"));
        }
        privileges.restore()?;
        let memory = payer.reserve(16384 + payer.lease_heap_bytes())?;
        Ok(ObservedWindowsAliases {
            pair: self.pair.clone(),
            source_pin: self.source_pin,
            plan_digest: self.plan_digest,
            input_digest: self.input_digest,
            aliases: self.entries.len(),
            converted_target: converted,
            _memory: memory,
        })
    }
    pub(super) fn require_input(&self, input: &impl InputDomain) -> io::Result<()> {
        if super::private_tree::metadata::input_digest_domain(input)? != self.input_digest {
            return Err(invalid(
                "derived alias observation belongs to a different canonical input",
            ));
        }
        Ok(())
    }
    pub(super) fn reserve_validation_memory(
        &self,
        payer: Option<&dyn report_memory::ReportMemoryAccountant>,
    ) -> io::Result<Option<Box<dyn report_memory::ReportMemoryLease>>> {
        let bytes = self.entries.iter().try_fold(0u64, |sum, row| {
            sum.checked_add(
                path_memory(&row.components)?
                    .checked_mul(16)
                    .ok_or_else(|| invalid("alias validation RAM overflow"))?,
            )
            .and_then(|n| n.checked_add(8192))
            .ok_or_else(|| invalid("alias validation RAM overflow"))
        })?;
        payer
            .map(|payer| {
                payer.reserve(
                    bytes
                        .checked_add(payer.lease_heap_bytes())
                        .ok_or_else(|| invalid("alias lease RAM overflow"))?,
                )
            })
            .transpose()
    }
}

/// Exact native alias refresh under real physical write protection. No public
/// constructor or deserialization can substitute a report for this witness.
pub struct ObservedWindowsAliases {
    pair: GeneralSourceShadowBinding,
    source_pin: [u8; 32],
    plan_digest: [u8; 32],
    input_digest: [u8; 32],
    aliases: usize,
    converted_target: bool,
    _memory: Box<dyn report_memory::ReportMemoryLease>,
}
impl ObservedWindowsAliases {
    pub fn len(&self) -> usize {
        self.aliases
    }
    pub fn is_empty(&self) -> bool {
        self.aliases == 0
    }
    pub fn require_scope(
        &self,
        pair: &GeneralSourceShadowBinding,
        source_pin: [u8; 32],
        plan_digest: [u8; 32],
    ) -> io::Result<()> {
        self.require_target_scope(pair, source_pin, plan_digest, false)
    }
    pub fn require_converted_scope(
        &self,
        pair: &GeneralSourceShadowBinding,
        source_pin: [u8; 32],
        plan_digest: [u8; 32],
    ) -> io::Result<()> {
        self.require_target_scope(pair, source_pin, plan_digest, true)
    }
    fn require_target_scope(
        &self,
        pair: &GeneralSourceShadowBinding,
        source_pin: [u8; 32],
        plan_digest: [u8; 32],
        converted: bool,
    ) -> io::Result<()> {
        if serde_json::to_vec(pair).map_err(io::Error::other)?
            != serde_json::to_vec(&self.pair).map_err(io::Error::other)?
            || source_pin != self.source_pin
            || plan_digest != self.plan_digest
            || self.converted_target != converted
        {
            return Err(invalid(
                "readonly alias witness belongs to a different plan or target phase",
            ));
        }
        Ok(())
    }
    pub fn require_input(&self, input: &impl InputDomain) -> io::Result<()> {
        if super::private_tree::metadata::input_digest_domain(input)? != self.input_digest {
            return Err(invalid("readonly alias input changed"));
        }
        Ok(())
    }
}
fn path_memory(path: &[String]) -> io::Result<u64> {
    path.iter().try_fold(
        (path.len() as u64)
            .checked_mul(64)
            .ok_or_else(|| invalid("alias path RAM overflow"))?,
        |sum, s| {
            sum.checked_add(s.len() as u64)
                .ok_or_else(|| invalid("alias path RAM overflow"))
        },
    )
}
fn row_memory(row: &WindowsAliasInputRef<'_>) -> io::Result<u64> {
    path_memory(row.components)?
        .checked_mul(8)
        .and_then(|n| n.checked_add(path_memory(row.canonical_components).ok()?.checked_mul(4)?))
        .and_then(|n| n.checked_add(8192))
        .ok_or_else(|| invalid("alias retained RAM overflow"))
}
fn row_digest(hash: &mut Sha256, row: &WindowsAliasInputRef<'_>) {
    hash.update((row.canonical_object_index as u64).to_le_bytes());
    hash.update((row.parent_object_index as u64).to_le_bytes());
    for path in [row.components, row.canonical_components] {
        hash.update((path.len() as u64).to_le_bytes());
        for part in path {
            hash.update((part.len() as u64).to_le_bytes());
            hash.update(part.as_bytes());
        }
    }
}
pub(super) fn validate_row(
    input: &impl InputDomain,
    row: &WindowsAliasInputRef<'_>,
    root: &str,
) -> io::Result<bool> {
    if row.components.is_empty()
        || row.canonical_components.is_empty()
        || row.components == row.canonical_components
        || !super::hard_links::resource_path_valid(root, row.components)
        || row
            .components
            .iter()
            .any(|part| !crate::shadow_names::valid_unicode_component(part))
    {
        return Err(invalid(
            "derived Windows alias is not an admitted same-parent canonical sibling",
        ));
    }
    input.with_alias_shape(row.canonical_object_index, |canonical| {
        input.with_alias_shape(row.parent_object_index, |parent| {
            if !parent.directory()
                || parent.is_reparse()
                || !parent.primary_path_matches(&row.components[..row.components.len() - 1])?
                || !parent.primary_path_matches(&row.canonical_components[..row.canonical_components.len() - 1])?
                || !canonical.contains_path(row.canonical_components)?
            {
                return Err(invalid(
                    "derived Windows alias is not an admitted same-parent canonical sibling",
                ));
            }
            Ok(canonical.directory())
        })
    })
}
struct StagedAlias {
    entry: VerifiedAlias,
    file: File,
}
pub(super) struct StagedWindowsAliases {
    rows: BTreeMap<Vec<String>, StagedAlias>,
    pair: GeneralSourceShadowBinding,
    source_pin: [u8; 32],
    input_digest: [u8; 32],
    plan_digest: [u8; 32],
    maximum_row_bytes: u64,
    recovering: bool,
    _memory: Box<dyn report_memory::ReportMemoryLease>,
    _working: Box<dyn report_memory::ReportMemoryLease>,
}
impl StagedWindowsAliases {
    pub(super) fn summary(&self) -> serde_json::Value {
        serde_json::json!({"kind":"constructor-owned-derived-Windows-aliases-v1","derived_aliases":self.rows.len(),
            "source_inspection_sha256":hex::encode(self.source_pin),"alias_plan_sha256":hex::encode(self.plan_digest),
            "source_identities_added":0,"source_hard_links_added":0,"source_payload_write_calls":0,"conversion_authorized":false})
    }
    pub(super) fn create(
        input: &impl InputDomain,
        aliases: &impl WindowsAliasInputDomain,
        pair: &GeneralSourceShadowBinding,
        handles: &BTreeMap<usize, File>,
        admission: SourceResourceAdmission,
        payer: &dyn report_memory::ReportMemoryAccountant,
    ) -> io::Result<Self> {
        Self::create_inner(input,aliases,pair,handles,admission,payer,None)
    }
    /// Existing aliases are actual held no-follow files from the complete
    /// native recovery namespace audit, never deserialized identities.
    pub(super) fn reconcile(
        input:&impl InputDomain,aliases:&impl WindowsAliasInputDomain,
        pair:&GeneralSourceShadowBinding,handles:&BTreeMap<usize,File>,
        admission:SourceResourceAdmission,payer:&dyn report_memory::ReportMemoryAccountant,
        existing:BTreeMap<Vec<String>,File>,
    )->io::Result<Self>{
        Self::create_inner(input,aliases,pair,handles,admission,payer,Some(existing))
    }
    fn create_inner(
        input:&impl InputDomain,aliases:&impl WindowsAliasInputDomain,
        pair:&GeneralSourceShadowBinding,handles:&BTreeMap<usize,File>,
        admission:SourceResourceAdmission,payer:&dyn report_memory::ReportMemoryAccountant,
        mut existing:Option<BTreeMap<Vec<String>,File>>,
    )->io::Result<Self>{
        let recovering=existing.is_some();
        if pair.source.layout_profile
            != crate::general_layout::GeneralDiskLayoutProfile::OfflineWindows
            || aliases.source_inspection_sha256() != admission.source_inspection_sha256
        {
            return Err(invalid(
                "derived alias construction requires the explicit bound Windows source",
            ));
        }
        input.require_mutation_binding(&pair.shadow)?;
        input.require_resource_metadata(admission)?;
        aliases.require_resource_metadata(admission)?;
        aliases.revalidate()?;
        let root = format!("{}\\", pair.shadow.volume_path()?);
        let plan_digest = aliases.semantic_sha256()?;
        let input_digest = super::private_tree::metadata::input_digest_domain(input)?;
        let workspace = admission
            .budget
            .max_row_bytes
            .checked_mul(8)
            .and_then(|n| n.checked_add(crate::windows_alias_native::WORKSPACE_BYTES))
            .ok_or_else(|| invalid("alias row workspace overflow"))?;
        let working = payer.reserve(workspace)?;
        let mut bytes = 4096u64;
        let mut preflight = Sha256::new();
        input.progress(Update::new(Phase::AliasValidation, Unit::Aliases, 0, Some(aliases.len() as u64)));
        for index in 0..aliases.len() {
            let row = aliases.alias(index)?;
            let view = row.input();
            validate_row(input, &view, &root)?;
            bytes = bytes
                .checked_add(row_memory(&view)?)
                .ok_or_else(|| invalid("alias total RAM overflow"))?;
            row_digest(&mut preflight, &view);
            input.progress(Update::new(Phase::AliasValidation, Unit::Aliases,
                index as u64 + 1, Some(aliases.len() as u64)));
        }
        let memory = payer.reserve(
            bytes
                .checked_add(payer.lease_heap_bytes())
                .ok_or_else(|| invalid("alias owner RAM overflow"))?,
        )?;
        let mut rows = BTreeMap::new();
        let mut actual = Sha256::new();
        let mut charged = 4096u64;
        let private = super::private_tree::private_descriptor()?;
        input.progress(Update::new(Phase::AliasCreation, Unit::Aliases, 0, Some(aliases.len() as u64)));
        for index in 0..aliases.len() {
            let owner = aliases.alias(index)?;
            let row = owner.input();
            let directory = validate_row(input, &row, &root)?;
            charged = charged
                .checked_add(row_memory(&row)?)
                .ok_or_else(|| invalid("alias creation RAM overflow"))?;
            if charged > bytes {
                return Err(invalid("alias rows changed after prepaid validation"));
            }
            row_digest(&mut actual, &row);
            if !handles.contains_key(&row.parent_object_index)
                || !handles.contains_key(&row.canonical_object_index)
            {
                return Err(invalid(
                    "derived alias lacks constructor-owned parent/target",
                ));
            }
            let point = crate::reparse_layout::Point::relative_component_alias(
                &row.canonical_components
                    .last()
                    .unwrap()
                    .encode_utf16()
                    .collect::<Vec<_>>(),
            )?;
            let initial = Input {
                components: row.components,
                additional_names: &[],
                directory,
                times: [1; 4],
                attributes: if directory { 16 } else { 128 },
                security: &private,
                expected_api_security: None,
                extended_attributes: None,
                reparse: None,
                payload: &[],
                expected_length: Some(0),
                expected_sha256: None,
                source_offset: None,
                source_runs: Vec::new(),
                named_streams: Vec::new(),
                sparse: None,
            };
            let path = format!("{root}{}", row.components.join("\\"));
            let file=if let Some(file)=existing.as_mut().and_then(|held|held.remove(row.components)) {
                if !crate::file_storage::final_path_guid(&file)?.eq_ignore_ascii_case(&path)
                    ||crate::reparse_native::capture(&file)?.as_ref().is_some_and(|actual|actual!=&point) {
                    return Err(invalid("held recovery alias path or reparse point differs"));
                }
                file
            }else{
                input.before_mutation(0)?;
                super::create(&path, &initial, 0, None)?;
                super::open(&path, directory, true)?
            };
            let id: [u8; 24] = super::info(&file, 18, 24)?
                .try_into()
                .map_err(|_| invalid("alias native ID width differs"))?;
            let entry = VerifiedAlias {
                components: row.components.to_vec(),
                canonical_components: row.canonical_components.to_vec(),
                canonical_object_index: row.canonical_object_index,
                parent_object_index: row.parent_object_index,
                directory,
                attributes: 0,
                file_id_info: id,
                canonical_file_id_info: super::info(&handles[&row.canonical_object_index], 18, 24)?
                    .try_into()
                    .map_err(|_| invalid("canonical native ID width differs"))?,
                parent_file_id_info: super::info(&handles[&row.parent_object_index], 18, 24)?
                    .try_into()
                    .map_err(|_| invalid("parent native ID width differs"))?,
                point,
            };
            if rows
                .insert(row.components.to_vec(), StagedAlias { entry, file })
                .is_some()
            {
                return Err(invalid("duplicate derived alias path"));
            }
            input.progress(Update::new(Phase::AliasCreation, Unit::Aliases,
                index as u64 + 1, Some(aliases.len() as u64)));
        }
        if preflight.finalize() != actual.finalize() {
            return Err(invalid("derived alias rows changed during construction"));
        }
        if existing.as_ref().is_some_and(|held|!held.is_empty()){return Err(invalid("recovery alias handles exceed the admitted alias plan"));}
        aliases.revalidate()?;
        if aliases.semantic_sha256()? != plan_digest {
            return Err(invalid("derived alias plan changed during construction"));
        }
        Ok(Self {
            rows,
            pair: pair.clone(),
            source_pin: admission.source_inspection_sha256,
            input_digest,
            plan_digest,
            maximum_row_bytes: admission.budget.max_row_bytes,
            recovering,
            _memory: memory,
            _working: working,
        })
    }
    pub(super) fn paths(&self) -> impl Iterator<Item = &[String]> {
        self.rows.keys().map(Vec::as_slice)
    }
    pub(super) fn entry(&self, path: &[String]) -> Option<&VerifiedAlias> {
        self.rows.get(path).map(|row| &row.entry)
    }
    pub(super) fn restore_metadata(
        &mut self,
        input: &impl InputDomain,
        handles: &BTreeMap<usize, File>,
        same: &impl Fn(&[u8], &[u8]) -> io::Result<bool>,
    ) -> io::Result<()> {
        self.restore_metadata_inner(input, handles, same, false).map(|_| ())
    }
    pub(super) fn restore_metadata_with_security_placeholders(
        &mut self,
        input: &impl InputDomain,
        handles: &BTreeMap<usize, File>,
        same: &impl Fn(&[u8], &[u8]) -> io::Result<bool>,
    ) -> io::Result<usize> {
        input.require_mutation_binding(&self.pair.shadow)?;
        if self.pair.source.layout_profile != crate::general_layout::GeneralDiskLayoutProfile::OfflineWindows {
            return Err(invalid("provisional alias security requires the explicit Windows constructor"));
        }
        self.restore_metadata_inner(input, handles, same, true)
    }
    fn restore_metadata_inner(
        &mut self,
        input: &impl InputDomain,
        handles: &BTreeMap<usize, File>,
        same: &impl Fn(&[u8], &[u8]) -> io::Result<bool>,
        security_placeholders: bool,
    ) -> io::Result<usize> {
        input.require_mutation_binding(&self.pair.shadow)?;
        let root = format!("{}\\", self.pair.shadow.volume_path()?);
        let mut provisional_aliases = 0usize;
        let total = self.rows.len() as u64;
        input.progress(Update::new(Phase::MetadataRestoration, Unit::Aliases, 0, Some(total)));
        for (ordinal, staged) in self.rows.values_mut().enumerate() {
            let entry = &mut staged.entry;
            let owner = input.object(entry.canonical_object_index)?;
            let canonical = owner.input();
            let target = File::options()
                .access_mode(0x01020189)
                .share_mode(3)
                .custom_flags(0x02200000)
                .open(format!("{root}{}", entry.canonical_components.join("\\")))?;
            super::suppress_access(&target)?;
            super::validate_bound_type(&target, &canonical)?;
            if super::info(&target, 18, 24)?
                != super::info(&handles[&entry.canonical_object_index], 18, 24)?
            {
                return Err(invalid("derived alias canonical link identity changed"));
            }
            let relative:Vec<u16>=entry.canonical_components.last().unwrap().encode_utf16().collect();
            if self.recovering&&crate::reparse_native::capture(&staged.file)?.is_some(){
                crate::windows_alias_native::verify_owned(&handles[&entry.parent_object_index],&target,
                    &staged.file,entry.directory,&relative)?;
            }else{
                input.before_mutation(0)?;
                crate::windows_alias_native::install_fresh_owned(
                &handles[&entry.parent_object_index],
                &target,
                &staged.file,
                entry.directory,
                &entry
                    .canonical_components
                    .last()
                    .unwrap()
                    .encode_utf16()
                    .collect::<Vec<_>>(),
                )?;
            }
            entry.attributes =
                (canonical.attributes & 0x2027) | 0x400 | if entry.directory { 16 } else { 0 };
            let temporary = if security_placeholders {
                crate::refs_security_descriptor::ConstructorSecurityViews::prepare(
                    canonical.security,
                    canonical.expected_api_security,
                    self.maximum_row_bytes,
                )?
            } else { None };
            if temporary.is_some() { provisional_aliases += 1; }
            let expected = Input {
                components: &entry.components,
                additional_names: &[],
                directory: entry.directory,
                times: canonical.times,
                attributes: entry.attributes,
                security: temporary.as_ref().map_or(canonical.security, |view| view.stored.as_slice()),
                expected_api_security: temporary.as_ref().map_or(canonical.expected_api_security, |view| view.api.as_deref()),
                extended_attributes: None,
                reparse: Some(&entry.point),
                payload: &[],
                expected_length: Some(0),
                expected_sha256: None,
                source_offset: None,
                source_runs: Vec::new(),
                named_streams: Vec::new(),
                sparse: None,
            };
            let before=self.recovering.then(||super::metadata_snapshot_with_limit(&staged.file,&expected,Some(self.maximum_row_bytes)));
            if !self.recovering||!super::security_matches(&expected,before.as_ref().expect("recovery snapshot"),same)? {
                input.before_mutation(expected.security.len() as u64)?;
                super::cache_refresh::restore_acl_protection_with_limit(
                &staged.file,
                &expected,
                Some(self.maximum_row_bytes),
                )?;
                input.before_mutation(expected.security.len() as u64)?;
                super::backup_security_with_limit(
                &staged.file,
                expected.security,
                Some(self.maximum_row_bytes),
                )?;
            }
            if !self.recovering||!super::basic_matches(&expected,super::query_bytes(before.as_ref().expect("recovery snapshot"),0,40)?) {
                input.before_mutation(0)?;
                super::basic(&staged.file, &expected)?;
            }
            if !entry.directory {
                staged.file.sync_all()?;
            }
            let actual = super::metadata_snapshot_with_limit(
                &staged.file,
                &expected,
                Some(self.maximum_row_bytes),
            );
            if super::query_bytes(&actual, 18, 24)? != entry.file_id_info
                || !super::basic_matches(&expected, super::query_bytes(&actual, 0, 40)?)
                || !super::security_matches(&expected, &actual, same)?
                || !super::reparse_matches(&expected, &actual)?
            {
                return Err(invalid("derived alias metadata verification differs"));
            }
            input.progress(Update::new(Phase::MetadataRestoration, Unit::Aliases,
                ordinal as u64 + 1, Some(total)));
        }
        Ok(provisional_aliases)
    }
    pub(super) fn finish(mut self) -> io::Result<VerifiedWindowsAliases> {
        let entries:Vec<_>=self.rows.into_values().map(|row|row.entry).collect();
        let path_bytes=|path:&Vec<String>|->io::Result<u64>{
            path.iter().try_fold((path.capacity() as u64).checked_mul(mem::size_of::<String>() as u64)
                .ok_or_else(||invalid("retained alias path RAM overflow"))?,|sum,part|
                sum.checked_add(part.capacity() as u64).ok_or_else(||invalid("retained alias path RAM overflow")))
        };
        let mut retained=(entries.capacity() as u64).checked_mul(mem::size_of::<VerifiedAlias>() as u64)
            .and_then(|n|n.checked_add(4096)).ok_or_else(||invalid("retained alias ledger RAM overflow"))?;
        for row in &entries{
            retained=retained.checked_add(path_bytes(&row.components)?)
                .and_then(|n|n.checked_add(path_bytes(&row.canonical_components).ok()?))
                .and_then(|n|n.checked_add(row.point.buffer.capacity() as u64))
                .ok_or_else(||invalid("retained alias ledger RAM overflow"))?;
        }
        self._memory.shrink_to(retained)?;
        Ok(VerifiedWindowsAliases {
            entries,
            pair: self.pair,
            source_pin: self.source_pin,
            input_digest: self.input_digest,
            plan_digest: self.plan_digest,
            maximum_row_bytes: self.maximum_row_bytes,
            retained_memory_bytes:retained,
            _memory: self._memory,
        })
    }
}
