//! Bounded metadata planning for an offline Windows installation. This path
//! holds read-only native readers and cannot freeze, admit or write a source.
use crate::ntfs_inspect::{
    PagedInspection, RootDirectoryDomain, RootFileDomain, SourceMetadataBudget,
    paged_storage::SourceScratch,
};
use anyhow::{Context, Result, ensure};
use n2r_win32::{
    general_layout::{GeneralDiskBinding, GeneralDiskLayoutProfile},
    partition_isolation::{
        PartitionObservationBudget, PartitionScopedReader, PartitionSourceBinding,
        metadata_destination_outside_source,
    },
    tree_resources::ResourceBudget,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, OpenOptions},
    io::Write,
    os::windows::fs::{MetadataExt, OpenOptionsExt},
    path::{Component, Path},
};

pub fn inspect(
    binding: GeneralDiskBinding,
    budget: ResourceBudget,
    observation: PartitionObservationBudget,
    output: &Path,
) -> Result<()> {
    ensure!(
        binding.layout_profile == GeneralDiskLayoutProfile::OfflineWindows,
        "explicit offline Windows topology required"
    );
    binding.validate()?;
    budget.validate()?;
    observation.validate()?;
    let parent = output.parent().context("inspection output parent absent")?;
    ensure!(
        output.is_absolute()
            && !output
                .components()
                .any(|p| matches!(p, Component::ParentDir))
            && !output.exists()
            && parent.is_dir(),
        "fresh absolute output beneath an existing directory required"
    );
    let mut parent_owners = Vec::new();
    for ancestor in parent.ancestors() {
        ensure!(
            (parent_owners.len() as u64) < budget.handle_slots,
            "metadata ancestry exceeds the admitted handle budget"
        );
        let file = OpenOptions::new()
            .access_mode(0x80)
            .share_mode(3)
            .custom_flags(0x0220_0000)
            .open(ancestor)?;
        ensure!(
            file.metadata()?.is_dir() && file.metadata()?.file_attributes() & 0x400 == 0,
            "metadata ancestry must contain ordinary directories"
        );
        parent_owners.push(file);
    }
    let available = n2r_win32::resource_native::observe_available_resources(parent)?;
    available.validate_budget(budget)?;
    let mut events = Vec::new();
    let selected = PartitionSourceBinding {
        storage: binding.clone(),
    };
    let destination = metadata_destination_outside_source(&selected, parent, &mut events)?;
    ensure!(
        destination.disk_number != binding.disk_number,
        "boot inspection scratch must be on another physical disk"
    );
    let before = n2r_win32::probe_general(binding.clone(), &mut events)?;
    let mut reader = PartitionScopedReader::open(selected, observation, &mut events)?;
    ensure!(
        reader.observation().windows_volume.disk_number != binding.disk_number,
        "the running Windows disk cannot be inspected as the offline source"
    );
    let source_budget = SourceMetadataBudget::from_resource_budget(budget)?;
    let scratch = SourceScratch::new(source_budget)?;
    let _io = scratch
        .lease_ram(n2r_win32::GeneralFrozenPartition::read_buffer_memory_bytes_for(&binding))?;
    fs::create_dir(output)?;
    save(
        &output.join("intent.json"),
        &serde_json::json!({"kind":"offline-Windows-metadata-inspection-intent-v1",
        "source":binding,"resource_budget":budget,"source_metadata_budget":source_budget,
        "available":available,"source_writes_authorized":false,"source_frozen":false,"source_admitted":false}),
    )?;
    let raw = PagedInspection::inspect_preparation_with_scratch(
        &mut reader,
        binding.identity.partition_bytes,
        budget,
        &output.join("source"),
        &scratch,
    )?;
    ensure!(
        raw.header().stream_hash_bytes == 0,
        "planning inspection unexpectedly hashed logical payload"
    );
    let scan_bytes = source_budget
        .record_bytes
        .checked_mul(8)
        .and_then(|n| n.checked_add(4 << 20))
        .context("source feature scan RAM overflow")?;
    let _scan = scratch.lease_ram(scan_bytes)?;
    let mut counts = BTreeMap::<&str, u64>::new();
    let mut members = BTreeSet::<(u64, &'static str, u64)>::new();
    let mut alias_plan = crate::ntfs_inspect::record_store::SortedRecordWriter::new(
        &output.join("dos-alias-plan"),
        *b"WINALIS1",
        &scratch,
    )?;
    let mut alias_count = 0u64;
    let labels = [
        "Windows",
        "System32",
        "config",
        "drivers",
        "SYSTEM",
        "SOFTWARE",
        "winload.efi",
        "ntoskrnl.exe",
        "refs.sys",
    ];
    for ordinal in 0..raw.file_count() {
        if ordinal % 4096 == 0 {
            eprintln!(
                "Windows source metadata: {ordinal}/{} records",
                raw.file_count()
            );
        }
        let file = raw.file(ordinal)?;
        *counts
            .entry(if file.is_directory {
                "directories"
            } else {
                "files"
            })
            .or_default() += 1;
        if file.hard_link_count > 1 {
            *counts.entry("identities_with_multiple_links").or_default() += 1;
        }
        if file.names.iter().any(|n| n.namespace == 2) {
            *counts.entry("identities_with_DOS_aliases").or_default() += 1;
            for (index, alias) in crate::boot_alias::aliases_for(&raw, &file)?
                .iter()
                .enumerate()
            {
                let mut key = [0u8; 16];
                key[..8].copy_from_slice(&file.record_number.to_be_bytes());
                key[8..].copy_from_slice(&u64::try_from(index)?.to_be_bytes());
                alias_plan.push(key, &alias)?;
                alias_count = alias_count
                    .checked_add(1)
                    .context("DOS alias plan count overflow")?;
            }
        }
        if file.attributes.iter().any(|a| a.type_code == 0xc0) {
            *counts
                .entry("identities_with_reparse_attributes")
                .or_default() += 1;
        }
        if file.extended_attributes.is_some() {
            *counts
                .entry("identities_with_extended_attributes")
                .or_default() += 1;
        }
        for stream in &file.streams {
            *counts.entry("streams").or_default() += 1;
            if !stream.name_utf16.is_empty() {
                *counts.entry("named_streams").or_default() += 1;
            }
            if stream.flags & 1 != 0 {
                *counts.entry("compressed_streams").or_default() += 1;
            }
            if stream.flags & 0x4000 != 0 {
                *counts.entry("encrypted_streams").or_default() += 1;
            }
            if stream.flags & 0x8000 != 0 {
                *counts.entry("sparse_streams").or_default() += 1;
            }
        }
        for name in &file.names {
            if name.namespace == 2 {
                continue;
            }
            if let Some(label) = labels
                .iter()
                .copied()
                .find(|label| name.name.eq_ignore_ascii_case(label))
            {
                ensure!(
                    (members.len() as u64).saturating_mul(128) < (4 << 20),
                    "Windows member index exceeds its paid RAM bound"
                );
                members.insert((name.parent_record_number, label, file.record_number));
            }
        }
    }
    fn child(rows: &BTreeSet<(u64, &'static str, u64)>, parent: u64, name: &str) -> Result<u64> {
        let matches: Vec<_> = rows
            .iter()
            .filter(|r| r.0 == parent && r.1.eq_ignore_ascii_case(name))
            .map(|r| r.2)
            .collect();
        ensure!(
            matches.len() == 1,
            "offline Windows member {name} is missing or ambiguous"
        );
        Ok(matches[0])
    }
    let windows = child(&members, 5, "Windows")?;
    let system = child(&members, windows, "System32")?;
    let config = child(&members, system, "config")?;
    let drivers = child(&members, system, "drivers")?;
    let windows_members = serde_json::json!({"Windows":windows,"System32":system,"config":config,"drivers":drivers,
        "SYSTEM":child(&members,config,"SYSTEM")?,"SOFTWARE":child(&members,config,"SOFTWARE")?,
        "winload.efi":child(&members,system,"winload.efi")?,"ntoskrnl.exe":child(&members,system,"ntoskrnl.exe")?,
        "refs.sys":child(&members,drivers,"refs.sys")?});
    let mut blockers = BTreeMap::<String, u64>::new();
    for ordinal in 0..raw.blocker_count() {
        let row = raw.blocker(ordinal)?;
        *blockers.entry(row.code).or_default() += 1;
    }
    raw.revalidate()?;
    reader.revalidate(&mut events)?;
    let alias_plan = alias_plan.finish()?;
    let after = n2r_win32::probe_general(binding.clone(), &mut events)?;
    ensure!(
        before.binding == after.binding
            && before.gpt_layout == after.gpt_layout
            && before.disk_attributes_after == after.disk_attributes_after,
        "source routing changed during planning inspection"
    );
    save(&output.join("inspection-pin.json"), raw.pin())?;
    save(
        &output.join("result.json"),
        &serde_json::json!({"kind":"offline-Windows-metadata-inspection-v1",
        "source":binding,"source_frozen":false,"source_admitted":false,"conversion_authorized":false,
        "all_payload_hashing_skipped":true,"preparation_only":true,"windows_installation_identified":true,
        "windows_members":windows_members,"header":raw.header(),"counts":counts,"blocker_counts":blockers,
        "dos_aliases":alias_count,"dos_alias_preparation_plan":alias_plan,
        "dos_alias_plan_kind":"derived-relative-symlink-paths-v1",
        "source_normalization_authorized":false,
        "directory_index_count":raw.directories().directory_count(),"source_native_bytes_read":reader.native_bytes_read(),
        "source_scratch_bytes":scratch.used_bytes(),"source_ram_accounted_bytes":scratch.working_ram_bytes(),
        "working_set_peak_measured":false,"source_payload_write_calls":0,"native_events":events}),
    )?;
    Ok(())
}
fn save(path: &Path, value: &impl serde::Serialize) -> Result<()> {
    let mut file = OpenOptions::new().create_new(true).write(true).open(path)?;
    serde_json::to_writer_pretty(&mut file, value)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(())
}
