use crate::{
    block_io::{self, SourceIdentity},
    ntfs_inspect::{self, NtfsInspection},
    refs_inspect::{self, RefsInspection},
};
use anyhow::{Result, bail, ensure};
use serde::{Deserialize, Serialize};
use std::{
    io::{Read, Seek, SeekFrom},
    path::Path,
};

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "filesystem", content = "details")]
pub enum Filesystem {
    Ntfs(NtfsInspection),
    Refs(RefsInspection),
}
#[derive(Debug, Serialize, Deserialize)]
pub struct Inspection {
    pub schema_version: u32,
    pub source: SourceIdentity,
    pub filesystem: Filesystem,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct Blocker {
    pub code: String,
    pub message: String,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct ConversionPlan {
    pub schema_version: u32,
    pub source: SourceIdentity,
    pub target: String,
    pub target_build: String,
    pub boot_volume: bool,
    pub journal_budget_bytes: u64,
    pub required_staging_bytes: Option<u64>,
    pub required_journal_bytes: Option<u64>,
    pub executable: bool,
    pub blockers: Vec<Blocker>,
}
pub fn inspect_image(path: &Path) -> Result<Inspection> {
    inspect_image_with_limits(path, ntfs_inspect::InspectionLimits::default())
}
pub fn inspect_image_with_limits(
    path: &Path,
    limits: ntfs_inspect::InspectionLimits,
) -> Result<Inspection> {
    let mut file = block_io::open_image(path)?;
    let source = block_io::identity(&mut file, path)?;
    file.seek(SeekFrom::Start(3))?;
    let mut signature = [0; 8];
    file.read_exact(&mut signature)?;
    file.seek(SeekFrom::Start(0))?;
    let filesystem = match &signature {
        b"NTFS    " => Filesystem::Ntfs(ntfs_inspect::inspect_with_limits(
            &mut file,
            source.length,
            limits,
        )?),
        b"ReFS\0\0\0\0" => Filesystem::Refs(refs_inspect::inspect(&mut file, source.length)?),
        _ => bail!(
            "unrecognized filesystem; supply a raw NTFS/ReFS partition, not a whole disk, ISO, encrypted volume, or VHDX"
        ),
    };
    let after = block_io::identity(&mut file, path)?;
    ensure!(
        after.length == source.length && after.sha256 == source.sha256,
        "image changed during inspection"
    );
    Ok(Inspection {
        schema_version: 1,
        source,
        filesystem,
    })
}
pub fn plan(
    inspection: Inspection,
    target: &str,
    build: &str,
    boot: bool,
    budget: u64,
) -> Result<ConversionPlan> {
    ensure!(
        target == "win11" || target == "server",
        "target must be win11 or server"
    );
    let components: Vec<_> = build.split('.').collect();
    ensure!(
        build.len() <= 64
            && (1..=2).contains(&components.len())
            && components
                .iter()
                .all(|part| !part.is_empty() && part.chars().all(|c| c.is_ascii_digit())),
        "target build must be numeric build[.revision]"
    );
    ensure!(budget > 0, "journal budget must be positive");
    let Filesystem::Ntfs(ntfs) = inspection.filesystem else {
        bail!("conversion source must be NTFS");
    };
    let mut blockers: Vec<Blocker> = ntfs
        .blockers
        .into_iter()
        .map(|b| Blocker {
            code: b.code,
            message: b.message,
        })
        .collect();
    let mut add = |code: &str, message: &str| {
        blockers.push(Blocker {
            code: code.into(),
            message: message.into(),
        })
    };
    if !ntfs.inventory_complete {
        add(
            "inventory_incomplete",
            "NTFS preservation inventory is not yet fully validated",
        );
    }
    if ntfs.geometry.cluster_size != 4096 {
        add(
            "cluster_size_not_qualified",
            "initial profile requires 4096-byte NTFS clusters",
        );
    }
    if ntfs.dirty != Some(false) {
        add(
            "source_not_clean",
            "source must be conclusively clean before conversion",
        );
    }
    add(
        "writer_not_qualified",
        "no ReFS writer/formatter profile has passed native-driver corpus qualification",
    );
    add(
        "partition_context_unverified",
        "a raw partition image alone cannot verify GPT/basic-disk identity or EFI/recovery partition context",
    );
    add(
        "write_plan_unavailable",
        "exact metadata allocation, relocation and journal bounds require a qualified writer",
    );
    add(
        "recovery_not_qualified",
        "on-disk journal and commit protocol have not passed native power-loss tests",
    );
    if boot {
        add(
            "boot_control_not_qualified",
            "the exact OS build requires an independent clean ReFS boot control",
        );
    }
    Ok(ConversionPlan {
        schema_version: 1,
        source: inspection.source,
        target: target.into(),
        target_build: build.into(),
        boot_volume: boot,
        journal_budget_bytes: budget,
        required_staging_bytes: None,
        required_journal_bytes: None,
        executable: false,
        blockers,
    })
}
pub fn require_writer() -> Result<()> {
    bail!(
        "conversion writes are unavailable: format, recovery and native-driver qualification gates have not passed; no source was opened for writing"
    )
}
