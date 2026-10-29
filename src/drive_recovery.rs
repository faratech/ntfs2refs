//! Confirmed recovery of an already activated compact conversion. The bundle
//! locates original inputs; only the existing native ticket/protocol authorizes
//! recovery. Declining never opens devices or creates a recovery directory.
use anyhow::Result;
use std::path::Path;

pub fn run(directory: &Path, recovery_sha256: &str, rollback: bool) -> Result<u8> {
    #[cfg(windows)]
    {
        windows::run(directory, recovery_sha256, rollback)
    }
    #[cfg(not(windows))]
    {
        let _ = (directory, recovery_sha256, rollback);
        anyhow::bail!("compact recovery requires Windows on the machine owning the data volumes")
    }
}

#[cfg(windows)]
mod windows {
    use super::*;
    use crate::{
        compact_recovery_bundle::HeldBundle,
        general_qualification,
        general_recovery::{ExperimentalCompactOperation, recover_compact_experimental},
    };
    use anyhow::{Context, ensure};
    use n2r_win32::{
        discovery::{self, Role},
        managed_shadow,
    };
    use sha2::{Digest, Sha256};
    use std::{
        io::{self, BufRead, Read, Write},
        path::{Component, PathBuf, Prefix},
        time::{SystemTime, UNIX_EPOCH},
    };

    fn display(value: &str) -> String {
        value
            .chars()
            .map(|character| {
                if character.is_control() {
                    '?'
                } else {
                    character
                }
            })
            .collect()
    }

    fn confirm() -> Result<bool> {
        print!("Proceed with this experimental data-volume recovery? [y/N] ");
        io::stdout().flush()?;
        let input = io::stdin();
        // An overlong response cannot become an affirmative answer.
        let mut bounded = input.lock().take(65);
        let mut answer = String::new();
        bounded.read_line(&mut answer)?;
        Ok(answer.len() < 65 && matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes"))
    }

    fn output_location() -> Result<(String, PathBuf)> {
        let system = std::env::var("SystemRoot").context("Windows system path unavailable")?;
        let bytes = system.as_bytes();
        ensure!(
            bytes.len() >= 3
                && bytes[0].is_ascii_alphabetic()
                && bytes[1] == b':'
                && bytes[2] == b'\\',
            "an ordinary local Windows system path is required"
        );
        let os_root = format!("{}\\", &system[..2]);
        let mut hash = Sha256::new();
        hash.update(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)?
                .as_nanos()
                .to_le_bytes(),
        );
        hash.update(std::process::id().to_le_bytes());
        let id = hex::encode(hash.finalize());
        let output = PathBuf::from(format!(
            "{os_root}ProgramData\\ntfs2refs\\runs\\recovery-{}",
            &id[..32]
        ));
        Ok((os_root, output))
    }

    pub(super) fn run(directory: &Path, recovery_sha256: &str, rollback: bool) -> Result<u8> {
        ensure!(
            directory.is_absolute()
                && directory.components().all(|component| match component {
                    Component::Prefix(prefix) => matches!(prefix.kind(), Prefix::Disk(_)),
                    Component::ParentDir | Component::CurDir => false,
                    _ => true,
                }),
            "recovery directory must be an absolute ordinary local path without traversal"
        );
        let bundle_path = directory.join("compact-recovery-bundle.json");
        let mut held = HeldBundle::open(&bundle_path, recovery_sha256)
            .context("cannot load the original pinned compact recovery bundle")?;
        let source = held.bundle().source.clone();
        let shadow = held.bundle().shadow.clone();
        ensure!(
            held.request().pair.source == source && held.request().pair.shadow == shadow,
            "bundle source/shadow identities differ from its original pinned request"
        );
        let managed = held.bundle().managed_shadow.as_ref().map(|descriptor| {
            (
                descriptor.location.path.clone(),
                descriptor.location.virtual_disk_id.clone(),
                descriptor.location.binding.clone(),
            )
        });
        if let Some((_, _, binding)) = &managed {
            ensure!(
                binding == &shadow,
                "managed shadow location differs from the original request binding"
            );
        }
        let inputs = held.inputs();
        println!(
            "Pinned source: disk {}, partition {}, {} bytes at offset {}",
            source.disk_number,
            source.identity.partition_number,
            source.identity.partition_bytes,
            source.identity.partition_offset
        );
        println!(
            "Disk GUID: {}\nPartition GUID: {}",
            display(&source.identity.disk_guid),
            display(&source.identity.partition_guid)
        );
        println!(
            "Action: {}",
            if rollback {
                "restore the original NTFS image and close journal replay"
            } else {
                "resume the interrupted conversion, then finalize and verify ReFS"
            }
        );
        println!(
            "The existing native recovery gates will recheck the actual device and journal state."
        );
        if !confirm()? {
            println!("Recovery cancelled.");
            return Ok(0);
        }

        held.revalidate()?;
        let (os_root, output) = output_location()?;
        println!("Recovery records: {}", output.display());
        let os = discovery::discover(
            &os_root,
            Role::Journal {
                allow_additional_partitions: true,
            },
        )
        .context("cannot verify independent Windows-volume recovery storage")?;
        ensure!(
            os.disk_is_windows_disk
                && os.binding.disk_number == os.windows_disk_number
                && os.binding.disk_number != source.disk_number
                && os.binding.disk_number != shadow.disk_number,
            "recovery records must be on the Windows disk, independent of source and shadow"
        );
        held.revalidate()?;
        // This is the same fresh OS-volume/ordinary-parent policy used by the
        // typed recovery artifact writer. It runs only after confirmation.
        general_qualification::create_output(&output)?;
        general_qualification::save(
            &output,
            "drive-recovery-intent.json",
            &serde_json::json!({
                "schema_version": 1,
                "kind": "confirmed-compact-drive-recovery",
                "bundle_path": bundle_path,
                "bundle_sha256": recovery_sha256,
                "operation": if rollback { "rollback" } else { "resume_then_finalize" },
                "source": source,
                "shadow": shadow,
                "fresh_apply_authorized": false,
                "source_certificate_recreated": false,
                "serialized_bundle_grants_recovery_authority": false
            }),
        )?;

        // Keep this owner AND the pinned bundle/request guard alive across all
        // native calls. Reattachment remains read-only and uses the exact
        // original provider/GPT/route binding; it cannot create another shadow.
        let managed_owner = match managed {
            Some((path, provider, binding)) => Some(
                managed_shadow::reattach_existing(&path, &provider, &binding)
                    .context("cannot reattach the exact original protected shadow")?,
            ),
            None => None,
        };
        held.revalidate()?;
        if rollback {
            recover_compact_experimental(
                ExperimentalCompactOperation::Rollback,
                &inputs,
                &output.join("rollback"),
            )
            .context("typed NTFS rollback refused or stopped; no alternate action was attempted")?;
        } else {
            recover_compact_experimental(
                ExperimentalCompactOperation::Resume,
                &inputs,
                &output.join("resume"),
            )
            .context("typed resume refused or stopped; no finalize or rollback was attempted")?;
            held.revalidate()?;
            recover_compact_experimental(
                ExperimentalCompactOperation::Finalize,
                &inputs,
                &output.join("finalize"),
            )
            .context("typed ReFS finalization refused or stopped; no rollback was attempted")?;
        }
        held.revalidate()?;
        drop(managed_owner);
        drop(held);
        println!(
            "{} Recovery records: {}",
            if rollback {
                "NTFS rollback completed."
            } else {
                "ReFS recovery completed."
            },
            output.display()
        );
        Ok(0)
    }
}
