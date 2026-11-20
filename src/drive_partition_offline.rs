//! One confirmed public command composes the existing Windows preparation,
//! independent recovery image and persistent boot handoff on the owning PC.
use super::*;
use crate::resource_partition_alpha::prepare_and_arm_shared_conversion;
use n2r_win32::{
    recovery_boot::RecoveryBootBudget,
    recovery_image::{RecoveryImageBudget, RecoveryImageInput, RecoveryImageRequest},
};
use std::os::windows::process::CommandExt;

fn input(path: PathBuf, source: &GeneralDiskBinding) -> Result<RecoveryImageInput> {
    let mut file = OpenOptions::new()
        .read(true)
        .share_mode(1)
        .custom_flags(0x0020_0000)
        .open(&path)?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file() && metadata.file_attributes() & 0x400 == 0 && metadata.len() > 0,
        "ordinary nonempty recovery input required: {}",
        path.display()
    );
    let actual = n2r_win32::file_storage::final_path_guid(&file)?;
    let source_prefix = format!("{}\\", source.volume_path()?.trim_end_matches('\\'));
    ensure!(
        !actual
            .get(..source_prefix.len())
            .is_some_and(|s| s.eq_ignore_ascii_case(&source_prefix)),
        "recovery inputs must be stored outside the selected source partition"
    );
    let sha256 = n2r_win32::metadata_pages::pinning_digest(&mut file, metadata.len())?;
    ensure!(
        file.metadata()?.len() == metadata.len()
            && file.metadata()?.modified()? == metadata.modified()?,
        "recovery input changed during hashing"
    );
    Ok(RecoveryImageInput {
        path,
        bytes: metadata.len(),
        sha256,
    })
}

/// The languages a `sources\\lang.ini` of installation media lists as its
/// setup environment's: the keys of its `[Available UI Languages]` section.
fn setup_languages(lang_ini: &str) -> Vec<String> {
    let mut inside = false;
    let mut languages = Vec::new();
    for line in lang_ini.lines().map(str::trim) {
        if line.starts_with('[') {
            inside = line.eq_ignore_ascii_case("[Available UI Languages]");
        } else if inside && !line.is_empty() && !line.starts_with(';') {
            let name = line.split('=').next().unwrap_or(line).trim();
            if !name.is_empty() {
                languages.push(name.to_owned());
            }
        }
    }
    languages
}

/// What is wrong with media whose setup environment has these languages,
/// if anything. The recovery environment is built from that environment
/// and prints its boot configuration (`bcdedit`) in its language; only the
/// English output is understood, and the conversion ends by reading it to
/// put the machine's boot selection back. Media that does not say (no
/// list) is not refused here.
fn setup_language_refusal(languages: &[String], media: &Path) -> Option<String> {
    if languages.is_empty()
        || languages
            .iter()
            .any(|language| language.eq_ignore_ascii_case("en-US"))
    {
        return None;
    }
    Some(format!(
        "the installation media in {} sets Windows up in {} and not in English (United States) (its sources\\lang.ini): the recovery environment built from it would print the boot configuration in that language, which this conversion cannot read to put the machine's boot selection back. Use en-US installation media. Nothing was changed.",
        media.display(),
        languages.join(", ")
    ))
}

/// Checked before the question is asked and long before anything changes.
fn require_english_setup_media(media: &Path, working: &Path) -> Result<()> {
    let path = media.join("sources").join("lang.ini");
    let bytes = match fs::metadata(&path) {
        Err(error) if matches!(error.raw_os_error(), Some(2 | 3)) => return Ok(()),
        Err(error) => {
            return Err(error).with_context(|| format!("looking for {}", path.display()));
        }
        Ok(metadata) => {
            let limit = resource_native::observe_available_resources(working)?
                .available_physical_bytes
                / 64;
            ensure!(
                metadata.len() <= limit,
                "{} is {} bytes, more than the {limit} bytes this run may hold of it. Nothing was changed.",
                path.display(),
                metadata.len()
            );
            fs::read(&path).with_context(|| format!("reading {}", path.display()))?
        }
    };
    let text = if bytes.starts_with(&[0xff, 0xfe]) {
        let units: Vec<u16> = bytes[2..]
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect();
        String::from_utf16_lossy(&units)
    } else {
        String::from_utf8_lossy(&bytes).into_owned()
    };
    match setup_language_refusal(&setup_languages(&text), media) {
        Some(refusal) => anyhow::bail!(refusal),
        None => Ok(()),
    }
}

pub(super) fn convert(
    args: &DriveArgs,
    selected: PartitionSelection,
    before: VolumeDiscovery,
    _authority: &crate::execution_mode::SourceChangeAuthority,
) -> Result<u8> {
    ensure!(
        before.disk_is_windows_disk
            && before.filesystem == "NTFS"
            && before.read_only
            && before.observed_twice_unchanged
            && before.source_write_requests == 0,
        "shared conversion requires the actual readonly NTFS/current-Windows-disk route"
    );
    ensure!(
        args.controlled_post_flush_pause_nonce.is_none()
            && !args.acknowledge_controlled_post_flush_pause,
        "offline shared conversion uses the native allocation-bounded shadow protocol"
    );
    let parent = args.scratch_directory.as_deref().context(
        "use --scratch-directory with an existing directory on a different physical disk for restart recovery")?;
    ordinary_existing(parent)?;
    let directory = OpenOptions::new()
        .access_mode(0x80)
        .share_mode(3)
        .custom_flags(0x0220_0000)
        .open(parent)?;
    let route = n2r_win32::file_storage::final_path_guid(&directory)?;
    let end = route
        .find('}')
        .context("recovery directory has no native volume route")?
        + 1;
    let j = discovery::discover(
        &format!("{}\\", &route[..end]),
        Role::Journal {
            allow_additional_partitions: true,
        },
    )?;
    ensure!(
        j.read_only
            && j.observed_twice_unchanged
            && j.source_write_requests == 0
            && j.binding.disk_number != before.binding.disk_number
            && n2r_win32::layout::guid_bytes(&j.binding.identity.disk_guid)?
                != n2r_win32::layout::guid_bytes(&before.binding.identity.disk_guid)?,
        "recovery directory must be on an actually observed independent physical disk"
    );
    let media = args
        .offline_recovery_media
        .as_ref()
        .context("Windows installation-media directory required")?;
    require_english_setup_media(media, parent)?;
    let wim_path = media.join("sources/boot.wim");
    let sdi_path = media.join("boot/boot.sdi");
    let runner_path = std::env::current_exe()?
        .parent()
        .context("application directory absent")?
        .join("ntfs2refs-recovery.exe");
    let sizes = [&wim_path, &sdi_path, &runner_path].into_iter().try_fold(
        0u64,
        |sum, path| -> Result<u64> {
            let m = fs::symlink_metadata(path)
                .with_context(|| format!("recovery input missing: {}", path.display()))?;
            ensure!(
                m.is_file() && m.file_attributes() & 0x400 == 0,
                "ordinary recovery input required"
            );
            sum.checked_add(m.len())
                .context("recovery input size overflow")
        },
    )?;
    let image_working = sizes
        .checked_mul(3)
        .and_then(|n| n.checked_add(16 * 1024 * 1024))
        .context("recovery image working reservation overflow")?;
    let available = resource_native::observe_available_resources(parent)?;
    let mut preparation_available = available;
    preparation_available.scratch_available_bytes = available
        .scratch_available_bytes
        .checked_sub(image_working)
        .context("independent storage cannot cover recovery image construction")?;
    let mut plan = automatic(preparation_available, parent, true, false)?;
    // Prepare-only has one more evidence artifact than the original live path.
    plan.arena = plan
        .arena
        .checked_sub(
            plan.evidence
                .checked_mul(4)
                .context("boot evidence overflow")?,
        )
        .context("working capacity cannot cover preparation and boot evidence")?;
    let format: TargetFormatProfile = args
        .target_format
        .as_deref()
        .unwrap_or("dev-drive")
        .parse()?;
    println!(
        "Selected: disk {}, partition {} — NTFS, {:.2} GiB.",
        selected.disk_number,
        selected.partition_number,
        before.binding.identity.partition_bytes as f64 / 1073741824.0
    );
    println!(
        "Recovery storage: {}. RAM budget: {} bytes; shadow: {} bytes; preparation arena: {} bytes; recovery image work: {} bytes.",
        parent.display(),
        plan.total,
        plan.stage,
        plan.arena,
        image_working
    );
    println!(
        "This experimental conversion restarts this PC into recovery, converts only the selected data partition, then returns to Windows. Keep the recovery disk connected until completion."
    );
    if !windows::confirm("Convert this NTFS data partition to ReFS and restart this PC? [y/N]")? {
        println!("Cancelled. No conversion started.");
        return Ok(0);
    }
    let current = discovery::discover(
        &selected.volume_guid_path,
        Role::Journal {
            allow_additional_partitions: true,
        },
    )?;
    ensure!(
        current.binding == before.binding
            && current.filesystem == "NTFS"
            && current.disk_is_windows_disk,
        "selected source changed while awaiting confirmation"
    );
    let boot_wim = input(wim_path, &current.binding)?;
    let boot_sdi = input(sdi_path, &current.binding)?;
    let runner = input(runner_path, &current.binding)?;
    ensure!(
        boot_wim
            .bytes
            .checked_add(boot_sdi.bytes)
            .and_then(|n| n.checked_add(runner.bytes))
            == Some(sizes),
        "recovery input sizes changed after upfront capacity admission"
    );
    let output = fresh(parent, "offline-conversion")?;
    let run_id = output
        .file_name()
        .and_then(|s| s.to_str())
        .context("fresh workflow name absent")?
        .rsplit('-')
        .next()
        .context("fresh workflow ID absent")?
        .to_owned();
    let request = PartitionAlphaRequest {
        schema_version: 1,
        source_root: selected.volume_guid_path,
        expected_source: current.binding,
        observation_budget: plan.observation,
        total_ram_bytes: plan.total,
        arena_scratch_bytes: plan.arena,
        maximum_staging_allocation_bytes: plan.stage,
        maximum_evidence_bytes: plan.evidence,
        minimum_free_bytes: plan.keep,
        verification_policy: args.verification_policy()?,
        target_format: format,
        selected_capacity_policy: if args.minimize_scratch {
            SelectedCapacityPolicy::SourceFreeActualBytesV1
        } else {
            SelectedCapacityPolicy::ConservativeV1
        },
    };
    let image = RecoveryImageRequest {
        root: output.join("recovery-image"),
        run_id,
        boot_wim,
        wim_index: 2,
        boot_sdi,
        runner,
        // The workflow replaces this routing input with its same actual newly
        // produced bundle before invoking the image builder.
        bootstrap: RecoveryImageInput {
            path: output.join("offline-request.json"),
            bytes: 0,
            sha256: [0; 32],
        },
        startup_args: Vec::new(),
        prepared_bundle_sha256: [0; 32],
        budget: RecoveryImageBudget {
            ram_bytes: plan.total / 8,
            maximum_input_bytes: sizes + 16 * 1024 * 1024,
            admitted_working_bytes: image_working,
            maximum_final_wim_bytes: image_working / 2,
            minimum_free_bytes: plan.keep,
            maximum_command_output_bytes: plan.evidence,
            maximum_command_seconds: 3600,
            maximum_evidence_bytes: plan.evidence,
        },
        observation: plan.observation,
    };
    let boot = RecoveryBootBudget {
        ram_bytes: plan.total / 8,
        maximum_store_bytes: plan.total / 128,
        maximum_control_bytes: plan.total / 64,
        maximum_image_bytes: image_working,
        minimum_free_bytes: plan.keep,
        tool_timeout_milliseconds: 120_000,
    };
    println!("Conversion and recovery records: {}", output.display());
    let run = output.clone();
    let worker = std::thread::Builder::new()
        .name("public-shared-offline-workflow".into())
        .stack_size(resource_partition_alpha::WORKER_STACK_BYTES)
        .spawn(move || prepare_and_arm_shared_conversion(request, &output, image, boot, true))?;
    // A failure of the workflow has already been taken back by it, and its
    // error says what became of the volume. A workflow that panicked is
    // taken back here, from the records it left.
    let receipt = match worker.join() {
        Ok(result) => result?,
        Err(_) => {
            return Err(resource_partition_alpha::after_failure_in_windows(
                &run,
                anyhow::anyhow!("the conversion's preparation stopped unexpectedly (a panic)"),
            ));
        }
    };
    println!(
        "Persistent recovery selected; intent SHA256: {}",
        hex::encode(receipt.intent_sha256)
    );
    for line in resource_partition_alpha::before_restart_lines(&run) {
        println!("{line}");
    }
    use std::io::Write;
    std::io::stdout().flush()?;
    if n2r_win32::lab_fail::is_armed(n2r_win32::lab_fail::RESTART_SKIP_REBOOT) {
        // Laboratory only: everything is done and selected; the restart is
        // left to the harness.
        println!(
            "{{\"kind\":\"lab-fail-v1\",\"point\":\"{}\",\"pid\":{}}}",
            n2r_win32::lab_fail::RESTART_SKIP_REBOOT,
            std::process::id()
        );
        println!(
            "The restart was not requested (--lab-fail-at restart-skip-reboot). The conversion starts at the next restart."
        );
        return Ok(0);
    }
    let restart = (|| -> Result<()> {
        let (windows_root, _) = native_windows_route()?;
        let exit = std::process::Command::new(windows_root.join("Windows/System32/shutdown.exe"))
            .args(["/r", "/t", "0"])
            .creation_flags(0x0800_0000)
            .status()?;
        ensure!(
            exit.success(),
            "the restart request failed (shutdown.exe ended with {exit})"
        );
        Ok(())
    })();
    // A restart that was not issued leaves a run that would start at some
    // later restart nobody asked for: it is taken back like any other
    // failure before the restart.
    restart.map_err(|cause| resource_partition_alpha::after_failure_in_windows(&run, cause))?;
    Ok(0)
}

#[cfg(test)]
mod setup_media_tests {
    use super::*;

    #[test]
    fn media_whose_setup_environment_is_not_english_is_refused_before_anything_changes() {
        let english = "[Available UI Languages]\r\nen-US = 3\r\n\r\n[Fallback Languages]\r\nen-US = en-us\r\n";
        assert_eq!(setup_languages(english), ["en-US"]);
        let media = Path::new("E:\\");
        assert_eq!(
            setup_language_refusal(&setup_languages(english), media),
            None
        );
        let german =
            "; setup\n[Available UI Languages]\nde-DE = 3\n[Fallback Languages]\nde-DE = en-us\n";
        assert_eq!(setup_languages(german), ["de-DE"]);
        let refusal = setup_language_refusal(&setup_languages(german), media).unwrap();
        assert!(
            refusal.contains("E:\\")
                && refusal.contains("de-DE")
                && refusal.contains("lang.ini")
                && refusal.contains("Nothing was changed"),
            "{refusal}"
        );
        // Media with English among several, and media that does not say.
        let both = "[available ui languages]\nde-DE = 3\nEN-us = 3\n";
        assert_eq!(setup_language_refusal(&setup_languages(both), media), None);
        assert_eq!(
            setup_language_refusal(&setup_languages("[Other]\nx = 1\n"), media),
            None
        );
        assert_eq!(setup_language_refusal(&[], media), None);
    }
}
