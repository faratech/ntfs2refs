//! Build-specific boot compatibility checks. These are routing/preservation
//! requirements; only the existing native source issuer authorizes writes.
use crate::execution_mode::{ExecutionMode, SourceChangeAuthority};
use anyhow::{Context, Result, bail, ensure};
use n2r_win32::general_layout::{GeneralDiskBinding, GeneralDiskLayoutProfile};
use sha2::{Digest, Sha256};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    os::windows::{
        fs::{MetadataExt, OpenOptionsExt},
        process::CommandExt,
    },
    path::Path,
    process::{Command, Stdio},
};

const REFS_GEOMETRY_UNIT: u64 = 64 << 20;

/// What preparing ReFS geometry requires of the source partition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum GeometryDecision {
    /// Its length is already a multiple of the ReFS geometry unit.
    Aligned,
    /// The Windows NTFS driver must first shrink it to one.
    Shrink {
        target_bytes: u64,
        shrink_bytes: u64,
    },
}

/// Decided from the partition length alone, before anything is asked of the
/// user, so that a diagnose run which could not be honoured never starts.
pub(super) fn geometry_decision(partition_bytes: u64) -> Result<GeometryDecision> {
    let shrink_bytes = partition_bytes % REFS_GEOMETRY_UNIT;
    if shrink_bytes == 0 {
        return Ok(GeometryDecision::Aligned);
    }
    let target_bytes = partition_bytes
        .checked_sub(shrink_bytes)
        .context("boot geometry underflow")?;
    ensure!(
        target_bytes > 0
            && shrink_bytes < REFS_GEOMETRY_UNIT
            && target_bytes.is_multiple_of(REFS_GEOMETRY_UNIT),
        "bounded ReFS geometry adjustment required"
    );
    Ok(GeometryDecision::Shrink {
        target_bytes,
        shrink_bytes,
    })
}

/// Diagnose never changes the source, so it cannot run where a conversion
/// would first have to shrink the partition. Asked for a Windows boot
/// volume; a data volume gets the read-only check instead.
pub(super) fn admit_geometry(
    decision: GeometryDecision,
    partition_bytes: u64,
    mode: ExecutionMode,
) -> Result<()> {
    if let (
        GeometryDecision::Shrink {
            target_bytes,
            shrink_bytes,
        },
        ExecutionMode::Diagnose,
    ) = (decision, mode)
    {
        bail!(
            "--diagnose cannot run on this partition: a conversion would first have the Windows NTFS driver shrink it by {shrink_bytes} bytes, from {partition_bytes} to {target_bytes} (ReFS covers a volume in whole units of 64 MiB), and diagnose never changes the source. Nothing was changed."
        );
    }
    Ok(())
}

pub(super) fn describe_geometry(decision: GeometryDecision) {
    if let GeometryDecision::Shrink {
        shrink_bytes: remainder,
        ..
    } = decision
    {
        println!(
            "ReFS covers a volume in whole units of 64 MiB. Once Windows has formatted the run's working volume, and before anything else is done, the Windows NTFS driver shrinks this NTFS partition by {remainder} bytes."
        );
        println!(
            "Its GUID and start remain unchanged. The recovery baseline begins after that resize; a later cancellation can leave a healthy, slightly smaller NTFS partition."
        );
    }
}

/// Called only after interactive confirmation and creation of the external run
/// intent. The existing NTFS driver owns every filesystem/GPT resize write.
pub(super) fn normalize_geometry(
    before: n2r_win32::discovery::VolumeDiscovery,
    run: &Path,
    // The NTFS driver resizes the source here, and it is not undone.
    _authority: &SourceChangeAuthority,
) -> Result<n2r_win32::discovery::VolumeDiscovery> {
    use n2r_win32::discovery::{self, Role};
    // The role the source was selected in: an offline Windows installation,
    // or a volume on a data disk of its own.
    let windows = before.binding.layout_profile == GeneralDiskLayoutProfile::OfflineWindows;
    let role = || {
        if windows {
            Role::OfflineWindowsSource
        } else {
            Role::Source
        }
    };
    let old = before.binding.identity.partition_bytes;
    let GeometryDecision::Shrink {
        target_bytes: target,
        shrink_bytes: remainder,
    } = geometry_decision(old)?
    else {
        return Ok(before);
    };
    let mut events = Vec::new();
    let fresh = discovery::discover(&before.volume_guid_path, role())?;
    ensure!(
        fresh.binding == before.binding
            && fresh.filesystem == "NTFS"
            && fresh.volume_serial_low32 == before.volume_serial_low32,
        "confirmed source changed before geometry maintenance"
    );
    let clean = n2r_win32::windows_boot_geometry::observe_clean(&before.binding, &mut events)?;
    ensure!(
        clean.ntfs_serial as u32 == before.volume_serial_low32,
        "native NTFS serial differs before geometry maintenance"
    );
    let mut parents = Vec::new();
    for parent in run.ancestors() {
        let file = OpenOptions::new()
            .access_mode(0x80)
            .share_mode(3)
            .custom_flags(0x0220_0000)
            .open(parent)?;
        let metadata = file.metadata()?;
        ensure!(
            metadata.is_dir() && metadata.file_attributes() & 0x400 == 0,
            "external resize records require ordinary held directories"
        );
        parents.push(file);
    }
    let current = n2r_win32::current_windows_directory()?;
    // Bind the actual containing volume of the ordinary held run directory;
    // never substitute a different directory when that observation fails.
    let native_run = n2r_win32::file_storage::final_path_guid(
        parents
            .first()
            .context("held resize-record directory absent")?,
    )?;
    ensure!(
        native_run.starts_with(r"\\?\Volume{"),
        "resize-record directory has no native GUID volume route"
    );
    let root_end = native_run
        .find("}\\")
        .and_then(|end| end.checked_add(2))
        .context("resize-record GUID volume root absent")?;
    let run_root = &native_run[..root_end];
    let journal = discovery::discover(
        &run_root,
        Role::Journal {
            allow_additional_partitions: true,
        },
    )?;
    // Any working disk other than the source may hold these records; it need
    // not be the disk the maintenance Windows booted from.
    ensure!(
        journal.binding.disk_number != before.binding.disk_number,
        "resize recovery records must be on a disk other than the source: records on disk {}, source disk {}",
        journal.binding.disk_number,
        before.binding.disk_number
    );
    // The partitions of the source disk, as its GPT lists them: the resize
    // must leave every one but the source exactly as it is.
    let partitions = clean
        .probe
        .gpt_layout
        .get(48..)
        .context("source GPT header absent")?
        .chunks_exact(144)
        .count();
    let intent = serde_json::json!({"kind": if windows { "confirmed-offline-Windows-NTFS-geometry-maintenance-v1" } else { "confirmed-data-volume-NTFS-geometry-maintenance-v1" },
        "source_before":before,"clean_native_before":clean,"native_events_before":events,
        "requested_partition_bytes":target,"shrink_bytes":remainder,"formatter_geometry_unit_bytes":REFS_GEOMETRY_UNIT,
        "native_ntfs_driver_resize_authorized":true,"raw_source_writes_authorized":false,
        "preserve_sibling_partitions":true,"source_disk_partitions":partitions,
        "conversion_recovery_baseline":"after successful clean NTFS resize",
        "later_cancellation_may_leave_smaller_healthy_ntfs":true});
    let _intent = write_new(
        &run.join("boot-geometry-intent.json"),
        &serde_json::to_vec_pretty(&intent)?,
    )?;
    let request = run.join("boot-geometry-request.json");
    let _request_owner = write_new(
        &request,
        &serde_json::to_vec(
            &serde_json::json!({"source":before.binding,"volume_guid_path":before.volume_guid_path,"target_bytes":target,"partitions":partitions}),
        )?,
    )?;
    let script = run.join("boot-geometry-resize.ps1");
    let _script_owner = write_new(&script, RESIZE_SCRIPT.as_bytes())?;
    println!(
        "Preparing exact ReFS geometry: Windows NTFS driver shrink of {remainder} bytes. Recovery intent: {}",
        run.join("boot-geometry-intent.json").display()
    );
    let powershell = current.join("System32\\WindowsPowerShell\\v1.0\\powershell.exe");
    // Windows' storage service has answered this shrink with a bare "Failed"
    // and left the partition as it was, and resized it when asked again
    // (#254). Such a failure is asked once more, after a short wait and with
    // the source verified again to be exactly as it was; any other failure,
    // or a second one, stops the run as it always did. Each attempt keeps
    // its own records: the second one's names end in "-retry".
    let mut retried = false;
    let (status, reply, after, after_clean) = loop {
        let attempt = if retried { "-retry" } else { "" };
        let result = run.join(format!("boot-geometry-child-result{attempt}.json"));
        let status = if powershell.exists() {
            Command::new(&powershell)
                .args([
                    "-NoProfile",
                    "-NonInteractive",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-File",
                ])
                .arg(&script)
                .arg("-InputPath")
                .arg(&request)
                .arg("-OutputPath")
                .arg(&result)
                .creation_flags(0x0800_0000)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()?
        } else {
            // A recovery environment has no PowerShell (#115). diskpart asks
            // the same NTFS driver to shrink the volume; everything is checked
            // below exactly as after the PowerShell child.
            shrink_with_diskpart(&current, run, &before.binding, remainder, &result)?
        };
        write_new(
            &run.join(format!("boot-geometry-child-exit{attempt}.json")),
            &serde_json::to_vec_pretty(
                &serde_json::json!({"actual_exit_code":status.code(),"success":status.success(),"resize_retry_performed":retried}),
            )?,
        )?;
        // Always rediscover after an actual child exit, including refusal: a
        // driver resize can have completed before a later provider
        // observation failed.
        let after = match discovery::discover(&before.volume_guid_path, role()) {
            Ok(value) => value,
            Err(error) => {
                write_new(
                    &run.join(format!("boot-geometry-after-error{attempt}.json")),
                    &serde_json::to_vec_pretty(
                        &serde_json::json!({"error":error.to_string(),"source_state_unknown":true,"preserve_external_intent":true}),
                    )?,
                )?;
                return Err(error.into());
            }
        };
        let after_clean =
            n2r_win32::windows_boot_geometry::observe_clean(&after.binding, &mut events);
        write_new(
            &run.join(format!("boot-geometry-after{attempt}.json")),
            &serde_json::to_vec_pretty(&serde_json::json!({
            "source_after":after,"clean_native_after":after_clean.as_ref().ok(),"native_error":after_clean.as_ref().err().map(ToString::to_string),
            "native_events":events,"conversion_baseline_not_yet_frozen":true}))?,
        )?;
        let after_clean = after_clean?;
        let mut output = Vec::new();
        File::open(&result)?
            .take((1 << 20) + 1)
            .read_to_end(&mut output)?;
        ensure!(
            output.len() <= 1 << 20,
            "resize child report exceeds its bound"
        );
        let reply: serde_json::Value = serde_json::from_slice(&output)?;
        let succeeded = status.success()
            && reply.get("success").and_then(|value| value.as_bool()) == Some(true);
        if succeeded
            || retried
            || !generic_storage_failure(&reply)
            || !source_unchanged(&before, &clean, &after, &after_clean)
        {
            break (status, reply, after, after_clean);
        }
        println!(
            "Windows' storage service answered the NTFS shrink with a bare \"Failed\" and left the partition as it was; asking it once more in {} seconds.",
            RETRY_WAIT.as_secs()
        );
        std::thread::sleep(RETRY_WAIT);
        // The shrink goes through the NTFS driver: the source is held to
        // what it was before it is asked again.
        let again = discovery::discover(&before.volume_guid_path, role())
            .map_err(anyhow::Error::from)
            .and_then(|again| {
                let again_clean =
                    n2r_win32::windows_boot_geometry::observe_clean(&again.binding, &mut events)?;
                Ok((again, again_clean))
            });
        let unchanged = again.as_ref().is_ok_and(|(again, again_clean)| {
            source_unchanged(&before, &clean, again, again_clean)
        });
        write_new(
            &run.join("boot-geometry-retry.json"),
            &serde_json::to_vec_pretty(&serde_json::json!({
            "first_error":reply.get("error"),"first_error_id":reply.get("error_id"),
            "source_before_retry":again.as_ref().ok().map(|(again, _)| again),
            "clean_native_before_retry":again.as_ref().ok().map(|(_, again_clean)| again_clean),
            "native_error":again.as_ref().err().map(ToString::to_string),
            "source_unchanged":unchanged,"resize_retry_performed":unchanged,"native_events":events}))?,
        )?;
        if !unchanged {
            break (status, reply, after, after_clean);
        }
        retried = true;
    };
    ensure!(
        status.success() && reply.get("success").and_then(|value| value.as_bool()) == Some(true),
        "native NTFS geometry maintenance stopped: {}; preserve {} (NTFS may already be slightly smaller)",
        reply.get("error").unwrap_or(&serde_json::Value::Null),
        run.display()
    );
    let mut expected = before.binding.clone();
    expected.identity.partition_bytes = target;
    ensure!(
        after.binding == expected
            && after.filesystem == "NTFS"
            && after.label == before.label
            && after.volume_serial_low32 == before.volume_serial_low32
            && after_clean.ntfs_serial == clean.ntfs_serial
            && after_clean.bytes_per_cluster == clean.bytes_per_cluster,
        "native NTFS identity/serial/geometry differs after resize"
    );
    let mut expected_layout = clean.probe.gpt_layout.clone();
    let mut changed = 0usize;
    for row in expected_layout
        .get_mut(48..)
        .context("source GPT header absent")?
        .chunks_exact_mut(144)
    {
        if u32::from_le_bytes(row[24..28].try_into()?) == before.binding.identity.partition_number {
            ensure!(
                u64::from_le_bytes(row[8..16].try_into()?)
                    == before.binding.identity.partition_offset
                    && u64::from_le_bytes(row[16..24].try_into()?) == old,
                "selected GPT extent changed before native resize"
            );
            row[16..24].copy_from_slice(&target.to_le_bytes());
            changed += 1;
        }
    }
    ensure!(
        changed == 1
            && expected_layout == after_clean.probe.gpt_layout
            && clean.probe.device == after_clean.probe.device
            && clean.probe.disk_length == after_clean.probe.disk_length
            && clean.probe.alignment == after_clean.probe.alignment,
        "source disk, sibling partitions or selected GPT metadata changed beyond the admitted length"
    );
    if windows {
        validate(&after.binding)?;
    }
    write_new(
        &run.join("boot-geometry-complete.json"),
        &serde_json::to_vec_pretty(&serde_json::json!({
        "kind":"native-NTFS-boot-geometry-maintenance-complete-v1","original_binding":before.binding,
        "conversion_baseline_binding":after.binding,"ntfs_serial_preserved":clean.ntfs_serial,
        "sibling_gpt_entries_byte_identical":true,"shrink_bytes":remainder,"source_still_ntfs":true,
        "raw_source_writes":false,"ntfs_driver_resize":true,"recovery_baseline_begins_after_resize":true}))?,
    )?;
    println!(
        "NTFS geometry adjustment completed; the disk's other partitions, this partition's GUID and start, and the NTFS serial are unchanged."
    );
    Ok(after)
}
/// How long the storage service is left alone before a shrink it answered
/// with a bare "Failed" is asked for again.
const RETRY_WAIT: std::time::Duration = std::time::Duration::from_secs(10);

/// Whether the PowerShell child's report is of `Resize-Partition` failing
/// with nothing more to say than "Failed": `MSFT_Partition.Resize`'s generic
/// return value 4, which the storage service has given intermittently
/// (#254). The error's identifier says so in every language; the English
/// message alone ("Failed" and the activity ID, as observed) says it too.
/// No other failure is retried, nor any of diskpart, whose report names it.
fn generic_storage_failure(reply: &serde_json::Value) -> bool {
    let text = |key: &str| reply.get(key).and_then(serde_json::Value::as_str);
    if reply.get("success").and_then(serde_json::Value::as_bool) != Some(false)
        || reply
            .get("resize_attempted")
            .and_then(serde_json::Value::as_bool)
            != Some(true)
        || reply.get("tool").is_some()
    {
        return false;
    }
    if text("error_id") == Some("StorageWMI 4,Resize-Partition") {
        return true;
    }
    let mut lines = text("error").unwrap_or_default().lines();
    lines.next().map(str::trim) == Some("Failed")
        && lines
            .next()
            .is_some_and(|line| line.trim_start().starts_with("Activity ID:"))
        && lines.all(|line| line.trim().is_empty())
}

/// Whether the source is exactly as it was before the shrink was asked for:
/// the same partition of the same disk, the same GPT byte for byte, and the
/// same clean NTFS of the same size.
fn source_unchanged(
    before: &n2r_win32::discovery::VolumeDiscovery,
    clean: &n2r_win32::windows_boot_geometry::CleanNtfsGeometry,
    after: &n2r_win32::discovery::VolumeDiscovery,
    after_clean: &n2r_win32::windows_boot_geometry::CleanNtfsGeometry,
) -> bool {
    after.binding == before.binding
        && after.filesystem == "NTFS"
        && after.label == before.label
        && after.volume_serial_low32 == before.volume_serial_low32
        && after_clean.ntfs_serial == clean.ntfs_serial
        && after_clean.bytes_per_cluster == clean.bytes_per_cluster
        && after_clean.filesystem_bytes == clean.filesystem_bytes
        && after_clean.probe.gpt_layout == clean.probe.gpt_layout
        && after_clean.probe.device == clean.probe.device
        && after_clean.probe.disk_length == clean.probe.disk_length
        && after_clean.probe.alignment == clean.probe.alignment
}

/// Shrinks the source partition by `shrink_bytes` with diskpart, where
/// PowerShell is not there, and writes the result where the PowerShell child
/// writes its own: `{"success": …, "error": …}`. diskpart shrinks by whole
/// MiB; a remainder that is not one is refused before anything is asked.
fn shrink_with_diskpart(
    windows: &Path,
    run: &Path,
    source: &GeneralDiskBinding,
    shrink_bytes: u64,
    result: &Path,
) -> Result<std::process::ExitStatus> {
    ensure!(
        shrink_bytes % (1 << 20) == 0 && shrink_bytes > 0,
        "the source's NTFS has to shrink by {shrink_bytes} bytes for whole 64 MiB ReFS units, which is not a whole number of MiB; without PowerShell, diskpart cannot do that. Nothing was changed."
    );
    let mib = shrink_bytes >> 20;
    let script = run.join("boot-geometry-diskpart.txt");
    let _script_owner = write_new(
        &script,
        format!(
            "select disk {}\r\nselect partition {}\r\nshrink desired={mib} minimum={mib}\r\n",
            source.disk_number, source.identity.partition_number
        )
        .as_bytes(),
    )?;
    let output = Command::new(windows.join("System32\\diskpart.exe"))
        .arg("/s")
        .arg(&script)
        .creation_flags(0x0800_0000)
        .stdin(Stdio::null())
        .output()?;
    let said = String::from_utf8_lossy(&output.stdout).into_owned();
    let _log = write_new(
        &run.join("boot-geometry-diskpart-output.txt"),
        said.as_bytes(),
    )?;
    // Do not match localized English stdout ("successfully shrunk"): diskpart
    // localizes its messages on non-English Windows/WinRE, and normalize_geometry
    // independently verifies the post-resize partition length, GPT layout, and
    // NTFS serial through Win32 APIs immediately after this returns.
    let shrunk = output.status.success();
    let _reply = write_new(
        result,
        &serde_json::to_vec(&serde_json::json!({
            "success": shrunk,
            "resize_attempted": true,
            "tool": "diskpart",
            "error": if shrunk { serde_json::Value::Null } else { serde_json::Value::String(said.chars().rev().take(2000).collect::<String>().chars().rev().collect()) },
            "raw_source_writes": false,
            "ntfs_driver_resize": true
        }))?,
    )?;
    Ok(output.status)
}
fn write_new(path: &Path, bytes: &[u8]) -> Result<File> {
    ensure!(
        bytes.len() <= 8 << 20,
        "boot maintenance metadata exceeds its bound"
    );
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .share_mode(1)
        .custom_flags(0x0020_0000)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    let identity = n2r_win32::file_storage::file_id_info(&file)?;
    let bridge = OpenOptions::new()
        .read(true)
        .share_mode(3)
        .custom_flags(0x0020_0000)
        .open(path)?;
    ensure!(
        n2r_win32::file_storage::file_id_info(&bridge)? == identity,
        "maintenance artifact changed before immutable hold"
    );
    drop(file);
    let held = OpenOptions::new()
        .read(true)
        .share_mode(1)
        .custom_flags(0x0020_0000)
        .open(path)?;
    ensure!(
        n2r_win32::file_storage::file_id_info(&held)? == identity,
        "maintenance artifact identity changed while closing writer"
    );
    drop(bridge);
    Ok(held)
}

const RESIZE_SCRIPT: &str = r#"param([Parameter(Mandatory)][string]$InputPath,[Parameter(Mandatory)][string]$OutputPath)
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';Set-StrictMode -Version Latest
$request=$null;$before=$null;$after=$null;$support=$null;$attempted=$false
function Emit($value){$bytes=[Text.UTF8Encoding]::new($false).GetBytes(($value|ConvertTo-Json -Depth 12 -Compress));if($bytes.Length-gt1048576){throw 'Geometry report exceeds its bound'};$f=[IO.File]::Open($OutputPath,'CreateNew','Write','Read');try{$f.Write($bytes,0,$bytes.Length);$f.Flush($true)}finally{$f.Dispose()}}
function State {
 $d=Get-Disk -Number $request.source.disk_number;$parts=@(Get-Partition -DiskNumber $d.Number|Sort-Object PartitionNumber)
 $selected=@($parts|Where-Object{$_.PartitionNumber-eq$request.source.identity.partition_number});if($selected.Count-ne1){throw 'Unique selected source partition required'}
 $p=$selected[0];$v=Get-Volume -Partition $p
 $rows=@(foreach($part in $parts){[ordered]@{number=[int]$part.PartitionNumber;guid=([guid]$part.Guid).ToString('D');gpt_type=([guid]$part.GptType).ToString('D');offset=[long]$part.Offset;size=[long]$part.Size;is_boot=$part.IsBoot;is_system=$part.IsSystem;is_readonly=$part.IsReadOnly;is_offline=$part.IsOffline;is_hidden=$part.IsHidden;no_default_drive_letter=$part.NoDefaultDriveLetter;access_paths=@($part.AccessPaths|Sort-Object)}})
 [ordered]@{disk=[ordered]@{number=[int]$d.Number;guid=([guid]$d.Guid).ToString('D');unique_id=[string]$d.UniqueId;size=[long]$d.Size;logical_sector=[int]$d.LogicalSectorSize;physical_sector=[int]$d.PhysicalSectorSize;is_boot=$d.IsBoot;is_system=$d.IsSystem;is_offline=$d.IsOffline;is_readonly=$d.IsReadOnly};parts=$rows;source=[ordered]@{guid=([guid]$p.Guid).ToString('D');offset=[long]$p.Offset;size=[long]$p.Size;filesystem=[string]$v.FileSystem;health=[string]$v.HealthStatus;volume_unique_id=[string]$v.UniqueId;volume_size=[long]$v.Size;paths=@($p.AccessPaths|Sort-Object)}}
}
function Guard($state,[long]$bytes){
 $d=$state.disk;$s=$request.source;$p=$state.source
 $current=Get-Partition -DriveLetter ([IO.Path]::GetPathRoot([Environment]::SystemDirectory).Substring(0,1))
 if($d.number-ne$s.disk_number-or$d.number-eq$current.DiskNumber-or[guid]$d.guid-ne[guid]$s.identity.disk_guid-or$d.size-ne$s.identity.disk_bytes-or$d.logical_sector-ne$s.identity.logical_sector_bytes-or$d.physical_sector-ne$s.identity.physical_sector_bytes-or$d.is_offline-ne$false-or$d.is_readonly-ne$false-or$d.is_boot-ne$false-or$d.is_system-ne$false){throw 'Source disk identity/current Windows role changed'}
 # ReadOnly is inapplicable/null on EFI, MSR and WinRE in the native storage
 # provider. Preserve that raw observation; these siblings are never resized.
 # The actual source partition and physical disk must be positively writable.
 if($state.parts.Count-ne[int]$request.partitions-or@($state.parts|Where-Object{$_.is_boot-ne$false-or$_.is_system-ne$false-or$_.is_offline-ne$false}).Count){throw 'Source sibling or critical partition roles changed'}
 $selected=@($state.parts|Where-Object{$_.number-eq$s.identity.partition_number})
 if($selected.Count-ne1-or$selected[0].is_readonly-ne$false){throw 'Selected NTFS partition is not positively writable'}
 if([guid]$p.guid-ne[guid]$s.identity.partition_guid-or$p.offset-ne$s.identity.partition_offset-or$p.size-ne$bytes-or$p.filesystem-cne'NTFS'-or$p.health-cne'Healthy'-or$p.paths-notcontains$request.volume_guid_path){throw 'Healthy mounted source NTFS binding changed'}
}
try{
 $request=Get-Content -LiteralPath $InputPath -Encoding UTF8 -Raw|ConvertFrom-Json
 $old=[long]$request.source.identity.partition_bytes;$target=[long]$request.target_bytes
 # A data disk's binding is written without its layout, which is the default.
 $profile=$request.source.PSObject.Properties['layout_profile'];$layout=if($profile){[string]$profile.Value}else{'dedicated_data'};$count=[int]$request.partitions
 if(($layout-cne'offline_windows'-and$layout-cne'dedicated_data'-and$layout-cne'shared_data')-or($layout-ceq'offline_windows'-and$count-ne4)-or($layout-ceq'dedicated_data'-and($count-lt1-or$count-gt2))-or($layout-ceq'shared_data'-and$count-lt2)-or$target-le0-or$target-ge$old-or($old-$target)-ge67108864-or$target%67108864-ne0-or$target-ne($old-$old%67108864)){throw 'Only the necessary sub64MiB geometry shrink of a Windows or data source is admitted'}
 $before=State;Guard $before $old
 $support=Get-PartitionSupportedSize -DiskNumber $request.source.disk_number -PartitionNumber $request.source.identity.partition_number
 if($target-lt[long]$support.SizeMin-or$target-gt[long]$support.SizeMax){throw 'NTFS driver cannot shrink to the exact required ReFS geometry'}
 $closing=State;Guard $closing $old
 if(($before.disk|ConvertTo-Json -Compress)-cne($closing.disk|ConvertTo-Json -Compress)-or($before.parts|ConvertTo-Json -Depth 8 -Compress)-cne($closing.parts|ConvertTo-Json -Depth 8 -Compress)){throw 'Source geometry or siblings changed during supported-size query'}
 $attempted=$true;Resize-Partition -DiskNumber $request.source.disk_number -PartitionNumber $request.source.identity.partition_number -Size $target -Confirm:$false -ErrorAction Stop|Out-Null
 $after=State;Guard $after $target
 $expected=@($before.parts|ForEach-Object{$copy=[ordered]@{};foreach($key in $_.Keys){$copy[$key]=$_[$key]};if($copy.number-eq$request.source.identity.partition_number){$copy.size=$target};$copy})
 if(($before.disk|ConvertTo-Json -Compress)-cne($after.disk|ConvertTo-Json -Compress)-or($expected|ConvertTo-Json -Depth 8 -Compress)-cne($after.parts|ConvertTo-Json -Depth 8 -Compress)-or$after.source.volume_unique_id-cne$before.source.volume_unique_id){throw 'Driver resize changed disk/sibling identity or unexpected partition metadata'}
 Emit @{success=$true;resize_attempted=$attempted;before=$before;after=$after;supported_min=[long]$support.SizeMin;supported_max=[long]$support.SizeMax;requested_bytes=$target;raw_source_writes=$false;ntfs_driver_resize=$true;cancel_may_leave_smaller_healthy_ntfs=$true}
 exit 0
}catch{$message=$_.Exception.Message;$id=[string]$_.FullyQualifiedErrorId;if($null-ne$request){try{$after=State}catch{}};Emit @{success=$false;resize_attempted=$attempted;before=$before;after=$after;error=$message.Substring(0,[Math]::Min(4096,$message.Length));error_id=$id.Substring(0,[Math]::Min(256,$id.Length));raw_source_writes=$false;source_may_already_be_resized=$attempted};exit 1}
"#;

/// Read the installed loader and ReFS driver before admitting a boot profile.
/// Conversion still validates the offline installation and its control OS.
pub(super) fn require_qualified_profile(
    root: &Path,
) -> Result<&'static crate::boot_profile::BootProfile> {
    let component_hash = |relative| {
        let path = root.join(relative);
        hash(&path)
            .with_context(|| format!("could not read Windows boot component {}", path.display()))
    };
    let winload = component_hash("System32\\winload.efi")?;
    let refs = component_hash("System32\\drivers\\refs.sys")?;
    crate::boot_profile::matching(&winload, &refs).with_context(|| {
        format!(
            "Windows at {} is outside every qualified boot profile. System32\\winload.efi SHA-256 is {winload}. System32\\drivers\\refs.sys SHA-256 is {refs}. Qualified profiles are {}.",
            root.display(),
            crate::boot_profile::qualified_ids()
        )
    })
}

pub(super) fn validate(
    binding: &GeneralDiskBinding,
) -> Result<&'static crate::boot_profile::BootProfile> {
    ensure!(
        binding.layout_profile == GeneralDiskLayoutProfile::OfflineWindows,
        "offline Windows topology required"
    );
    let root = std::path::PathBuf::from(binding.volume_path()? + "\\Windows");
    let current = n2r_win32::current_windows_directory()?;
    let mut held = Vec::new();
    for relative in ["", "System32", "System32\\drivers", "System32\\config"] {
        let path = root.join(relative);
        let file = OpenOptions::new()
            .access_mode(0x80)
            .share_mode(3)
            .custom_flags(0x0220_0000)
            .open(path)?;
        let meta = file.metadata()?;
        ensure!(
            meta.is_dir() && meta.file_attributes() & 0x400 == 0,
            "offline Windows directories must be ordinary bound directories"
        );
        held.push(file);
    }
    let profile = require_qualified_profile(&root)?;
    ensure!(
        profile.geometry_unit_bytes == REFS_GEOMETRY_UNIT,
        "boot profile {} expects a different ReFS geometry unit",
        profile.id
    );
    // The ReFS of the new volume is written by the converting Windows'
    // refs.sys, and read afterwards by the offline Windows' own. The two
    // agree where the kernels are the same file (a second Windows of the
    // same build), and where the two ReFS drivers are of one Windows build,
    // whatever their revisions: the case of the machine's own recovery
    // environment (WinRE), which is serviced apart from Windows (#115). The
    // ReFS version itself is checked against the profile when the new
    // volume is formatted.
    let kernel_matches = hash(&root.join("System32\\ntoskrnl.exe"))?
        == hash(&current.join("System32\\ntoskrnl.exe"))?;
    let refs_build = if kernel_matches {
        None
    } else {
        let offline =
            n2r_win32::file_version::file_version(&root.join("System32\\drivers\\refs.sys"))?;
        let converting =
            n2r_win32::file_version::file_version(&current.join("System32\\drivers\\refs.sys"))?;
        ensure!(
            offline.same_build(&converting),
            "offline and converting Windows differ: their kernels are not the same file, and their ReFS drivers are of different builds (the offline Windows' refs.sys {offline}, the converting Windows' {converting}); convert from a Windows, or a recovery environment, of the same build"
        );
        Some((offline, converting))
    };
    for name in ["SYSTEM", "SOFTWARE"] {
        let mut file = ordinary(&root.join("System32\\config").join(name))?;
        let mut magic = [0; 4];
        file.read_exact(&mut magic)?;
        ensure!(
            magic == *b"regf",
            "offline Windows {name} is not a registry hive"
        );
    }
    match refs_build {
        None => println!(
            "Offline Windows boot profile: admitted loader and ReFS driver ({}). The recovery kernel is identical.",
            profile.id
        ),
        Some((offline, converting)) => println!(
            "Offline Windows boot profile: admitted loader and ReFS driver ({}). The converting ReFS driver {converting} has the same build as the offline driver {offline}.",
            profile.id
        ),
    }
    println!(
        "The running Windows disk remains excluded. EFI, MSR and WinRE partitions are preserved."
    );
    Ok(profile)
}
fn ordinary(path: &Path) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .share_mode(1)
        .custom_flags(0x0020_0000)
        .open(path)?;
    let meta = file.metadata()?;
    ensure!(
        meta.is_file() && meta.len() > 0 && meta.file_attributes() & 0x400 == 0,
        "ordinary Windows component required"
    );
    Ok(file)
}
fn hash(path: &Path) -> Result<String> {
    let mut file = ordinary(path)?;
    let before = file.metadata()?;
    ensure!(
        before.len() <= 32 << 20,
        "boot component exceeds the bounded profile"
    );
    let mut magic = [0; 2];
    file.read_exact(&mut magic)?;
    ensure!(magic == *b"MZ", "Windows executable header differs");
    file.seek(SeekFrom::Start(0))?;
    let mut hash = Sha256::new();
    let mut buffer = [0; 65536];
    let mut count = 0u64;
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        count = count
            .checked_add(n as u64)
            .context("boot hash length overflow")?;
        ensure!(count <= before.len(), "boot component grew");
        hash.update(&buffer[..n]);
    }
    let after = file.metadata()?;
    ensure!(
        count == before.len()
            && after.len() == before.len()
            && after.modified()? == before.modified()?,
        "boot component changed during hashing"
    );
    Ok(hex::encode(hash.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;
    const UNIT: u64 = 64 << 20;

    #[test]
    fn every_qualified_profile_uses_the_geometry_unit_that_is_enforced() {
        for profile in crate::boot_profile::QUALIFIED {
            assert_eq!(
                profile.geometry_unit_bytes, REFS_GEOMETRY_UNIT,
                "{}",
                profile.id
            );
        }
    }

    #[test]
    fn boot_profile_preflight_refuses_an_unmatched_loader_and_driver() {
        let windows = tempfile::tempdir().unwrap();
        let system = windows.path().join("System32");
        let drivers = system.join("drivers");
        std::fs::create_dir_all(&drivers).unwrap();
        let loader = b"MZ unqualified loader";
        let refs = b"MZ unqualified ReFS driver";
        std::fs::write(system.join("winload.efi"), loader).unwrap();
        std::fs::write(drivers.join("refs.sys"), refs).unwrap();

        let error = require_qualified_profile(windows.path())
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("outside every qualified boot profile"),
            "{error}"
        );
        assert!(
            error.contains(&hex::encode(Sha256::digest(loader))),
            "{error}"
        );
        assert!(
            error.contains(&hex::encode(Sha256::digest(refs))),
            "{error}"
        );
        assert!(
            error.contains(&crate::boot_profile::qualified_ids()),
            "{error}"
        );
    }

    #[test]
    fn geometry_is_decided_from_the_partition_length_alone() {
        assert_eq!(
            geometry_decision(987 * UNIT).unwrap(),
            GeometryDecision::Aligned
        );
        assert_eq!(
            geometry_decision(987 * UNIT + 4096).unwrap(),
            GeometryDecision::Shrink {
                target_bytes: 987 * UNIT,
                shrink_bytes: 4096
            }
        );
        assert_eq!(
            geometry_decision(2 * UNIT - 512).unwrap(),
            GeometryDecision::Shrink {
                target_bytes: UNIT,
                shrink_bytes: UNIT - 512
            }
        );
        // Shrinking to nothing is not an adjustment.
        assert!(geometry_decision(UNIT - 4096).is_err());
    }

    #[test]
    fn only_a_bare_failed_from_the_storage_service_shrink_is_asked_again() {
        let reply = |value: serde_json::Value| {
            let mut reply = serde_json::json!({"success":false,"resize_attempted":true});
            reply
                .as_object_mut()
                .unwrap()
                .extend(value.as_object().unwrap().clone());
            reply
        };
        // As observed (#254), and as its identifier says in any language.
        let observed = "Failed\nActivity ID: {1479e018-7a0b-0002-2315-7a140b7add01}";
        assert!(generic_storage_failure(&reply(
            serde_json::json!({"error":observed})
        )));
        assert!(generic_storage_failure(&reply(
            serde_json::json!({"error":"Fehlgeschlagen\r\nAktivitäts-ID: {x}","error_id":"StorageWMI 4,Resize-Partition"})
        )));
        assert!(generic_storage_failure(&reply(
            serde_json::json!({"error":"Failed\r\nActivity ID: {x}\r\n","error_id":"StorageWMI 4,Resize-Partition"})
        )));
        // Every other failure stops the run as before.
        for other in [
            serde_json::json!({"error":"Size Not Supported\nActivity ID: {x}","error_id":"StorageWMI 4097,Resize-Partition"}),
            serde_json::json!({"error":"Fehlgeschlagen\nAktivitäts-ID: {x}","error_id":"StorageWMI 4,Get-Volume"}),
            serde_json::json!({"error":"Healthy mounted source NTFS binding changed"}),
            serde_json::json!({"error":"Failed"}),
            serde_json::json!({"error":"Failed\nActivity ID: {x}\nMore"}),
            serde_json::json!({"error":observed,"resize_attempted":false}),
            serde_json::json!({"error":observed,"success":true}),
            serde_json::json!({"error":observed,"tool":"diskpart"}),
        ] {
            assert!(!generic_storage_failure(&reply(other.clone())), "{other}");
        }
    }

    #[test]
    fn diagnose_is_refused_only_where_a_conversion_would_shrink_the_partition() {
        let shrink = GeometryDecision::Shrink {
            target_bytes: 987 * UNIT,
            shrink_bytes: 4096,
        };
        let unaligned = 987 * UNIT + 4096;
        for mode in [ExecutionMode::Convert, ExecutionMode::Diagnose] {
            assert!(admit_geometry(GeometryDecision::Aligned, 987 * UNIT, mode).is_ok());
        }
        assert!(admit_geometry(shrink, unaligned, ExecutionMode::Convert).is_ok());
        let refusal = admit_geometry(shrink, unaligned, ExecutionMode::Diagnose)
            .unwrap_err()
            .to_string();
        assert!(
            refusal.contains("shrink it by 4096 bytes")
                && refusal.contains(&unaligned.to_string())
                && refusal.contains("Nothing was changed"),
            "{refusal}"
        );
    }
}
