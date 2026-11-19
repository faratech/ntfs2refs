//! Converting the Windows that is running: prepared here, converted in its own
//! Windows Recovery Environment, which the machine restarts into.
//!
//! The running Windows cannot be converted from itself: its volume is in use.
//! The run stages the machine's own `winre.wim` on the working volume with a
//! start script, makes it the boot default and restarts. In the recovery
//! environment the converter runs on the offline Windows exactly as it does
//! for an installed Windows that is not running (`--windows-boot-volume`),
//! then puts the boot menu back and restarts into the converted Windows.
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

/// The directory of a run's staged recovery environment, under the working
/// directory.
pub const STAGING_DIRECTORY: &str = "n2r-running";
const SESSION_FILE: &str = "session.json";
const RESULT_FILE: &str = "session-result.txt";

/// What the recovery environment needs to know, written before the restart.
#[derive(Debug, Serialize, Deserialize)]
pub struct Session {
    /// The serial number of the Windows volume, as `vol` prints it.
    pub volume_serial: String,
    /// The firmware boot entry of the boot partition, first in the firmware's
    /// order until the run ends.
    pub firmware_entry: String,
    /// Options handed on to the converter.
    pub converter_args: Vec<String>,
    /// The working disk and the Windows disk by their identity (a GPT disk
    /// GUID or an MBR signature, as `diskpart` prints it), and the working
    /// directory on its volume without the drive. The environment starts
    /// with every disk offline and brings these online itself.
    pub scratch_disk_id: String,
    pub windows_disk_id: String,
    pub scratch_relative: String,
}

/// What the user asked for that the converter in the recovery environment is
/// to be told.
pub struct Request<'a> {
    pub windows_drive: char,
    pub volume_serial: String,
    pub scratch_directory: &'a Path,
    /// A FAT32 volume on another disk than Windows', from which the machine
    /// starts the recovery environment: the disk a machine starts from cannot
    /// be taken offline, and the conversion takes the Windows disk offline.
    pub boot_volume: char,
    pub scratch_disk_id: String,
    pub windows_disk_id: String,
    pub diagnose: bool,
    pub target_format: Option<&'a str>,
    pub verify_full_content: bool,
}

fn tool(program: &str, args: &[&str]) -> Result<String> {
    let output = Command::new(program)
        .args(args)
        .output()
        .with_context(|| format!("starting {program}"))?;
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    ensure!(
        output.status.success(),
        "{program} {} failed ({}): {}",
        args.join(" "),
        output.status,
        text.trim()
    );
    Ok(text)
}

/// The first `{...}` identifier in a tool's output.
fn identifier(text: &str) -> Result<String> {
    let start = text
        .find('{')
        .with_context(|| format!("no identifier in: {}", text.trim()))?;
    let end = text[start..]
        .find('}')
        .with_context(|| format!("no identifier in: {}", text.trim()))?;
    Ok(text[start..start + end + 1].to_owned())
}

/// The value of a line `name   value` of `bcdedit /enum` output.
fn bcd_value(text: &str, name: &str) -> Option<String> {
    text.lines().find_map(|line| {
        let line = line.trim();
        let rest = line.strip_prefix(name)?;
        rest.starts_with(char::is_whitespace)
            .then(|| rest.trim().to_owned())
    })
}

/// Where the machine's Windows Recovery Environment image is, from
/// `reagentc /info`, which names its directory as a device path.
fn winre_image() -> Result<PathBuf> {
    let info = tool("reagentc.exe", &["/info"])?;
    let enabled = info
        .lines()
        .any(|line| line.contains("Enabled") && line.contains("Windows RE status"));
    let location = info
        .lines()
        .find_map(|line| {
            line.split_once(':')
                .filter(|(k, _)| k.contains("Windows RE location"))
        })
        .map(|(_, value)| value.trim().to_owned())
        .unwrap_or_default();
    ensure!(
        enabled && !location.is_empty(),
        "this Windows has no Windows Recovery Environment turned on, which converting the running Windows restarts into. Turn it on (`reagentc /enable`, which needs the recovery image in C:\\Windows\\System32\\Recovery or on the recovery partition), then run the conversion again. `reagentc /info` said:\n{}",
        info.trim()
    );
    let image = PathBuf::from(location).join("winre.wim");
    ensure!(
        image.exists(),
        "the Windows Recovery Environment image {} named by `reagentc /info` is not there",
        image.display()
    );
    Ok(image)
}

/// `runs\` for a working directory `runs`, nothing for a drive's root.
fn prefix(relative: &str) -> String {
    let trimmed = relative.trim_matches('\\');
    if trimmed.is_empty() {
        String::new()
    } else {
        format!("{trimmed}\\")
    }
}

fn script(firmware_entry: &str) -> String {
    [
        "@echo off".to_owned(),
        "wpeinit".to_owned(),
        r"if exist X:\n2r-hold.flag cmd /k".to_owned(),
        r"X:\n2r\ntfs2refs.exe --running-windows-session X:\n2r\session.json".to_owned(),
        "if errorlevel 3 goto :hold".to_owned(),
        "if errorlevel 1 goto :failed".to_owned(),
        "wpeutil reboot".to_owned(),
        "exit /b".to_owned(),
        ":hold".to_owned(),
        "echo ntfs2refs: this machine needs a person; see above. The next start is this environment again.".to_owned(),
        "cmd /k".to_owned(),
        "wpeutil reboot".to_owned(),
        "exit /b".to_owned(),
        ":failed".to_owned(),
        "rem Whatever went wrong, the next start is Windows' own.".to_owned(),
        format!("bcdedit /set {{fwbootmgr}} displayorder {firmware_entry} /remove"),
        "echo Restarting Windows in 30 seconds.".to_owned(),
        "ping -n 31 127.0.0.1 >nul".to_owned(),
        "wpeutil reboot".to_owned(),
    ]
    .join("\r\n")
        + "\r\n"
}

/// Writes a SAN policy into every control set of the mounted image's SYSTEM
/// hive: 4 brings every disk up offline.
fn set_san_policy(mount: &Path, policy: &str) -> Result<()> {
    let hive = mount.join(r"Windows\System32\config\SYSTEM");
    tool(
        "reg.exe",
        &["load", r"HKLM\N2R_IMAGE", &hive.to_string_lossy()],
    )?;
    let set = (|| -> Result<()> {
        let mut written = 0;
        for n in 1..=3 {
            let set = format!(r"HKLM\N2R_IMAGE\ControlSet{n:03}");
            if tool("reg.exe", &["query", &set]).is_err() {
                continue;
            }
            tool(
                "reg.exe",
                &[
                    "add",
                    &format!(r"{set}\Services\partmgr\Parameters"),
                    "/v",
                    "SanPolicy",
                    "/t",
                    "REG_DWORD",
                    "/d",
                    policy,
                    "/f",
                ],
            )?;
            written += 1;
        }
        ensure!(written > 0, "the image's SYSTEM hive has no control set");
        Ok(())
    })();
    let unloaded = tool("reg.exe", &["unload", r"HKLM\N2R_IMAGE"]);
    set?;
    unloaded?;
    Ok(())
}

/// The description of the firmware entry this program makes.
const FIRMWARE_DESCRIPTION: &str = "ntfs2refs boot partition";

/// The firmware boot entries this program made, found by their description.
fn own_firmware_entries() -> Result<Vec<String>> {
    let text = tool("bcdedit.exe", &["/enum", "firmware", "/v"])?;
    let mut found = Vec::new();
    let mut identifier: Option<String> = None;
    for line in text.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("identifier") {
            identifier = Some(rest.trim().to_owned());
        } else if let Some(rest) = line.strip_prefix("description") {
            if rest.trim() == FIRMWARE_DESCRIPTION {
                found.extend(identifier.clone());
            }
        }
    }
    Ok(found)
}

fn remove_firmware_entry(id: &str) {
    let _ = tool(
        "bcdedit.exe",
        &["/set", "{fwbootmgr}", "displayorder", id, "/remove"],
    );
    let _ = tool("bcdedit.exe", &["/delete", id]);
}

/// Removes the loader and ramdisk entries an earlier version of this route
/// put into Windows' own store, found by their descriptions; this version
/// does not touch that store otherwise.
fn remove_stale_system_entries() -> Result<()> {
    let text = tool("bcdedit.exe", &["/enum", "all", "/v"])?;
    let mut identifier_of_block: Option<String> = None;
    let mut stale = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("identifier") {
            identifier_of_block = Some(rest.trim().to_owned());
        } else if let Some(rest) = line.strip_prefix("description") {
            let description = rest.trim();
            if description == "ntfs2refs recovery ramdisk" || description == "ntfs2refs conversion"
            {
                stale.extend(identifier_of_block.clone());
            }
        }
    }
    for id in stale {
        let _ = tool("bcdedit.exe", &["/displayorder", &id, "/remove"]);
        let _ = tool("bcdedit.exe", &["/delete", &id, "/f"]);
    }
    Ok(())
}

/// In Windows: stages the recovery environment on the working disk and its
/// boot files on the boot partition, puts that partition first in the
/// firmware's boot order and restarts. Nothing on the Windows volume, and
/// nothing of Windows' own boot files, is touched.
pub fn stage_and_restart(request: &Request<'_>) -> Result<()> {
    let scratch = request.scratch_directory;
    let absolute = fs::canonicalize(scratch).unwrap_or_else(|_| scratch.to_path_buf());
    let text = absolute
        .to_string_lossy()
        .trim_start_matches(r"\\?\")
        .to_owned();
    let (scratch_letter, relative) = match text.as_bytes() {
        [letter, b':', b'\\', ..] if letter.is_ascii_alphabetic() => {
            ((*letter as char).to_ascii_uppercase(), text[3..].to_owned())
        }
        _ => bail!(
            "the working directory {} has to be named with a drive letter, as the recovery environment finds it by it",
            scratch.display()
        ),
    };
    let windows = request.windows_drive.to_ascii_uppercase();
    let boot = request.boot_volume.to_ascii_uppercase();
    ensure!(
        scratch_letter != windows,
        "the working directory is on the Windows volume that is converted; give one on another disk"
    );
    let boot_fs = file_system_of(boot)
        .with_context(|| format!("the file system of the boot partition {boot}: could not be read"))?;
    ensure!(
        boot_fs == "FAT32",
        "the boot partition {boot}: is {boot_fs}; the firmware starts only from FAT32. Format a partition of another disk (a USB stick will do, 100 MB or more) as FAT32 and give its drive letter. Nothing was changed."
    );
    // Laboratory: another boot image and its index ("path|index"), such as
    // installation media's boot.wim, in place of the machine's WinRE.
    let (image, index) = match std::env::var("N2R_LAB_IMAGE") {
        Ok(spec) => {
            let (path, index) = spec.split_once('|').unwrap_or((spec.as_str(), "1"));
            (PathBuf::from(path), index.to_owned())
        }
        Err(_) => (winre_image()?, "1".to_owned()),
    };
    let directory = absolute.join(STAGING_DIRECTORY);
    if directory.exists() {
        let _ = Command::new("dism.exe")
            .args(["/Unmount-Image", "/MountDir:"])
            .arg(directory.join("mount"))
            .arg("/Discard")
            .output();
        fs::remove_dir_all(&directory)
            .with_context(|| format!("clearing an earlier {}", directory.display()))?;
    }
    fs::create_dir_all(directory.join("mount"))
        .with_context(|| format!("creating {}", directory.display()))?;

    // The boot files first: their firmware entry gives the start script the
    // identifier it takes out of the boot order when anything fails. Entries
    // an earlier run left on this partition go.
    for stale in own_firmware_entries()? {
        remove_firmware_entry(&stale);
    }
    remove_stale_system_entries()?;
    println!("Writing boot files to {boot}: (bcdboot); Windows' own boot files are not touched");
    tool(
        "bcdboot.exe",
        &[
            &format!(r"{windows}:\Windows"),
            "/s",
            &format!("{boot}:"),
            "/f",
            "UEFI",
            "/addlast",
        ],
    )?;
    // A firmware entry of its own: a copy of the Windows Boot Manager entry
    // that starts the boot manager on the boot partition, which reads the
    // store beside it.
    let firmware_entry = identifier(&tool(
        "bcdedit.exe",
        &["/copy", "{bootmgr}", "/d", FIRMWARE_DESCRIPTION],
    )?)?;
    let pointed = (|| -> Result<()> {
        tool(
            "bcdedit.exe",
            &["/set", &firmware_entry, "device", &format!("partition={boot}:")],
        )?;
        tool(
            "bcdedit.exe",
            &["/set", &firmware_entry, "path", r"\EFI\Microsoft\Boot\bootmgfw.efi"],
        )?;
        Ok(())
    })();
    if let Err(error) = pointed {
        remove_firmware_entry(&firmware_entry);
        return Err(error.context("making the firmware entry of the boot partition"));
    }
    // The boot manager the firmware starts looks itself up by the entry's
    // identifier in the store beside it, so that store is an export of the
    // system store, which holds the entry; the recovery environment is added
    // to it below.
    let store = format!(r"{boot}:\EFI\Microsoft\Boot\BCD");
    let exported = (|| -> Result<()> {
        let _ = fs::remove_file(&store);
        let _ = fs::remove_file(format!("{store}.LOG"));
        tool("bcdedit.exe", &["/export", &store])?;
        Ok(())
    })();
    if let Err(error) = exported {
        remove_firmware_entry(&firmware_entry);
        return Err(error.context("writing the boot partition's store"));
    }
    let armed = (|| -> Result<()> {
        println!(
            "Staging the Windows Recovery Environment ({}) on {}",
            image.display(),
            directory.display()
        );
        let wim = directory.join("winre.wim");
        fs::copy(&image, &wim).with_context(|| format!("copying {}", image.display()))?;
        let mut permissions = fs::metadata(&wim)?.permissions();
        #[allow(clippy::permissions_set_readonly_false)]
        permissions.set_readonly(false);
        fs::set_permissions(&wim, permissions)?;
        let mount = directory.join("mount");
        let wim_text = wim.to_string_lossy().into_owned();
        let mount_text = mount.to_string_lossy().into_owned();
        tool(
            "dism.exe",
            &[
                "/Mount-Image",
                &format!("/ImageFile:{wim_text}"),
                &format!("/Index:{index}"),
                &format!("/MountDir:{mount_text}"),
                "/Quiet",
            ],
        )?;
        let session = Session {
            volume_serial: request.volume_serial.clone(),
            firmware_entry: firmware_entry.clone(),
            converter_args: converter_args(request),
            scratch_disk_id: request.scratch_disk_id.clone(),
            windows_disk_id: request.windows_disk_id.clone(),
            scratch_relative: prefix(&relative),
        };
        let session_json = serde_json::to_vec_pretty(&session)?;
        fs::write(directory.join(SESSION_FILE), &session_json)?;
        let edited = (|| -> Result<()> {
            // Every disk arrives offline in the environment: nothing mounts
            // the Windows volume, half converted or not, before the run
            // decides; the run brings online what it needs (runc-cut-apply-5:
            // after a power cut the disk came back online and its recovery
            // refused it).
            set_san_policy(&mount, "4")?;
            fs::create_dir_all(mount.join("n2r"))?;
            fs::copy(std::env::current_exe()?, mount.join(r"n2r\ntfs2refs.exe"))?;
            fs::write(mount.join(r"n2r\session.json"), &session_json)?;
            // Laboratory: stop at a command prompt before any disk is looked at.
            if std::env::var_os("N2R_LAB_HOLD_IN_IMAGE").is_some() {
                fs::write(mount.join("n2r-hold.flag"), "hold")?;
            }
            fs::write(mount.join("n2r-start.cmd"), script(&firmware_entry))?;
            fs::write(
                mount.join(r"Windows\System32\winpeshl.ini"),
                "[LaunchApps]\r\n%SYSTEMROOT%\\System32\\cmd.exe, /c X:\\n2r-start.cmd",
            )?;
            Ok(())
        })();
        let unmounted = tool(
            "dism.exe",
            &[
                "/Unmount-Image",
                &format!("/MountDir:{mount_text}"),
                if edited.is_ok() {
                    "/Commit"
                } else {
                    "/Discard"
                },
                "/Quiet",
            ],
        );
        edited.context("adding the start script to the recovery image")?;
        unmounted?;
        let _ = fs::remove_dir(&mount);
        let system_root =
            std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_owned());
        fs::copy(
            Path::new(&system_root).join(r"Boot\DVD\EFI\boot.sdi"),
            directory.join("boot.sdi"),
        )
        .context("copying boot.sdi from the running Windows")?;
        let exe = std::env::current_exe()?;
        fs::copy(&exe, directory.join("ntfs2refs.exe"))
            .with_context(|| format!("copying {}", exe.display()))?;

        // The boot partition's own store: the recovery environment first and
        // the default, Windows second.
        let bcd = |args: &[&str]| -> Result<String> {
            let mut all = vec!["/store", store.as_str()];
            all.extend_from_slice(args);
            tool("bcdedit.exe", &all)
        };
        let drive = format!("partition={scratch_letter}:");
        let sdi_path = format!("\\{}{STAGING_DIRECTORY}\\boot.sdi", prefix(&relative));
        let wim_path = format!("\\{}{STAGING_DIRECTORY}\\winre.wim", prefix(&relative));
        let options = identifier(&bcd(&[
            "/create",
            "/d",
            "ntfs2refs recovery ramdisk",
            "/device",
        ])?)?;
        bcd(&["/set", &options, "ramdisksdidevice", &drive])?;
        bcd(&["/set", &options, "ramdisksdipath", &sdi_path])?;
        let loader = identifier(&bcd(&[
            "/create",
            "/d",
            "ntfs2refs conversion",
            "/application",
            "osloader",
        ])?)?;
        let device = format!("ramdisk=[{scratch_letter}:]{wim_path},{options}");
        for (name, value) in [
            ("device", device.as_str()),
            ("osdevice", device.as_str()),
            ("path", r"\windows\system32\boot\winload.efi"),
            ("systemroot", r"\windows"),
            ("winpe", "yes"),
            ("detecthal", "yes"),
        ] {
            bcd(&["/set", &loader, name, value])?;
        }
        bcd(&["/set", &firmware_entry, "default", &loader])?;
        bcd(&["/set", &firmware_entry, "displayorder", &loader])?;
        bcd(&["/set", &firmware_entry, "timeout", "0"])?;
        // Last: the boot partition becomes the firmware's first choice.
        tool(
            "bcdedit.exe",
            &["/set", "{fwbootmgr}", "displayorder", &firmware_entry, "/addfirst"],
        )?;
        Ok(())
    })();
    if let Err(error) = armed {
        remove_firmware_entry(&firmware_entry);
        return Err(error.context(
            "staging the recovery environment; the firmware's boot order is as it was",
        ));
    }
    // Staged here, in Windows, before anything is converted: the report opens
    // at the first logon afterwards, from the working disk.
    let report = directory.join(RESULT_FILE);
    let opened = tool(
        "reg.exe",
        &[
            "add",
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            "/v",
            "ntfs2refs",
            "/t",
            "REG_SZ",
            "/d",
            &format!("cmd.exe /c start \"\" notepad.exe \"{}\"", report.display()),
            "/f",
        ],
    );
    if let Err(error) = opened {
        println!("Note: the report will not open by itself at the next logon ({error:#}).");
    }
    println!(
        "The next start is the recovery environment, from {boot}: (firmware entry {firmware_entry}); the conversion runs there and Windows starts again. Keep {boot}: and {} connected until Windows is back. Its report is {}.",
        directory.display(),
        report.display()
    );
    tool(
        "shutdown.exe",
        &["/r", "/t", "10", "/c", "ntfs2refs: converting this Windows"],
    )?;
    println!("Restarting in 10 seconds. `shutdown /a` stops it.");
    Ok(())
}

fn converter_args(request: &Request<'_>) -> Vec<String> {
    let mut args = Vec::new();
    if request.diagnose {
        args.push("--diagnose".to_owned());
    }
    if let Some(format) = request.target_format {
        args.push("--target-format".to_owned());
        args.push(format.to_owned());
    }
    if request.verify_full_content {
        args.push("--verify-full-content".to_owned());
    }
    // Laboratory: a hold point for the converter in the environment, to cut
    // the power there and exercise the recovery after it.
    if let Ok(point) = std::env::var("N2R_LAB_HOLD_AT") {
        args.push("--lab-hold-at".to_owned());
        args.push(point);
        args.push("--acknowledge-lab-hold-never-completes".to_owned());
    }
    args
}

fn volume_serial_of(letter: char) -> Option<String> {
    let output = Command::new("cmd.exe")
        .args(["/c", &format!("vol {letter}:")])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&output.stdout).into_owned();
    text.lines()
        .find(|line| line.contains("Serial Number"))
        .and_then(|line| line.split_whitespace().last().map(str::to_owned))
}

const RECOVER_FILE: &str = "recover-command.json";

/// The recovery command the converter printed last: the directory and the
/// checksum its `--recover` line names, and whether that line undoes the
/// conversion (a preparation can only be rolled back).
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecoverCommand {
    pub directory: String,
    pub sha256: String,
    pub rollback_only: bool,
}

/// The `--recover "<dir>" --recovery-sha256 <hex> [--rollback]` of a line
/// the converter printed.
fn recover_command_in(line: &str) -> Option<RecoverCommand> {
    let after = line.split_once("--recover \"")?.1;
    let (directory, rest) = after.split_once('"')?;
    let sha256 = rest
        .split_once("--recovery-sha256 ")?
        .1
        .split_whitespace()
        .next()?
        .to_owned();
    (!directory.is_empty() && sha256.len() == 64).then(|| RecoverCommand {
        directory: directory.to_owned(),
        sha256,
        rollback_only: rest.contains("--rollback"),
    })
}

fn run_converter(
    directory: &Path,
    scratch: &Path,
    letter: char,
    session: &Session,
    note: &mut dyn FnMut(String),
) -> u8 {
    use std::io::{BufRead, BufReader};
    use std::process::Stdio;
    let child = Command::new(directory.join("ntfs2refs.exe"))
        .args([
            "--drive",
            &letter.to_string(),
            "--windows-boot-volume",
            "--yes",
            "--volume-serial",
            &session.volume_serial,
            "--scratch-directory",
        ])
        .arg(scratch.join("conversion"))
        .args(&session.converter_args)
        .stdout(Stdio::piped())
        .stderr(match fs::File::create(directory.join("converter-errors.txt")) {
            Ok(file) => Stdio::from(file),
            Err(_) => Stdio::inherit(),
        })
        .spawn();
    let mut child = match child {
        Ok(child) => child,
        Err(error) => {
            note(format!("The converter did not start: {error}"));
            return 1;
        }
    };
    // What it prints is shown as it comes; the line that says how to recover
    // is kept on the working disk, for a run cut off before it ends.
    let mut transcript = fs::File::create(directory.join("converter-output.txt")).ok();
    if let Some(stdout) = child.stdout.take() {
        for line in BufReader::new(stdout).lines().map_while(|l| l.ok()) {
            println!("{line}");
            if let Some(file) = transcript.as_mut() {
                use std::io::Write;
                let _ = writeln!(file, "{line}");
            }
            if let Some(command) = recover_command_in(&line) {
                if let Ok(bytes) = serde_json::to_vec_pretty(&command) {
                    let _ = fs::write(directory.join(RECOVER_FILE), bytes);
                }
            }
        }
    }
    match child.wait() {
        Ok(status) => {
            note(format!("The converter ended with {status}."));
            if !status.success() {
                if let Ok(errors) = fs::read_to_string(directory.join("converter-errors.txt")) {
                    for line in errors.lines().filter(|l| !l.trim().is_empty()) {
                        note(format!("  {line}"));
                    }
                }
            }
            status.code().unwrap_or(1).clamp(0, 255) as u8
        }
        Err(error) => {
            note(format!("The converter could not be waited for: {error}"));
            1
        }
    }
}

/// How a recovery ended.
#[derive(Debug, PartialEq, Eq)]
enum Recovered {
    /// Finished forward: the volume is ReFS.
    Forward,
    /// Put back: the volume is NTFS again.
    BackToNtfs,
    /// Neither: the volume may be half converted.
    Failed,
}

/// The exit code that says the machine needs a person: the boot entry of the
/// recovery environment stays the default and its console stays open.
pub const NEEDS_ATTENTION: u8 = 3;

/// Runs the recovery command the converter printed: forward where the command
/// allows it, and back to NTFS where that fails.
fn recover_from(
    directory: &Path,
    command: &RecoverCommand,
    note: &mut dyn FnMut(String),
) -> Recovered {
    let saved = directory.join(RECOVER_FILE);
    // The working volume may have another letter on this start than on the
    // one that printed the command: the directory is taken on this start's.
    let recovery_directory = rebased(&command.directory, directory);
    let recover = |rollback: bool| -> bool {
        let mut process = Command::new(directory.join("ntfs2refs.exe"));
        process.args([
            "--recover",
            &recovery_directory,
            "--recovery-sha256",
            &command.sha256,
            "--yes",
        ]);
        if rollback {
            process.arg("--rollback");
        }
        process.status().is_ok_and(|status| status.success())
    };
    let forward = !command.rollback_only;
    let outcome = if forward && recover(false) {
        Recovered::Forward
    } else {
        if forward {
            note("Recovering forward did not finish; putting the NTFS volume back.".to_owned());
        }
        if recover(true) {
            Recovered::BackToNtfs
        } else {
            Recovered::Failed
        }
    };
    if outcome != Recovered::Failed {
        let _ = fs::rename(&saved, directory.join("recover-command.done.json"));
    }
    outcome
}

/// `recorded` (`D:\\runs\\...`) on the drive `here` is on, when the two
/// differ only by their drive letter.
fn rebased(recorded: &str, here: &Path) -> String {
    let here = here.to_string_lossy();
    match (recorded.as_bytes(), here.as_bytes()) {
        ([_, b':', b'\\', ..], [h, b':', b'\\', ..]) if h.is_ascii_alphabetic() => {
            format!("{}{}", *h as char, &recorded[1..])
        }
        _ => recorded.to_owned(),
    }
}

/// The file system of a volume, from `fsutil`.
fn file_system_of(letter: char) -> Option<String> {
    let text = tool(
        "fsutil.exe",
        &["fsinfo", "volumeinfo", &format!("{letter}:")],
    )
    .ok()?;
    text.lines().find_map(|line| {
        line.split_once(':')
            .filter(|(key, _)| key.trim() == "File System Name")
            .map(|(_, value)| value.trim().to_owned())
    })
}

/// A first start runs the conversion. A start where an earlier one printed a
/// recovery command and did not end (the power went, the machine was reset)
/// recovers instead. A conversion that fails is recovered at once, from the
/// command it printed last. 0: converted; 1: it did not convert and the
/// volume is NTFS as it was; `NEEDS_ATTENTION`: a person has to look.
fn run_or_recover(
    directory: &Path,
    scratch: &Path,
    letter: char,
    session: &Session,
    note: &mut dyn FnMut(String),
) -> u8 {
    let saved = directory.join(RECOVER_FILE);
    let pending = || {
        fs::read(&saved)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<RecoverCommand>(&bytes).ok())
    };
    let mut code = 0;
    if let Some(command) = pending() {
        note(format!(
            "An earlier start of this run was cut off. Recovering from {}",
            command.directory
        ));
    } else {
        note(format!(
            "Converting the Windows on {letter}: (serial {}), working in {}",
            session.volume_serial,
            scratch.display()
        ));
        code = run_converter(directory, scratch, letter, session, note);
        if code == 0 {
            // It ended on its own: nothing is left to recover from a cut.
            let _ = fs::rename(&saved, directory.join("recover-command.done.json"));
            return 0;
        }
    }
    match pending() {
        Some(command) => {
            if code != 0 {
                note(format!("Recovering from {}", command.directory));
            }
            match recover_from(directory, &command, note) {
                Recovered::Forward => {
                    note("The recovery finished: the volume is converted.".to_owned());
                    0
                }
                Recovered::BackToNtfs => {
                    note("The recovery put the NTFS volume back.".to_owned());
                    code.max(1)
                }
                Recovered::Failed => {
                    note(format!(
                        "The recovery did not finish. Run `ntfs2refs --recover \"{}\" --recovery-sha256 {} --rollback` from a command prompt in this environment.",
                        command.directory, command.sha256
                    ));
                    NEEDS_ATTENTION
                }
            }
        }
        // Nothing was printed to recover from: the converter stopped before
        // it touched the volume, or it is not what the volume is now.
        None => match file_system_of(letter).as_deref() {
            Some("NTFS") => code.max(1),
            other => {
                note(format!(
                    "The converter failed and the volume is {}: it needs a person.",
                    other.unwrap_or("unreadable")
                ));
                NEEDS_ATTENTION
            }
        },
    }
}

/// A disk's identity as `diskpart` prints it: its GPT GUID without braces,
/// or its MBR signature in hexadecimal.
pub fn disk_identity(disk: &n2r_win32::drive_inventory::DiskInventory) -> Option<String> {
    disk.disk_guid
        .as_deref()
        .map(|guid| guid.trim_matches(|c| c == '{' || c == '}').to_ascii_uppercase())
        .or_else(|| disk.mbr_signature.map(|signature| format!("{signature:08X}")))
}

/// Brings the disk with this identity online and writable (`diskpart`).
fn online_disk(identity: &str) -> Result<u32> {
    let inventory = n2r_win32::drive_inventory::inventory_drives_readonly()?;
    let disk = inventory
        .disks
        .iter()
        .find(|disk| disk_identity(disk).is_some_and(|id| id.eq_ignore_ascii_case(identity)))
        .with_context(|| format!("no disk with identity {identity} is attached"))?;
    let script = std::env::temp_dir().join(format!("n2r-online-{}.txt", disk.disk_number));
    fs::write(
        &script,
        format!(
            "select disk {}\r\nonline disk noerr\r\nattributes disk clear readonly noerr\r\n",
            disk.disk_number
        ),
    )?;
    tool("diskpart.exe", &["/s", &script.to_string_lossy()])?;
    Ok(disk.disk_number)
}

/// The staging directory on the working volume, once its letter is there.
fn find_staging(relative: &str) -> Result<PathBuf> {
    for _ in 0..30 {
        if let Some(found) = ('C'..='Z')
            .map(|letter| PathBuf::from(format!("{letter}:\\{relative}{STAGING_DIRECTORY}")))
            .find(|dir| dir.join(SESSION_FILE).exists())
        {
            return Ok(found);
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    bail!("the working directory \\{relative}{STAGING_DIRECTORY} was not found on any volume")
}

/// The Windows volume by its serial number, once its letter is there.
fn find_windows(serial: &str) -> Option<char> {
    for _ in 0..30 {
        if let Some(letter) = ('C'..='Z').find(|letter| {
            volume_serial_of(*letter).is_some_and(|found| found.eq_ignore_ascii_case(serial))
                && Path::new(&format!("{letter}:\\Windows\\System32\\ntoskrnl.exe")).exists()
        }) {
            return Some(letter);
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    None
}

/// In the recovery environment: runs the conversion of the Windows volume
/// the session names, then puts the boot menu back. Returns the converter's
/// exit code.
pub fn run_session(session_path: &Path) -> Result<u8> {
    let session: Session = serde_json::from_slice(&fs::read(session_path)?)
        .with_context(|| format!("reading {}", session_path.display()))?;
    online_disk(&session.scratch_disk_id)
        .context("bringing the working disk online")?;
    let directory = find_staging(&session.scratch_relative)?;
    let mut report = String::new();
    let mut note = |line: String| {
        println!("{line}");
        report.push_str(&line);
        report.push('\n');
    };
    let windows: Option<char> = None;
    let scratch = directory
        .parent()
        .context("the staging directory has no parent")?;
    // A run cut off while it wrote the volume leaves its disk offline and the
    // volume half converted: it has no drive letter and no Windows to find.
    // Its recovery command is what it is recovered from, never the letter
    // (runc-cut-midranges-3 found no volume and restarted into a Windows that
    // could not start).
    let pending = directory.join(RECOVER_FILE).exists();
    let windows = if pending {
        // A recovery takes the Windows disk as it found it: offline.
        windows
    } else {
        online_disk(&session.windows_disk_id)
            .context("bringing the Windows disk online for the conversion")?;
        find_windows(&session.volume_serial)
    };
    let code = match (windows, pending) {
        (Some(letter), _) => run_or_recover(&directory, scratch, letter, &session, &mut note),
        // The letter is used only to convert, which a pending recovery
        // never does.
        (None, true) => run_or_recover(&directory, scratch, '?', &session, &mut note),
        (None, false) => {
            note(format!(
                "No volume with serial {} and a Windows on it was found here; nothing was converted.",
                session.volume_serial
            ));
            2
        }
    };
    if code == NEEDS_ATTENTION {
        note(
            "The boot partition stays first in the firmware's boot order, so the next start is this environment again. When the volume is dealt with, `bcdedit /set {fwbootmgr} displayorder <entry> /remove` and `wpeutil reboot` start Windows."
                .to_owned(),
        );
        let _ = fs::write(directory.join(RESULT_FILE), &report);
        return Ok(code);
    }
    // The firmware's boot order as it was: Windows' own entry first again.
    let restored = tool(
        "bcdedit.exe",
        &[
            "/set",
            "{fwbootmgr}",
            "displayorder",
            &session.firmware_entry,
            "/remove",
        ],
    );
    let restored_ok = restored.is_ok();
    match restored {
        Ok(_) => {
            let _ = tool("bcdedit.exe", &["/delete", &session.firmware_entry]);
            note("The firmware starts Windows' own boot entry again.".to_owned());
        }
        Err(error) => note(format!(
            "The firmware's boot order could not be put back ({error:#}). Choose Windows in the firmware's boot menu, or disconnect the boot partition."
        )),
    }
    let _ = fs::write(directory.join(RESULT_FILE), &report);
    Ok(if !restored_ok && code == 0 { 1 } else { code })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifiers_and_values_come_out_of_bcdedit_text() {
        let created = "The entry {01c539dd-da36-11f1-a8c2-9ea6113f8611} was successfully created.";
        assert_eq!(
            identifier(created).unwrap(),
            "{01c539dd-da36-11f1-a8c2-9ea6113f8611}"
        );
        assert!(identifier("nothing here").is_err());
        let manager = "Windows Boot Manager\n--------\nidentifier              {bootmgr}\ndefault                 {current}\ntimeout                 30\n";
        assert_eq!(bcd_value(manager, "default").as_deref(), Some("{current}"));
        assert_eq!(bcd_value(manager, "displayorder"), None);
    }

    #[test]
    fn a_recovery_directory_follows_the_working_volume_to_its_letter_on_this_start() {
        assert_eq!(
            rebased(r"D:\runs\conversion\x", Path::new(r"E:\runs\n2r-running")),
            r"E:\runs\conversion\x"
        );
        assert_eq!(
            rebased(r"\\?\Volume{1}\x", Path::new(r"E:\runs")),
            r"\\?\Volume{1}\x"
        );
    }

    #[test]
    fn the_recovery_command_is_found_in_what_the_converter_prints() {
        let sha = "8df4f61a6b299dd8113dbdaa88827f27a05bd516f61725ba19effe65815a5180";
        let line = format!(
            "If this run is cut off while it prepares: ntfs2refs --recover \"E:\\runs\\conversion\" --recovery-sha256 {sha} --rollback"
        );
        let found = recover_command_in(&line).unwrap();
        assert_eq!(found.directory, "E:\\runs\\conversion");
        assert_eq!(found.sha256, sha);
        assert!(found.rollback_only);
        let forward = format!("To recover: ntfs2refs --recover \"E:\\x\" --recovery-sha256 {sha}");
        assert!(!recover_command_in(&forward).unwrap().rollback_only);
        assert_eq!(recover_command_in("Verifying ReFS metadata"), None);
    }

    #[test]
    fn the_start_script_runs_the_converter_inside_the_image() {
        let text = script("{00000000-0000-0000-0000-000000000000}");
        assert!(text.contains(r"X:\n2r\ntfs2refs.exe --running-windows-session X:\n2r\session.json"));
        assert!(text.contains(
            "bcdedit /set {fwbootmgr} displayorder {00000000-0000-0000-0000-000000000000} /remove"
        ));
        let run = text.find("--running-windows-session").unwrap();
        assert!(run < text.find(":hold").unwrap());
        assert!(text.contains("if errorlevel 3 goto :hold"));
    }
}
