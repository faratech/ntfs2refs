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
    /// The boot loader entry made for the recovery environment, the ramdisk
    /// options it uses, and the entry that was the default before.
    pub loader: String,
    pub options: String,
    pub original_default: String,
    /// Options handed on to the converter.
    pub converter_args: Vec<String>,
}

/// What the user asked for that the converter in the recovery environment is
/// to be told.
pub struct Request<'a> {
    pub windows_drive: char,
    pub volume_serial: String,
    pub scratch_directory: &'a Path,
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

fn script(relative: &str, original_default: &str) -> String {
    let letters: String = ('C'..='Z').map(|c| format!("{c} ")).collect();
    format!(
        "@echo off\r\n\
wpeinit\r\n\
set S=\r\n\
for %%d in ({letters}) do if exist %%d:\\{relative}{STAGING_DIRECTORY}\\{SESSION_FILE} set S=%%d:\r\n\
if \"%S%\"==\"\" goto :lost\r\n\
set D=%S%\\{relative}{STAGING_DIRECTORY}\r\n\
%D%\\ntfs2refs.exe --running-windows-session %D%\\{SESSION_FILE}\r\n\
if errorlevel 1 goto :failed\r\n\
wpeutil reboot\r\n\
exit /b\r\n\
:lost\r\n\
echo ntfs2refs: the working directory of the run was not found on any volume.\r\n\
:failed\r\n\
rem Whatever went wrong, the next start is the Windows that was the default.\r\n\
bcdedit /default {original_default}\r\n\
echo Restarting Windows in 30 seconds.\r\n\
ping -n 31 127.0.0.1 >nul\r\n\
wpeutil reboot\r\n",
        relative = prefix(relative),
    )
}

/// In Windows: stages the recovery environment and the boot entry, and
/// restarts. Nothing on the volume is touched.
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
    ensure!(
        scratch_letter != request.windows_drive.to_ascii_uppercase(),
        "the working directory is on the Windows volume that is converted; give one on another disk"
    );
    // The old default is written down, before anything is made.
    let manager = tool("bcdedit.exe", &["/enum", "{bootmgr}", "/v"])?;
    // `/v` prints the identifier itself, not an alias such as {current}, which
    // names another entry in the recovery environment.
    let original_default = bcd_value(&manager, "default")
        .filter(|id| id.len() == 38 && id.starts_with('{'))
        .context("the boot manager names no default entry by its identifier; the boot menu is not touched")?;
    let image = winre_image()?;
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
            "/Index:1",
            &format!("/MountDir:{mount_text}"),
            "/Quiet",
        ],
    )?;
    let edited = (|| -> Result<()> {
        fs::write(
            mount.join("n2r-start.cmd"),
            script(&relative, &original_default),
        )?;
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
    let windows = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_owned());
    fs::copy(
        Path::new(&windows).join(r"Boot\DVD\EFI\boot.sdi"),
        directory.join("boot.sdi"),
    )
    .context("copying boot.sdi from the running Windows")?;
    let exe = std::env::current_exe()?;
    fs::copy(&exe, directory.join("ntfs2refs.exe"))
        .with_context(|| format!("copying {}", exe.display()))?;

    // The boot menu: a ramdisk entry and a loader for the image, first in
    // the menu and the default.
    let drive = format!("partition={scratch_letter}:");
    let sdi_path = format!("\\{}{STAGING_DIRECTORY}\\boot.sdi", prefix(&relative));
    let wim_path = format!("\\{}{STAGING_DIRECTORY}\\winre.wim", prefix(&relative));
    let options = identifier(&tool(
        "bcdedit.exe",
        &["/create", "/d", "ntfs2refs recovery ramdisk", "/device"],
    )?)?;
    let mut created = vec![options.clone()];
    let armed = (|| -> Result<String> {
        tool(
            "bcdedit.exe",
            &["/set", &options, "ramdisksdidevice", &drive],
        )?;
        tool(
            "bcdedit.exe",
            &["/set", &options, "ramdisksdipath", &sdi_path],
        )?;
        let loader = identifier(&tool(
            "bcdedit.exe",
            &[
                "/create",
                "/d",
                "ntfs2refs conversion",
                "/application",
                "osloader",
            ],
        )?)?;
        created.push(loader.clone());
        let device = format!("ramdisk=[{scratch_letter}:]{wim_path},{options}");
        for (name, value) in [
            ("device", device.as_str()),
            ("osdevice", device.as_str()),
            ("path", r"\windows\system32\boot\winload.efi"),
            ("systemroot", r"\windows"),
            ("winpe", "yes"),
            ("detecthal", "yes"),
        ] {
            tool("bcdedit.exe", &["/set", &loader, name, value])?;
        }
        let session = Session {
            volume_serial: request.volume_serial.clone(),
            loader: loader.clone(),
            options: options.clone(),
            original_default: original_default.clone(),
            converter_args: converter_args(request),
        };
        fs::write(
            directory.join(SESSION_FILE),
            serde_json::to_vec_pretty(&session)?,
        )?;
        tool("bcdedit.exe", &["/displayorder", &loader, "/addfirst"])?;
        tool("bcdedit.exe", &["/default", &loader])?;
        Ok(loader)
    })();
    let loader = match armed {
        Ok(loader) => loader,
        Err(error) => {
            // The menu as it was.
            let _ = tool("bcdedit.exe", &["/default", &original_default]);
            for id in created.iter().rev() {
                let _ = tool("bcdedit.exe", &["/displayorder", id, "/remove"]);
                let _ = tool("bcdedit.exe", &["/delete", id, "/f"]);
            }
            return Err(error.context("arming the boot entry; the boot menu was put back"));
        }
    };
    println!(
        "The next start is the recovery environment ({loader}); the conversion runs there and Windows starts again on ReFS. The original boot entry {original_default} is restored when it ends, whatever its result is; its report is {}.",
        directory.join(RESULT_FILE).display()
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
    if let Some(stdout) = child.stdout.take() {
        for line in BufReader::new(stdout).lines().map_while(|l| l.ok()) {
            println!("{line}");
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
            status.code().unwrap_or(1).clamp(0, 255) as u8
        }
        Err(error) => {
            note(format!("The converter could not be waited for: {error}"));
            1
        }
    }
}

/// A first start runs the conversion. A start where an earlier one printed a
/// recovery command and did not end (the power went, the machine was reset)
/// recovers instead: forward where the command allows it, and back to NTFS
/// where that fails.
fn run_or_recover(
    directory: &Path,
    scratch: &Path,
    letter: char,
    session: &Session,
    note: &mut dyn FnMut(String),
) -> u8 {
    let saved = directory.join(RECOVER_FILE);
    let Some(command) = fs::read(&saved)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<RecoverCommand>(&bytes).ok())
    else {
        note(format!(
            "Converting the Windows on {letter}: (serial {}), working in {}",
            session.volume_serial,
            scratch.display()
        ));
        let code = run_converter(directory, scratch, letter, session, note);
        // It ended on its own: nothing is left to recover from a cut.
        let _ = fs::rename(&saved, directory.join("recover-command.done.json"));
        return code;
    };
    note(format!(
        "An earlier start of this run was cut off. Recovering from {}",
        command.directory
    ));
    let recover = |rollback: bool| -> Option<bool> {
        let mut process = Command::new(directory.join("ntfs2refs.exe"));
        process.args([
            "--recover",
            &command.directory,
            "--recovery-sha256",
            &command.sha256,
        ]);
        if rollback {
            process.arg("--rollback");
        }
        process.status().ok().map(|status| status.success())
    };
    let forward = !command.rollback_only;
    let mut done = if forward { recover(false) } else { None };
    if done != Some(true) {
        if forward {
            note("Recovering forward did not finish; putting the NTFS volume back.".to_owned());
        }
        done = recover(true);
    }
    let _ = fs::rename(&saved, directory.join("recover-command.done.json"));
    match done {
        Some(true) => {
            note("The recovery finished.".to_owned());
            0
        }
        _ => {
            note(format!(
                "The recovery did not finish. Run `ntfs2refs --recover \"{}\" --recovery-sha256 {} --rollback` from a command prompt in the recovery environment or Windows.",
                command.directory, command.sha256
            ));
            1
        }
    }
}

/// In the recovery environment: runs the conversion of the Windows volume
/// the session names, then puts the boot menu back. Returns the converter's
/// exit code.
pub fn run_session(session_path: &Path) -> Result<u8> {
    let directory = session_path
        .parent()
        .context("the session file has no directory")?
        .to_path_buf();
    let session: Session = serde_json::from_slice(&fs::read(session_path)?)
        .with_context(|| format!("reading {}", session_path.display()))?;
    let mut report = String::new();
    let mut note = |line: String| {
        println!("{line}");
        report.push_str(&line);
        report.push('\n');
    };
    let windows = ('A'..='Z').find(|letter| {
        volume_serial_of(*letter)
            .is_some_and(|serial| serial.eq_ignore_ascii_case(&session.volume_serial))
            && Path::new(&format!("{letter}:\\Windows\\System32\\ntoskrnl.exe")).exists()
    });
    let code = match windows {
        None => {
            note(format!(
                "No volume with serial {} and a Windows on it was found here; nothing was converted.",
                session.volume_serial
            ));
            2
        }
        Some(letter) => {
            let scratch = directory
                .parent()
                .context("the staging directory has no parent")?;
            note(format!(
                "Converting the Windows on {letter}: (serial {}), working in {}",
                session.volume_serial,
                scratch.display()
            ));
            run_or_recover(&directory, scratch, letter, &session, &mut note)
        }
    };
    // The boot menu as it was, whatever happened.
    let restored = (|| -> Result<()> {
        tool("bcdedit.exe", &["/default", &session.original_default])?;
        let _ = tool(
            "bcdedit.exe",
            &["/displayorder", &session.loader, "/remove"],
        );
        let _ = tool("bcdedit.exe", &["/delete", &session.loader, "/f"]);
        let _ = tool("bcdedit.exe", &["/delete", &session.options, "/f"]);
        Ok(())
    })();
    let restored_ok = restored.is_ok();
    match restored {
        Ok(()) => note(format!(
            "The boot menu is as it was: {} is the default again.",
            session.original_default
        )),
        Err(error) => note(format!(
            "The boot menu could not be put back ({error:#}). Choose Windows from the boot menu; `bcdedit /default {}` makes it the default.",
            session.original_default
        )),
    }
    let _ = fs::write(directory.join(RESULT_FILE), report);
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
    fn the_start_script_finds_the_working_directory_by_its_session_file() {
        let text = script("runs\\", "{00000000-0000-0000-0000-000000000000}");
        assert!(text.contains(r"if exist %%d:\runs\n2r-running\session.json set S=%%d:"));
        assert!(text.contains("--running-windows-session"));
        assert!(text.contains("wpeutil reboot"));
        assert!(text.contains("bcdedit /default {00000000-0000-0000-0000-000000000000}"));
    }
}
