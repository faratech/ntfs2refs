//! Prepare only a pinned, read-only public operation-state command.
//! This optional helper neither executes the command nor determines lifecycle,
//! admission, cancellation or recovery authority. The frozen engine is unchanged.
use anyhow::{Context, Result, ensure};
use clap::Parser;
use serde::{Deserialize, Serialize, de::IgnoredAny};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom},
    path::{Component, Path, PathBuf},
    process::ExitCode,
};

#[derive(Parser)]
#[command(
    version,
    about = "Prepare a read-only operation-state command; never execute it."
)]
struct Cli {
    /// Existing public conversion run containing conversion-intent.json.
    #[arg(long)]
    run_directory: PathBuf,
    /// Fresh OS-volume artifact directory for the future operation-state call.
    #[arg(long)]
    state_output: PathBuf,
    /// Reviewed converter name/path. This helper does not verify its executable.
    #[arg(long, default_value = "ntfs2refs")]
    executable: String,
}

struct ArtifactSpec {
    name: &'static str,
    flag: &'static str,
    maximum_bytes: u64,
    mandatory: bool,
}

// Match general_operation_state::load's public input bounds without invoking it.
const ARTIFACTS: [ArtifactSpec; 5] = [
    ArtifactSpec {
        name: "conversion-intent.json",
        flag: "--intent-sha256",
        maximum_bytes: 16384,
        mandatory: true,
    },
    ArtifactSpec {
        name: "qualification/source-frozen.json",
        flag: "--frozen-source-sha256",
        maximum_bytes: 64 << 20,
        mandatory: false,
    },
    ArtifactSpec {
        name: "qualification/source-mount-paths.json",
        flag: "--mount-paths-sha256",
        maximum_bytes: 1 << 20,
        mandatory: false,
    },
    ArtifactSpec {
        name: "request.json",
        flag: "--request-sha256",
        maximum_bytes: 131072,
        mandatory: false,
    },
    ArtifactSpec {
        name: "ticket.json",
        flag: "--ticket-sha256",
        maximum_bytes: 65536,
        mandatory: false,
    },
];

#[derive(Serialize)]
struct ArtifactPin {
    relative_path: &'static str,
    sha256_option: &'static str,
    bytes: u64,
    sha256: String,
}

#[derive(Serialize)]
struct PreparedCommand {
    schema_version: u32,
    kind: &'static str,
    executable: String,
    arguments: Vec<String>,
    powershell_command: String,
    artifacts: Vec<ArtifactPin>,
    command_executed: bool,
    lifecycle_inferred: bool,
    mutation_authorized: bool,
    executable_identity_verified: bool,
    artifact_schema_validated: bool,
    artifacts_immutable_after_return: bool,
}

fn ordinary(path: &Path, directory: bool) -> Result<fs::Metadata> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("read ordinary path {}", path.display()))?;
    let mut redirected = metadata.file_type().is_symlink();
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        redirected |= metadata.file_attributes() & 0x400 != 0;
    }
    ensure!(
        !redirected
            && if directory {
                metadata.is_dir()
            } else {
                metadata.is_file()
            },
        "ordinary {} required: {}",
        if directory { "directory" } else { "file" },
        path.display()
    );
    Ok(metadata)
}

fn local_absolute(path: &Path) -> Result<&str> {
    let text = path.to_str().context("Unicode artifact path required")?;
    ensure!(
        path.is_absolute() && text.len() <= 512 && !text.chars().any(char::is_control),
        "bounded absolute artifact path required"
    );
    ensure!(
        !path
            .components()
            .any(|part| matches!(part, Component::ParentDir | Component::CurDir)),
        "relative path components refused"
    );
    #[cfg(windows)]
    {
        let bytes = text.as_bytes();
        ensure!(
            bytes.len() > 3
                && bytes[0].is_ascii_alphabetic()
                && bytes[1..3] == *b":\\"
                && !text[3..].contains([':', '/'])
                && !text.contains(".."),
            "ordinary local DOS path required; no device, UNC or stream paths"
        );
    }
    Ok(text)
}

fn ordinary_ancestors(path: &Path, missing_allowed: bool) -> Result<()> {
    for ancestor in path.ancestors() {
        match fs::symlink_metadata(ancestor) {
            Ok(_) => {
                ordinary(ancestor, true)?;
            }
            Err(error) if missing_allowed && error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("read directory {}", ancestor.display()));
            }
        }
    }
    Ok(())
}

fn pin_artifact(path: &Path, spec: &ArtifactSpec) -> Result<(File, ArtifactPin)> {
    ordinary_ancestors(path.parent().context("artifact parent absent")?, false)?;
    let metadata = ordinary(path, false)?;
    ensure!(
        metadata.len() > 0 && metadata.len() <= spec.maximum_bytes,
        "{} exceeds its public input bound",
        spec.name
    );
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        // Read contents only; deny ordinary write/delete sharing and do not
        // follow a replaced leaf reparse point. No raw disk/volume is opened.
        options.share_mode(1).custom_flags(0x0020_0000);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("open {} read-only", spec.name))?;
    let opened = file.metadata()?;
    ensure!(
        opened.is_file() && opened.len() == metadata.len(),
        "{} changed at open",
        spec.name
    );
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        ensure!(
            opened.file_attributes() & 0x400 == 0,
            "reparse artifact refused"
        );
    }
    let mut hash = Sha256::new();
    let mut buffer = [0_u8; 65536];
    let mut bytes = 0_u64;
    let mut opening = None;
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        bytes = bytes
            .checked_add(count as u64)
            .context("artifact length overflow")?;
        ensure!(
            bytes <= spec.maximum_bytes,
            "{} grew beyond its public input bound",
            spec.name
        );
        opening = opening.or_else(|| {
            buffer[..count]
                .iter()
                .copied()
                .find(|byte| !byte.is_ascii_whitespace())
        });
        hash.update(&buffer[..count]);
    }
    ensure!(
        bytes == metadata.len() && file.metadata()?.len() == bytes && opening == Some(b'{'),
        "{} changed or is not a JSON object",
        spec.name
    );
    // Check syntax in bounded streaming memory; device identities, schemas,
    // lifecycle and artifact relationships remain the actual CLI's decisions.
    file.seek(SeekFrom::Start(0))?;
    let mut json = serde_json::Deserializer::from_reader((&mut file).take(spec.maximum_bytes + 1));
    IgnoredAny::deserialize(&mut json).with_context(|| format!("parse {}", spec.name))?;
    json.end()
        .with_context(|| format!("finish {}", spec.name))?;
    Ok((
        file,
        ArtifactPin {
            relative_path: spec.name,
            sha256_option: spec.flag,
            bytes,
            sha256: hex::encode(hash.finalize()),
        },
    ))
}

fn quote_powershell(argument: &str) -> String {
    // PowerShell treats these typographic quotes as delimiters too. Double
    // each original character so tokenization preserves the literal path.
    let mut quoted = String::with_capacity(argument.len() + 2);
    quoted.push('\'');
    for character in argument.chars() {
        quoted.push(character);
        if matches!(character, '\'' | '\u{2018}'..='\u{201b}') {
            quoted.push(character);
        }
    }
    quoted.push('\'');
    quoted
}

fn prepare(run: &Path, destination: &Path, executable: &str) -> Result<PreparedCommand> {
    let run_text = local_absolute(run)?;
    let destination_text = local_absolute(destination)?;
    ensure!(
        !executable.is_empty()
            && executable.len() <= 512
            && !executable.chars().any(char::is_control),
        "bounded executable name/path required"
    );
    ordinary_ancestors(run, false)?;
    match fs::symlink_metadata(destination) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).context("read future state output"),
        Ok(_) => anyhow::bail!("state output already exists; choose a fresh directory"),
    }
    ordinary_ancestors(
        destination.parent().context("state output parent absent")?,
        true,
    )?;
    let separator = std::path::MAIN_SEPARATOR;
    let run_lower = run_text.trim_end_matches(separator).to_lowercase();
    let destination_lower = destination_text.trim_end_matches(separator).to_lowercase();
    ensure!(
        destination_lower != run_lower
            && !destination_lower.starts_with(&(run_lower + &separator.to_string())),
        "state output must be outside the preserved conversion run"
    );
    let mut files = Vec::new();
    let mut pins = Vec::new();
    for spec in &ARTIFACTS {
        let path = run.join(spec.name);
        match fs::symlink_metadata(&path) {
            Ok(_) => {
                let (file, pin) = pin_artifact(&path, spec)?;
                files.push(file);
                pins.push(pin);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound && !spec.mandatory => {}
            Err(error) => return Err(error).with_context(|| format!("read {}", spec.name)),
        }
    }
    // Do not hide artifacts which appeared/disappeared while pins were read.
    for spec in &ARTIFACTS {
        let present = match fs::symlink_metadata(run.join(spec.name)) {
            Ok(_) => true,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
            Err(error) => return Err(error).context("recheck artifact presence"),
        };
        ensure!(
            present == pins.iter().any(|pin| pin.relative_path == spec.name),
            "run artifacts changed; inspect the existing operation before preparing again"
        );
    }
    let mut arguments = vec![
        "operation-state".into(),
        "--run-directory".into(),
        run_text.into(),
    ];
    for pin in &pins {
        arguments.extend([pin.sha256_option.into(), pin.sha256.clone()]);
    }
    arguments.extend(["--output".into(), destination_text.into()]);
    let command = std::iter::once(executable)
        .chain(arguments.iter().map(String::as_str))
        .map(quote_powershell)
        .collect::<Vec<_>>()
        .join(" ");
    Ok(PreparedCommand {
        schema_version: 1,
        kind: "read-only-operation-state-command-preparation",
        executable: executable.into(),
        arguments,
        powershell_command: format!("& {command}"),
        artifacts: pins,
        command_executed: false,
        lifecycle_inferred: false,
        mutation_authorized: false,
        executable_identity_verified: false,
        artifact_schema_validated: false,
        artifacts_immutable_after_return: false,
    })
}

fn run(cli: Cli) -> Result<()> {
    ensure!(
        cfg!(windows),
        "the public operation-state workflow requires Windows"
    );
    #[cfg(windows)]
    {
        let system_root = std::env::var("SystemRoot").context("Windows SystemRoot unavailable")?;
        for path in [&cli.run_directory, &cli.state_output] {
            let text = local_absolute(path)?;
            ensure!(
                text.get(..3)
                    .zip(system_root.get(..3))
                    .is_some_and(|(a, b)| a.eq_ignore_ascii_case(b)),
                "public run/state output must be on the Windows OS volume"
            );
        }
    }
    let report = prepare(&cli.run_directory, &cli.state_output, &cli.executable)?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error:#}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (tempfile::TempDir, PathBuf, PathBuf) {
        let temp = tempfile::tempdir().unwrap();
        let run = temp.path().join("run's evidence");
        fs::create_dir(&run).unwrap();
        fs::write(
            run.join("conversion-intent.json"),
            b"{\"schema_version\":1}",
        )
        .unwrap();
        let output = temp.path().join("fresh status");
        (temp, run, output)
    }
    #[test]
    fn prepares_only_state_without_creating_output_or_changing_evidence() {
        let (_temp, run, output) = fixture();
        let before = fs::read(run.join("conversion-intent.json")).unwrap();
        let report = prepare(&run, &output, "ntfs2refs").unwrap();
        assert_eq!(report.arguments[0], "operation-state");
        assert_eq!(report.artifacts.len(), 1);
        assert_eq!(
            report.artifacts[0].sha256,
            hex::encode(Sha256::digest(&before))
        );
        assert!(report.powershell_command.contains("run''s evidence"));
        assert!(
            !report.command_executed && !report.lifecycle_inferred && !report.mutation_authorized
        );
        assert!(!output.exists());
        assert_eq!(
            fs::read(run.join("conversion-intent.json")).unwrap(),
            before
        );
    }
    #[test]
    fn includes_each_present_optional_artifact_with_its_own_pin() {
        let (_temp, run, output) = fixture();
        fs::create_dir(run.join("qualification")).unwrap();
        for (index, spec) in ARTIFACTS.iter().enumerate().skip(1) {
            fs::write(run.join(spec.name), format!("{{\"fixture\":{index}}}")).unwrap();
        }
        let report = prepare(&run, &output, "reviewed executable.exe").unwrap();
        assert_eq!(report.artifacts.len(), 5);
        for pin in &report.artifacts {
            assert!(
                report
                    .arguments
                    .windows(2)
                    .any(|pair| pair == [pin.sha256_option, &pin.sha256])
            );
            assert_eq!(
                pin.sha256,
                hex::encode(Sha256::digest(
                    fs::read(run.join(pin.relative_path)).unwrap()
                ))
            );
        }
    }
    #[test]
    fn missing_malformed_oversized_or_nonordinary_artifacts_refuse() {
        for bytes in [
            Vec::new(),
            b"[]".to_vec(),
            b"{broken".to_vec(),
            vec![b' '; 16385],
        ] {
            let (_temp, run, output) = fixture();
            fs::write(run.join("conversion-intent.json"), bytes).unwrap();
            assert!(prepare(&run, &output, "ntfs2refs").is_err());
            assert!(!output.exists());
        }
        let (_temp, run, output) = fixture();
        fs::remove_file(run.join("conversion-intent.json")).unwrap();
        assert!(prepare(&run, &output, "ntfs2refs").is_err());
        fs::create_dir(run.join("conversion-intent.json")).unwrap();
        assert!(prepare(&run, &output, "ntfs2refs").is_err());
    }
    #[test]
    fn refuses_existing_or_nested_output_and_control_arguments() {
        let (_temp, run, output) = fixture();
        assert!(prepare(&run, &run.join("state"), "ntfs2refs").is_err());
        fs::create_dir(&output).unwrap();
        assert!(prepare(&run, &output, "ntfs2refs").is_err());
        assert!(prepare(&run, &output.with_file_name("other"), "ntfs2refs\nanything").is_err());
        assert_eq!(
            quote_powershell("x'; $(anything)`y"),
            "'x''; $(anything)`y'"
        );
    }
    #[cfg(windows)]
    #[test]
    fn refuses_device_unc_relative_and_stream_paths_before_open() {
        for path in [
            r"\\.\PhysicalDrive0",
            r"\\?\C:\run",
            r"\\server\run",
            r"C:run",
            r"C:\run:stream",
            r"C:\run\..\other",
        ] {
            assert!(local_absolute(Path::new(path)).is_err(), "{path}");
        }
    }
    #[test]
    fn trailing_run_separator_does_not_hide_descendant_output() {
        let (_temp, run, _output) = fixture();
        let trailing = PathBuf::from(format!("{}{}", run.display(), std::path::MAIN_SEPARATOR));
        assert!(prepare(&trailing, &run.join("state"), "ntfs2refs").is_err());
    }
    #[cfg(windows)]
    #[test]
    fn powershell_parser_preserves_all_quote_delimiters_as_literal_arguments() {
        use std::{
            io::Write,
            os::windows::process::CommandExt,
            process::{Command, Stdio},
        };
        let temp = tempfile::tempdir().unwrap();
        let run = temp.path().join("‘left’ ‚low‛ and's evidence");
        fs::create_dir(&run).unwrap();
        fs::write(run.join("conversion-intent.json"), b"{}").unwrap();
        let output = temp.path().join("status ‘left’ ‚low‛ and's output");
        let executable = temp
            .path()
            .join("ntfs2refs ‘left’ ‚low‛ and's $(not-run).exe");
        let executable = executable.to_str().unwrap();
        let prepared = prepare(&run, &output, executable).unwrap();
        // Parse only. The generated command and its executable never run.
        const PARSER: &str = r#"
$ErrorActionPreference='Stop'
[Console]::InputEncoding=[Text.UTF8Encoding]::new($false)
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseInput([Console]::In.ReadToEnd(),[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Generated command has parser errors.'}
$commands=@($ast.FindAll({param($n)$n-is[Management.Automation.Language.CommandAst]},$true))
if($commands.Count-ne1-or$commands[0].InvocationOperator-ne[Management.Automation.Language.TokenKind]::Ampersand){throw 'One literal command required.'}
$values=@()
foreach($element in $commands[0].CommandElements){
 if($element-isnot[Management.Automation.Language.StringConstantExpressionAst]-or$element.StringConstantType.ToString()-cne'SingleQuoted'){throw 'Single-quoted literal required.'}
 $values+=[string]$element.Value
}
ConvertTo-Json -InputObject $values -Compress
"#;
        let powershell = PathBuf::from(std::env::var_os("SystemRoot").unwrap())
            .join(r"System32\WindowsPowerShell\v1.0\powershell.exe");
        let mut child = Command::new(powershell)
            .args(["-NoProfile", "-NonInteractive", "-Command", PARSER])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .creation_flags(0x0800_0000)
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(prepared.powershell_command.as_bytes())
            .unwrap();
        let result = child.wait_with_output().unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        let actual: Vec<String> = serde_json::from_slice(&result.stdout).unwrap();
        let expected: Vec<String> = std::iter::once(executable.to_owned())
            .chain(prepared.arguments)
            .collect();
        assert_eq!(actual, expected);
        assert!(!output.exists());
    }
}
