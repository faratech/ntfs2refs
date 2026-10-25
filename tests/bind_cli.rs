#![cfg(windows)]

use std::{fs, process::Command};
fn cli(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_ntfs2refs-bind"))
        .args(args)
        .output()
        .unwrap()
}
#[test]
fn binding_help_describes_explicit_roots_and_optional_journal_os_permission() {
    let out = cli(&["--help"]);
    assert!(out.status.success());
    let help = String::from_utf8(out.stdout).unwrap();
    assert!(
        help.contains("--source")
            && help.contains("--shadow")
            && help.contains("--journal-additional-partitions")
    );
}
#[cfg(windows)]
#[test]
fn invalid_experiment_budget_and_root_are_refused_without_creating_request() {
    let dir = tempfile::tempdir().unwrap();
    let output = dir.path().join("devices.json");
    let call = |id: &str, budget: &str, source: &str| {
        cli(&[
            "--source",
            source,
            "--shadow",
            "R:\\",
            "--journal",
            "J:\\",
            "--experiment-id",
            id,
            "--max-journal-bytes",
            budget,
            "--output",
            output.to_str().unwrap(),
        ])
    };
    for (id, budget, source, expected) in [
        ("..", "1024", "F:\\", "experiment identifier"),
        (
            "0123456789abcdef0123456789abcdef",
            "0",
            "F:\\",
            "journal budget",
        ),
        (
            "0123456789abcdef0123456789abcdef",
            "1024",
            "relative",
            "explicit bounded local volume root",
        ),
    ] {
        let result = call(id, budget, source);
        assert!(!result.status.success());
        assert!(
            String::from_utf8_lossy(&result.stderr).contains(expected),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert!(!output.exists());
    }
    assert!(fs::read_dir(dir.path()).unwrap().next().is_none());
}
