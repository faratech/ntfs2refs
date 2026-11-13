//! `lab/RETIRED.md` lists the lab scripts that can no longer run, because the
//! virtual machine or checkpoint each was written for is gone. This keeps the
//! list true: a script that names a retired VM is listed there, as retired or
//! as one of the stated exceptions, and every listed script exists.
use std::{collections::BTreeSet, fs, path::PathBuf};

fn lab() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("lab")
}

/// The spans a line puts in backticks.
fn named(line: &str) -> Vec<&str> {
    line.split('`').skip(1).step_by(2).collect()
}

struct Manifest {
    /// Ids and names of retired VMs, lower case.
    retired_vms: Vec<String>,
    retired: BTreeSet<String>,
    exceptions: BTreeSet<String>,
}

fn manifest() -> Manifest {
    let text = fs::read_to_string(lab().join("RETIRED.md")).expect("lab/RETIRED.md");
    let mut manifest = Manifest {
        retired_vms: Vec::new(),
        retired: BTreeSet::new(),
        exceptions: BTreeSet::new(),
    };
    let mut section = "";
    for line in text.lines() {
        if let Some(title) = line.strip_prefix("## ") {
            section = title;
            continue;
        }
        let names = named(line);
        match section {
            "Retired virtual machines"
                if line.starts_with("| `") || line.starts_with("Retired VM names") =>
            {
                manifest
                    .retired_vms
                    .extend(names.iter().map(|name| name.to_lowercase()));
            }
            "Retired scripts" if line.starts_with("- `") => {
                manifest.retired.insert(names[0].to_owned());
            }
            "Not retired, though they name a retired VM" if line.starts_with("- `") => {
                manifest.exceptions.insert(names[0].to_owned());
            }
            _ => (),
        }
    }
    manifest
}

/// Every script in `lab/`, with its text in lower case.
fn scripts() -> Vec<(String, String)> {
    let mut scripts = Vec::new();
    for entry in fs::read_dir(lab()).expect("lab/") {
        let path = entry.expect("lab/ entry").path();
        let is_script = path
            .extension()
            .and_then(|extension| extension.to_str())
            .is_some_and(|extension| {
                extension.eq_ignore_ascii_case("ps1") || extension.eq_ignore_ascii_case("psm1")
            });
        if is_script {
            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .expect("script name")
                .to_owned();
            let text = String::from_utf8_lossy(&fs::read(&path).expect("script")).to_lowercase();
            scripts.push((name, text));
        }
    }
    scripts
}

#[test]
fn the_manifest_names_the_retired_vms_and_only_scripts_that_exist() {
    let manifest = manifest();
    // Four retired VM ids, and at least the names three of them went by.
    let ids = manifest
        .retired_vms
        .iter()
        .filter(|vm| vm.len() == 36 && vm.matches('-').count() == 4)
        .count();
    assert!(ids >= 4, "retired VM ids listed: {ids}");
    assert!(manifest.retired_vms.len() >= ids + 3);
    assert!(!manifest.retired.is_empty());
    assert!(manifest.retired.is_disjoint(&manifest.exceptions));
    let present: BTreeSet<String> = scripts().into_iter().map(|(name, _)| name).collect();
    for listed in manifest.retired.iter().chain(&manifest.exceptions) {
        assert!(
            present.contains(listed),
            "lab/RETIRED.md lists {listed}, which is not in lab/"
        );
    }
}

#[test]
fn a_script_that_names_a_retired_vm_is_listed() {
    let manifest = manifest();
    for (name, text) in scripts() {
        let named: Vec<&String> = manifest
            .retired_vms
            .iter()
            .filter(|vm| text.contains(vm.as_str()))
            .collect();
        assert!(
            named.is_empty()
                || manifest.retired.contains(&name)
                || manifest.exceptions.contains(&name),
            "lab/{name} names a retired VM ({named:?}) and is not listed in lab/RETIRED.md: \
             a script for a VM that no longer exists cannot run; list it, or write it for \
             the current harness"
        );
    }
}
