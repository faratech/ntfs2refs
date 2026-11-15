//! The scripts of the retired lab stages left the tree (`lab/RETIRED.md` says
//! where they are). This keeps one from coming back unnoticed: a script in
//! `lab/` that names a retired virtual machine cannot run, so it has to be one
//! of the exceptions `lab/RETIRED.md` states, and every exception exists.
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
    exceptions: BTreeSet<String>,
}

fn manifest() -> Manifest {
    let text = fs::read_to_string(lab().join("RETIRED.md")).expect("lab/RETIRED.md");
    let mut manifest = Manifest {
        retired_vms: Vec::new(),
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
            "Not retired, though they name a retired VM" if line.starts_with("- `") => {
                manifest.exceptions.insert(names[0].to_owned());
            }
            _ => (),
        }
    }
    manifest
}

/// Every script in `lab/` and `lab/guest/`, with its text in lower case.
fn scripts() -> Vec<(String, String)> {
    let mut scripts = Vec::new();
    for directory in [lab(), lab().join("guest")] {
        for entry in fs::read_dir(&directory).expect("lab directory") {
            let path = entry.expect("lab entry").path();
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
                let text =
                    String::from_utf8_lossy(&fs::read(&path).expect("script")).to_lowercase();
                scripts.push((name, text));
            }
        }
    }
    scripts
}

#[test]
fn the_manifest_names_the_retired_vms_and_only_exceptions_that_exist() {
    let manifest = manifest();
    // Four retired VM ids, and at least the names three of them went by.
    let ids = manifest
        .retired_vms
        .iter()
        .filter(|vm| vm.len() == 36 && vm.matches('-').count() == 4)
        .count();
    assert!(ids >= 4, "retired VM ids listed: {ids}");
    assert!(manifest.retired_vms.len() >= ids + 3);
    let present: BTreeSet<String> = scripts().into_iter().map(|(name, _)| name).collect();
    for listed in &manifest.exceptions {
        assert!(
            present.contains(listed),
            "lab/RETIRED.md lists {listed}, which is not in lab/"
        );
    }
}

#[test]
fn no_script_names_a_retired_vm_unless_it_is_a_stated_exception() {
    let manifest = manifest();
    for (name, text) in scripts() {
        let named: Vec<&String> = manifest
            .retired_vms
            .iter()
            .filter(|vm| text.contains(vm.as_str()))
            .collect();
        assert!(
            named.is_empty() || manifest.exceptions.contains(&name),
            "lab/{name} names a retired VM ({named:?}): a script for a VM that no longer \
             exists cannot run. Write it for the current harness, or state in \
             lab/RETIRED.md why it names that VM"
        );
    }
}
