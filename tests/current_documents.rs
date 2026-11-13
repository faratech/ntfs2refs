//! The documents that describe the tool as it is: the README, the guide, the
//! two matrices, the lab guide and AGENTS.md. Everything else under `docs/`
//! is history and says so in `docs/history/README.md`.
//!
//! These checks keep the current ones from pointing at files that are gone
//! and from naming a version other than the one the executable reports.
use std::{fs, path::Path};

const CURRENT: &[&str] = &[
    "README.md",
    "AGENTS.md",
    "docs/cli-workflow.md",
    "docs/feature-matrix.md",
    "docs/recovery-matrix.md",
    "lab/README.md",
    "docs/history/README.md",
];

fn root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

/// The targets of `[text](target)` links that are files of the repository.
fn relative_links(text: &str) -> Vec<String> {
    let mut found = Vec::new();
    let mut rest = text;
    while let Some(at) = rest.find("](") {
        rest = &rest[at + 2..];
        let Some(end) = rest.find(')') else { break };
        let target = rest[..end].split_whitespace().next().unwrap_or("");
        let path = target.split('#').next().unwrap_or("");
        if !path.is_empty() && !path.contains("://") && !path.starts_with("mailto:") {
            found.push(path.to_owned());
        }
        rest = &rest[end..];
    }
    found
}

#[test]
fn every_link_of_a_current_document_leads_to_a_file() {
    for document in CURRENT {
        let path = root().join(document);
        let text = fs::read_to_string(&path).unwrap_or_else(|error| panic!("{document}: {error}"));
        let directory = path.parent().unwrap();
        for link in relative_links(&text) {
            assert!(
                directory.join(&link).exists(),
                "{document} links to {link}, which does not exist"
            );
        }
    }
}

#[test]
fn only_current_documents_and_history_are_under_docs() {
    let mut loose = Vec::new();
    for entry in fs::read_dir(root().join("docs")).unwrap() {
        let entry = entry.unwrap();
        let name = entry.file_name().to_string_lossy().into_owned();
        if entry.file_type().unwrap().is_file()
            && !CURRENT.contains(&format!("docs/{name}").as_str())
        {
            loose.push(name);
        }
    }
    assert!(
        loose.is_empty(),
        "{loose:?}: a document under docs/ is either current (and listed in this test) or belongs in docs/history"
    );
}

#[test]
fn the_readme_and_the_guide_name_the_version_the_executable_reports() {
    let version = env!("CARGO_PKG_VERSION");
    for document in ["README.md", "docs/cli-workflow.md"] {
        let text = fs::read_to_string(root().join(document)).unwrap();
        assert!(
            text.contains(version),
            "{document} does not name version {version}"
        );
        // No other version of the tool is presented as the present one.
        for line in text.lines().filter(|line| line.contains("version 0.")) {
            assert!(line.contains(version), "{document}: {line}");
        }
    }
}

#[test]
fn the_guide_quotes_the_line_a_run_prints_for_a_preparation_that_is_cut_off() {
    // As the source spells it, and as it appears on the screen.
    let in_source = r#"If this run is cut off while it prepares (before any \"To recover:\" line), the volume stays offline and read-only. To get it back as NTFS: ntfs2refs --recover"#;
    let on_screen = in_source.replace("\\\"", "\"");
    let source = fs::read_to_string(root().join("src/resource_preparation.rs")).unwrap();
    assert!(
        source.contains(in_source),
        "the converter no longer prints this line"
    );
    let guide = fs::read_to_string(root().join("docs/cli-workflow.md")).unwrap();
    assert!(
        guide.contains(&on_screen),
        "docs/cli-workflow.md does not quote the line"
    );
}

#[test]
fn the_history_index_lists_every_document_beside_it() {
    let index = fs::read_to_string(root().join("docs/history/README.md")).unwrap();
    for entry in fs::read_dir(root().join("docs/history")).unwrap() {
        let name = entry.unwrap().file_name().to_string_lossy().into_owned();
        if name != "README.md" {
            assert!(
                index.contains(&format!("]({name})")),
                "docs/history/README.md does not list {name}"
            );
        }
    }
}
