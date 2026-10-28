//! Explicit allocation-only namespace template. Source JSON is diagnostic
//! input, not admission; this command cannot write or convert the source.
#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    use anyhow::{Result, ensure};
    use clap::Parser;
    use ntfs2refs::{general_shadow, ntfs_admission::ResourceProfile, shadow_tree};
    use sha2::{Digest, Sha256};
    use std::{
        fs::{File, OpenOptions},
        io::{Read, Write},
        path::{Path, PathBuf},
    };

    #[derive(Parser)]
    struct Args {
        #[arg(long)]
        request: PathBuf,
        #[arg(long)]
        request_sha256: String,
        #[arg(long)]
        tree: PathBuf,
        #[arg(long)]
        tree_sha256: String,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        observe_existing: bool,
    }
    fn evidence(path: &Path) -> Result<Vec<u8>> {
        let file = File::open(path)?;
        ensure!(
            file.metadata()?.is_file(),
            "ordinary evidence file required"
        );
        let mut bytes = vec![];
        file.take(16 * 1024 * 1024 + 1).read_to_end(&mut bytes)?;
        ensure!(bytes.len() <= 16 * 1024 * 1024, "evidence budget exceeded");
        Ok(bytes)
    }
    fn save(path: &Path, value: &serde_json::Value) -> Result<()> {
        let bytes = serde_json::to_vec_pretty(value)?;
        ensure!(
            bytes.len() <= 64 * 1024 * 1024,
            "private tree report exceeds bound"
        );
        let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        Ok(())
    }
    let args = Args::parse();
    ensure!(!args.output.exists(), "fresh report required");
    let request_bytes = evidence(&args.request)?;
    let tree_bytes = evidence(&args.tree)?;
    ensure!(
        hex::encode(Sha256::digest(&request_bytes)) == args.request_sha256
            && hex::encode(Sha256::digest(&tree_bytes)) == args.tree_sha256,
        "input pins differ"
    );
    let request: general_shadow::Request = serde_json::from_slice(&request_bytes)?;
    let resources = ResourceProfile::ExperimentalStreamingTreeV2;
    request.validate_with_resource_profile(resources)?;
    let expected: shadow_tree::ExpectedTree = serde_json::from_slice(&tree_bytes)?;
    expected.validate_with_resource_profile(resources)?;
    let tree = shadow_tree::Tree {
        profile: resources.ordinary_shadow_profile(),
        objects: expected.objects,
        logical_bytes: expected.logical_bytes,
        internal_replacement_pending: expected.internal_replacement_pending,
    };
    save(
        &args.output.with_extension("intent.json"),
        &serde_json::json!({
        "kind":if args.observe_existing {"private-tree-observation-intent"}else{"private-tree-allocation-intent"},
        "observe_existing":args.observe_existing,"allocation_writes_authorized":!args.observe_existing,
        "request_sha256":args.request_sha256,
        "tree_sha256":args.tree_sha256,"source_writes_authorized":false,
        "source_image_hash_reverified":false,"source_admitted":false,"conversion_qualified":false}),
    )?;
    let attempt = if args.observe_existing {
        n2r_win32::shadow_native::private_tree::observe_existing(
            &request.pair,
            &general_shadow::native_inputs(&tree),
        )
        .map_err(anyhow::Error::from)
    } else {
        general_shadow::allocate_private_tree(&request.pair, &tree)
            .and_then(|template| Ok(template.report()?))
    };
    let failure = attempt.as_ref().err().map(ToString::to_string);
    let native = match attempt {
        Ok(value) => value,
        Err(error) => {
            serde_json::json!({"kind":"private-tree-allocation-failure","error":error.to_string()})
        }
    };
    save(
        &args.output,
        &serde_json::json!({"schema_version":1,"kind":"private-tree-allocation",
        "success":failure.is_none(),"observe_existing":args.observe_existing,
        "request_sha256":args.request_sha256,"tree_sha256":args.tree_sha256,
        "request":request,"native":native,"source_image_hash_reverified":false,
        "source_admitted":false,"conversion_qualified":false}),
    )?;
    if let Some(error) = failure {
        anyhow::bail!("private allocation failed: {error}");
    }
    println!(
        "Private tree staging/observation complete; payload supply and metadata restoration remain pending."
    );
    Ok(())
}

#[cfg(not(windows))]
fn main() {
    eprintln!("private tree allocation requires Windows");
    std::process::exit(1);
}
