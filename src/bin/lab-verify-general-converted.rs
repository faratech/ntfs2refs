//! Repeatable native ReFS verification after the original data disk has
//! crossed journal handoff. No journal replay or raw partition write exists.
#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    use anyhow::{Result, ensure};
    use clap::Parser;
    use n2r_win32::{mounted_filesystem_general, rediscover_general_volume, shadow_native};
    use ntfs2refs::{general_reconstruct, ntfs_attestation, shadow_tree};
    use serde::Serialize;
    use sha2::{Digest, Sha256};
    use std::{
        fs::{self, OpenOptions},
        io::{Read, Write},
        os::windows::fs::{MetadataExt, OpenOptionsExt},
        path::PathBuf,
    };

    #[derive(Parser)]
    struct Args {
        #[arg(long)]
        request: PathBuf,
        #[arg(long)]
        request_sha256: String,
        #[arg(long)]
        expectation: PathBuf,
        #[arg(long)]
        expectation_sha256: String,
        #[arg(long)]
        output: PathBuf,
    }
    fn pinned(path: &PathBuf, expected: &str, max: u64) -> Result<Vec<u8>> {
        let metadata = fs::symlink_metadata(path)?;
        ensure!(
            metadata.is_file() && metadata.file_attributes() & 0x400 == 0 && metadata.len() <= max,
            "verification input is not an ordinary bounded file"
        );
        let mut file = OpenOptions::new().read(true).share_mode(1).open(path)?;
        let mut bytes = Vec::new();
        (&mut file).take(max + 1).read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() as u64 <= max
                && expected.len() == 64
                && hex::encode(Sha256::digest(&bytes)) == expected,
            "verification input pin differs"
        );
        Ok(bytes)
    }
    fn save(path: &PathBuf, value: &impl Serialize) -> Result<()> {
        let bytes = serde_json::to_vec_pretty(value)?;
        ensure!(
            bytes.len() <= 16 * 1024 * 1024,
            "verification report exceeds bound"
        );
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .share_mode(0)
            .open(path)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        Ok(())
    }
    let args = Args::parse();
    ensure!(!args.output.exists(), "fresh verification output required");
    let request: general_reconstruct::Request =
        serde_json::from_slice(&pinned(&args.request, &args.request_sha256, 131072)?)?;
    request.validate()?;
    let expected_bytes = pinned(
        &args.expectation,
        &args.expectation_sha256,
        16 * 1024 * 1024,
    )?;
    ensure!(
        args.expectation_sha256 == request.expected_tree_sha256,
        "post-handoff expected tree differs from request"
    );
    let expected: shadow_tree::ExpectedTree = serde_json::from_slice(&expected_bytes)?;
    expected.validate()?;
    let mut events = Vec::new();
    let mut pair = request.pair.clone();
    pair.source = rediscover_general_volume(pair.source, &mut events)?;
    let filesystem = mounted_filesystem_general(pair.source.clone(), &mut events)?;
    let input: Vec<_> = expected
        .objects
        .iter()
        .map(|object| shadow_native::Input {
            components: &object.path,
            directory: object.directory,
            times: object.stored_times,
            attributes: object.attributes,
            security: &object.security,
            payload: &[],
            expected_length: if object.directory {
                None
            } else {
                Some(object.length)
            },
            expected_sha256: if object.directory {
                None
            } else {
                object.sha256.as_deref()
            },
            source_offset: object.source_offset,
        })
        .collect();
    let same_security = |a: &[u8], b: &[u8]| {
        ntfs_attestation::same_security(a, b)
            .map_err(|error| std::io::Error::other(error.to_string()))
    };
    let attempted = if filesystem == "ReFS" {
        shadow_native::verify_general_converted_ordinary(pair, &input, same_security)
    } else {
        Err(std::io::Error::other(
            "original data disk is not mounted as ReFS",
        ))
    };
    let success = attempted.is_ok();
    let error = attempted.as_ref().err().map(ToString::to_string);
    save(
        &args.output,
        &serde_json::json!({"schema_version":1,"kind":"general-post-handoff-refs-verification",
            "request_sha256":args.request_sha256,"expected_tree_sha256":args.expectation_sha256,
            "filesystem":filesystem,"native":attempted.ok(),"error":error,
            "events":events,"source_payload_writes":0,
            "ordinary_tree_verified":success,"production_conversion_qualified":false}),
    )?;
    ensure!(
        success,
        "post-handoff ReFS verification refused; report saved"
    );
    Ok(())
}

#[cfg(not(windows))]
fn main() {
    eprintln!("post-handoff verification requires Windows on the owning machine");
    std::process::exit(1);
}
