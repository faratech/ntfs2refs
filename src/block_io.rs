//! Read-only raw image access. Never opens a source for writing.
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Seek, SeekFrom},
    path::{Path, PathBuf},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceIdentity {
    pub path: PathBuf,
    pub length: u64,
    pub sha256: String,
}

pub fn open_image(path: &Path) -> Result<File> {
    ensure!(path.is_file(), "input must be a regular raw image file");
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.share_mode(1);
    }
    let mut file = options.open(path)?;
    let length = file.metadata()?.len();
    ensure!(length >= 512, "image is shorter than a boot sector");
    let mut magic = [0; 8];
    file.read_exact(&mut magic)?;
    ensure!(
        &magic != b"vhdxfile" && &magic != b"conectix",
        "VHD/VHDX is a container, not a raw partition image"
    );
    file.seek(SeekFrom::End(-512))?;
    file.read_exact(&mut magic)?;
    ensure!(
        &magic != b"conectix",
        "VHD is a container, not a raw partition image"
    );
    file.seek(SeekFrom::Start(0))?;
    Ok(file)
}

pub fn identity(file: &mut File, path: &Path) -> Result<SourceIdentity> {
    let position = file.stream_position()?;
    let length = file.metadata()?.len();
    file.seek(SeekFrom::Start(0))?;
    let mut hash = Sha256::new();
    let mut buffer = vec![0; 1024 * 1024];
    let mut count = 0u64;
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hash.update(&buffer[..n]);
        count += n as u64;
    }
    ensure!(
        length == count && length == file.metadata()?.len(),
        "image length changed during hashing"
    );
    file.seek(SeekFrom::Start(position))?;
    Ok(SourceIdentity {
        path: path.canonicalize()?,
        length,
        sha256: hex::encode(hash.finalize()),
    })
}
