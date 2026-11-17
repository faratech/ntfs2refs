//! Recovery for an already activated conversion on the machine owning its disks.
use crate::{
    general_qualification as artifacts, general_reconstruct as protocol,
    lab_reconstruct::JournalTicket,
};
use anyhow::{Context, Result, ensure};
use n2r_win32::{
    GeneralFrozenPartition, GeneralJournaledPartition, NativeEvent,
    journal_file::observe_general_journal_file_with_profile,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    os::windows::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

mod allocation;
pub(crate) use allocation::recover_allocation_redundant_for_lab;
pub use allocation::{AllocationRecoveryOutcome, preview_allocation, recover_allocation};
mod compact;
pub use compact::{
    ExperimentalCompactInputs, ExperimentalCompactOperation, recover_compact_experimental,
};

fn canonical_pin(pin: &str) -> bool {
    pin.len() == 64
        && pin
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
fn save_bytes(root: &Path, name: &str, bytes: &[u8]) -> Result<()> {
    ensure!(
        bytes.len() <= 16 * 1024 * 1024,
        "recovery input copy exceeds bound"
    );
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .share_mode(0)
        .custom_flags(0x0020_0000)
        .open(root.join(name))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}
