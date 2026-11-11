//! Explicit lab-only bounded console wait. Only Continue input is accepted;
//! this module has no source/J writer, control API, power or suspend operation.
use super::PreparedOfflineBootRequest;
use anyhow::{Context, Result, ensure};
use n2r_win32::{
    journal_file::{GeneralJournalStorageBinding, JournalFileIdentity},
    partition_isolation::PartitionSourceBinding,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    os::windows::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
    sync::mpsc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
const WAIT_MS: u64 = 120_000;
const MAX_LINE: usize = 96;
const MAX_RECORD: u64 = 64 * 1024;
#[derive(Serialize)]
pub(crate) struct PreparedPostFlushReceipt<'a> {
    pub(crate) kind: &'static str,
    pub(crate) actual_pid: u32,
    pub(crate) actual_process_creation_100ns: u64,
    pub(crate) actual_boot_identifier: &'a [u8],
    pub(crate) source: &'a PartitionSourceBinding,
    pub(crate) outer_bundle_sha256: [u8; 32],
    pub(crate) immutable_journal_sha256: [u8; 32],
    pub(crate) index_sha256: [u8; 32],
    pub(crate) journal_binding: &'a GeneralJournalStorageBinding,
    pub(crate) journal_identity: &'a JournalFileIdentity,
    pub(crate) image_bytes: u64,
    pub(crate) selected_bytes: u64,
    pub(crate) range_count: u32,
    pub(crate) native_bytes_written: u64,
    pub(crate) native_write_bytes_requested: u64,
    pub(crate) delayed_discovery_bytes: u64,
    pub(crate) flush_and_pending_readback_succeeded: bool,
    pub(crate) native_writer_revalidation_succeeded: bool,
    pub(crate) discovery_write_not_requested: bool,
    pub(crate) first_write_qualified: bool,
}
pub(crate) fn require_nonce(nonce: &str) -> Result<()> {
    ensure!(
        nonce.len() == 64
            && nonce
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "controlled pause requires canonical64-hex nonce"
    );
    Ok(())
}
fn continue_line(nonce: &str) -> std::result::Result<(), String> {
    let expected = format!("N2R-CONTINUE {nonce}");
    let lf = format!("{expected}\n");
    let crlf = format!("{expected}\r\n");
    let stdin = io::stdin();
    let mut input = stdin.lock();
    let mut bytes = [0u8; MAX_LINE];
    for at in 0..MAX_LINE {
        input
            .read_exact(&mut bytes[at..at + 1])
            .map_err(|e| format!("controlled console input:{e}"))?;
        if bytes[at] == b'\n' {
            return if &bytes[..=at] == lf.as_bytes() || &bytes[..=at] == crlf.as_bytes() {
                Ok(())
            } else {
                Err("Continue nonce/protocol differs".into())
            };
        }
    }
    Err("Continue line exceeds96 bytes".into())
}
fn persist(
    path: &Path,
    value: &impl Serialize,
    journal: &GeneralJournalStorageBinding,
    identity: &JournalFileIdentity,
) -> Result<()> {
    let bytes = serde_json::to_vec(value)?;
    ensure!(
        bytes.len() as u64 <= MAX_RECORD,
        "pause record exceeds prepaid evidence bound"
    );
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .share_mode(1)
        .custom_flags(0x0020_0000)
        .create_new(true)
        .open(path)?;
    let before =
        n2r_win32::reference_file::observe_reference_file_handle_with_limit(&file, MAX_RECORD)?;
    let prefix = format!("{}\\", journal.disk.volume_path()?);
    ensure!(
        before.file_bytes == 0
            && before.number_of_links == 1
            && before.volume_serial_number == identity.volume_serial_number
            && before
                .final_path
                .get(..prefix.len())
                .is_some_and(|s| s.eq_ignore_ascii_case(&prefix)),
        "pause evidence is not actual admitted J"
    );
    file.write_all(&bytes)?;
    file.sync_all()?;
    file.seek(SeekFrom::Start(0))?;
    let mut readback = vec![0; bytes.len()];
    file.read_exact(&mut readback)?;
    let mut eof = [0];
    ensure!(
        file.read(&mut eof)? == 0 && readback == bytes,
        "pause evidence flush/readback/EOF failed"
    );
    let after =
        n2r_win32::reference_file::observe_reference_file_handle_with_limit(&file, MAX_RECORD)?;
    ensure!(
        after.file_id_128 == before.file_id_128
            && after.volume_serial_number == before.volume_serial_number
            && after.final_path == before.final_path
            && after.number_of_links == 1
            && after.file_bytes == bytes.len() as u64,
        "pause evidence same-file identity changed"
    );
    Ok(())
}
pub(crate) fn wait(
    request: &PreparedOfflineBootRequest,
    actual: &PreparedPostFlushReceipt<'_>,
) -> Result<()> {
    let Some(nonce) = &request.postflush_pause_nonce else {
        return Ok(());
    };
    require_nonce(nonce)?;
    ensure!(
        actual.actual_pid == std::process::id()
            && actual.actual_process_creation_100ns > 0
            && actual.native_bytes_written > 0
            && actual.delayed_discovery_bytes == 4096
            && actual.flush_and_pending_readback_succeeded
            && actual.native_writer_revalidation_succeeded
            && actual.discovery_write_not_requested
            && !actual.first_write_qualified,
        "actual positive non-discovery postflush proof required"
    );
    let parent = request
        .output
        .parent()
        .context("boot proof parent absent")?;
    let directory = parent.join("postflush-pause");
    ensure!(
        !directory.exists(),
        "fresh controlled pause evidence required"
    );
    let metadata = fs::symlink_metadata(parent)?;
    ensure!(
        metadata.is_dir() && metadata.file_attributes() & 0x400 == 0,
        "ordinary admitted pause parent required"
    );
    fs::create_dir(&directory)?;
    let _directory_guard = OpenOptions::new()
        .access_mode(0x0010_0080)
        .share_mode(1)
        .custom_flags(0x0220_0000)
        .open(&directory)?;
    let began = Instant::now();
    let started: u64 = SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_millis()
        .try_into()?;
    let deadline = started
        .checked_add(WAIT_MS)
        .context("pause deadline overflow")?;
    let (send, receive) = mpsc::sync_channel(1);
    let nonce_input = nonce.clone();
    let reader = std::thread::Builder::new()
        .name("prepared-console-Continue".into())
        .stack_size(256 * 1024)
        .spawn(move || {
            let _ = send.send(continue_line(&nonce_input));
        })
        .context("admitted console reader creation")?;
    // Detached reader has stdin/string only; watchdog never waits for join.
    drop(reader);
    let ready = serde_json::json!({"kind":"offline-prepared-controlled-postflush-ready-v1","nonce":nonce,"actual_postflush":actual,
        "maximum_wait_ms":WAIT_MS,"started_unix_ms":started,"deadline_unix_ms":deadline,
        "continue_protocol":"N2R-CONTINUE <exact64hexnonce> LF or CRLF","source_or_recovery_authority_from_input":false,
        "first_write_qualified":false,"physical_power_loss_qualified":false});
    persist(
        &directory.join("ready.json"),
        &ready,
        actual.journal_binding,
        actual.journal_identity,
    )?;
    let limit = Duration::from_millis(WAIT_MS);
    ensure!(
        began.elapsed() < limit,
        "pause receipt completed after original watchdog deadline"
    );
    println!("N2R POSTFLUSH PAUSED");
    println!("NONCE={nonce}");
    println!(
        "PID={} birth={} bytes={} BEFORE-VBR deadline={deadline}",
        actual.actual_pid, actual.actual_process_creation_100ns, actual.native_bytes_written
    );
    println!(
        "N2R BUNDLE={} J={}",
        hex::encode(actual.outer_bundle_sha256),
        hex::encode(actual.immutable_journal_sha256)
    );
    io::stdout().flush()?;
    let mut refusal = None;
    let outcome = match receive.recv_timeout(limit.saturating_sub(began.elapsed())) {
        Ok(Ok(())) => "nonce-bound-Continue",
        Ok(Err(error)) => {
            refusal = Some(error);
            std::thread::sleep(limit.saturating_sub(began.elapsed()));
            "watchdog-after-refused-input"
        }
        Err(mpsc::RecvTimeoutError::Timeout) => "watchdog-timeout",
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            refusal = Some("bounded Continue reader disconnected".into());
            std::thread::sleep(limit.saturating_sub(began.elapsed()));
            "watchdog-after-input-disconnected"
        }
    };
    let released = serde_json::json!({"kind":"offline-prepared-controlled-postflush-released-v1","nonce":nonce,"pid":actual.actual_pid,
        "reason":outcome,"actual_input_error":refusal,"elapsed_ms":began.elapsed().as_millis(),"deadline_unix_ms":deadline,"discovery_write_not_requested":true,
        "source_or_recovery_authority_from_input":false,"ready_sha256":hex::encode(Sha256::digest(serde_json::to_vec(&ready)?))});
    persist(
        &directory.join("released.json"),
        &released,
        actual.journal_binding,
        actual.journal_identity,
    )?;
    println!("N2R POSTFLUSH RELEASED nonce={nonce} reason={outcome}");
    io::stdout().flush()?;
    Ok(())
}
