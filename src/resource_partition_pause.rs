//! Hidden lab control only: the actual apply callback owns the source while
//! this bounded wait runs. The input command permits Continue, never I/O.
use super::{Observer, save};
use crate::{
    resource_preparation::partition_preparation::PartitionPublicationReceipt,
    selected_journal::resource_domain::prepare::PartitionPostFlushReceipt,
};
use anyhow::{Context, Result, ensure};
use std::{
    io::{self, Read},
    path::Path,
    sync::mpsc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

pub(super) const READER_STACK_BYTES: usize = 256 * 1024;
pub(super) const RAM_RESERVE_BYTES: u64 = 512 * 1024;
pub(super) const EVIDENCE_RESERVE_BYTES: u64 = 1024 * 1024;
const WAIT_MILLISECONDS: u64 = 120_000;
const MAX_COMMAND_BYTES: usize = 96;

pub(super) fn require_nonce(nonce: &str) -> Result<()> {
    ensure!(nonce.len() == 64 && nonce.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "controlled pause requires an independently chosen canonical64-hex nonce");
    Ok(())
}

fn continue_command(expected: &str) -> std::result::Result<(), String> {
    let stdin = io::stdin();
    let mut input = stdin.lock();
    let mut bytes = [0u8; MAX_COMMAND_BYTES];
    for at in 0..MAX_COMMAND_BYTES {
        input.read_exact(&mut bytes[at..at + 1])
            .map_err(|error| format!("controlled Continue input failed: {error}"))?;
        if bytes[at] == b'\n' {
            return if &bytes[..=at] == expected.as_bytes() {
                Ok(())
            } else {
                Err("controlled Continue line did not match the exact nonce/protocol".into())
            };
        }
    }
    Err("controlled Continue line exceeded its96-byte bound".into())
}

/// The launcher retains this process's redirected StandardInput pipe. There
/// is no pathname reopen, source handle, setter, suspend, kill or power call.
pub(super) fn wait(
    observer: &Observer,
    output: &Path,
    nonce: &str,
    published: &PartitionPublicationReceipt,
    flushed: &PartitionPostFlushReceipt,
) -> Result<()> {
    require_nonce(nonce)?;
    let expected = format!("N2R-CONTINUE {nonce}\n");
    let (send, receive) = mpsc::sync_channel(1);
    let reader = std::thread::Builder::new()
        .name("partition-lab-continue".into())
        .stack_size(READER_STACK_BYTES)
        .spawn(move || {
            let _ = send.send(continue_command(&expected));
        })
        .context("creating admitted bounded Continue reader")?;
    // This reader owns no source/J/admission handle. On timeout a blocked
    // stdin read may remain until process exit; it cannot delay the worker.
    drop(reader);
    let began = Instant::now();
    let now: u64 = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis().try_into()?;
    let deadline = now.checked_add(WAIT_MILLISECONDS).context("pause deadline overflow")?;
    let ready = serde_json::json!({
        "kind":"partition-postflush-controlled-pause-ready-v1",
        "pid":std::process::id(),"nonce":nonce,"pause_started_unix_ms":now,
        "deadline_unix_ms":deadline,"maximum_wait_ms":WAIT_MILLISECONDS,
        "publication":published,"actual_postflush":flushed,
        "protocol":"N2R-CONTINUE <exact64hexnonce>\\n",
        "continue_route":"same actual child StandardInput handle retained by launcher",
        "birth_identity_must_match_launchers_actual_owned_process":true,
        "source_worker_stays_inside_synchronous_postflush_callback_until_release":true,
        "source_or_recovery_authority_from_command":false,
        "first_flushed_write_qualified":false,"physical_power_loss_qualified":false
    });
    observer.lock()?.record(&ready)?;
    save(&output.join("control/postflush-pause-ready.json"), &ready, 512 * 1024)?;
    let limit = Duration::from_millis(WAIT_MILLISECONDS);
    let outcome = match receive.recv_timeout(limit.saturating_sub(began.elapsed())) {
        Ok(Ok(())) => "nonce-bound-Continue",
        Ok(Err(error)) => {
            observer.lock()?.record(&serde_json::json!({
                "kind":"partition-postflush-Continue-refused-v1","pid":std::process::id(),
                "nonce":nonce,"error":error,"source_or_recovery_authority_issued":false,
                "wait_until_original_deadline":true
            }))?;
            std::thread::sleep(limit.saturating_sub(began.elapsed()));
            "watchdog-timeout-after-refused-input"
        }
        Err(mpsc::RecvTimeoutError::Timeout) => "watchdog-timeout",
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            observer.lock()?.record(&serde_json::json!({
                "kind":"partition-postflush-Continue-reader-disconnected-v1",
                "pid":std::process::id(),"nonce":nonce,
                "wait_until_original_deadline":true
            }))?;
            std::thread::sleep(limit.saturating_sub(began.elapsed()));
            "watchdog-timeout-after-reader-disconnected"
        }
    };
    let released = serde_json::json!({
        "kind":"partition-postflush-controlled-pause-released-v1",
        "pid":std::process::id(),"nonce":nonce,"reason":outcome,
        "elapsed_ms":began.elapsed().as_millis(),"deadline_unix_ms":deadline,
        "source_worker_still_inside_postflush_callback":true,
        "next_discovery_write_not_yet_requested":true,
        "reader_stack_reservation_bytes":READER_STACK_BYTES,
        "reader_and_control_ram_reservation_bytes":RAM_RESERVE_BYTES,
        "source_or_recovery_authority_from_command":false
    });
    observer.lock()?.record(&released)?;
    save(&output.join("control/postflush-pause-released.json"), &released, 16 * 1024)?;
    Ok(())
}
