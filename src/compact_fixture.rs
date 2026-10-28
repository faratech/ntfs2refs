//! Exact disposable-fixture experiment, not production source admission.
use crate::{
    general_reconstruct::{self as protocol, RecoveryOperation, Request},
    lab_reconstruct::JournalTicket,
    refs_hybrid::delta::VerifiedDeltaArtifact,
};
use anyhow::{Result, ensure};
use n2r_win32::{GeneralFrozenPartition, GeneralJournaledPartition};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{File, OpenOptions},
    io::Write,
    path::Path,
};
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Operation {
    Apply,
    Resume,
    Rollback,
    Finalize,
}
fn save(root: &Path, name: &str, value: &impl Serialize) -> Result<()> {
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(root.join(name))?;
    f.write_all(&serde_json::to_vec_pretty(value)?)?;
    f.sync_all()?;
    Ok(())
}
fn gate(
    r: &Request,
    t: &JournalTicket,
    a: &VerifiedDeltaArtifact,
    e: &[u8],
    ack: bool,
) -> Result<()> {
    ensure!(
        ack && std::env::var("COMPUTERNAME").ok().as_deref() == Some("N2R-WIN11"),
        "explicit enrolled disposable-fixture acknowledgment required"
    );
    r.validate()?;
    ensure!(
        r.pair.source.disk_number == 1
            && r.pair.shadow.disk_number == 3
            && r.journal.disk.disk_number == 2
            && r.pair
                .source
                .identity
                .disk_guid
                .eq_ignore_ascii_case("1b191872-c372-41ee-a416-e18863996f54")
            && r.pair
                .shadow
                .identity
                .disk_guid
                .eq_ignore_ascii_case("c0f2cd39-ad3d-484e-9990-0e6eba74485f")
            && r.journal
                .disk
                .identity
                .disk_guid
                .eq_ignore_ascii_case("09fcc613-b8c2-4a1a-8833-226f9399be7f")
            && r.comparison.expected_length == 52 * 1024 * 1024 * 1024
            && r.comparison.source_sha256
                == "ec5b89de85e24bbb0cdc5f99e907450dc847228ca997465961ab22f89d983dac"
            && r.comparison.shadow_sha256
                == "2b2aa8c51a0ed3676a31255f6121152fedfb29b459c20246c1546135fe769391"
            && r.expected_tree_sha256
                == "1602601cde53a7aa78d95e34c3de2ea18f5c0b65ddd8287ece9c84d81cbce215"
            && hex::encode(Sha256::digest(e)) == r.expected_tree_sha256
            && t.immutable_sha256
                == "4b1353889efb1ee328286da224e105733d4f622f8ebca4a46f4147ecc0d56c94"
            && a.pins().report_sha256
                == "a480fe897a0c76a92822d5312f5cde27dea341a296b9db16dae9386d81fc4b0f"
            && a.pins().packed_sha256
                == "dc5d6e1df69e72c85df7df5da83a51f50317c6b7cb82becd79b58ebb1390a8d8",
        "only the exact non-unique disposable corpus is authorized by this experiment"
    );
    let mut driver = File::open("C:\\Windows\\System32\\drivers\\refs.sys")?;
    let n = driver.metadata()?.len();
    ensure!(
        hex::encode(n2r_win32::sha256_native::hash_range(&mut driver, 0, n)?)
            == "3aa5d90958fc582c5f6567d2b970a3a37b3d4d80a4b58b5a8676943b7860d3c4",
        "fixture driver differs"
    );
    Ok(())
}
/// No SourceCertificate is issued. This is independent explicit test authority
/// for the fully hashed, non-unique enrolled corpus; general drives stay gated.
pub fn run(
    op: Operation,
    r: &Request,
    t: &JournalTicket,
    a: &mut VerifiedDeltaArtifact,
    j: &mut File,
    expected: &[u8],
    out: &Path,
    ack: bool,
    finalize: bool,
    interrupt: Option<u32>,
) -> Result<()> {
    gate(r, t, a, expected, ack)?;
    ensure!(!out.exists(), "fresh fixture output required");
    std::fs::create_dir(out)?;
    save(
        out,
        "intent.json",
        &serde_json::json!({"kind":"enrolled-compact-fixture-experiment","operation":op,
        "exact_fixture_only":true,"production_source_admitted":false,"finalize":finalize,"interrupt_after_writes":interrupt}),
    )?;
    let result = (|| -> Result<()> {
        let mut events = Vec::new();
        let shadow = GeneralFrozenPartition::reopen(r.pair.shadow.clone(), &mut events)?;
        let mut target = if matches!(op, Operation::Apply) {
            let mut source = GeneralFrozenPartition::reopen(r.pair.source.clone(), &mut events)?;
            let before = source.state(&mut events)?;
            let n = source.byte_len();
            let hash = hex::encode(crate::lab_reconstruct::hash_range_with_resource_profile(
                &mut source,
                0,
                n,
                crate::ntfs_admission::ResourceProfile::ExperimentalStreamingTreeV2,
            )?);
            ensure!(
                hash == r.comparison.source_sha256 && source.state(&mut events)? == before,
                "fresh fixture source bytes/state differ"
            );
            save(
                out,
                "source-fixture.json",
                &serde_json::json!({"sha256":hash,"state":before,"source_admitted":false}),
            )?;
            protocol::compact::activate(r, source, &shadow, a, j, t, &mut events)?
        } else {
            GeneralJournaledPartition::reopen(r.pair.source.clone(), &mut events)?
        };
        if matches!(op, Operation::Finalize) {
            ensure!(interrupt.is_none(), "finalize cannot inject interruption");
            let f = protocol::compact_finalize::finalize_after_marker(
                r, target, &shadow, a, j, t, expected,
            )?;
            save(out, "finalization.json", &f)?;
            ensure!(f.success, "completed compact handoff failed: {:?}", f.error);
        } else {
            let mode = match op {
                Operation::Apply => RecoveryOperation::Apply,
                Operation::Resume => RecoveryOperation::Resume,
                Operation::Rollback => RecoveryOperation::Rollback,
                _ => unreachable!(),
            };
            let execution = protocol::compact::execute(
                mode,
                r,
                &mut target,
                &shadow,
                a,
                j,
                t,
                &mut events,
                interrupt,
            )?;
            save(out, "execution.json", &execution)?;
            if finalize {
                ensure!(
                    !matches!(op, Operation::Rollback),
                    "compact rollback native completion remains separate"
                );
                let f =
                    protocol::compact_finalize::finalize(r, target, &shadow, a, j, t, expected)?;
                save(out, "finalization.json", &f)?;
                ensure!(f.success, "compact native handoff failed: {:?}", f.error);
            }
        }
        save(out, "events.json", &events)?;
        save(
            out,
            "result.json",
            &serde_json::json!({"kind":"enrolled-compact-fixture-experiment","success":true,
            "operation":op,"native_handoff_requested":finalize||matches!(op,Operation::Finalize),"source_admitted":false,"general_conversion_qualified":false}),
        )?;
        Ok(())
    })();
    if let Err(ref error) = result {
        save(
            out,
            "failed.json",
            &serde_json::json!({"error":format!("{error:#}"),"automatic_rollback_attempted":false}),
        )?;
    }
    result
}
