//! Certificate-backed same-partition conversion. Qualification, journal
//! preparation, durable recovery inputs and cutover stay in one process.
use crate::{general_qualification as qualification, general_reconstruct as reconstruct};
use anyhow::{Result, ensure};
use n2r_win32::{
    NativeEvent,
    general_layout::GeneralSourceShadowBinding,
    journal_file::{GeneralJournalStorageBinding, MAX_JOURNAL_BYTES, observe_general_journal_file},
    layout::guid_bytes,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, OpenOptions},
    io::Read,
    os::windows::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub schema_version: u32,
    pub experiment_id: String,
    pub pair: GeneralSourceShadowBinding,
    pub journal: GeneralJournalStorageBinding,
    pub max_journal_bytes: u64,
    #[serde(default)]
    pub verify_existing_shadow: bool,
}
impl Request {
    pub fn validate(&self) -> Result<()> {
        self.pair.validate()?;
        self.journal.validate()?;
        ensure!(
            self.schema_version == 1
                && self.experiment_id.len() == 32
                && self
                    .experiment_id
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                && (1..=MAX_JOURNAL_BYTES).contains(&self.max_journal_bytes),
            "conversion request profile differs"
        );
        for disk in [&self.pair.source, &self.pair.shadow] {
            ensure!(
                disk.disk_number != self.journal.disk.disk_number
                    && guid_bytes(&disk.identity.disk_guid)?
                        != guid_bytes(&self.journal.disk.identity.disk_guid)?
                    && guid_bytes(&disk.identity.partition_guid)?
                        != guid_bytes(&self.journal.disk.identity.partition_guid)?
                    && guid_bytes(&disk.volume_guid)?
                        != guid_bytes(&self.journal.disk.volume_guid)?,
                "journal storage must be independent of both data disks"
            );
        }
        Ok(())
    }
}

pub fn convert(request: &Request, output: &Path) -> Result<()> {
    request.validate()?;
    qualification::create_output(output)?;
    qualification::save(output, "conversion-intent.json", request)?;
    let mut phase = "qualification";
    let attempted = (|| -> Result<()> {
        let qualified = qualification::prepare(
            request.pair.clone(),
            &output.join("qualification"),
            request.verify_existing_shadow,
        )?;
        let qualification::QualifiedTree {
            mut source,
            mut target,
            certificate,
            comparison,
            expected,
            mount_paths,
        } = qualified;
        let plan = reconstruct::Request {
            schema_version: 1,
            experiment_id: request.experiment_id.clone(),
            expected_tree_sha256: hex::encode(Sha256::digest(&expected)),
            expected_mount_paths: Some(mount_paths.paths),
            pair: request.pair.clone(),
            comparison,
            journal: request.journal.clone(),
            max_journal_bytes: request.max_journal_bytes,
        };
        plan.validate()?;
        ensure!(
            certificate.binds_request(&plan),
            "live certificate does not bind the exact conversion plan"
        );
        qualification::save(output, "request.json", &plan)?;
        let expectation: crate::shadow_tree::ExpectedTree = serde_json::from_slice(&expected)?;
        qualification::save(output, "expectation.json", &expectation)?;
        phase = "journal-preparation";
        let parent = std::path::PathBuf::from(format!(
            "{}\\ntfs2refs-shadow",
            request.journal.disk.volume_path()?
        ));
        if !parent.exists() {
            fs::create_dir(&parent)?;
        }
        let meta = fs::symlink_metadata(&parent)?;
        ensure!(
            meta.is_dir() && meta.file_attributes() & 0x400 == 0,
            "ordinary journal parent required"
        );
        let directory = parent.join(&request.experiment_id);
        ensure!(!directory.exists(), "fresh journal experiment required");
        fs::create_dir(&directory)?;
        let journal_path = directory.join("reconstruction.journal");
        let mut journal = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .share_mode(0)
            .custom_flags(0x0020_0000)
            .open(&journal_path)?;
        let observed = observe_general_journal_file(&journal, &request.journal)?;
        ensure!(observed.file_bytes == 0, "fresh empty journal required");
        qualification::save(
            output,
            "journal-location.json",
            &serde_json::json!({"path":journal_path,"identity":observed.identity}),
        )?;
        let prepared = reconstruct::prepare(&plan, &mut source, &mut target, &mut journal)?;
        qualification::save(output, "prepare.json", &prepared)?;
        let ticket_pin = qualification::save(output, "ticket.json", &prepared.journal.ticket)?;
        // Read back the durable external ticket while holding its file handle
        // exclusively. Neither a JSON success flag nor an unsaved ticket arms I/O.
        let mut ticket_file = OpenOptions::new()
            .read(true)
            .share_mode(0)
            .custom_flags(0x0020_0000)
            .open(output.join("ticket.json"))?;
        let mut ticket_bytes = Vec::new();
        (&mut ticket_file)
            .take(65537)
            .read_to_end(&mut ticket_bytes)?;
        ensure!(
            ticket_bytes.len() <= 65536 && hex::encode(Sha256::digest(&ticket_bytes)) == ticket_pin,
            "durable ticket readback differs"
        );
        let ticket: crate::lab_reconstruct::JournalTicket = serde_json::from_slice(&ticket_bytes)?;
        phase = "activate-apply";
        let mut events = Vec::<NativeEvent>::new();
        let mut original = reconstruct::activate(
            &plan,
            source,
            &mut target,
            &mut journal,
            &ticket,
            &mut events,
        )?;
        let applied = reconstruct::execute(
            reconstruct::RecoveryOperation::Apply,
            &plan,
            &mut original,
            &mut target,
            &mut journal,
            &ticket,
            &mut events,
        )?;
        qualification::save(output, "apply.json", &applied)?;
        phase = "handoff";
        let finalization = reconstruct::finalize(
            &plan,
            original,
            &mut target,
            &mut journal,
            &ticket,
            &expected,
        )?;
        qualification::save(output, "finalization.json", &finalization)?;
        ensure!(
            finalization.success,
            "native ReFS handoff/verification failed: {:?}",
            finalization.error
        );
        qualification::save(
            output,
            "result.json",
            &serde_json::json!({"schema_version":1,"kind":"certificate-backed-ntfs-refs-conversion",
            "success":true,"source_admitted":true,"rollback_closed":finalization.rollback_closed,
            "journal_path":journal_path,"ticket_sha256":ticket_pin,"expected_tree_sha256":plan.expected_tree_sha256,
            "comparison":plan.comparison,"events":events}),
        )?;
        Ok(())
    })();
    if let Err(error) = attempted {
        qualification::save(
            output,
            "failed.json",
            &serde_json::json!({"phase":phase,"error":format!("{error:#}"),
            "recovery_materials":output,"automatic_rollback_attempted":false}),
        )?;
        return Err(error);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use n2r_win32::{general_layout::GeneralDiskBinding, layout::PartitionIdentity};
    fn disk(number: u32, identity: &str, partition: &str, bytes: u64) -> GeneralDiskBinding {
        GeneralDiskBinding {
            disk_number: number,
            volume_guid: partition.into(),
            identity: PartitionIdentity {
                disk_guid: identity.into(),
                partition_guid: partition.into(),
                partition_number: 2,
                disk_bytes: bytes,
                partition_offset: 16 * 1024 * 1024,
                partition_bytes: if number == 2 {
                    bytes - 32 * 1024 * 1024
                } else {
                    52 * 1024 * 1024 * 1024
                },
                logical_sector_bytes: 512,
                physical_sector_bytes: 4096,
            },
        }
    }
    fn request() -> Request {
        Request {
            schema_version: 1,
            experiment_id: "a".repeat(32),
            pair: GeneralSourceShadowBinding {
                source: disk(
                    1,
                    "11111111-1111-1111-1111-111111111111",
                    "12121212-1212-1212-1212-121212121212",
                    64 * 1024 * 1024 * 1024,
                ),
                shadow: disk(
                    3,
                    "33333333-3333-3333-3333-333333333333",
                    "34343434-3434-3434-3434-343434343434",
                    64 * 1024 * 1024 * 1024,
                ),
            },
            journal: GeneralJournalStorageBinding {
                disk: disk(
                    2,
                    "22222222-2222-2222-2222-222222222222",
                    "23232323-2323-2323-2323-232323232323",
                    8 * 1024 * 1024 * 1024,
                ),
                externally_enrolled_disk_unique_id: "lab-journal".into(),
                allow_additional_partitions: false,
            },
            max_journal_bytes: MAX_JOURNAL_BYTES,
            verify_existing_shadow: false,
        }
    }
    #[test]
    fn conversion_rejects_journal_aliases_and_invalid_experiments_before_io() {
        let good = request();
        good.validate().unwrap();
        for data in [&good.pair.source, &good.pair.shadow] {
            let mut bad = good.clone();
            bad.journal.disk.disk_number = data.disk_number;
            assert!(bad.validate().is_err());
            let mut bad = good.clone();
            bad.journal.disk.identity.disk_guid = data.identity.disk_guid.clone();
            assert!(bad.validate().is_err());
            let mut bad = good.clone();
            bad.journal.disk.volume_guid = data.volume_guid.clone();
            assert!(bad.validate().is_err());
        }
        let mut bad = good.clone();
        bad.max_journal_bytes = 0;
        assert!(bad.validate().is_err());
        let mut bad = good.clone();
        bad.max_journal_bytes = MAX_JOURNAL_BYTES + 1;
        assert!(bad.validate().is_err());
        let mut bad = good;
        bad.experiment_id = "..".repeat(16);
        assert!(bad.validate().is_err());
    }
}
