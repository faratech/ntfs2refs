//! Independent intent storage for preparation in full Windows. This does not
//! alter source protection, issue a writer, or reinterpret legacy C: origins.
use super::*;
use crate::journal_file::GeneralJournalStorageBinding;

pub(super) struct ExternalIntentEnrollment {
    journal: GeneralJournalStorageBinding,
    source: PartitionSourceBinding,
    volume: File,
}
impl ExternalIntentEnrollment {
    pub(super) fn observe(
        journal: &GeneralJournalStorageBinding,
        source: &PartitionSourceBinding,
        volume: File,
        actual_path: &str,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<Self> {
        journal.validate()?;
        source.validate()?;
        require(
            journal.disk.disk_number != source.storage.disk_number
                && crate::layout::guid_bytes(&journal.disk.identity.disk_guid)?
                    != crate::layout::guid_bytes(&source.storage.identity.disk_guid)?,
            "offline preparation intent must be on an independent physical disk",
        )?;
        let actual = Self {
            journal: journal.clone(),
            source: source.clone(),
            volume,
        };
        actual.revalidate(actual_path, events)?;
        Ok(actual)
    }
    pub(super) fn binding(&self) -> &GeneralJournalStorageBinding {
        &self.journal
    }
    pub(super) fn revalidate(
        &self,
        actual_path: &str,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<()> {
        let root = format!("{}\\", self.journal.disk.volume_path()?);
        require(
            actual_path
                .get(..root.len())
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case(&root)),
            "actual held intent file is not on the enrolled journal GUID volume",
        )?;
        let role = crate::discovery::Role::Journal {
            allow_additional_partitions: self.journal.allow_additional_partitions,
        };
        let before = crate::discovery::discover(&root, role)?;
        require(
            before.binding == self.journal.disk
                && before.read_only
                && before.observed_twice_unchanged
                && before.source_write_requests == 0
                && before.filesystem == "NTFS"
                && !before.disk_is_windows_disk,
            "independent journal discovery or native filesystem differs",
        )?;
        let extents = control(
            &self.volume,
            "external-preparation-intent-volume-extents",
            super::super::super::VOLUME_EXTENTS,
            &[],
            32,
            events,
        )?;
        self.journal.disk.validate_volume_extent(&extents)?;
        let device = control(
            &self.volume,
            "external-preparation-intent-device",
            super::super::super::DEVICE,
            &[],
            12,
            events,
        )?;
        let info = control(
            &self.volume,
            "external-preparation-intent-partition",
            GET_PARTITION,
            &[],
            144,
            events,
        )?;
        let id = &self.journal.disk.identity;
        require(
            device.len() == 12
                && crate::layout::u32_at(&device, 4)? == self.journal.disk.disk_number
                && crate::layout::u32_at(&device, 8)? == id.partition_number
                && info.len() == 144
                && info[48..64] == crate::layout::guid_bytes(&id.partition_guid)?
                && crate::layout::u64_at(&info, 8)? == id.partition_offset
                && crate::layout::u64_at(&info, 16)? == id.partition_bytes
                && self.journal.disk.disk_number != self.source.storage.disk_number,
            "actual held external intent volume changed device, partition or extent",
        )?;
        let after = crate::discovery::discover(&root, role)?;
        require(
            before.evidence == after.evidence
                && before.binding == after.binding
                && after.binding == self.journal.disk
                && after.read_only
                && after.observed_twice_unchanged
                && after.source_write_requests == 0,
            "external intent journal changed across native handle checks",
        )
    }
}
