//! Private journal owner used by selected allocation orchestration. Only the
//! explicit lab route currently constructs native marker storage; production
//! selection shares the compiled qualification gate below. No handle or mutable
//! inner accessor can turn a buffered File into the sealed capability.
use crate::{
    lab_reconstruct::{DurableIo, ReadSeek},
    selected_journal as sj,
};
use anyhow::{Result, ensure};
use n2r_win32::journal_file::{
    GeneralJournalStorageBinding, JournalFileIdentity, JournalProfile, LabMarkerCopyPause,
    MARKER_STORAGE_NATIVE_QUALIFIED, MarkerJournalFile, MarkerStorageObservation, MarkerStorageUse,
    UnbufferedJournalFile, observe_general_journal_file_with_profile,
};
use std::{
    fs::{File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    os::windows::fs::OpenOptionsExt,
    path::Path,
};

/// Shared production format selection, never a storage capability or fresh
/// source authority. Only a source change backed by native qualification can
/// enable this; saved requests/tickets and lab options cannot change the gate.
/// Ineligible plans retain the legacy format. The caller must still validate
/// the selected profile, so an invalid plan cannot gain a fallback write path.
pub(crate) fn production_marker_profile(
    plan: &sj::SelectedPlan,
) -> Option<sj::SelectedMarkerProfile> {
    (MARKER_STORAGE_NATIVE_QUALIFIED && plan.validate_redundant_source_free().is_ok())
        .then_some(sj::SelectedMarkerProfile::RedundantSourceFreeV1)
}

pub(crate) struct NativeSelectedJournal {
    storage: Storage,
    lab_pause: Option<LabMarkerCopyPause>,
}

enum Storage {
    Buffered(File),
    Constructing(UnbufferedJournalFile),
    Sealed(MarkerJournalFile),
    Unavailable,
}

fn unavailable() -> io::Error {
    io::Error::other("selected journal owner unavailable after failed sealing")
}

impl NativeSelectedJournal {
    pub(crate) fn create_new(
        path: &Path,
        binding: &GeneralJournalStorageBinding,
        profile: JournalProfile,
        markers: Option<sj::SelectedMarkerProfile>,
        marker_use: MarkerStorageUse,
        lab_pause: Option<LabMarkerCopyPause>,
    ) -> Result<(Self, JournalFileIdentity)> {
        if markers.is_some() {
            let file = UnbufferedJournalFile::create_new(path, binding, profile, marker_use)?;
            let identity = file.identity().clone();
            return Ok((
                Self {
                    storage: Storage::Constructing(file),
                    lab_pause,
                },
                identity,
            ));
        }
        ensure!(
            lab_pause.is_none(),
            "marker pause requires explicit native format six"
        );
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .share_mode(0)
            .custom_flags(0x0020_0000)
            .open(path)?;
        let observed = observe_general_journal_file_with_profile(&file, binding, profile)?;
        ensure!(
            observed.file_bytes == 0,
            "fresh empty selected journal required"
        );
        Ok((
            Self {
                storage: Storage::Buffered(file),
                lab_pause: None,
            },
            observed.identity,
        ))
    }

    pub(crate) fn open_recovery(
        path: &Path,
        binding: &GeneralJournalStorageBinding,
        profile: JournalProfile,
        ticket: &sj::SelectedTicket,
        marker_identity: Option<&JournalFileIdentity>,
        marker_use: MarkerStorageUse,
        lab_pause: Option<LabMarkerCopyPause>,
    ) -> Result<(Self, serde_json::Value)> {
        if ticket.marker_profile.is_some() {
            let identity = marker_identity.ok_or_else(|| {
                anyhow::anyhow!(
                    "native marker recovery needs its independently pinned file identity"
                )
            })?;
            let mut file = MarkerJournalFile::open_recovery(
                path,
                binding,
                profile,
                marker_use,
                identity,
                ticket.journal_length,
            )?;
            if let Some(pause) = lab_pause {
                file.attach_lab_copy_pause(pause)?;
            }
            let observed = serde_json::to_value(file.observation())?;
            return Ok((
                Self {
                    storage: Storage::Sealed(file),
                    lab_pause: None,
                },
                observed,
            ));
        }
        ensure!(
            marker_identity.is_none() && lab_pause.is_none(),
            "legacy journal has marker storage identity or lab pause"
        );
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .share_mode(0)
            .custom_flags(0x0020_0000)
            .open(path)?;
        let observed = observe_general_journal_file_with_profile(&file, binding, profile)?;
        ensure!(
            observed.file_bytes == ticket.journal_length,
            "opened selected journal length differs from the pinned ticket"
        );
        Ok((
            Self {
                storage: Storage::Buffered(file),
                lab_pause: None,
            },
            serde_json::to_value(observed)?,
        ))
    }

    /// Called only before the prepared owner is published. On failure the
    /// original owner is dropped and this wrapper becomes permanently unusable.
    pub(crate) fn seal_redundant(&mut self, ticket: &sj::SelectedTicket) -> Result<()> {
        ensure!(
            ticket.marker_profile == Some(sj::SelectedMarkerProfile::RedundantSourceFreeV1),
            "native sealing requires explicit redundant source-free markers"
        );
        let construction = std::mem::replace(&mut self.storage, Storage::Unavailable);
        let Storage::Constructing(file) = construction else {
            anyhow::bail!("native marker sealing requires its actual construction owner");
        };
        let mut file = file.seal_marker_storage(ticket.journal_length)?;
        if let Some(pause) = self.lab_pause.take() {
            file.attach_lab_copy_pause(pause)?;
        }
        self.storage = Storage::Sealed(file);
        Ok(())
    }

    pub(crate) fn marker_observation(&self) -> Option<&MarkerStorageObservation> {
        match &self.storage {
            Storage::Sealed(file) => Some(file.observation()),
            _ => None,
        }
    }

    pub(crate) fn require_native_mount_barriers(
        &mut self,
        ticket: &sj::SelectedTicket,
    ) -> Result<()> {
        if ticket.marker_profile.is_none() {
            return Ok(());
        }
        ensure!(
            matches!(&self.storage, Storage::Sealed(_)),
            "native markers require actual sealed storage"
        );
        sj::require_redundant_terminal_barriers(self, ticket)
    }
}

impl Read for NativeSelectedJournal {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        match &mut self.storage {
            Storage::Buffered(file) => file.read(bytes),
            Storage::Constructing(file) => file.read(bytes),
            Storage::Sealed(file) => file.read(bytes),
            Storage::Unavailable => Err(unavailable()),
        }
    }
}
impl Write for NativeSelectedJournal {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        match &mut self.storage {
            Storage::Buffered(file) => file.write(bytes),
            Storage::Constructing(file) => file.write(bytes),
            Storage::Sealed(file) => file.write(bytes),
            Storage::Unavailable => Err(unavailable()),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        match &mut self.storage {
            Storage::Buffered(file) => file.flush(),
            Storage::Constructing(file) => file.flush(),
            Storage::Sealed(file) => file.flush(),
            Storage::Unavailable => Err(unavailable()),
        }
    }
}
impl Seek for NativeSelectedJournal {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        match &mut self.storage {
            Storage::Buffered(file) => file.seek(from),
            Storage::Constructing(file) => file.seek(from),
            Storage::Sealed(file) => file.seek(from),
            Storage::Unavailable => Err(unavailable()),
        }
    }
}
impl ReadSeek for NativeSelectedJournal {
    fn byte_len(&mut self) -> io::Result<u64> {
        match &mut self.storage {
            Storage::Buffered(file) => Ok(file.metadata()?.len()),
            Storage::Constructing(file) => file.byte_len(),
            Storage::Sealed(file) => file.byte_len(),
            Storage::Unavailable => Err(unavailable()),
        }
    }
}
impl DurableIo for NativeSelectedJournal {
    fn sync_all(&mut self) -> io::Result<()> {
        match &mut self.storage {
            Storage::Buffered(file) => file.sync_all(),
            Storage::Constructing(file) => file.sync_all(),
            Storage::Sealed(file) => file.sync_all(),
            Storage::Unavailable => Err(unavailable()),
        }
    }
}
