//! The plain copy store: the bytes of an object a conversion makes a plain
//! file, as a program reading it through Windows sees them.
//!
//! Some features keep a file's contents somewhere the raw NTFS reader does
//! not see as the file's data: WOF in a compressed stream behind its
//! reparse point, EFS as ciphertext, Data Deduplication in its chunk store.
//! Windows' filters show a program the plain bytes. For such an object the
//! run reads the stream through the filter, on the frozen source mounted
//! read-only, opened *without* FILE_FLAG_OPEN_REPARSE_POINT (and with
//! FILE_FLAG_OPEN_NO_RECALL, so nothing is ever recalled from elsewhere),
//! and keeps the bytes here, in a working store of its own. The shadow is
//! then supplied from this copy (`SupplyKind::PlainCopy`), never from the
//! source's clusters.
//!
//! Each copy is hashed as it is written, read back once and then held open
//! with no other writer or deleter allowed, as every working file of a run
//! is. [`PlainCopyStore::reverify`] reads every copy again at the verify
//! gate; [`PlainCopyStore::remove`] deletes the store when the run is
//! finalized, cancelled or rolled back. A store that is dropped is left on
//! the disk, so a run cut short keeps its working files for the way back.
//!
//! No feature is converted through this store yet: it is the mechanism, with
//! its tests, for those that will be (WOF first).
use sha2::{Digest, Sha256};
use std::{
    fs::{File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

/// FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_SEQUENTIAL_SCAN |
/// FILE_FLAG_OPEN_NO_RECALL, and not FILE_FLAG_OPEN_REPARSE_POINT: a read
/// through the filter that owns the object, as a program makes it, that
/// recalls nothing.
pub const PLAIN_READ_FLAGS: u32 = 0x0a10_0000;
/// FILE_FLAG_OPEN_REPARSE_POINT, which a plain read never has.
pub const OPEN_REPARSE_POINT: u32 = 0x0020_0000;

/// Which stream of which object a copy holds.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct PlainCopyKey {
    pub record_number: u64,
    pub sequence_number: u16,
    /// Empty for the unnamed stream.
    pub stream_name_utf16: Vec<u16>,
}

impl PlainCopyKey {
    /// The copy's file name: the identity and the stream name in hex, so
    /// that no two keys share one and no name needs escaping.
    pub fn file_name(&self) -> String {
        let mut name = format!("{:016x}-{:04x}", self.record_number, self.sequence_number);
        if !self.stream_name_utf16.is_empty() {
            name.push('-');
            for unit in &self.stream_name_utf16 {
                name.push_str(&format!("{unit:04x}"));
            }
        }
        name.push_str(".plain");
        name
    }
}

/// One copy in the store.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct PlainCopyPin {
    pub record_number: u64,
    pub sequence_number: u16,
    pub stream_name_utf16: Vec<u16>,
    pub file_name: String,
    pub bytes: u64,
    pub sha256: String,
    /// The copy's [`crate::content_digest`] (XXH3-128): what the shadow's
    /// expected stream carries, and holds the converted file to.
    pub content_digest: String,
}

struct Held {
    pin: PlainCopyPin,
    file: File,
}

/// The run's plain copies, in a directory of their own.
pub struct PlainCopyStore {
    directory: PathBuf,
    copies: Vec<Held>,
}

fn invalid(message: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

/// SHA-256 and length of what `reader` holds from where it is.
fn digest(reader: &mut impl Read, buffer: &mut [u8]) -> io::Result<(u64, String)> {
    let mut hash = Sha256::new();
    let mut bytes = 0u64;
    loop {
        let count = reader.read(buffer)?;
        if count == 0 {
            return Ok((bytes, hex::encode(hash.finalize())));
        }
        hash.update(&buffer[..count]);
        bytes += count as u64;
    }
}

impl PlainCopyStore {
    /// Makes the store's directory, which must not exist yet.
    pub fn create(directory: &Path) -> io::Result<Self> {
        std::fs::create_dir(directory).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!(
                    "the plain copy store {} could not be made: {error}",
                    directory.display()
                ),
            )
        })?;
        Ok(Self {
            directory: directory.to_owned(),
            copies: Vec::new(),
        })
    }

    pub fn directory(&self) -> &Path {
        &self.directory
    }
    pub fn pins(&self) -> impl Iterator<Item = &PlainCopyPin> {
        self.copies.iter().map(|held| &held.pin)
    }
    /// The bytes the store holds, for the working-storage account.
    pub fn bytes(&self) -> u64 {
        self.copies
            .iter()
            .fold(0u64, |sum, held| sum.saturating_add(held.pin.bytes))
    }

    /// Copies what `source` reads into the store under `key`. `expected` is
    /// the length the source said the stream has; a read that ends
    /// elsewhere is an error, and nothing of it is kept.
    pub fn copy(
        &mut self,
        key: PlainCopyKey,
        source: &mut impl Read,
        expected: u64,
    ) -> io::Result<&PlainCopyPin> {
        if self.copies.iter().any(|held| {
            held.pin.record_number == key.record_number
                && held.pin.sequence_number == key.sequence_number
                && held.pin.stream_name_utf16 == key.stream_name_utf16
        }) {
            return Err(invalid(format!(
                "MFT record {} already has a plain copy of that stream",
                key.record_number
            )));
        }
        let file_name = key.file_name();
        let path = self.directory.join(&file_name);
        let written = (|| {
            let mut file = OpenOptions::new()
                .create_new(true)
                .write(true)
                .read(true)
                .open(&path)?;
            let mut buffer = vec![0u8; 1 << 20];
            let mut hash = Sha256::new();
            let mut content = crate::content_digest::Hasher::new();
            let mut bytes = 0u64;
            loop {
                let count = source.read(&mut buffer)?;
                if count == 0 {
                    break;
                }
                hash.update(&buffer[..count]);
                content.update(&buffer[..count]);
                file.write_all(&buffer[..count])?;
                bytes += count as u64;
            }
            if bytes != expected {
                return Err(invalid(format!(
                    "the plain read of MFT record {} gave {bytes} bytes, and the stream has {expected}",
                    key.record_number
                )));
            }
            file.sync_all()?;
            let sha256 = hex::encode(hash.finalize());
            // Read back once, through the handle it was written with.
            file.seek(SeekFrom::Start(0))?;
            let (read, read_sha256) = digest(&mut file, &mut buffer)?;
            if read != bytes || read_sha256 != sha256 {
                return Err(invalid(format!(
                    "the plain copy of MFT record {} did not read back as it was written",
                    key.record_number
                )));
            }
            Ok((bytes, sha256, content.finish()))
        })();
        let (bytes, sha256, content_digest) = match written {
            Ok(done) => done,
            Err(error) => {
                // Nothing half-written stays in the store.
                let _ = std::fs::remove_file(&path);
                return Err(error);
            }
        };
        let file = hold(&path)?;
        self.copies.push(Held {
            pin: PlainCopyPin {
                record_number: key.record_number,
                sequence_number: key.sequence_number,
                stream_name_utf16: key.stream_name_utf16,
                file_name,
                bytes,
                sha256,
                content_digest,
            },
            file,
        });
        Ok(&self.copies.last().expect("just pushed").pin)
    }

    fn find(&self, key: &PlainCopyKey) -> Option<&Held> {
        self.copies.iter().find(|held| {
            held.pin.record_number == key.record_number
                && held.pin.sequence_number == key.sequence_number
                && held.pin.stream_name_utf16 == key.stream_name_utf16
        })
    }

    /// Reads `output.len()` bytes of one copy from `offset`; a range past
    /// its end is an error.
    pub fn read_at(&self, key: &PlainCopyKey, offset: u64, output: &mut [u8]) -> io::Result<()> {
        let held = self.find(key).ok_or_else(|| {
            invalid(format!(
                "MFT record {} has no plain copy of that stream",
                key.record_number
            ))
        })?;
        if offset
            .checked_add(output.len() as u64)
            .is_none_or(|end| end > held.pin.bytes)
        {
            return Err(invalid(format!(
                "a read of {} bytes at {offset} escapes the {}-byte plain copy of MFT record {}",
                output.len(),
                held.pin.bytes,
                key.record_number
            )));
        }
        let mut file = &held.file;
        file.seek(SeekFrom::Start(offset))?;
        file.read_exact(output)
    }

    /// Reads one copy from its start, for the shadow to be supplied from.
    pub fn reader(&self, key: &PlainCopyKey) -> io::Result<impl Read + '_> {
        let held = self.find(key).ok_or_else(|| {
            invalid(format!(
                "MFT record {} has no plain copy of that stream",
                key.record_number
            ))
        })?;
        let mut file = &held.file;
        file.seek(SeekFrom::Start(0))?;
        Ok(file.take(held.pin.bytes))
    }

    /// Reads every copy again and holds it to what was written: the verify
    /// gate before the first write to the source.
    pub fn reverify(&self) -> io::Result<()> {
        let mut buffer = vec![0u8; 1 << 20];
        for held in &self.copies {
            let mut file = &held.file;
            file.seek(SeekFrom::Start(0))?;
            let (bytes, sha256) = digest(&mut file, &mut buffer)?;
            if bytes != held.pin.bytes || sha256 != held.pin.sha256 {
                return Err(invalid(format!(
                    "the plain copy {} of MFT record {} changed: {bytes} bytes, sha256 {sha256}; it was {} bytes, sha256 {}",
                    held.pin.file_name, held.pin.record_number, held.pin.bytes, held.pin.sha256
                )));
            }
        }
        Ok(())
    }

    /// Deletes every copy and the store's directory: when the run is
    /// finalized, cancelled or rolled back. Anything in the directory that
    /// the store did not write is left, and the directory with it, and that
    /// is an error that names it.
    pub fn remove(self) -> io::Result<()> {
        let Self { directory, copies } = self;
        for held in copies {
            drop(held.file);
            std::fs::remove_file(directory.join(&held.pin.file_name))?;
        }
        if let Some(entry) = std::fs::read_dir(&directory)?.next() {
            return Err(io::Error::other(format!(
                "the plain copy store {} holds {} that it did not write; it is left",
                directory.display(),
                entry?.file_name().to_string_lossy()
            )));
        }
        std::fs::remove_dir(&directory)
    }
}

/// The directory of a run's plain copies, in the run's directory.
pub const DIRECTORY: &str = "plain-copies";

/// One stream to copy when the frozen source is observed: its identity and
/// the length the raw source gives it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlainCopyRequest {
    pub key: PlainCopyKey,
    pub bytes: u64,
    pub through: PlainRead,
}

/// How a copy is read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PlainRead {
    /// Through the filter that owns the object (WOF), as [`PLAIN_READ_FLAGS`].
    Filter,
    /// An EFS file, opened as any program opens it, without backup
    /// semantics, with this process's token: EFS decrypts it only where that
    /// token holds its key, and refuses the open otherwise.
    Decrypted,
    /// A Single Instance Storage link's: the unnamed stream of the common
    /// store file its reparse point names (an ordinary file, opened by its
    /// file reference as [`PlainRead::Filter`] opens one). The link itself
    /// is not opened: no filter of this Windows reads it.
    CommonStore {
        record_number: u64,
        sequence_number: u16,
    },
}

/// FILE_FLAG_SEQUENTIAL_SCAN | FILE_FLAG_OPEN_NO_RECALL: [`PlainRead::Decrypted`].
pub const DECRYPTED_READ_FLAGS: u32 = 0x0810_0000;

enum Lifecycle {
    Idle,
    /// What to copy, and where, at the next read-only observation.
    Armed {
        directory: PathBuf,
        requests: Vec<PlainCopyRequest>,
    },
    /// The copies, held, until the run is finalized, cancelled or rolled back.
    Taken(PlainCopyStore),
}

static LIFECYCLE: std::sync::Mutex<Lifecycle> = std::sync::Mutex::new(Lifecycle::Idle);

fn lifecycle() -> std::sync::MutexGuard<'static, Lifecycle> {
    LIFECYCLE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Names the streams this run copies at its read-only observation of the
/// frozen source, into `directory` (made then; it must not exist).
pub fn arm(directory: &Path, requests: Vec<PlainCopyRequest>) -> io::Result<()> {
    let mut state = lifecycle();
    if !matches!(*state, Lifecycle::Idle) {
        return Err(invalid(
            "this process already has plain copies to take or held".into(),
        ));
    }
    if !requests.is_empty() {
        *state = Lifecycle::Armed {
            directory: directory.to_owned(),
            requests,
        };
    }
    Ok(())
}

/// Takes the armed copies, each read by `open` (a read through the filter
/// that owns the object, on the frozen source mounted read-only). Nothing
/// to do when nothing is armed. A copy that fails leaves the store's
/// directory for the way back, and the copies are not taken.
pub fn take_armed_with<R: Read>(
    mut open: impl FnMut(&PlainCopyKey) -> io::Result<R>,
) -> io::Result<()> {
    let mut state = lifecycle();
    let Lifecycle::Armed {
        directory,
        requests,
    } = &*state
    else {
        return Ok(());
    };
    let mut store = PlainCopyStore::create(directory)?;
    for request in requests {
        let mut source = open(&request.key).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!(
                    "opening MFT record {} for its plain copy: {error}",
                    request.key.record_number
                ),
            )
        })?;
        store.copy(request.key.clone(), &mut source, request.bytes)?;
    }
    *state = Lifecycle::Taken(store);
    Ok(())
}

/// [`take_armed_with`] on the volume `volume` (`\\?\Volume{...}\`), each
/// object opened by its file reference, without FILE_FLAG_OPEN_REPARSE_POINT:
/// the reference names the record and its sequence number, so a reused
/// record is not opened.
#[cfg(windows)]
pub fn take_armed(volume: &str) -> io::Result<()> {
    if !matches!(*lifecycle(), Lifecycle::Armed { .. }) {
        return Ok(());
    }
    let volume = open_volume(volume.trim_end_matches('\\'))?;
    let throughs: std::collections::BTreeMap<(u64, u16), PlainRead> = match &*lifecycle() {
        Lifecycle::Armed { requests, .. } => requests
            .iter()
            .map(|r| ((r.key.record_number, r.key.sequence_number), r.through))
            .collect(),
        _ => Default::default(),
    };
    take_armed_with(|key| {
        if !key.stream_name_utf16.is_empty() {
            return Err(invalid("a named stream is not copied plain".into()));
        }
        match throughs.get(&(key.record_number, key.sequence_number)) {
            Some(PlainRead::Decrypted) => open_by_id_with(
                &volume,
                key.record_number,
                key.sequence_number,
                DECRYPTED_READ_FLAGS,
            )
            .map_err(|error| {
                if error.raw_os_error() == Some(5) {
                    io::Error::new(
                        error.kind(),
                        format!("MFT record {} is EFS-encrypted, and {error}: this account holds no key for it", key.record_number),
                    )
                } else {
                    error
                }
            }),
            Some(PlainRead::CommonStore {
                record_number,
                sequence_number,
            }) => open_plain_by_id(&volume, *record_number, *sequence_number),
            _ => open_plain_by_id(&volume, key.record_number, key.sequence_number),
        }
    })
}

/// Fails when copies were armed and never taken: the observation that
/// takes them did not run (a reopened source cache, say).
pub fn require_taken() -> io::Result<()> {
    match &*lifecycle() {
        Lifecycle::Armed { requests, .. } => Err(invalid(format!(
            "{} plain cop(ies) were to be taken at the read-only observation of the frozen source, which did not take them",
            requests.len()
        ))),
        _ => Ok(()),
    }
}

/// The copy of a stream, where this process holds one.
pub fn taken_pin(key: &PlainCopyKey) -> Option<PlainCopyPin> {
    match &*lifecycle() {
        Lifecycle::Taken(store) => store.find(key).map(|held| held.pin.clone()),
        _ => None,
    }
}

/// Reads `output.len()` bytes of a held copy from `offset`.
pub fn read_taken(key: &PlainCopyKey, offset: u64, output: &mut [u8]) -> io::Result<()> {
    match &*lifecycle() {
        Lifecycle::Taken(store) => store.read_at(key, offset, output),
        _ => Err(invalid(format!(
            "MFT record {} has no plain copy in this process",
            key.record_number
        ))),
    }
}

/// [`PlainCopyStore::reverify`] of the held copies, at the gate before the
/// first write to the source. How many there are.
pub fn reverify_taken() -> io::Result<usize> {
    match &*lifecycle() {
        Lifecycle::Taken(store) => {
            store.reverify()?;
            Ok(store.copies.len())
        }
        Lifecycle::Armed { .. } => Err(invalid(
            "plain copies were armed and never taken before the gate".into(),
        )),
        Lifecycle::Idle => Ok(0),
    }
}

/// Deletes the held copies and their directory, when the run is finalized,
/// cancelled or rolled back. A process that holds none deletes what a run
/// left in `run` instead (a recovery, or a cancellation, of a run made by
/// another process). Whether there was anything.
pub fn remove(run: &Path) -> io::Result<bool> {
    let held = std::mem::replace(&mut *lifecycle(), Lifecycle::Idle);
    match held {
        Lifecycle::Taken(store) => store.remove().map(|()| true),
        _ => {
            let directory = run.join(DIRECTORY);
            if !directory.exists() {
                return Ok(false);
            }
            std::fs::remove_dir_all(&directory).map_err(|error| {
                io::Error::new(
                    error.kind(),
                    format!(
                        "the plain copies at {} could not be deleted: {error}",
                        directory.display()
                    ),
                )
            })?;
            Ok(true)
        }
    }
}

#[cfg(windows)]
fn open_volume(volume: &str) -> io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt;
    // FILE_FLAG_BACKUP_SEMANTICS: the volume's root, for OpenFileById.
    OpenOptions::new()
        .read(true)
        .share_mode(7)
        .custom_flags(0x0200_0000)
        .open(format!("{volume}\\"))
}

/// Whether this process's account can read an EFS-encrypted file: it is
/// opened for its data as any program opens it, without backup semantics,
/// and closed without a byte read. EFS refuses the open (access denied)
/// where the account holds no key for it.
#[cfg(windows)]
pub fn probe_decryption(path: &Path) -> io::Result<()> {
    use std::os::windows::fs::OpenOptionsExt;
    OpenOptions::new()
        // FILE_READ_DATA | SYNCHRONIZE
        .access_mode(0x0010_0001)
        .share_mode(7)
        .custom_flags(DECRYPTED_READ_FLAGS)
        .open(path)
        .map(drop)
}

/// Whether this Windows has the Data Deduplication filter, through which a
/// deduplicated file reads as its whole contents: its driver's service is
/// registered and not disabled.
#[cfg(windows)]
pub fn dedup_filter_present() -> bool {
    use windows_sys::Win32::System::Registry::{
        HKEY, HKEY_LOCAL_MACHINE, KEY_READ, RRF_RT_REG_DWORD, RegCloseKey, RegGetValueW,
        RegOpenKeyExW,
    };
    let path: Vec<u16> = "SYSTEM\\CurrentControlSet\\Services\\Dedup"
        .encode_utf16()
        .chain(Some(0))
        .collect();
    let mut key: HKEY = std::ptr::null_mut();
    // SAFETY: a terminated path and an out pointer that lives across the call.
    if unsafe { RegOpenKeyExW(HKEY_LOCAL_MACHINE, path.as_ptr(), 0, KEY_READ, &mut key) } != 0 {
        return false;
    }
    let name: Vec<u16> = "Start".encode_utf16().chain(Some(0)).collect();
    let mut start = 0u32;
    let mut size = 4u32;
    // SAFETY: the key just opened, a terminated name and a DWORD of room.
    let read = unsafe {
        RegGetValueW(
            key,
            std::ptr::null(),
            name.as_ptr(),
            RRF_RT_REG_DWORD,
            std::ptr::null_mut(),
            (&mut start as *mut u32).cast(),
            &mut size,
        )
    };
    // SAFETY: closes the key opened above, once.
    unsafe { RegCloseKey(key) };
    // SERVICE_DISABLED is 4.
    read == 0 && start != 4
}

/// Opens one object of the volume by its file reference for a plain read.
#[cfg(windows)]
pub fn open_plain_by_id(volume: &File, record: u64, sequence: u16) -> io::Result<File> {
    open_by_id_with(volume, record, sequence, PLAIN_READ_FLAGS)
}

/// Opens one object of the volume by its file reference for reading its
/// data, with `flags`, which never hold FILE_FLAG_OPEN_REPARSE_POINT.
#[cfg(windows)]
pub fn open_by_id_with(volume: &File, record: u64, sequence: u16, flags: u32) -> io::Result<File> {
    if flags & OPEN_REPARSE_POINT != 0 {
        return Err(invalid("a plain read never opens the reparse point".into()));
    }
    use std::os::windows::io::{AsRawHandle, FromRawHandle};
    use windows_sys::Win32::{
        Foundation::INVALID_HANDLE_VALUE,
        Storage::FileSystem::{FILE_ID_DESCRIPTOR, FILE_ID_DESCRIPTOR_0, FileIdType, OpenFileById},
    };
    let descriptor = FILE_ID_DESCRIPTOR {
        dwSize: std::mem::size_of::<FILE_ID_DESCRIPTOR>() as u32,
        Type: FileIdType,
        Anonymous: FILE_ID_DESCRIPTOR_0 {
            FileId: (record | (u64::from(sequence) << 48)) as i64,
        },
    };
    // SAFETY: a live volume handle, a complete descriptor; FILE_READ_DATA |
    // FILE_READ_ATTRIBUTES | SYNCHRONIZE, shared, and PLAIN_READ_FLAGS (no
    // reparse point opened, nothing recalled).
    let handle = unsafe {
        OpenFileById(
            volume.as_raw_handle(),
            &descriptor,
            0x0010_0081,
            7,
            std::ptr::null(),
            flags,
        )
    };
    if handle == INVALID_HANDLE_VALUE || handle.is_null() {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the handle was just opened and is owned here alone.
    Ok(unsafe { File::from_raw_handle(handle) })
}

/// Opens a written copy for reading only, with nobody else allowed to
/// write, rename or delete it while it is held.
fn hold(path: &Path) -> io::Result<File> {
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        // FILE_SHARE_READ only.
        OpenOptions::new().read(true).share_mode(1).open(path)
    }
    #[cfg(not(windows))]
    {
        File::open(path)
    }
}

/// Opens an object of a mounted volume for a plain read: through whatever
/// filter owns it, without FILE_FLAG_OPEN_REPARSE_POINT, recalling nothing.
/// `path` is a Win32 path, such as `\\?\Volume{...}\dir\file` or with a
/// stream name after a colon.
#[cfg(windows)]
pub fn open_plain(path: &Path) -> io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt;
    OpenOptions::new()
        // FILE_READ_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE
        .access_mode(0x0010_0081)
        .share_mode(7)
        .custom_flags(PLAIN_READ_FLAGS)
        .open(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(record: u64, stream: &str) -> PlainCopyKey {
        PlainCopyKey {
            record_number: record,
            sequence_number: 3,
            stream_name_utf16: stream.encode_utf16().collect(),
        }
    }

    #[test]
    fn a_plain_read_never_opens_the_reparse_point() {
        assert_eq!(PLAIN_READ_FLAGS & OPEN_REPARSE_POINT, 0);
        // A decrypting read is a program's: no reparse point, no backup
        // semantics (which would not be the account's own access).
        assert_eq!(DECRYPTED_READ_FLAGS & OPEN_REPARSE_POINT, 0);
        assert_eq!(DECRYPTED_READ_FLAGS & 0x0200_0000, 0);
        // Backup semantics and no recall are both asked for.
        assert_eq!(PLAIN_READ_FLAGS & 0x0200_0000, 0x0200_0000);
        assert_eq!(PLAIN_READ_FLAGS & 0x0010_0000, 0x0010_0000);
    }

    #[test]
    fn each_stream_has_a_name_of_its_own() {
        assert_eq!(key(0x41, "").file_name(), "0000000000000041-0003.plain");
        assert_eq!(
            key(0x41, "ab").file_name(),
            "0000000000000041-0003-00610062.plain"
        );
        assert_ne!(key(0x41, "").file_name(), key(0x42, "").file_name());
        assert_ne!(key(0x41, "a").file_name(), key(0x41, "b").file_name());
    }

    #[test]
    fn a_copy_is_hashed_held_read_back_and_removed() {
        let parent = tempfile::tempdir().unwrap();
        let directory = parent.path().join("plain-copies");
        let mut store = PlainCopyStore::create(&directory).unwrap();
        // A second store in the same place is refused.
        assert!(PlainCopyStore::create(&directory).is_err());
        let data: Vec<u8> = (0..3_000_000u32).map(|i| (i % 251) as u8).collect();
        let pin = store
            .copy(key(64, ""), &mut data.as_slice(), data.len() as u64)
            .unwrap()
            .clone();
        assert_eq!(pin.bytes, data.len() as u64);
        assert_eq!(pin.sha256, hex::encode(Sha256::digest(&data)));
        store
            .copy(key(64, "s"), &mut &b"named"[..], 5)
            .expect("a named stream of the same object");
        assert_eq!(store.bytes(), data.len() as u64 + 5);
        assert_eq!(store.pins().count(), 2);
        // The same stream twice is refused.
        assert!(store.copy(key(64, ""), &mut &b"x"[..], 1).is_err());

        let mut back = Vec::new();
        store
            .reader(&key(64, ""))
            .unwrap()
            .read_to_end(&mut back)
            .unwrap();
        assert_eq!(back, data);
        assert!(store.reader(&key(65, "")).is_err());
        store.reverify().unwrap();

        // Held: nobody else may write to a copy meanwhile.
        #[cfg(windows)]
        assert!(
            OpenOptions::new()
                .write(true)
                .open(directory.join(&pin.file_name))
                .is_err()
        );

        store.remove().unwrap();
        assert!(!directory.exists());
    }

    #[test]
    fn a_short_or_long_read_keeps_nothing() {
        let parent = tempfile::tempdir().unwrap();
        let directory = parent.path().join("plain-copies");
        let mut store = PlainCopyStore::create(&directory).unwrap();
        let error = store
            .copy(key(70, ""), &mut &b"abc"[..], 4)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("gave 3 bytes, and the stream has 4"),
            "{error}"
        );
        assert!(store.copy(key(70, ""), &mut &b"abcde"[..], 4).is_err());
        assert_eq!(store.pins().count(), 0);
        assert_eq!(std::fs::read_dir(&directory).unwrap().count(), 0);
        store.remove().unwrap();
    }

    #[test]
    fn a_store_with_a_stranger_in_it_is_not_removed_silently() {
        let parent = tempfile::tempdir().unwrap();
        let directory = parent.path().join("plain-copies");
        let mut store = PlainCopyStore::create(&directory).unwrap();
        store.copy(key(80, ""), &mut &b"abc"[..], 3).unwrap();
        std::fs::write(directory.join("stranger.txt"), b"?").unwrap();
        let error = store.remove().unwrap_err().to_string();
        assert!(error.contains("stranger.txt"), "{error}");
        assert!(directory.join("stranger.txt").exists());
        assert!(!directory.join(key(80, "").file_name()).exists());
    }

    #[test]
    fn copies_are_armed_taken_read_reverified_and_removed_once() {
        let run = tempfile::tempdir().unwrap();
        let directory = run.path().join(DIRECTORY);
        let data: Vec<u8> = (0..70_000u32).map(|i| (i % 7) as u8).collect();
        // Nothing armed: nothing taken, nothing held, nothing to remove.
        take_armed_with(|_| Ok(&b""[..])).unwrap();
        assert_eq!(reverify_taken().unwrap(), 0);
        assert!(!remove(run.path()).unwrap());
        arm(
            &directory,
            vec![PlainCopyRequest {
                key: key(41, ""),
                bytes: data.len() as u64,
                through: PlainRead::Filter,
            }],
        )
        .unwrap();
        assert!(require_taken().is_err());
        assert!(reverify_taken().is_err());
        assert!(arm(&directory, Vec::new()).is_err());
        take_armed_with(|_| Ok(data.as_slice())).unwrap();
        require_taken().unwrap();
        let pin = taken_pin(&key(41, "")).unwrap();
        assert_eq!(pin.content_digest, crate::content_digest::of(&data));
        assert!(taken_pin(&key(42, "")).is_none());
        let mut middle = [0u8; 100];
        read_taken(&key(41, ""), 1000, &mut middle).unwrap();
        assert_eq!(&middle[..], &data[1000..1100]);
        assert!(read_taken(&key(41, ""), data.len() as u64 - 50, &mut middle).is_err());
        assert_eq!(reverify_taken().unwrap(), 1);
        assert!(remove(run.path()).unwrap());
        assert!(!directory.exists());
        assert!(taken_pin(&key(41, "")).is_none());

        // What another process left is removed by its path.
        std::fs::create_dir(&directory).unwrap();
        std::fs::write(directory.join("x.plain"), b"x").unwrap();
        assert!(remove(run.path()).unwrap());
        assert!(!directory.exists());
    }

    #[cfg(windows)]
    #[test]
    fn a_plain_read_reads_an_ordinary_file_as_it_is() {
        let parent = tempfile::tempdir().unwrap();
        let source = parent.path().join("source.bin");
        std::fs::write(&source, b"plain bytes").unwrap();
        let mut file = open_plain(&source).unwrap();
        let mut store = PlainCopyStore::create(&parent.path().join("copies")).unwrap();
        let pin = store.copy(key(90, ""), &mut file, 11).unwrap();
        assert_eq!(pin.sha256, hex::encode(Sha256::digest(b"plain bytes")));
        store.remove().unwrap();
    }
}
