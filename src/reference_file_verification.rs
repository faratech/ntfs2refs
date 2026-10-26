//! Bounded read-only reference reproducibility proof. No storage authority.
use crate::{fixed_vhd, refs_reference_transport as transport};
use anyhow::{Context, Result, ensure};
use n2r_win32::reference_file::{ReferenceFileSnapshot, observe_reference_file_handle};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{Cursor, Read, Seek, SeekFrom},
    path::{Path, PathBuf},
    time::{Instant, SystemTime},
};

pub const PACKET_SHA256: &str = "585df94c07190bcd3476a596ee870d1c3e60d793d03d9d4d3bd545780f23df5b";
pub const FIXED_VHD_SHA256: &str =
    "b671d327fba46dc371b65a0e20d631525db13af02fa85e9c797412cba58269b7";
const PACKET_BYTES: u64 = 68_162_693;
const FIXED_BYTES: u64 = (64_u64 << 30) + 512;

#[derive(Serialize)]
pub struct VerificationReport {
    pub schema_version: u32,
    pub kind: &'static str,
    pub status: &'static str,
    pub packet_path: PathBuf,
    pub source_path: PathBuf,
    pub packet_sha256: String,
    pub current_fixed_vhd_sha256: String,
    pub reconstructed_fixed_vhd_sha256: String,
    pub reconstructed_bytes_including_footer: u64,
    pub footer_matches_current_file: bool,
    pub packet_before: ReferenceFileSnapshot,
    pub packet_after: ReferenceFileSnapshot,
    pub source_before: ReferenceFileSnapshot,
    pub source_after: ReferenceFileSnapshot,
    pub elapsed_milliseconds: u128,
    pub input_handles_read_only: bool,
    pub windows_write_delete_sharing_excluded: bool,
    pub reconstructed_output_bytes_written: u64,
    pub devices_opened: u64,
    pub cleanup_authorized: bool,
    pub limitations: [&'static str; 3],
}

struct HeldFile {
    path: PathBuf,
    file: File,
    before: ReferenceFileSnapshot,
    modified: SystemTime,
}
impl HeldFile {
    fn open(path: &Path) -> Result<Self> {
        let path = fixed_vhd::checked_path(path, false)?;
        let file = fixed_vhd::open_read_only(&path)?;
        let before = observe_reference_file_handle(&file)?;
        let modified = file.metadata()?.modified()?;
        Ok(Self {
            path,
            file,
            before,
            modified,
        })
    }
    fn unchanged(&self) -> Result<ReferenceFileSnapshot> {
        let after = observe_reference_file_handle(&self.file)?;
        ensure!(
            after == self.before && self.file.metadata()?.modified()? == self.modified,
            "held reference identity, length, attributes or modification time changed"
        );
        // A held identity is primary. Also refuse a replaced/reparse pathname.
        let path = fixed_vhd::checked_path(&self.path, false)?;
        let reopened = fixed_vhd::open_read_only(&path)?;
        ensure!(
            observe_reference_file_handle(&reopened)? == after,
            "reference pathname no longer resolves to the held file"
        );
        Ok(after)
    }
}

fn hash_exact(reader: &mut impl Read, length: u64) -> Result<String> {
    let mut hash = Sha256::new();
    let mut buffer = vec![0; transport::CHUNK_BYTES];
    let mut remaining = length;
    let mut next_progress = 8_u64 << 30;
    while remaining != 0 {
        let n = remaining.min(buffer.len() as u64) as usize;
        reader
            .read_exact(&mut buffer[..n])
            .context("read complete current fixed VHD")?;
        hash.update(&buffer[..n]);
        remaining -= n as u64;
        if length - remaining >= next_progress {
            eprintln!("current fixed VHD hashed {} bytes", length - remaining);
            next_progress += 8_u64 << 30;
        }
    }
    ensure!(
        reader.read(&mut [0; 1])? == 0,
        "unexpected bytes after expected file length"
    );
    Ok(hex::encode(hash.finalize()))
}

/// Both handles remain read-only and deny ordinary writer/delete sharing until
/// all content/identity checks finish. No journal, device or filesystem API is used.
pub fn verify_pinned_files(packet: &Path, source: &Path) -> Result<VerificationReport> {
    verify_files(
        packet,
        source,
        PACKET_SHA256,
        FIXED_VHD_SHA256,
        PACKET_BYTES,
        FIXED_BYTES,
    )
}

fn verify_files(
    packet_path: &Path,
    source_path: &Path,
    packet_pin: &str,
    fixed_pin: &str,
    packet_length: u64,
    source_length: u64,
) -> Result<VerificationReport> {
    let started = Instant::now();
    let mut packet_file = HeldFile::open(packet_path)?;
    let mut source_file = HeldFile::open(source_path)?;
    ensure!(
        packet_file.before.file_bytes == packet_length
            && packet_length > 0
            && packet_length <= transport::MAX_PACKET_BYTES,
        "packet length differs from bound/pin"
    );
    ensure!(
        source_file.before.file_bytes == source_length,
        "current fixed VHD length differs from pin"
    );
    ensure!(
        packet_file.before.volume_serial_number != source_file.before.volume_serial_number
            || packet_file.before.file_id_128 != source_file.before.file_id_128,
        "packet and fixed source alias the same file"
    );
    let mut bytes = Vec::with_capacity(packet_length as usize);
    (&mut packet_file.file)
        .take(packet_length + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 == packet_length,
        "packet length changed while reading"
    );
    let packet_sha256 = hex::encode(Sha256::digest(&bytes));
    ensure!(
        packet_sha256 == packet_pin,
        "current packet SHA-256 differs from pin"
    );
    let packet = transport::decode(&mut Cursor::new(&bytes))?;
    drop(bytes);
    ensure!(
        packet.header.selection.fixed_vhd_sha256 == fixed_pin
            && packet.header.selection.disk_bytes.checked_add(512) == Some(source_length),
        "packet fixed VHD identity/length pin differs"
    );
    packet_file.unchanged()?;
    source_file.unchanged()?;
    eprintln!("verifying complete packet reconstruction, including stored fixed-VHD footer");
    // This existing verifier hashes every reconstructed byte, including zero
    // gaps, then the exact footer; it also verifies partition and payload pins.
    packet.verify_reconstructed_contents()?;
    eprintln!("hashing current fixed VHD through held read-only handle");
    source_file.file.seek(SeekFrom::Start(0))?;
    let current_fixed_vhd_sha256 = hash_exact(&mut source_file.file, source_length)?;
    ensure!(
        current_fixed_vhd_sha256 == fixed_pin,
        "current fixed VHD SHA-256 differs from pin"
    );
    source_file.file.seek(SeekFrom::End(-512))?;
    let mut footer = [0; 512];
    source_file.file.read_exact(&mut footer)?;
    ensure!(
        hex::encode(footer) == packet.header.fixed_footer_hex,
        "current footer differs from packet"
    );
    let source_after = source_file.unchanged()?;
    let packet_after = packet_file.unchanged()?;
    Ok(VerificationReport {
        schema_version: 1,
        kind: "read-only-reference-reproducibility",
        status: "verified",
        packet_path: packet_file.path,
        source_path: source_file.path,
        packet_sha256,
        current_fixed_vhd_sha256,
        reconstructed_fixed_vhd_sha256: packet.header.selection.fixed_vhd_sha256,
        reconstructed_bytes_including_footer: source_length,
        footer_matches_current_file: true,
        packet_before: packet_file.before,
        packet_after,
        source_before: source_file.before,
        source_after,
        elapsed_milliseconds: started.elapsed().as_millis(),
        input_handles_read_only: true,
        windows_write_delete_sharing_excluded: true,
        reconstructed_output_bytes_written: 0,
        devices_opened: 0,
        cleanup_authorized: false,
        limitations: [
            "Point-in-time same-handle content/identity proof; not future deletion authority.",
            "Sharing excludes ordinary conflicting opens, not pre-existing writable mappings, kernel/storage actors or a hostile administrator.",
            "Does not prove VM ancestry, exclusive physical block ownership, reclaimable bytes, licensing or native filesystem correctness.",
        ],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, io};
    struct Fixture {
        _dir: tempfile::TempDir,
        packet: PathBuf,
        source: PathBuf,
        packet_pin: String,
        fixed_pin: String,
        packet_len: u64,
        source_len: u64,
    }
    impl Fixture {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let source = dir.path().join("control.vhd");
            let packet = dir.path().join("reference.n2rref");
            let mut body = vec![0; 3 * transport::CHUNK_BYTES];
            body[0] = 0x42;
            body[transport::CHUNK_BYTES..transport::CHUNK_BYTES + 4096].fill(0x6d);
            let disk_bytes = body.len() as u64;
            let mut footer = [0; 512];
            footer[..8].copy_from_slice(b"conectix");
            footer[8..12].copy_from_slice(&2_u32.to_be_bytes());
            footer[12..16].copy_from_slice(&0x10000_u32.to_be_bytes());
            footer[16..24].copy_from_slice(&u64::MAX.to_be_bytes());
            footer[40..48].copy_from_slice(&disk_bytes.to_be_bytes());
            footer[48..56].copy_from_slice(&disk_bytes.to_be_bytes());
            footer[60..64].copy_from_slice(&2_u32.to_be_bytes());
            footer[68..84].fill(1);
            let sum: u32 = footer.iter().map(|b| u32::from(*b)).sum();
            footer[64..68].copy_from_slice(&(!sum).to_be_bytes());
            let hash = |b: &[u8]| hex::encode(Sha256::digest(b));
            let partition_sha256 = hash(&body[transport::CHUNK_BYTES..]);
            let payload_sha256 = hash(&body[transport::CHUNK_BYTES..transport::CHUNK_BYTES + 4096]);
            body.extend_from_slice(&footer);
            let fixed_pin = hash(&body);
            let selection = transport::Selection {
                schema_version: 1,
                disk_bytes,
                fixed_vhd_sha256: fixed_pin.clone(),
                partition_offset: transport::CHUNK_BYTES as u64,
                partition_bytes: 2 * transport::CHUNK_BYTES as u64,
                partition_sha256,
                payload_offset: 0,
                payload_bytes: 4096,
                payload_sha256,
            };
            let mut packed = vec![];
            transport::encode(&mut Cursor::new(&body), &mut packed, &selection).unwrap();
            fs::write(&source, &body).unwrap();
            fs::write(&packet, &packed).unwrap();
            Self {
                _dir: dir,
                packet,
                source,
                packet_pin: hash(&packed),
                fixed_pin,
                packet_len: packed.len() as u64,
                source_len: body.len() as u64,
            }
        }
        fn run(&self) -> Result<VerificationReport> {
            verify_files(
                &self.packet,
                &self.source,
                &self.packet_pin,
                &self.fixed_pin,
                self.packet_len,
                self.source_len,
            )
        }
    }
    #[test]
    fn verifies_current_file_and_reconstruction_without_creating_output() {
        let f = Fixture::new();
        let before: Vec<_> = fs::read_dir(f._dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        let r = f.run().unwrap();
        assert_eq!(r.current_fixed_vhd_sha256, r.reconstructed_fixed_vhd_sha256);
        assert!(!r.cleanup_authorized);
        assert_eq!(r.reconstructed_output_bytes_written, 0);
        assert_eq!(r.source_before, r.source_after);
        let after: Vec<_> = fs::read_dir(f._dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(before, after);
    }
    #[test]
    fn rejects_bad_pins_missing_files_changed_contents_and_malformed_packets() {
        let mut f = Fixture::new();
        f.packet_pin = "0".repeat(64);
        assert!(f.run().is_err());
        let f = Fixture::new();
        let mut b = fs::read(&f.source).unwrap();
        b[123] ^= 1;
        fs::write(&f.source, b).unwrap();
        assert!(f.run().is_err());
        let mut f = Fixture::new();
        let mut b = fs::read(&f.packet).unwrap();
        b[0] ^= 1;
        f.packet_pin = hex::encode(Sha256::digest(&b));
        fs::write(&f.packet, b).unwrap();
        assert!(f.run().is_err());
        let f = Fixture::new();
        fs::remove_file(&f.source).unwrap();
        assert!(f.run().is_err());
        let f = Fixture::new();
        fs::write(&f.source, b"short").unwrap();
        assert!(f.run().is_err());
    }
    #[test]
    fn exact_reader_refuses_early_eof_extra_bytes_and_read_errors() {
        assert!(hash_exact(&mut Cursor::new(b"abc"), 4).is_err());
        assert!(hash_exact(&mut Cursor::new(b"abcd"), 3).is_err());
        struct Fails;
        impl Read for Fails {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::other("injected"))
            }
        }
        assert!(hash_exact(&mut Fails, 1).is_err());
    }
    #[test]
    fn held_file_denies_writes_delete_access_and_detects_snapshot_changes() {
        use std::{fs::OpenOptions, os::windows::fs::OpenOptionsExt};
        let f = Fixture::new();
        let mut held = HeldFile::open(&f.source).unwrap();
        let write_error = OpenOptions::new().write(true).open(&f.source).unwrap_err();
        assert_eq!(write_error.raw_os_error(), Some(32)); // ERROR_SHARING_VIOLATION.
        let delete_error = OpenOptions::new()
            .access_mode(0x10000)
            .share_mode(7)
            .open(&f.source)
            .unwrap_err();
        assert_eq!(delete_error.raw_os_error(), Some(32));
        held.before.file_bytes += 1;
        assert!(held.unchanged().is_err());
        drop(held);
        // Positive controls distinguish sharing exclusion from unrelated errors.
        assert!(OpenOptions::new().write(true).open(&f.source).is_ok());
        assert!(
            OpenOptions::new()
                .access_mode(0x10000)
                .share_mode(7)
                .open(&f.source)
                .is_ok()
        );
        assert!(HeldFile::open(Path::new(r"\\.\PhysicalDrive0")).is_err());
        assert!(HeldFile::open(Path::new(r"\\?\C:\device.vhd")).is_err());
    }
    #[test]
    fn directory_reparse_paths_are_refused_without_opening_the_target() {
        let f = Fixture::new();
        assert!(HeldFile::open(f._dir.path()).is_err());
        let link = f._dir.path().join("junction");
        let result = std::process::Command::new("cmd.exe")
            .args(["/c", "mklink", "/J"])
            .arg(&link)
            .arg(f._dir.path())
            .output()
            .unwrap();
        assert!(result.status.success());
        assert!(HeldFile::open(&link.join("control.vhd")).is_err());
    }
}
