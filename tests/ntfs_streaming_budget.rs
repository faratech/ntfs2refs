#[allow(dead_code, reason = "Shared synthetic NTFS fixture")]
mod support;

use ntfs2refs::ntfs_inspect::{self, Extent, StreamTransferBudget};
use sha2::{Digest, Sha256};
use std::io::{self, Cursor, Read, Seek, SeekFrom, Write};

// Sparse test reader: only the 2 MiB fixture is stored, the rest is generated
// as zeroes. No payload-sized image or output allocation is needed.
struct VirtualImage {
    prefix: Vec<u8>,
    length: u64,
    position: u64,
    max_read: usize,
    total_read: u64,
}

impl Read for VirtualImage {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let amount = output.len().min((self.length - self.position) as usize);
        self.max_read = self.max_read.max(amount);
        output[..amount].fill(0);
        if self.position < self.prefix.len() as u64 {
            let start = self.position as usize;
            let prefix_len = amount.min(self.prefix.len() - start);
            output[..prefix_len].copy_from_slice(&self.prefix[start..start + prefix_len]);
        }
        self.position += amount as u64;
        self.total_read += amount as u64;
        Ok(amount)
    }
}

impl Seek for VirtualImage {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        let next = match from {
            SeekFrom::Start(offset) => i128::from(offset),
            SeekFrom::Current(offset) => i128::from(self.position) + i128::from(offset),
            SeekFrom::End(offset) => i128::from(self.length) + i128::from(offset),
        };
        if next < 0 || next > i128::from(self.length) {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "out of range"));
        }
        self.position = next as u64;
        Ok(self.position)
    }
}

// The stream's content digest (XXH3-128) over everything written.
#[derive(Default)]
struct CountingWriter {
    bytes: u64,
    max_write: usize,
    digest: n2r_win32::content_digest::Hasher,
}
impl Write for CountingWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.bytes += bytes.len() as u64;
        self.max_write = self.max_write.max(bytes.len());
        self.digest.update(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn large_virtual_fixture() -> (VirtualImage, ntfs_inspect::NtfsInspection, u64, String) {
    let mut prefix = support::image();
    let mut raw = ntfs_inspect::inspect(&mut Cursor::new(&prefix), prefix.len() as u64).unwrap();
    let size: u64 = 256 * 1024 * 1024 + 4096;
    let clusters = size / 4096;
    let length = (100 + clusters + 1) * 4096;
    prefix[40..48].copy_from_slice(&(length / 512).to_le_bytes());
    raw.geometry = ntfs_inspect::inspect_boot_sector(&prefix[..512], length).unwrap();

    // Record 16 retains the same names/identity but its one ordinary DATA run
    // now covers a 256 MiB + 4 KiB virtual payload beginning at LCN 100.
    let record = 4 * 4096 + 16 * 1024;
    let mut at =
        record + u16::from_le_bytes(prefix[record + 20..record + 22].try_into().unwrap()) as usize;
    loop {
        let kind = u32::from_le_bytes(prefix[at..at + 4].try_into().unwrap());
        assert_ne!(kind, u32::MAX, "unnamed DATA attribute absent");
        if kind == 0x80 && prefix[at + 9] == 0 {
            assert_eq!(prefix[at + 8], 1);
            prefix[at + 24..at + 32].copy_from_slice(&(clusters - 1).to_le_bytes());
            for offset in [40, 48, 56] {
                prefix[at + offset..at + offset + 8].copy_from_slice(&size.to_le_bytes());
            }
            prefix[at + 64..at + 70].copy_from_slice(&[0x13, 0x01, 0x00, 0x01, 0x64, 0]);
            break;
        }
        at += u32::from_le_bytes(prefix[at + 4..at + 8].try_into().unwrap()) as usize;
    }
    let mut hash = n2r_win32::content_digest::Hasher::new();
    hash.update(b"Synthetic content");
    let zero = [0u8; 65536];
    let mut remaining = size - 17;
    while remaining > 0 {
        let count = remaining.min(zero.len() as u64) as usize;
        hash.update(&zero[..count]);
        remaining -= count as u64;
    }
    let expected = hash.finish();
    let file = raw
        .files
        .iter_mut()
        .find(|f| f.record_number == 16)
        .unwrap();
    let data = file
        .attributes
        .iter_mut()
        .find(|a| a.type_code == 0x80 && a.name_utf16.is_empty())
        .unwrap();
    data.logical_size = size;
    data.initialized_size = size;
    data.allocated_size = size;
    data.extents = vec![Extent {
        logical_offset: 0,
        physical_offset: Some(100 * 4096),
        length: size,
    }];
    let stream = file
        .streams
        .iter_mut()
        .find(|s| s.name_utf16.is_empty())
        .unwrap();
    stream.logical_size = size;
    stream.initialized_size = size;
    stream.allocated_size = size;
    stream.extents = data.extents.clone();
    stream.logical_sha256 = Some(expected.clone());
    (
        VirtualImage {
            prefix,
            length,
            position: 0,
            max_read: 0,
            total_read: 0,
        },
        raw,
        size,
        expected,
    )
}

#[test]
fn larger_than_alpha_file_streams_with_bounded_memory_and_cumulative_budget() {
    let (mut image, raw, size, expected) = large_virtual_fixture();
    let mut legacy = CountingWriter::default();
    assert!(ntfs_inspect::copy_plain_stream(&mut image, &raw, 16, size, &mut legacy).is_err());
    assert_eq!(legacy.bytes, 0);

    let mut budget = StreamTransferBudget::new(size, size + 17).unwrap();
    let mut sink = CountingWriter::default();
    let proof =
        ntfs_inspect::copy_plain_stream_with_budget(&mut image, &raw, 16, &mut budget, &mut sink)
            .unwrap();
    assert_eq!(proof.logical_bytes, size);
    assert_eq!(proof.sha256, expected);
    assert_eq!(sink.bytes, size);
    assert_eq!(sink.digest.finish(), expected);
    // Memory stays bounded by the reader's fixed chunk, whatever the file size.
    assert!(
        image.max_read <= ntfs_inspect::SESSION_READ_BYTES
            && sink.max_write <= ntfs_inspect::SESSION_READ_BYTES
    );
    assert_eq!(budget.reserved_bytes(), size);

    let tail =
        ntfs_inspect::hash_plain_stream_range_with_budget(&mut image, &raw, 16, 0, 17, &mut budget)
            .unwrap();
    assert_eq!(tail, hex::encode(Sha256::digest(b"Synthetic content")));
    assert_eq!(budget.reserved_bytes(), size + 17);
    assert!(
        ntfs_inspect::hash_plain_stream_range_with_budget(&mut image, &raw, 16, 0, 1, &mut budget,)
            .is_err()
    );
    // A caller may bound total I/O below the full file size when reading only
    // a small range; the separate per-stream limit still covers the file.
    let mut range_budget = StreamTransferBudget::new(size, 17).unwrap();
    let reads_before = image.total_read;
    assert_eq!(
        ntfs_inspect::hash_plain_stream_range_with_budget(
            &mut image,
            &raw,
            16,
            0,
            17,
            &mut range_budget,
        )
        .unwrap(),
        hex::encode(Sha256::digest(b"Synthetic content"))
    );
    assert_eq!(range_budget.reserved_bytes(), 17);
    assert!(image.total_read - reads_before > 17); // Metadata rereads are not charged.
    assert!(
        ntfs_inspect::hash_plain_stream_range_with_budget(
            &mut image,
            &raw,
            16,
            u64::MAX,
            2,
            &mut range_budget,
        )
        .is_err()
    );
    assert_eq!(range_budget.reserved_bytes(), 17);
}

#[test]
fn failed_transfer_keeps_its_budget_reservation_and_legacy_memory_limit() {
    let mut image = support::image();
    let raw = ntfs_inspect::inspect(&mut Cursor::new(&image), image.len() as u64).unwrap();
    image[100 * 4096] ^= 1;
    let mut budget = StreamTransferBudget::new(1024, 1024).unwrap();
    let mut sink = CountingWriter::default();
    assert!(
        ntfs_inspect::copy_plain_stream_with_budget(
            &mut Cursor::new(&image),
            &raw,
            16,
            &mut budget,
            &mut sink,
        )
        .is_err()
    );
    assert_eq!(budget.reserved_bytes(), 17);
    assert_eq!(sink.bytes, 17); // Caller must discard partial output on error.
    let mut named = Vec::new();
    let name: Vec<u16> = "note".encode_utf16().collect();
    ntfs_inspect::copy_plain_named_stream_with_budget(
        &mut Cursor::new(&image),
        &raw,
        16,
        &name,
        &mut budget,
        &mut named,
    )
    .unwrap();
    assert_eq!(named, b"metadata");
    assert_eq!(budget.reserved_bytes(), 25);
    assert!(
        ntfs_inspect::read_plain_stream(&mut Cursor::new(&image), &raw, 16, 256 * 1024 * 1024 + 1,)
            .is_err()
    );
    assert!(StreamTransferBudget::new(0, 1).is_err());
    assert!(StreamTransferBudget::new(2, 0).is_err());
}
