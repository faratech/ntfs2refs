//! Read-only, independent decoder for the laboratory REFSNT copy-on-write
//! block trace. The GPL writer experiment remains outside this Rust crate.
//! This reader never opens the Windows-generated base image for writing.
use anyhow::{Context, Result, ensure};
use std::{
    fs::File,
    io::{self, Read, Seek, SeekFrom},
    path::Path,
};

const HEADER: &[u8; 8] = b"N2RCOW01";
const RECORD: &[u8; 8] = b"N2RREC01";
const MAX_RECORD_BYTES: u32 = 1 << 20;
const MAX_OVERLAY_BYTES: u64 = 512 * 1024 * 1024;
const MAX_RECORDS: usize = 65536;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WriteRange {
    pub offset: u64,
    pub length: u32,
    data_at: u64,
}

pub struct RefsCowOverlay {
    base: File,
    overlay: File,
    length: u64,
    position: u64,
    writes: Vec<WriteRange>,
}

fn fnv32(offset: u64, data: &[u8]) -> u32 {
    offset
        .to_le_bytes()
        .iter()
        .chain(data)
        .fold(2166136261u32, |hash, byte| {
            (hash ^ u32::from(*byte)).wrapping_mul(16777619)
        })
}

impl RefsCowOverlay {
    pub fn open(base_path: &Path, overlay_path: &Path) -> Result<Self> {
        let base = File::open(base_path).context("open read-only base image")?;
        let mut overlay = File::open(overlay_path).context("open read-only overlay")?;
        let length = base.metadata()?.len();
        let overlay_length = overlay.metadata()?.len();
        ensure!(
            (16..=MAX_OVERLAY_BYTES).contains(&overlay_length),
            "overlay length outside laboratory bound"
        );
        let mut header = [0u8; 16];
        overlay.read_exact(&mut header)?;
        ensure!(
            &header[..8] == HEADER && u64::from_le_bytes(header[8..].try_into()?) == length,
            "overlay magic or base length differs"
        );
        let mut writes = Vec::new();
        while overlay.stream_position()? < overlay_length {
            ensure!(
                writes.len() < MAX_RECORDS && overlay_length - overlay.stream_position()? >= 24,
                "overlay record budget or truncated header"
            );
            let mut entry = [0u8; 24];
            overlay.read_exact(&mut entry)?;
            let offset = u64::from_le_bytes(entry[8..16].try_into()?);
            let size = u32::from_le_bytes(entry[16..20].try_into()?);
            let checksum = u32::from_le_bytes(entry[20..24].try_into()?);
            let data_at = overlay.stream_position()?;
            ensure!(
                &entry[..8] == RECORD
                    && (1..=MAX_RECORD_BYTES).contains(&size)
                    && offset
                        .checked_add(u64::from(size))
                        .is_some_and(|end| end <= length)
                    && data_at + u64::from(size) <= overlay_length,
                "overlay record signature, size or image range differs"
            );
            let mut data = vec![0; size as usize];
            overlay.read_exact(&mut data)?;
            ensure!(
                fnv32(offset, &data) == checksum,
                "overlay record checksum differs"
            );
            writes.push(WriteRange {
                offset,
                length: size,
                data_at,
            });
        }
        Ok(Self {
            base,
            overlay,
            length,
            position: 0,
            writes,
        })
    }

    pub fn length(&self) -> u64 {
        self.length
    }

    pub fn writes(&self) -> &[WriteRange] {
        &self.writes
    }

    pub fn writes_overlap(&self, offset: u64, length: u64) -> Result<bool> {
        let end = offset
            .checked_add(length)
            .context("overlap range overflow")?;
        ensure!(end <= self.length, "overlap range outside base image");
        Ok(self
            .writes
            .iter()
            .any(|write| write.offset < end && write.offset + u64::from(write.length) > offset))
    }
}

impl Read for RefsCowOverlay {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if self.position >= self.length || output.is_empty() {
            return Ok(0);
        }
        let count = (self.length - self.position).min(output.len() as u64) as usize;
        self.base.seek(SeekFrom::Start(self.position))?;
        self.base.read_exact(&mut output[..count])?;
        let start = self.position;
        let end = start + count as u64;
        for write in &self.writes {
            let lo = start.max(write.offset);
            let hi = end.min(write.offset + u64::from(write.length));
            if lo < hi {
                self.overlay
                    .seek(SeekFrom::Start(write.data_at + lo - write.offset))?;
                self.overlay
                    .read_exact(&mut output[(lo - start) as usize..(hi - start) as usize])?;
            }
        }
        self.position = end;
        Ok(count)
    }
}

impl Seek for RefsCowOverlay {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        let requested = match position {
            SeekFrom::Start(value) => i128::from(value),
            SeekFrom::Current(value) => i128::from(self.position) + i128::from(value),
            SeekFrom::End(value) => i128::from(self.length) + i128::from(value),
        };
        if !(0..=i128::from(u64::MAX)).contains(&requested) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid overlay seek",
            ));
        }
        self.position = requested as u64;
        Ok(self.position)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{io::Write, path::PathBuf};

    fn fixture() -> (tempfile::TempDir, PathBuf, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join("base.img");
        let overlay = dir.path().join("overlay.log");
        std::fs::write(&base, b"abcdefghijklmnop").unwrap();
        let mut file = File::create(&overlay).unwrap();
        file.write_all(HEADER).unwrap();
        file.write_all(&16u64.to_le_bytes()).unwrap();
        for (offset, data) in [(2u64, b"WXYZ".as_slice()), (4, b"Q".as_slice())] {
            file.write_all(RECORD).unwrap();
            file.write_all(&offset.to_le_bytes()).unwrap();
            file.write_all(&(data.len() as u32).to_le_bytes()).unwrap();
            file.write_all(&fnv32(offset, data).to_le_bytes()).unwrap();
            file.write_all(data).unwrap();
        }
        (dir, base, overlay)
    }

    #[test]
    fn overlay_reads_latest_write_without_changing_base() {
        let (_dir, base, overlay) = fixture();
        let mut image = RefsCowOverlay::open(&base, &overlay).unwrap();
        assert_eq!(image.writes().len(), 2);
        assert!(image.writes_overlap(2, 4).unwrap());
        assert!(!image.writes_overlap(8, 4).unwrap());
        let mut bytes = [0; 16];
        image.read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes, b"abWXQZghijklmnop");
        assert_eq!(std::fs::read(base).unwrap(), b"abcdefghijklmnop");
    }

    #[test]
    fn damaged_overlay_record_is_rejected() {
        let (_dir, base, overlay) = fixture();
        let mut bytes = std::fs::read(&overlay).unwrap();
        *bytes.last_mut().unwrap() ^= 1;
        std::fs::write(&overlay, bytes).unwrap();
        assert!(RefsCowOverlay::open(&base, &overlay).is_err());
    }
}
