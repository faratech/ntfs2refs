//! Versioned count admission within the existing owning-tree resource envelope.
//! These facts do not supply native evidence, a source certificate or write authority.
use serde::{Deserialize, Serialize};
use std::io;

pub const OBJECT_SLOTS: usize = 1280;
pub const RAW_IDENTITIES: usize = 2048;
pub const DATA_STREAMS: usize = 16_384;
pub const EXPECTED_TREE_BYTES: usize = 16 * 1024 * 1024;
pub const INSPECTION_BYTES: usize = 64 * 1024 * 1024;
pub const NATIVE_REPORT_BYTES: usize = 64 * 1024 * 1024;
// metadata_targets: <=objects; native sparse/ADS target and optional carrier:
// <=two per DATA stream; eight slots cover volume/root/carrier/temporary opens.
pub const OWNED_HANDLE_SLOTS: usize = OBJECT_SLOTS + 2 * DATA_STREAMS + 8;

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CountAdmission {
    pub schema_version: u32,
    pub source_inspection_sha256: [u8; 32],
    pub raw_identities: u32,
    pub files: u32,
    pub directories: u32,
    pub data_streams: u32,
    pub object_slots: u32,
    pub raw_identity_slots: u32,
    pub data_stream_slots: u32,
    pub maximum_expected_tree_bytes: u32,
    pub maximum_inspection_bytes: u32,
    pub maximum_native_report_bytes: u32,
    pub projected_owned_handle_slots: u32,
    pub maximum_owned_handle_slots: u32,
    pub maximum_constructor_input_metadata_bytes: u32,
}

impl CountAdmission {
    pub fn new(
        source_inspection_sha256: [u8; 32],
        raw: usize,
        files: usize,
        dirs: usize,
        streams: usize,
    ) -> io::Result<Self> {
        let narrow = |n| u32::try_from(n).map_err(io::Error::other);
        let value = Self {
            schema_version: 1,
            source_inspection_sha256,
            raw_identities: narrow(raw)?,
            files: narrow(files)?,
            directories: narrow(dirs)?,
            data_streams: narrow(streams)?,
            object_slots: OBJECT_SLOTS as u32,
            raw_identity_slots: RAW_IDENTITIES as u32,
            data_stream_slots: DATA_STREAMS as u32,
            maximum_expected_tree_bytes: EXPECTED_TREE_BYTES as u32,
            maximum_inspection_bytes: INSPECTION_BYTES as u32,
            maximum_native_report_bytes: NATIVE_REPORT_BYTES as u32,
            projected_owned_handle_slots: narrow(
                files
                    .checked_add(dirs)
                    .and_then(|n| streams.checked_mul(2).and_then(|s| n.checked_add(s)))
                    .and_then(|n| n.checked_add(8))
                    .ok_or_else(|| io::Error::other("owning handle projection overflow"))?,
            )?,
            maximum_owned_handle_slots: OWNED_HANDLE_SLOTS as u32,
            maximum_constructor_input_metadata_bytes: EXPECTED_TREE_BYTES as u32,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> io::Result<()> {
        let objects = u64::from(self.files) + u64::from(self.directories);
        if self.schema_version != 1
            || self.source_inspection_sha256 == [0; 32]
            || self.directories == 0
            || self.raw_identities == 0
            || objects > u64::from(self.raw_identities)
            || objects > u64::from(self.object_slots)
            || self.files > self.data_streams
            || self.data_streams > self.data_stream_slots
            || self.raw_identities > self.raw_identity_slots
            || self.object_slots == 0
            || self.object_slots as usize > OBJECT_SLOTS
            || self.raw_identity_slots == 0
            || self.raw_identity_slots as usize > RAW_IDENTITIES
            || self.data_stream_slots == 0
            || self.data_stream_slots as usize > DATA_STREAMS
            || self.maximum_expected_tree_bytes == 0
            || self.maximum_expected_tree_bytes as usize > EXPECTED_TREE_BYTES
            || self.maximum_inspection_bytes == 0
            || self.maximum_inspection_bytes as usize > INSPECTION_BYTES
            || self.maximum_native_report_bytes == 0
            || self.maximum_native_report_bytes as usize > NATIVE_REPORT_BYTES
            || u64::from(self.projected_owned_handle_slots)
                != objects + 2 * u64::from(self.data_streams) + 8
            || self.projected_owned_handle_slots > self.maximum_owned_handle_slots
            || self.maximum_owned_handle_slots as usize > OWNED_HANDLE_SLOTS
            || self.maximum_constructor_input_metadata_bytes == 0
            || self.maximum_constructor_input_metadata_bytes as usize > EXPECTED_TREE_BYTES
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid bounded tree count admission",
            ));
        }
        Ok(())
    }

    pub fn validate_tree(&self, files: usize, dirs: usize, streams: usize) -> io::Result<()> {
        self.validate()?;
        if files != self.files as usize
            || dirs != self.directories as usize
            || streams != self.data_streams as usize
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "complete tree counts differ from source admission",
            ));
        }
        Ok(())
    }

    pub fn validate_expected_bytes(&self, value: &impl Serialize) -> io::Result<usize> {
        self.validate_serialized_bytes(value, self.maximum_expected_tree_bytes as usize)
    }
    pub fn validate_constructor_metadata(&self, value: &impl Serialize) -> io::Result<usize> {
        self.validate_serialized_bytes(
            value,
            self.maximum_constructor_input_metadata_bytes as usize,
        )
    }
    pub fn validate_inspection_bytes(&self, value: &impl Serialize) -> io::Result<usize> {
        self.validate_serialized_bytes(value, self.maximum_inspection_bytes as usize)
    }
    fn validate_serialized_bytes(&self, value: &impl Serialize, limit: usize) -> io::Result<usize> {
        struct Count {
            used: usize,
            limit: usize,
        }
        impl io::Write for Count {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                self.used = self
                    .used
                    .checked_add(bytes.len())
                    .filter(|n| *n <= self.limit)
                    .ok_or_else(|| {
                        io::Error::other("metadata exceeds pinned tree resource byte ceiling")
                    })?;
                Ok(bytes.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        self.validate()?;
        let mut count = Count { used: 0, limit };
        serde_json::to_writer_pretty(&mut count, value).map_err(io::Error::other)?;
        Ok(count.used)
    }
}
