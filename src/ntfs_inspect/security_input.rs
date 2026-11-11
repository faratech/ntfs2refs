//! Streaming security capture for the already protected raw source.
use super::*;
use super::{
    namespace_capture::capture_attribute,
    paged_storage::{PagedMetadataRange, SourcePagePin, SourceScratch},
    record_store::{RecordStorePin, SortedRecordStore, SortedRecordWriter},
    source_domain::{
        LegacySecurityRecord, RootSecurityCaptureDomain, SourceIndexRanges, SourceMetadataRange,
    },
};
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityIndexPins {
    root: SourcePagePin,
    allocation: Option<SourcePagePin>,
    bitmap: Option<SourcePagePin>,
    initialized_allocation_bytes: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityCapturePins {
    schema_version: u32,
    sds: SourcePagePin,
    sii: SecurityIndexPins,
    sdh: SecurityIndexPins,
    legacy: RecordStorePin,
}
struct IndexOwner {
    root: PagedMetadataRange,
    allocation: Option<PagedMetadataRange>,
    bitmap: Option<PagedMetadataRange>,
    initialized: u64,
}
impl IndexOwner {
    fn open(pin: &SecurityIndexPins, scratch: &SourceScratch) -> Result<Self> {
        Ok(Self {
            root: PagedMetadataRange::open(&pin.root, scratch)?,
            allocation: pin
                .allocation
                .as_ref()
                .map(|p| PagedMetadataRange::open(p, scratch))
                .transpose()?,
            bitmap: pin
                .bitmap
                .as_ref()
                .map(|p| PagedMetadataRange::open(p, scratch))
                .transpose()?,
            initialized: pin.initialized_allocation_bytes,
        })
    }
    fn ranges(&self) -> SourceIndexRanges<'_> {
        SourceIndexRanges {
            root: &self.root,
            allocation: self
                .allocation
                .as_ref()
                .map(|r| r as &dyn SourceMetadataRange),
            bitmap: self.bitmap.as_ref().map(|r| r as &dyn SourceMetadataRange),
            initialized_allocation_bytes: self.initialized,
        }
    }
    fn revalidate(&self) -> Result<()> {
        self.root.revalidate()?;
        if let Some(a) = &self.allocation {
            a.revalidate()?;
        }
        if let Some(b) = &self.bitmap {
            b.revalidate()?;
        }
        Ok(())
    }
}
pub(super) struct PagedSecurityCapture {
    root: PathBuf,
    scratch: SourceScratch,
    legacy: SortedRecordWriter,
    secure: Option<(SourcePagePin, SecurityIndexPins, SecurityIndexPins)>,
}
fn key(number: u64) -> [u8; 16] {
    let mut value = [0; 16];
    value[..8].copy_from_slice(&number.to_be_bytes());
    value
}
impl PagedSecurityCapture {
    pub(super) fn new(root: &Path, scratch: &SourceScratch) -> Result<Self> {
        Ok(Self {
            root: root.to_owned(),
            scratch: scratch.clone(),
            legacy: SortedRecordWriter::new(
                &root.join("captured-legacy-security"),
                *b"N2RSLGC1",
                scratch,
            )?,
            secure: None,
        })
    }
    fn named<'a>(record: &'a Record, kind: u32, name: &str) -> Result<Option<&'a Attribute>> {
        let name: Vec<u16> = name.encode_utf16().collect();
        let mut matches = record
            .attributes
            .iter()
            .filter(|a| a.report.type_code == kind && a.report.name_utf16 == name);
        let found = matches.next();
        ensure!(
            matches.next().is_none(),
            "duplicate security metadata attribute"
        );
        if let Some(a) = found {
            ensure!(
                a.report.lowest_vcn == 0,
                "unassembled security metadata VCN"
            );
        }
        Ok(found)
    }
    fn capture<R: Read + Seek>(
        &self,
        reader: &mut R,
        a: &Attribute,
        geometry: &NtfsGeometry,
        leaf: &str,
        tag: [u8; 8],
        initialized: bool,
    ) -> Result<SourcePagePin> {
        ensure!(
            !initialized || a.report.initialized_size == a.report.logical_size,
            "security metadata is not fully initialized"
        );
        capture_attribute(
            reader,
            a,
            geometry,
            &self.root.join(leaf),
            tag,
            &self.scratch,
            None,
        )
    }
    fn index<R: Read + Seek>(
        &self,
        reader: &mut R,
        record: &Record,
        geometry: &NtfsGeometry,
        name: &str,
        tag: [u8; 8],
    ) -> Result<SecurityIndexPins> {
        let root = Self::named(record, 0x90, name)?.context("missing security index root")?;
        ensure!(
            root.report.resident && (48..=4096).contains(&root.report.logical_size),
            "unsupported security root layout"
        );
        let root_pin = self.capture(
            reader,
            root,
            geometry,
            &format!("security-{name}-root.pages"),
            tag,
            true,
        )?;
        let allocation = Self::named(record, 0xa0, name)?;
        let bitmap = Self::named(record, 0xb0, name)?;
        ensure!(
            allocation.is_none() || bitmap.is_some(),
            "security allocation lacks its bitmap"
        );
        if let Some(a) = allocation {
            ensure!(
                !a.report.resident,
                "security index allocation must be nonresident"
            );
        }
        let mut allocation_tag = tag;
        allocation_tag[7] ^= 1;
        let mut bitmap_tag = tag;
        bitmap_tag[7] ^= 2;
        Ok(SecurityIndexPins {
            root: root_pin,
            allocation: allocation
                .map(|a| {
                    self.capture(
                        reader,
                        a,
                        geometry,
                        &format!("security-{name}-allocation.pages"),
                        allocation_tag,
                        false,
                    )
                })
                .transpose()?,
            bitmap: bitmap
                .map(|a| {
                    self.capture(
                        reader,
                        a,
                        geometry,
                        &format!("security-{name}-bitmap.pages"),
                        bitmap_tag,
                        true,
                    )
                })
                .transpose()?,
            initialized_allocation_bytes: allocation.map_or(0, |a| a.report.initialized_size),
        })
    }
    pub(super) fn observe<R: Read + Seek>(
        &mut self,
        reader: &mut R,
        record: &Record,
        number: u64,
        geometry: &NtfsGeometry,
    ) -> Result<()> {
        ensure!(
            record.base == 0 && !record.attributes.iter().any(|a| a.report.type_code == 0x20),
            "unresolved extension/list cannot establish complete security capture"
        );
        if number == 9 {
            ensure!(
                self.secure.is_none()
                    && geometry.bytes_per_sector == 512
                    && geometry.index_record_size == 4096
                    && crate::ntfs_index::supports_cluster_size(geometry.cluster_size),
                "unsupported or duplicate Secure index geometry"
            );
            let sds = Self::named(record, 0x80, "$SDS")?.context("Secure lacks SDS metadata")?;
            let sds = self.capture(
                reader,
                sds,
                geometry,
                "security-SDS.pages",
                *b"N2RSDS01",
                true,
            )?;
            let sii = self.index(reader, record, geometry, "$SII", *b"N2RSII01")?;
            let sdh = self.index(reader, record, geometry, "$SDH", *b"N2RSDH01")?;
            self.secure = Some((sds, sii, sdh));
        }
        let mut descriptors = record
            .attributes
            .iter()
            .filter(|a| a.report.type_code == 0x50);
        if let Some(a) = descriptors.next() {
            ensure!(
                descriptors.next().is_none()
                    && a.report.name_utf16.is_empty()
                    && a.report.flags == 0
                    && a.report.compression_unit == 0
                    && a.report.lowest_vcn == 0
                    && a.report.initialized_size == a.report.logical_size,
                "ambiguous or encoded legacy security descriptor"
            );
            let maximum = self.scratch.budget().record_bytes;
            let charge = a
                .report
                .logical_size
                .checked_mul(4)
                .context("legacy security memory overflow")?;
            let _ram = self.scratch.lease_ram(charge)?;
            let bytes = read_small_attribute(reader, a, geometry, maximum)?;
            // The same complete descriptor parser remains mandatory before a
            // row can reach the independently reconciled binding domain.
            crate::ntfs_security::parse_descriptor_with_limit(&bytes, maximum)?;
            self.legacy.push(
                key(number),
                &LegacySecurityRecord {
                    record_number: number,
                    sequence_number: record.sequence,
                    bytes,
                },
            )?;
        }
        Ok(())
    }
    pub(super) fn finish(self) -> Result<PagedSecurityInput> {
        let (sds, sii, sdh) = self.secure.context("complete Secure capture absent")?;
        let pin = SecurityCapturePins {
            schema_version: 1,
            sds,
            sii,
            sdh,
            legacy: self.legacy.finish()?,
        };
        PagedSecurityInput::open(&pin, &self.scratch)
    }
}
pub struct PagedSecurityInput {
    sds: PagedMetadataRange,
    sii: IndexOwner,
    sdh: IndexOwner,
    legacy: SortedRecordStore,
    pin: SecurityCapturePins,
}
impl PagedSecurityInput {
    pub fn open(pin: &SecurityCapturePins, scratch: &SourceScratch) -> Result<Self> {
        ensure!(
            pin.schema_version == 1,
            "unsupported security capture schema"
        );
        let value = Self {
            sds: PagedMetadataRange::open(&pin.sds, scratch)?,
            sii: IndexOwner::open(&pin.sii, scratch)?,
            sdh: IndexOwner::open(&pin.sdh, scratch)?,
            legacy: SortedRecordStore::open(&pin.legacy, scratch)?,
            pin: pin.clone(),
        };
        let mut previous = None;
        for ordinal in 0..value.legacy.len() {
            let row: LegacySecurityRecord = value.legacy.get(ordinal)?;
            ensure!(
                value.legacy.key(ordinal)? == key(row.record_number)
                    && previous.is_none_or(|n| n < row.record_number),
                "legacy security key/identity/order differs"
            );
            previous = Some(row.record_number);
        }
        value.revalidate()?;
        Ok(value)
    }
    pub fn pins(&self) -> &SecurityCapturePins {
        &self.pin
    }
}
impl RootSecurityCaptureDomain for PagedSecurityInput {
    fn sds(&self) -> &dyn SourceMetadataRange {
        &self.sds
    }
    fn index(&self, kind: crate::ntfs_security::IndexKind) -> Result<SourceIndexRanges<'_>> {
        Ok(match kind {
            crate::ntfs_security::IndexKind::Id => self.sii.ranges(),
            crate::ntfs_security::IndexKind::Hash => self.sdh.ranges(),
        })
    }
    fn legacy_count(&self) -> u64 {
        self.legacy.len()
    }
    fn legacy(&self, ordinal: u64) -> Result<LegacySecurityRecord> {
        self.legacy.get(ordinal)
    }
    fn revalidate(&self) -> Result<()> {
        self.sds.revalidate()?;
        self.sii.revalidate()?;
        self.sdh.revalidate()?;
        self.legacy.revalidate()
    }
}
