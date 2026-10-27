//! Pure consistency assessment of supplied NTFS attribute intervals and a bitmap.
//! No source parsing, source authentication, certificate, or write authority.
//! Cluster units are relative to an independently established bitmap domain.
use sha2::{Digest, Sha256};
use std::io::{self, Read, Seek, SeekFrom};

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct AttributeKey {
    pub record_number: u64,
    pub sequence_number: u16,
    pub type_code: u32,
    pub name_utf16: Vec<u16>,
    pub instance: u16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PhysicalInterval {
    pub owner: AttributeKey,
    pub vcn_start: u64,
    pub lcn_start: u64,
    pub clusters: u64,
}

#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub max_intervals: usize,
    pub max_bitmap_bytes: usize,
    pub max_cluster_checks: u64,
    pub max_total_name_units: usize,
    pub max_sort_bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_intervals: 4096,
            max_bitmap_bytes: 2 * 1024 * 1024,
            max_cluster_checks: 16 * 1024 * 1024,
            max_total_name_units: 16 * 1024,
            max_sort_bytes: 4096 * std::mem::size_of::<usize>(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Refusal {
    EmptyDomain,
    BudgetExceeded(&'static str),
    BitmapLength {
        expected: usize,
        actual: usize,
    },
    InvalidOwner {
        input: usize,
    },
    EmptyInterval {
        input: usize,
    },
    Overflow {
        input: usize,
        coordinate: &'static str,
    },
    OutsideDomain {
        input: usize,
    },
    VcnOverlap {
        first: usize,
        second: usize,
    },
    PhysicalOverlap {
        first: usize,
        second: usize,
        lcn: u64,
    },
    ClaimedFree {
        input: usize,
        lcn: u64,
    },
    AllocatedUnowned {
        lcn: u64,
    },
    AllocationFailed,
    BitmapRead {
        byte_offset: u64,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Consistency {
    pub domain_clusters: u64,
    pub allocated_clusters: u64,
    pub free_clusters: u64,
    pub physical_intervals: usize,
    pub distinct_attributes: usize,
    pub bitmap_bytes_checked: usize,
    pub cluster_checks: u64,
    /// Outside-domain padding is reported, not mistaken for volume allocation.
    pub padding_bits_set: u32,
    pub sorting_storage_bytes: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Assessment {
    /// Only the supplied interval/bitmap model reconciles. Not source admission.
    Consistent(Consistency),
    /// No partially accepted tree or ledger is returned.
    Rejected(Refusal),
}

impl Assessment {
    /// This assessment never supplies a conversion capability or certificate.
    pub fn grants_write_authority(&self) -> bool {
        false
    }
}

/// Return the first bit whose allocation state differs from the expected state
/// in a half-open cluster range. Whole words are checked together, while edge
/// masks ensure that adjacent owners and out-of-domain padding are never read
/// as part of the range.
fn first_unexpected_bit(bitmap: &[u8], start: u64, end: u64, allocated: bool) -> Option<u64> {
    let mut cursor = start;
    if !cursor.is_multiple_of(8) && cursor < end {
        let bit = (cursor % 8) as u32;
        let count = (8 - u64::from(bit)).min(end - cursor) as u32;
        let mask = (((1u16 << count) - 1) << bit) as u8;
        let byte = bitmap[(cursor / 8) as usize];
        let unexpected = (if allocated { !byte } else { byte }) & mask;
        if unexpected != 0 {
            return Some(cursor / 8 * 8 + u64::from(unexpected.trailing_zeros()));
        }
        cursor += u64::from(count);
    }
    while end - cursor >= 64 {
        let at = (cursor / 8) as usize;
        let word = u64::from_le_bytes(bitmap[at..at + 8].try_into().unwrap());
        let unexpected = if allocated { !word } else { word };
        if unexpected != 0 {
            return Some(cursor + u64::from(unexpected.trailing_zeros()));
        }
        cursor += 64;
    }
    while end - cursor >= 8 {
        let byte = bitmap[(cursor / 8) as usize];
        let unexpected = if allocated { !byte } else { byte };
        if unexpected != 0 {
            return Some(cursor + u64::from(unexpected.trailing_zeros()));
        }
        cursor += 8;
    }
    if cursor < end {
        let count = (end - cursor) as u32;
        let mask = ((1u16 << count) - 1) as u8;
        let byte = bitmap[(cursor / 8) as usize];
        let unexpected = (if allocated { !byte } else { byte }) & mask;
        if unexpected != 0 {
            return Some(cursor + u64::from(unexpected.trailing_zeros()));
        }
    }
    None
}

pub fn assess(
    domain_clusters: u64,
    bitmap: &[u8],
    intervals: &[PhysicalInterval],
    limits: Limits,
) -> Assessment {
    match reconcile(domain_clusters, &mut SliceBitmap(bitmap), intervals, limits) {
        Ok(summary) => Assessment::Consistent(summary),
        Err(reason) => Assessment::Rejected(reason),
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct BitmapSummary {
    pub sha256: String,
    pub bitmap_bytes: u64,
    pub allocated_clusters: u64,
    pub free_clusters: u64,
}

/// Hash and count a logical allocation bitmap with the same bounded window.
pub fn summarize_stream<R: Read + Seek>(
    domain_clusters: u64,
    bitmap: &mut R,
) -> io::Result<BitmapSummary> {
    StreamingBitmap::new(bitmap, domain_clusters)?.finish()
}

trait BitmapAccess {
    fn byte_len(&self) -> usize;
    fn mismatch(&mut self, start: u64, end: u64, allocated: bool) -> Result<Option<u64>, Refusal>;
    fn padding_bits(&mut self, domain: u64) -> Result<u32, Refusal>;
}

struct SliceBitmap<'a>(&'a [u8]);
impl BitmapAccess for SliceBitmap<'_> {
    fn byte_len(&self) -> usize {
        self.0.len()
    }
    fn mismatch(&mut self, start: u64, end: u64, allocated: bool) -> Result<Option<u64>, Refusal> {
        Ok(first_unexpected_bit(self.0, start, end, allocated))
    }
    fn padding_bits(&mut self, domain: u64) -> Result<u32, Refusal> {
        let bits = (domain % 8) as u32;
        Ok(if bits == 0 {
            0
        } else {
            (self.0[self.0.len() - 1] & !((1u8 << bits) - 1)).count_ones()
        })
    }
}

/// Reconcile a seekable logical bitmap using a fixed 64 KiB window. Every byte
/// is hashed and counted, even when the ownership model is rejected. A read,
/// length or EOF failure returns no summary and cannot become consistency.
pub fn assess_stream<R: Read + Seek>(
    domain_clusters: u64,
    bitmap: &mut R,
    intervals: &[PhysicalInterval],
    limits: Limits,
) -> io::Result<(Assessment, BitmapSummary)> {
    let mut source = StreamingBitmap::new(bitmap, domain_clusters)?;
    let assessment = match reconcile(domain_clusters, &mut source, intervals, limits) {
        Ok(summary) => Assessment::Consistent(summary),
        Err(reason) => Assessment::Rejected(reason),
    };
    let summary = source.finish()?;
    Ok((assessment, summary))
}

struct StreamingBitmap<'a, R> {
    reader: &'a mut R,
    domain: u64,
    needed: usize,
    loaded: usize,
    window_start: usize,
    window_len: usize,
    window: [u8; 64 * 1024],
    hash: Sha256,
    allocated: u64,
    padding: u32,
    failure: Option<io::Error>,
}

impl<'a, R: Read + Seek> StreamingBitmap<'a, R> {
    fn new(reader: &'a mut R, domain: u64) -> io::Result<Self> {
        if domain == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "empty bitmap domain",
            ));
        }
        let needed = usize::try_from(domain.div_ceil(8)).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "bitmap exceeds stream addressability",
            )
        })?;
        if reader.seek(SeekFrom::End(0))? != needed as u64 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "bitmap stream length differs",
            ));
        }
        reader.seek(SeekFrom::Start(0))?;
        Ok(Self {
            reader,
            domain,
            needed,
            loaded: 0,
            window_start: 0,
            window_len: 0,
            window: [0; 64 * 1024],
            hash: Sha256::new(),
            allocated: 0,
            padding: 0,
            failure: None,
        })
    }
    fn load(&mut self) -> io::Result<()> {
        if self.loaded == self.needed {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "bitmap window escapes EOF",
            ));
        }
        let count = (self.needed - self.loaded).min(self.window.len());
        self.reader.read_exact(&mut self.window[..count])?;
        self.hash.update(&self.window[..count]);
        let mut allocated = self.window[..count]
            .iter()
            .map(|b| u64::from(b.count_ones()))
            .sum::<u64>();
        self.window_start = self.loaded;
        self.window_len = count;
        self.loaded += count;
        let bits = (self.domain % 8) as u32;
        if self.loaded == self.needed && bits != 0 {
            self.padding = (self.window[count - 1] & !((1u8 << bits) - 1)).count_ones();
            allocated -= u64::from(self.padding);
        }
        self.allocated = self.allocated.checked_add(allocated).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "bitmap allocated-cluster count overflow",
            )
        })?;
        Ok(())
    }
    fn ensure_byte(&mut self, at: usize) -> Result<(), Refusal> {
        while at < self.window_start || at >= self.window_start + self.window_len {
            if at < self.loaded || self.loaded == self.needed {
                return Err(Refusal::BitmapRead {
                    byte_offset: at as u64,
                });
            }
            if let Err(error) = self.load() {
                self.failure = Some(error);
                return Err(Refusal::BitmapRead {
                    byte_offset: self.loaded as u64,
                });
            }
        }
        Ok(())
    }
    fn finish(mut self) -> io::Result<BitmapSummary> {
        if let Some(error) = self.failure.take() {
            return Err(error);
        }
        while self.loaded < self.needed {
            self.load()?;
        }
        let mut extra = [0; 1];
        if self.reader.read(&mut extra)? != 0
            || self.reader.seek(SeekFrom::End(0))? != self.needed as u64
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "bitmap stream length or EOF changed",
            ));
        }
        Ok(BitmapSummary {
            sha256: hex::encode(self.hash.finalize()),
            bitmap_bytes: self.needed as u64,
            allocated_clusters: self.allocated,
            free_clusters: self.domain - self.allocated,
        })
    }
}

impl<R: Read + Seek> BitmapAccess for StreamingBitmap<'_, R> {
    fn byte_len(&self) -> usize {
        self.needed
    }
    fn mismatch(&mut self, start: u64, end: u64, allocated: bool) -> Result<Option<u64>, Refusal> {
        let mut cursor = start;
        while cursor < end {
            self.ensure_byte((cursor / 8) as usize)?;
            let base = self.window_start as u64 * 8;
            let stop = end.min(((self.window_start + self.window_len) as u64).saturating_mul(8));
            if let Some(bit) = first_unexpected_bit(
                &self.window[..self.window_len],
                cursor - base,
                stop - base,
                allocated,
            ) {
                return Ok(Some(base + bit));
            }
            cursor = stop;
        }
        Ok(None)
    }
    fn padding_bits(&mut self, _domain: u64) -> Result<u32, Refusal> {
        self.ensure_byte(self.needed - 1)?;
        Ok(self.padding)
    }
}

fn reconcile<B: BitmapAccess>(
    domain: u64,
    bitmap: &mut B,
    intervals: &[PhysicalInterval],
    limits: Limits,
) -> Result<Consistency, Refusal> {
    if domain == 0 {
        return Err(Refusal::EmptyDomain);
    }
    if domain > limits.max_cluster_checks {
        return Err(Refusal::BudgetExceeded("cluster checks"));
    }
    let needed = usize::try_from(domain.div_ceil(8))
        .map_err(|_| Refusal::BudgetExceeded("bitmap addressability"))?;
    if needed > limits.max_bitmap_bytes || bitmap.byte_len() > limits.max_bitmap_bytes {
        return Err(Refusal::BudgetExceeded("bitmap bytes"));
    }
    if bitmap.byte_len() != needed {
        return Err(Refusal::BitmapLength {
            expected: needed,
            actual: bitmap.byte_len(),
        });
    }
    if intervals.len() > limits.max_intervals {
        return Err(Refusal::BudgetExceeded("interval count"));
    }
    let sort_bytes = intervals
        .len()
        .checked_mul(std::mem::size_of::<usize>())
        .ok_or(Refusal::BudgetExceeded("sorting storage"))?;
    if sort_bytes > limits.max_sort_bytes {
        return Err(Refusal::BudgetExceeded("sorting storage"));
    }
    let mut name_units = 0usize;
    for (input, interval) in intervals.iter().enumerate() {
        let key = &interval.owner;
        if key.record_number > 0x0000_ffff_ffff_ffff
            || key.sequence_number == 0
            || key.type_code == 0
            || !key.type_code.is_multiple_of(16)
            || key.name_utf16.len() > 255
        {
            return Err(Refusal::InvalidOwner { input });
        }
        name_units = name_units
            .checked_add(key.name_utf16.len())
            .ok_or(Refusal::BudgetExceeded("attribute name units"))?;
        if name_units > limits.max_total_name_units {
            return Err(Refusal::BudgetExceeded("attribute name units"));
        }
        if interval.clusters == 0 {
            return Err(Refusal::EmptyInterval { input });
        }
        let end = interval
            .lcn_start
            .checked_add(interval.clusters)
            .ok_or(Refusal::Overflow {
                input,
                coordinate: "LCN",
            })?;
        interval
            .vcn_start
            .checked_add(interval.clusters)
            .ok_or(Refusal::Overflow {
                input,
                coordinate: "VCN",
            })?;
        if end > domain {
            return Err(Refusal::OutsideDomain { input });
        }
    }
    let mut order = Vec::new();
    order
        .try_reserve_exact(intervals.len())
        .map_err(|_| Refusal::AllocationFailed)?;
    let actual_sort_bytes = order
        .capacity()
        .checked_mul(std::mem::size_of::<usize>())
        .ok_or(Refusal::BudgetExceeded("sorting storage"))?;
    if actual_sort_bytes > limits.max_sort_bytes {
        return Err(Refusal::BudgetExceeded("sorting storage"));
    }
    order.extend(0..intervals.len());
    order.sort_unstable_by(|&a, &b| {
        intervals[a]
            .owner
            .cmp(&intervals[b].owner)
            .then(intervals[a].vcn_start.cmp(&intervals[b].vcn_start))
            .then(a.cmp(&b))
    });
    let mut distinct_attributes = usize::from(!order.is_empty());
    for pair in order.windows(2) {
        let (a, b) = (&intervals[pair[0]], &intervals[pair[1]]);
        if a.owner == b.owner {
            if a.vcn_start + a.clusters > b.vcn_start {
                return Err(Refusal::VcnOverlap {
                    first: pair[0],
                    second: pair[1],
                });
            }
        } else {
            distinct_attributes += 1;
        }
    }
    order.sort_unstable_by_key(|&i| (intervals[i].lcn_start, i));
    for pair in order.windows(2) {
        let (a, b) = (&intervals[pair[0]], &intervals[pair[1]]);
        if a.lcn_start + a.clusters > b.lcn_start {
            return Err(Refusal::PhysicalOverlap {
                first: pair[0],
                second: pair[1],
                lcn: b.lcn_start,
            });
        }
    }
    let mut cursor = 0u64;
    let mut allocated = 0u64;
    for &input in &order {
        let interval = &intervals[input];
        if let Some(lcn) = bitmap.mismatch(cursor, interval.lcn_start, false)? {
            return Err(Refusal::AllocatedUnowned { lcn });
        }
        let end = interval.lcn_start + interval.clusters;
        if let Some(lcn) = bitmap.mismatch(interval.lcn_start, end, true)? {
            return Err(Refusal::ClaimedFree { input, lcn });
        }
        allocated += interval.clusters;
        cursor = end;
    }
    if let Some(lcn) = bitmap.mismatch(cursor, domain, false)? {
        return Err(Refusal::AllocatedUnowned { lcn });
    }
    let padding_bits_set = bitmap.padding_bits(domain)?;
    Ok(Consistency {
        domain_clusters: domain,
        allocated_clusters: allocated,
        free_clusters: domain - allocated,
        physical_intervals: intervals.len(),
        distinct_attributes,
        bitmap_bytes_checked: needed,
        cluster_checks: domain,
        padding_bits_set,
        sorting_storage_bytes: actual_sort_bytes,
    })
}
