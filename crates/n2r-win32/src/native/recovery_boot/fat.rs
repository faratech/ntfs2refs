//! Read-only FAT32 namespace/chain check for the CURRENT installed BCD file.
//! A stale but valid raw hive at a former allocation cannot satisfy this check.
use super::*;
use metadata::{EfiIdentity, StorePin};
use std::collections::BTreeSet;
struct Fat<'a> {
    file: &'a mut File,
    base: u64,
    end: u64,
    sector: u64,
    cluster: u64,
    reserved: u64,
    fat_sectors: u64,
    data: u64,
    total_clusters: u64,
    root: u32,
    boot_sha256: [u8; 32],
    used: u64,
    limit: u64,
    cached: [Option<(u64, Vec<u8>)>; 2],
}
impl<'a> Fat<'a> {
    fn open(
        file: &'a mut File,
        efi: &EfiIdentity,
        expected: [u8; 32],
        limit: u64,
    ) -> io::Result<Self> {
        Self::open_with_live_epoch(file, efi, expected, None, limit)
    }
    fn open_with_live_epoch(
        file: &'a mut File,
        efi: &EfiIdentity,
        expected: [u8; 32],
        second_live_epoch: Option<[u8; 32]>,
        limit: u64,
    ) -> io::Result<Self> {
        let base = efi.binding.identity.partition_offset;
        let end = base
            .checked_add(efi.binding.identity.partition_bytes)
            .ok_or_else(|| bad("EFI end overflow"))?;
        let mut boot = vec![0; efi.binding.identity.logical_sector_bytes as usize];
        file.seek(SeekFrom::Start(base))?;
        file.read_exact(&mut boot)?;
        let observed = digest(&boot);
        let signature_valid = boot.len() >= 512 && boot[510..512] == [0x55, 0xaa];
        let fat32_tag_valid = boot.len() >= 512 && &boot[82..90] == b"FAT32   ";
        let boot_matches = if let Some(second) = second_live_epoch {
            // Windows fastfat uses FAT32 CurrentHead (offset 0x41) for its
            // transient dirty flag. The available-source caller must hold the
            // actual available disk/EFI identity proof. Every other bit stays covered by
            // BOTH full-sector pins; no normalized hash replaces either pin.
            // Test-surface (0x02) and all unknown flag bits remain refusals.
            if boot.len() >= 512 && matches!(boot[65], 0 | 1) {
                if observed == expected && observed == second {
                    true
                } else {
                    let mut alternate = boot.clone();
                    alternate[65] ^= 1;
                    let alternate_sha256 = digest(&alternate);
                    (observed == expected || alternate_sha256 == expected)
                        && (observed == second || alternate_sha256 == second)
                }
            } else {
                false
            }
        } else {
            observed == expected
        };
        if !boot_matches || !signature_valid || !fat32_tag_valid {
            // Capture the exact failing read, without a second read, retry,
            // mutable-bit exception or replacement of the authenticated hash.
            return Err(bad(&format!(
                "current EFI FAT32 boot sector differs: expected_sha256={}, observed_sha256={}, partition_offset={base}, logical_sector_bytes={}, signature_valid={signature_valid}, fat32_tag_valid={fat32_tag_valid}, observed_boot_hex={}",
                hex::encode(expected),
                hex::encode(observed),
                boot.len(),
                hex::encode(&boot)
            )));
        }
        let sector = u64::from(u16::from_le_bytes(
            boot[11..13].try_into().map_err(io::Error::other)?,
        ));
        let spc = u64::from(boot[13]);
        let reserved = u64::from(u16::from_le_bytes(
            boot[14..16].try_into().map_err(io::Error::other)?,
        ));
        let fats = u64::from(boot[16]);
        let fat_sectors = u64::from(layout::u32_at(&boot, 36)?);
        let total = u64::from(layout::u32_at(&boot, 32)?);
        let flags = u16::from_le_bytes(boot[40..42].try_into().map_err(io::Error::other)?);
        let version = u16::from_le_bytes(boot[42..44].try_into().map_err(io::Error::other)?);
        let data_sector = reserved
            .checked_add(
                fats.checked_mul(fat_sectors)
                    .ok_or_else(|| bad("FAT sector multiplication overflow"))?,
            )
            .ok_or_else(|| bad("FAT data sector overflow"))?;
        need(
            sector == u64::from(efi.binding.identity.logical_sector_bytes)
                && spc.is_power_of_two()
                && spc <= 128
                && reserved > 0
                && fats == 2
                && fat_sectors > 0
                && boot[17..19] == [0, 0]
                && boot[22..24] == [0, 0]
                && flags & 0x80 == 0
                && version == 0
                && total > data_sector
                && total
                    .checked_mul(sector)
                    .is_some_and(|n| n <= efi.binding.identity.partition_bytes),
            "bounded mirrored FAT32 EFI geometry required",
        )?;
        let cluster = spc
            .checked_mul(sector)
            .ok_or_else(|| bad("FAT cluster overflow"))?;
        need(
            cluster <= 65536,
            "FAT directory cluster exceeds admitted metadata buffer",
        )?;
        let total_clusters = (total - data_sector) / spc;
        let root = layout::u32_at(&boot, 44)? & 0x0fff_ffff;
        need(
            total_clusters >= 65525
                && total_clusters + 2 <= fat_sectors * sector / 4
                && u64::from(root) >= 2
                && u64::from(root) < total_clusters + 2,
            "complete FAT32 root/cluster geometry invalid",
        )?;
        Ok(Self {
            file,
            base,
            end,
            sector,
            cluster,
            reserved,
            fat_sectors,
            data: data_sector * sector,
            total_clusters,
            root,
            boot_sha256: observed,
            used: sector,
            limit,
            cached: [None, None],
        })
    }
    fn read(&mut self, relative: u64, bytes: u64) -> io::Result<Vec<u8>> {
        need(
            relative.is_multiple_of(self.sector)
                && bytes > 0
                && bytes.is_multiple_of(self.sector)
                && self
                    .base
                    .checked_add(relative)
                    .and_then(|p| p.checked_add(bytes))
                    .is_some_and(|n| n <= self.end),
            "FAT metadata read outside aligned EFI bounds",
        )?;
        self.used = self
            .used
            .checked_add(bytes)
            .ok_or_else(|| bad("FAT metadata read charge overflow"))?;
        need(
            self.used <= self.limit,
            "FAT metadata read budget exhausted",
        )?;
        let mut out = vec![0; usize::try_from(bytes).map_err(io::Error::other)?];
        self.file.seek(SeekFrom::Start(self.base + relative))?;
        self.file.read_exact(&mut out)?;
        Ok(out)
    }
    fn cluster_offset(&self, c: u32) -> io::Result<u64> {
        need(
            c >= 2 && u64::from(c) < self.total_clusters + 2,
            "FAT chain cluster outside data area",
        )?;
        self.data
            .checked_add(
                (u64::from(c) - 2)
                    .checked_mul(self.cluster)
                    .ok_or_else(|| bad("FAT chain multiplication overflow"))?,
            )
            .ok_or_else(|| bad("FAT chain offset overflow"))
    }
    fn next(&mut self, c: u32) -> io::Result<Option<u32>> {
        self.cluster_offset(c)?;
        let at = u64::from(c) * 4;
        let mut values = [0; 2];
        for copy in 0..2 {
            let sector = self.reserved + (copy as u64) * self.fat_sectors + at / self.sector;
            if !self.cached[copy].as_ref().is_some_and(|v| v.0 == sector) {
                let bytes = self.read(sector * self.sector, self.sector)?;
                self.cached[copy] = Some((sector, bytes));
            }
            let data = &self.cached[copy]
                .as_ref()
                .ok_or_else(|| bad("FAT sector cache missing"))?
                .1;
            values[copy] = layout::u32_at(data, (at % self.sector) as usize)? & 0x0fff_ffff;
        }
        need(values[0] == values[1], "current mirrored FAT chain differs")?;
        let n = values[0];
        if n >= 0x0fff_fff8 {
            return Ok(None);
        }
        need(
            n >= 2 && n < 0x0fff_fff0,
            "current BCD FAT chain free/bad/reserved",
        )?;
        self.cluster_offset(n)?;
        Ok(Some(n))
    }
    fn find(&mut self, start: u32, name: &str, directory: bool) -> io::Result<(u32, u64)> {
        let mut current = Some(start);
        let mut seen = BTreeSet::new();
        let mut found = None;
        let mut lfn: Option<(u8, u8, Vec<u16>)> = None;
        while let Some(c) = current {
            need(
                seen.insert(c) && seen.len() as u64 <= self.limit / self.cluster,
                "FAT directory chain repeats/exceeds bound",
            )?;
            let block = self.read(self.cluster_offset(c)?, self.cluster)?;
            for e in block.chunks_exact(32) {
                if e[0] == 0 {
                    return found.ok_or_else(|| bad("current FAT BCD namespace component absent"));
                }
                if e[0] == 0xe5 {
                    lfn = None;
                    continue;
                }
                if e[11] == 0x0f {
                    let n = e[0] & 0x1f;
                    if !(1..=20).contains(&n) || e[12] != 0 || e[26..28] != [0, 0] {
                        lfn = None;
                        continue;
                    }
                    if e[0] & 0x40 != 0 {
                        lfn = Some((n, e[13], vec![0xffff; usize::from(n) * 13]));
                    }
                    if let Some((next, sum, units)) = &mut lfn {
                        if *next != n || *sum != e[13] {
                            lfn = None;
                            continue;
                        }
                        let offsets = [1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30];
                        for (i, at) in offsets.iter().enumerate() {
                            units[(usize::from(n) - 1) * 13 + i] =
                                u16::from_le_bytes([e[*at], e[*at + 1]]);
                        }
                        *next -= 1;
                    }
                    continue;
                }
                let checksum = e[..11]
                    .iter()
                    .fold(0u8, |sum, b| sum.rotate_right(1).wrapping_add(*b));
                let long = lfn.take().and_then(|(next, sum, units)| {
                    if next != 0 || sum != checksum {
                        return None;
                    }
                    let end = units.iter().position(|v| *v == 0).unwrap_or(units.len());
                    if units[..end].contains(&0xffff)
                        || units[end..].iter().any(|v| !matches!(*v, 0 | 0xffff))
                    {
                        return None;
                    }
                    String::from_utf16(&units[..end]).ok()
                });
                if e[11] & 8 != 0 {
                    continue;
                }
                let short = if e[..11].is_ascii() {
                    let first = String::from_utf8_lossy(&e[..8]).trim_end().to_owned();
                    let ext = String::from_utf8_lossy(&e[8..11]).trim_end().to_owned();
                    Some(if ext.is_empty() {
                        first
                    } else {
                        format!("{first}.{ext}")
                    })
                } else {
                    None
                };
                if !long
                    .as_deref()
                    .is_some_and(|v| v.eq_ignore_ascii_case(name))
                    && !short
                        .as_deref()
                        .is_some_and(|v| v.eq_ignore_ascii_case(name))
                {
                    continue;
                }
                need(
                    found.is_none() && (e[11] & 0x10 != 0) == directory,
                    "current FAT BCD namespace duplicate/type mismatch",
                )?;
                let cluster = (u32::from(u16::from_le_bytes(
                    e[20..22].try_into().map_err(io::Error::other)?,
                )) << 16)
                    | u32::from(u16::from_le_bytes(
                        e[26..28].try_into().map_err(io::Error::other)?,
                    ));
                self.cluster_offset(cluster)?;
                found = Some((cluster, u64::from(layout::u32_at(e, 28)?)));
            }
            current = self.next(c)?;
        }
        found.ok_or_else(|| bad("current FAT BCD namespace component absent"))
    }
}
pub(super) fn boot_sha(file: &mut File, efi: &EfiIdentity) -> io::Result<[u8; 32]> {
    let mut bytes = vec![0; efi.binding.identity.logical_sector_bytes as usize];
    file.seek(SeekFrom::Start(efi.binding.identity.partition_offset))?;
    file.read_exact(&mut bytes)?;
    Ok(digest(&bytes))
}
pub(super) fn require_current_map(
    file: &mut File,
    efi: &EfiIdentity,
    pin: &StorePin,
    limit: u64,
) -> io::Result<()> {
    let fat = Fat::open(file, efi, pin.fat_boot_sha256, limit)?;
    require_current_map_inner(fat, efi, pin, limit)
}
/// Only the positively available/live EFI lane may select this comparison.
/// Protected/offline callers continue to use exact `require_current_map`.
pub(super) fn require_current_map_live(
    file: &mut File,
    efi: &EfiIdentity,
    pin: &StorePin,
    limit: u64,
) -> io::Result<()> {
    let fat = Fat::open_with_live_epoch(
        file,
        efi,
        pin.fat_boot_sha256,
        Some(pin.fat_boot_sha256),
        limit,
    )?;
    require_current_map_inner(fat, efi, pin, limit)
}
/// Bind two recorded complete VBR epochs to ONE actual sector read. Both must
/// match all bytes except the documented transient dirty bit; return the full
/// observed digest unchanged. This routine performs no write or retry.
pub(super) fn require_live_boot(
    file: &mut File,
    efi: &EfiIdentity,
    first_full_sha256: [u8; 32],
    second_full_sha256: [u8; 32],
    limit: u64,
) -> io::Result<[u8; 32]> {
    need(
        u64::from(efi.binding.identity.logical_sector_bytes) <= limit,
        "live EFI boot-sector read exceeds metadata budget",
    )?;
    let fat = Fat::open_with_live_epoch(
        file,
        efi,
        first_full_sha256,
        Some(second_full_sha256),
        limit,
    )?;
    Ok(fat.boot_sha256)
}
fn require_current_map_inner(
    mut fat: Fat<'_>,
    efi: &EfiIdentity,
    pin: &StorePin,
    limit: u64,
) -> io::Result<()> {
    let mut current = fat.root;
    for name in ["EFI", "Microsoft", "Boot"] {
        current = fat.find(current, name, true)?.0;
    }
    let (first, bytes) = fat.find(current, "BCD", false)?;
    need(
        bytes == pin.bytes && bytes > 0,
        "current installed BCD directory EOF changed",
    )?;
    let mut current = Some(first);
    let mut covered = 0;
    let mut seen = BTreeSet::new();
    while let Some(c) = current {
        need(
            seen.insert(c) && seen.len() as u64 <= limit / 4,
            "BCD FAT allocation chain repeats/exceeds bound",
        )?;
        let at = efi
            .binding
            .identity
            .partition_offset
            .checked_add(fat.cluster_offset(c)?)
            .ok_or_else(|| bad("current BCD physical addition overflow"))?;
        let n = fat.cluster.min(bytes - covered);
        let spans: Vec<_> = pin
            .spans
            .iter()
            .filter(|s| {
                s.file_offset <= covered
                    && s.file_offset
                        .checked_add(s.bytes)
                        .is_some_and(|end| covered + n <= end)
            })
            .collect();
        need(
            n > 0
                && spans.len() == 1
                && spans[0]
                    .physical_offset
                    .checked_add(covered - spans[0].file_offset)
                    == Some(at),
            "current BCD FAT allocation differs from immutable Windows retrieval map",
        )?;
        covered += n;
        current = fat.next(c)?;
        if covered == bytes {
            need(
                current.is_none(),
                "BCD has an unexpected FAT allocation tail",
            )?;
            break;
        }
    }
    need(
        covered == bytes,
        "current BCD FAT allocation does not cover exact file EOF",
    )
}
