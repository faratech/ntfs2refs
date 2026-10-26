//! Owning-guest import of the pinned reference packet and strict writer overlay.
//! This experiment is separate from NTFS conversion and never links its writer.
use crate::{general_qualification as artifacts, refs_reference_transport as transport};
use anyhow::{Context, Result, ensure};
use n2r_win32::reference_import::{self as native, Binding, FreshReferenceDisk};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, OpenOptions},
    io::{Cursor, Read, Seek, SeekFrom, Write},
    os::windows::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub schema_version: u32,
    pub binding: Binding,
    pub packet_path: PathBuf,
    pub packet_sha256: String,
    pub cow_path: PathBuf,
    pub cow_sha256: String,
    pub trace_path: PathBuf,
    pub trace_sha256: String,
}
fn hash(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}
fn canonical(p: &str) -> bool {
    p.len() == 64
        && p.bytes()
            .all(|v| v.is_ascii_digit() || (b'a'..=b'f').contains(&v))
}
fn pinned(path: &Path, pin: &str, limit: u64) -> Result<Vec<u8>> {
    ensure!(canonical(pin), "canonical SHA-256 pin required");
    let text = path
        .to_str()
        .context("ordinary Unicode input path required")?;
    ensure!(
        text.get(..3) == Some("C:\\")
            && !text[3..].contains(':')
            && !text.contains(['/', '\0'])
            && path
                .components()
                .all(|p| !matches!(p, std::path::Component::ParentDir)),
        "ordinary absolute C input required"
    );
    for parent in path.ancestors().skip(1) {
        let m = fs::symlink_metadata(parent)?;
        ensure!(
            m.is_dir() && m.file_attributes() & 0x400 == 0,
            "input has nonordinary ancestry"
        );
    }
    let m = fs::symlink_metadata(path)?;
    ensure!(
        m.is_file() && m.len() <= limit && m.file_attributes() & 0x400 == 0,
        "bounded ordinary input required"
    );
    let mut f = OpenOptions::new()
        .read(true)
        .share_mode(1)
        .custom_flags(0x00200000)
        .open(path)?;
    let m = f.metadata()?;
    ensure!(
        m.is_file() && m.len() <= limit && m.file_attributes() & 0x400 == 0,
        "opened input differs"
    );
    let mut b = vec![];
    (&mut f).take(limit + 1).read_to_end(&mut b)?;
    ensure!(
        b.len() as u64 <= limit && hash(&b) == pin,
        "input SHA-256 differs"
    );
    Ok(b)
}
pub fn load_request(path: &Path, pin: &str) -> Result<Request> {
    let r: Request = serde_json::from_slice(&pinned(path, pin, 16384)?)?;
    r.validate()?;
    Ok(r)
}
impl Request {
    pub fn validate(&self) -> Result<()> {
        self.binding.validate()?;
        ensure!(
            self.schema_version == 1
                && [&self.packet_sha256, &self.cow_sha256, &self.trace_sha256]
                    .into_iter()
                    .all(|p| canonical(p)),
            "reference import request differs"
        );
        Ok(())
    }
}
struct Patch {
    offset: u64,
    old: String,
    new: String,
    data: Vec<u8>,
}
fn word64(b: &[u8], at: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(
        b.get(at..at + 8)
            .context("truncated overlay u64")?
            .try_into()?,
    ))
}
fn word32(b: &[u8], at: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(
        b.get(at..at + 4)
            .context("truncated overlay u32")?
            .try_into()?,
    ))
}
fn fnv(offset: u64, data: &[u8]) -> u32 {
    offset
        .to_le_bytes()
        .iter()
        .chain(data)
        .fold(2166136261u32, |h, b| {
            (h ^ u32::from(*b)).wrapping_mul(16777619)
        })
}
fn patches(cow: &[u8], trace: &[u8], packet: &transport::ReferencePacket) -> Result<Vec<Patch>> {
    ensure!(
        cow.len() == 131280
            && &cow[..8] == b"N2RCOW01"
            && word64(cow, 8)? == native::PARTITION_BYTES,
        "exact eight-page overlay framing differs"
    );
    let lines = std::str::from_utf8(trace)?;
    let mut intents = vec![];
    let mut readbacks = vec![];
    for (number, line) in lines.lines().enumerate() {
        ensure!(number < 64 && line.len() <= 2048, "trace bound exceeded");
        let v: serde_json::Value = serde_json::from_str(line)?;
        if number == 0 {
            ensure!(
                v["format"] == "n2r-refsnt-strict-io-v1"
                    && v["image_bytes"].as_u64() == Some(native::PARTITION_BYTES)
                    && v["protected_offset"].as_u64() == Some(native::PAYLOAD_OFFSET)
                    && v["protected_length"].as_u64() == Some(native::PAYLOAD_BYTES),
                "trace header differs"
            );
        }
        match v["op"].as_str() {
            Some("write-intent") => intents.push(v),
            Some("write-readback") => readbacks.push(v),
            _ => {}
        }
    }
    ensure!(
        intents.len() == 8 && readbacks.len() == 8,
        "eight complete traced page writes required"
    );
    let mut result: Vec<Patch> = vec![];
    let mut at = 16;
    let mut base = packet.reader();
    let mut previous_seq = 0;
    for (index, intent) in intents.into_iter().enumerate() {
        ensure!(
            &cow[at..at + 8] == b"N2RREC01",
            "overlay record signature differs"
        );
        let offset = word64(cow, at + 8)?;
        let length = word32(cow, at + 16)? as usize;
        let checksum = word32(cow, at + 20)?;
        at += 24;
        ensure!(
            length == 16384
                && offset.is_multiple_of(4096)
                && offset
                    .checked_add(length as u64)
                    .is_some_and(|e| e <= native::PARTITION_BYTES)
                && !(offset < native::PAYLOAD_OFFSET + native::PAYLOAD_BYTES
                    && native::PAYLOAD_OFFSET < offset + length as u64),
            "overlay range/protected payload differs"
        );
        let data = cow
            .get(at..at + length)
            .context("truncated overlay page")?
            .to_vec();
        at += length;
        let old = intent["old_sha256"]
            .as_str()
            .context("old page hash absent")?;
        let new = intent["new_sha256"]
            .as_str()
            .context("new page hash absent")?;
        let seq = intent["seq"].as_u64().context("trace sequence absent")?;
        ensure!(
            canonical(old)
                && canonical(new)
                && hash(&data) == new
                && fnv(offset, &data) == checksum
                && seq > previous_seq
                && intent["offset"].as_u64() == Some(offset)
                && intent["length"].as_u64() == Some(length as u64),
            "overlay/trace/hash differ"
        );
        previous_seq = seq;
        let readback = &readbacks[index];
        ensure!(
            readback["offset"].as_u64() == Some(offset)
                && readback["length"].as_u64() == Some(length as u64)
                && readback["seq"].as_u64().is_some_and(|v| v > seq),
            "trace readback differs"
        );
        ensure!(
            result
                .iter()
                .all(|p| offset >= p.offset + p.data.len() as u64
                    || p.offset >= offset + length as u64),
            "overlapping overlay pages refused"
        );
        let mut before = vec![0; length];
        base.seek(SeekFrom::Start(native::PARTITION_OFFSET + offset))?;
        base.read_exact(&mut before)?;
        ensure!(
            hash(&before) == old,
            "overlay old page differs from reference packet"
        );
        result.push(Patch {
            offset,
            old: old.into(),
            new: new.into(),
            data,
        });
    }
    ensure!(at == cow.len(), "trailing overlay bytes");
    Ok(result)
}
fn save_bytes(root: &Path, name: &str, b: &[u8]) -> Result<()> {
    ensure!(b.len() <= 16384, "request copy exceeds bound");
    let mut f = OpenOptions::new()
        .create_new(true)
        .write(true)
        .share_mode(0)
        .custom_flags(0x00200000)
        .open(root.join(name))?;
    f.write_all(b)?;
    f.sync_all()?;
    Ok(())
}
pub fn run(request: &Request, output: &Path, handoff: bool) -> Result<()> {
    run_profile(request, output, handoff, false)
}
/// Lab control that imports the unmodified Windows reference rather than
/// applying the strict writer overlay. It retains every blank/import gate.
pub fn run_profile(
    request: &Request,
    output: &Path,
    handoff: bool,
    baseline_only: bool,
) -> Result<()> {
    request.validate()?;
    let packet_bytes = pinned(
        &request.packet_path,
        &request.packet_sha256,
        transport::MAX_PACKET_BYTES,
    )?;
    let packet = transport::decode(&mut Cursor::new(&packet_bytes))?;
    let selection = &packet.header.selection;
    ensure!(
        selection.disk_bytes == native::DISK_BYTES
            && selection.partition_offset == native::PARTITION_OFFSET
            && selection.partition_bytes == native::PARTITION_BYTES
            && selection.payload_offset == native::PAYLOAD_OFFSET
            && selection.payload_bytes == native::PAYLOAD_BYTES
            && selection.fixed_vhd_sha256
                == "b671d327fba46dc371b65a0e20d631525db13af02fa85e9c797412cba58269b7"
            && selection.partition_sha256
                == "805eecc9f17436bac644b2b774e96896ace8af2aec8c66dcaf6c3bbb8e4be0c9"
            && selection.payload_sha256
                == "6234f364d8fb1b532234405c7e2bb1c8e08337ef7fc6e4138f80c8b3d9411786",
        "reference profile differs from pinned Windows corpus"
    );
    let patches = if baseline_only {
        vec![]
    } else {
        let cow = pinned(&request.cow_path, &request.cow_sha256, 131280)?;
        let trace = pinned(&request.trace_path, &request.trace_sha256, 65536)?;
        patches(&cow, &trace, &packet)?
    };
    let writer_metadata_bytes = patches.iter().map(|p| p.data.len() as u64).sum::<u64>();
    artifacts::create_output(output)?;
    save_bytes(output, "request.json", &serde_json::to_vec_pretty(request)?)?;
    artifacts::save(
        output,
        "intent.json",
        &serde_json::json!({"kind":"restricted-reference-import-intent","packet_sha256":request.packet_sha256,"cow_sha256":request.cow_sha256,"trace_sha256":request.trace_sha256,"baseline_only":baseline_only,"overlay_inputs_consumed":!baseline_only,"adopted_file_expected":!baseline_only,"handoff_requested":handoff,"native_writer_qualified":false,"ntfs_conversion":false}),
    )?;
    let mut phase = "blank-disk-proof";
    let attempted = (|| -> Result<()> {
        let mut disk = FreshReferenceDisk::open_blank(request.binding.clone())?;
        artifacts::save(output, "blank-disk.json", &disk.state()?)?;
        phase = "reference-chunks";
        for chunk in packet.chunks() {
            disk.write_reference_chunk(chunk.offset, chunk.data())?;
        }
        phase = "complete-import-hash";
        let proof = disk.verify_reference(
            &packet.summary.disk_sha256,
            &selection.payload_sha256,
            &selection.fixed_vhd_sha256,
            &hex::decode(&packet.header.fixed_footer_hex)?,
        )?;
        artifacts::save(output, "import.json", &proof)?;
        phase = if baseline_only {
            "baseline-reference-preparation"
        } else {
            "writer-metadata"
        };
        for (index, patch) in patches.iter().enumerate() {
            artifacts::save(
                output,
                &format!("patch-{index:02}-intent.json"),
                &serde_json::json!({"offset":patch.offset,"length":patch.data.len(),"old_sha256":patch.old,"new_sha256":patch.new}),
            )?;
            disk.apply_metadata_patch(patch.offset, &patch.data, &patch.old, &patch.new)?;
        }
        phase = "prepared-offline";
        let prepared = if baseline_only {
            disk.finish_baseline()?
        } else {
            disk.finish_overlay()?
        };
        artifacts::save(output, "prepared.json", &prepared)?;
        if handoff {
            phase = "explicit-native-handoff";
            let bytes = fs::read(output.join("prepared.json"))?;
            ensure!(
                bytes == serde_json::to_vec_pretty(&prepared)?,
                "persisted prepared proof differs"
            );
            artifacts::save(
                output,
                "handoff-intent.json",
                &serde_json::json!({"kind":"reference-native-handoff-intent","prepared_sha256":hash(&bytes),"baseline_only":baseline_only,"adopted_file_expected":!baseline_only,"only_reference_disk":true,"ntfs_conversion":false}),
            )?;
            let state = disk.handoff(&prepared)?;
            artifacts::save(output, "handoff.json", &state)?;
        }
        disk.restore_privileges()?;
        artifacts::save(
            output,
            "result.json",
            &serde_json::json!({"kind":"restricted-reference-import","success":true,"baseline_only":baseline_only,"overlay_inputs_consumed":!baseline_only,"adopted_file_expected":!baseline_only,"imported_disk_sha256":proof.disk_sha256,"reference_bytes_written":proof.reference_bytes_written,"writer_metadata_bytes":writer_metadata_bytes,"writer_metadata_pages":patches.len(),"payload_sha256":proof.payload_sha256,"writer_payload_writes":0,"handoff_performed":handoff,"native_writer_qualified":false,"ntfs_conversion_qualified":false}),
        )?;
        Ok(())
    })();
    if let Err(error) = attempted {
        artifacts::save(
            output,
            "failed.json",
            &serde_json::json!({"kind":"restricted-reference-import-failure","phase":phase,"baseline_only":baseline_only,"error":format!("{error:#}"),"automatic_retry":false,"native_writer_qualified":false}),
        )?;
        return Err(error);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[ignore = "requires pinned N2R_REFERENCE_PACKET and N2R_REFERENCE_OVERLAY_DIR; ordinary-file reads only"]
    fn pinned_overlay_binds_every_old_and_new_page_without_device_access() {
        let packet_bytes = fs::read(std::env::var("N2R_REFERENCE_PACKET").unwrap()).unwrap();
        assert_eq!(
            hash(&packet_bytes),
            "585df94c07190bcd3476a596ee870d1c3e60d793d03d9d4d3bd545780f23df5b"
        );
        let packet = transport::decode(&mut Cursor::new(&packet_bytes)).unwrap();
        let root = PathBuf::from(std::env::var("N2R_REFERENCE_OVERLAY_DIR").unwrap());
        let cow = fs::read(root.join("final-metadata.cow")).unwrap();
        let trace = fs::read(root.join("io.jsonl")).unwrap();
        assert_eq!(
            hash(&cow),
            "d25e7b8ec70256a47159a30c78b436ffcd525c00fc4ec4c34f1a533c6feb7eaf"
        );
        let accepted = patches(&cow, &trace, &packet).unwrap();
        assert_eq!(accepted.len(), 8);
        assert_eq!(accepted.iter().map(|p| p.data.len()).sum::<usize>(), 131072);
        let mut damaged = cow.clone();
        damaged[40] ^= 1;
        assert!(patches(&damaged, &trace, &packet).is_err());
        let mut oversized = cow.clone();
        oversized[32..36].copy_from_slice(&32768u32.to_le_bytes());
        assert!(patches(&oversized, &trace, &packet).is_err());
        let mut payload = cow.clone();
        payload[24..32].copy_from_slice(&native::PAYLOAD_OFFSET.to_le_bytes());
        assert!(patches(&payload, &trace, &packet).is_err());
        let mut trace_values: Vec<serde_json::Value> = std::str::from_utf8(&trace)
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        trace_values
            .iter_mut()
            .find(|v| v["op"] == "write-intent")
            .unwrap()["old_sha256"] = "0".repeat(64).into();
        let altered = trace_values
            .iter()
            .map(|v| serde_json::to_string(v).unwrap())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(patches(&cow, altered.as_bytes(), &packet).is_err());
    }
}
