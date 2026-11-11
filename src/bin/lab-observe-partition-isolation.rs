//! Read-only native observation of an explicitly pinned data partition.
//! No source lock, offline operation, activation, recovery, or payload writer.
#[cfg(not(windows))]
fn main() {
    eprintln!("partition observation requires Windows");
    std::process::exit(1);
}

#[cfg(windows)]
fn main() {
    if let Err(error) = run() {
        eprintln!("partition observation: {error}");
        std::process::exit(1);
    }
}
#[cfg(windows)]
fn run() -> std::io::Result<()> {
    use n2r_win32::partition_isolation::{
        PartitionObservationBudget, PartitionScopedReader, PartitionSourceBinding,
    };
    use serde::{Deserialize, Serialize};
    use sha2::{Digest, Sha256};
    use std::{
        fs::{self, OpenOptions},
        io::{self, BufWriter, Read, Seek, SeekFrom, Write},
        os::windows::fs::{MetadataExt, OpenOptionsExt},
        path::{Path, PathBuf},
    };
    fn bad(message: &str) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidData, message)
    }
    fn need(value: bool, message: &str) -> io::Result<()> {
        if value { Ok(()) } else { Err(bad(message)) }
    }
    fn ordinary_parents(path: &Path) -> io::Result<()> {
        need(
            path.is_absolute()
                && !path.components().any(|v| {
                    matches!(
                        v,
                        std::path::Component::CurDir | std::path::Component::ParentDir
                    )
                }),
            "absolute ordinary path required",
        )?;
        for parent in path
            .parent()
            .ok_or_else(|| bad("parent absent"))?
            .ancestors()
        {
            let meta = fs::symlink_metadata(parent)?;
            need(
                meta.is_dir() && meta.file_attributes() & 0x400 == 0,
                "redirected ancestor refused",
            )?;
        }
        Ok(())
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Request {
        binding: PartitionSourceBinding,
        budget: PartitionObservationBudget,
        read_offset: u64,
        read_bytes: u64,
    }
    let mut args = std::env::args_os().skip(1);
    let mut request = None;
    let mut pin = None;
    let mut output = None;
    let mut request_limit = None;
    while let Some(key) = args.next() {
        let key = key.to_str().ok_or_else(|| bad("UTF-8 option required"))?;
        let value = args.next().ok_or_else(|| bad("option value absent"))?;
        match key {
            "--request" => {
                need(request.is_none(), "duplicate request")?;
                request = Some(PathBuf::from(value));
            }
            "--request-sha256" => {
                need(pin.is_none(), "duplicate pin")?;
                pin = Some(value.into_string().map_err(|_| bad("UTF-8 pin required"))?);
            }
            "--output" => {
                need(output.is_none(), "duplicate output")?;
                output = Some(PathBuf::from(value));
            }
            "--request-budget-bytes" => {
                need(request_limit.is_none(), "duplicate request budget")?;
                request_limit = Some(
                    value
                        .into_string()
                        .map_err(|_| bad("numeric budget required"))?
                        .parse::<u64>()
                        .map_err(|_| bad("numeric budget required"))?,
                );
            }
            _ => {
                return Err(bad(
                    "use --request PATH --request-sha256 SHA --output NEW_PATH --request-budget-bytes BYTES",
                ));
            }
        }
    }
    let request = request.ok_or_else(|| bad("request required"))?;
    let pin = pin.ok_or_else(|| bad("external pin required"))?;
    let output = output.ok_or_else(|| bad("new metadata output required"))?;
    let request_limit = request_limit.ok_or_else(|| bad("explicit request budget required"))?;
    need(
        request_limit > 0
            && request_limit <= usize::MAX as u64
            && pin.len() == 64
            && pin
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "canonical pin and addressable request budget required",
    )?;
    ordinary_parents(&request)?;
    ordinary_parents(&output)?;
    let mut file = OpenOptions::new()
        .read(true)
        .share_mode(1)
        .custom_flags(0x0020_0000)
        .open(&request)?;
    let snapshot =
        n2r_win32::reference_file::observe_reference_file_handle_with_limit(&file, request_limit)?;
    let modified = file.metadata()?.modified()?;
    need(
        snapshot.file_bytes > 0 && snapshot.number_of_links == 1,
        "ordinary single-link request required",
    )?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(
            usize::try_from(snapshot.file_bytes).map_err(|_| bad("request size overflow"))?,
        )
        .map_err(io::Error::other)?;
    (&mut file)
        .take(
            snapshot
                .file_bytes
                .checked_add(1)
                .ok_or_else(|| bad("request length overflow"))?,
        )
        .read_to_end(&mut bytes)?;
    need(
        bytes.len() as u64 == snapshot.file_bytes && hex::encode(Sha256::digest(&bytes)) == pin,
        "request differs from external pin",
    )?;
    let parsed: Request = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
    drop(bytes);
    parsed.budget.validate()?;
    need(
        parsed.read_bytes > 0
            && parsed.read_bytes <= u64::from(parsed.budget.read_buffer_bytes)
            && parsed
                .read_offset
                .checked_add(parsed.read_bytes)
                .is_some_and(|end| end <= parsed.binding.storage.identity.partition_bytes),
        "bounded partition-relative read required",
    )?;
    let mut events = Vec::new();
    let metadata_destination = n2r_win32::partition_isolation::metadata_destination_outside_source(
        &parsed.binding,
        output
            .parent()
            .ok_or_else(|| bad("metadata output parent absent"))?,
        &mut events,
    )?;
    let mut source = PartitionScopedReader::open(parsed.binding, parsed.budget, &mut events)?;
    source.revalidate(&mut events)?;
    source.seek(SeekFrom::Start(parsed.read_offset))?;
    let mut data = Vec::new();
    data.try_reserve_exact(parsed.read_bytes as usize)
        .map_err(io::Error::other)?;
    data.resize(parsed.read_bytes as usize, 0);
    source.read_exact(&mut data)?;
    let digest = hex::encode(Sha256::digest(&data));
    drop(data);
    source.revalidate(&mut events)?;
    file.seek(SeekFrom::Start(0))?;
    need(
        n2r_win32::reference_file::observe_reference_file_handle_with_limit(&file, request_limit)?
            == snapshot
            && file.metadata()?.modified()? == modified
            && hex::encode(n2r_win32::sha256_native::hash_range(
                &mut file,
                0,
                snapshot.file_bytes,
            )?) == pin,
        "held request changed during native observation",
    )?;
    #[derive(Serialize)]
    struct Report<'a> {
        schema_version: u32,
        kind: &'static str,
        request_sha256: &'a str,
        observation: &'a n2r_win32::partition_isolation::PartitionIsolationObservation,
        metadata_destination: &'a n2r_win32::partition_isolation::PartitionVolumeExtent,
        read_offset: u64,
        read_bytes: u64,
        read_sha256: &'a str,
        partition_payload_native_bytes_read: u64,
        native_events: &'a [n2r_win32::NativeEvent],
        dump_configuration_collected: bool,
        conversion_qualified: bool,
        isolation_requests: u64,
        source_write_requests: u64,
        raw_source_payload_exported: bool,
        serialized_facts_grant_authority: bool,
    }
    let report = Report {
        schema_version: 1,
        kind: "native-partition-scoped-readonly-observation",
        request_sha256: &pin,
        observation: source.observation(),
        metadata_destination: &metadata_destination,
        read_offset: parsed.read_offset,
        read_bytes: parsed.read_bytes,
        read_sha256: &digest,
        partition_payload_native_bytes_read: source.native_bytes_read(),
        native_events: &events,
        dump_configuration_collected: false,
        conversion_qualified: false,
        isolation_requests: 0,
        source_write_requests: 0,
        raw_source_payload_exported: false,
        serialized_facts_grant_authority: false,
    };
    let mut out = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&output)?;
    {
        let mut writer =
            BufWriter::with_capacity(parsed.budget.read_buffer_bytes as usize, &mut out);
        serde_json::to_writer(&mut writer, &report).map_err(io::Error::other)?;
        writer.flush()?;
    }
    out.write_all(b"\n")?;
    out.sync_all()?;
    println!(
        "{}",
        serde_json::json!({"kind":"native-partition-observation-complete","output":output,"read_sha256":digest,
        "source_write_requests":0,"isolation_requests":0,"conversion_qualified":false})
    );
    Ok(())
}
