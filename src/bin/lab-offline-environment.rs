//! Read-only native PE/environment observations. JSON goes to caller-owned
//! stdout; this program never creates an output file or opens a source writer.
#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    std::thread::Builder::new()
        .name("offline-environment-observer".into())
        .stack_size(8 * 1024 * 1024)
        .spawn(run)?
        .join()
        .map_err(|_| anyhow::anyhow!("readonly environment observer panicked"))?
}
#[cfg(not(windows))]
fn main() {
    eprintln!("offline environment observation requires Windows");
    std::process::exit(1);
}
#[cfg(windows)]
fn run() -> anyhow::Result<()> {
    use anyhow::{Context, ensure};
    use clap::Parser;
    use n2r_win32::{
        general_layout::GeneralDiskBinding,
        offline_environment::{self, ProbeBudget, SourceQuery},
    };
    use serde::Serialize;
    use sha2::{Digest, Sha256};
    use std::{
        fs::OpenOptions,
        io::{self, Read, Write},
        os::windows::fs::OpenOptionsExt,
        path::PathBuf,
    };
    #[derive(Parser)]
    struct Args {
        #[arg(long)]
        ram_bytes: u64,
        #[arg(long)]
        maximum_output_bytes: u64,
        #[arg(long)]
        maximum_component_bytes: u64,
        #[arg(long)]
        source_volume: Option<String>,
        #[arg(long, requires = "source_binding_sha256")]
        source_binding: Option<PathBuf>,
        #[arg(long, requires = "source_binding")]
        source_binding_sha256: Option<String>,
        #[arg(long)]
        query_vss: bool,
        /// Require a current native RAM-Windows owner proof. This does not
        /// open the selected source filesystem or issue write authority.
        #[arg(long, requires = "source_binding")]
        require_offline_owner: bool,
    }
    let args = Args::parse();
    const STACKS: u64 = 9 * 1024 * 1024;
    ensure!(
        args.ram_bytes <= offline_environment::available_ram_bytes()?,
        "total probe RAM exceeds current sampled availability"
    );
    let workspace = args
        .ram_bytes
        .checked_sub(STACKS)
        .context("RAM must cover8MiBworker+1MiBlauncher")?;
    // Facts and proof remain alive together through serialization. Reserve
    // distinct workspaces rather than admitting both against the same RAM.
    let facts_workspace = if args.require_offline_owner {
        workspace / 2
    } else {
        workspace
    };
    let budget = ProbeBudget {
        ram_bytes: facts_workspace,
        maximum_json_bytes: args.maximum_output_bytes,
        maximum_component_bytes: args.maximum_component_bytes,
    };
    budget.validate()?;
    let mut binding = None;
    if let Some(path) = &args.source_binding {
        let pin = args
            .source_binding_sha256
            .as_deref()
            .context("binding checksum absent")?;
        ensure!(
            pin.len() == 64
                && pin
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "independently supplied canonical binding SHA256 required"
        );
        let mut file = OpenOptions::new()
            .read(true)
            .share_mode(1)
            .custom_flags(0x0020_0000)
            .open(path)?;
        n2r_win32::file_storage::require_readonly_access(&file)?;
        let maximum = budget.ram_bytes / 64;
        let before =
            n2r_win32::reference_file::observe_reference_file_handle_with_limit(&file, maximum)?;
        ensure!(
            before.file_bytes > 0 && before.number_of_links == 1,
            "ordinary bounded single-link binding file required"
        );
        let modified = file.metadata()?.modified()?;
        let mut bytes = Vec::new();
        (&mut file)
            .take(
                before
                    .file_bytes
                    .checked_add(1)
                    .context("binding length overflow")?,
            )
            .read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() as u64 == before.file_bytes && hex::encode(Sha256::digest(&bytes)) == pin,
            "actual held binding checksum/length differs"
        );
        ensure!(
            n2r_win32::reference_file::observe_reference_file_handle_with_limit(&file, maximum)?
                == before
                && file.metadata()?.modified()? == modified,
            "binding changed during read"
        );
        let decoded: GeneralDiskBinding = serde_json::from_slice(&bytes)?;
        decoded.validate()?;
        binding = Some(decoded);
    }
    let selected = args.source_volume.map(|volume_path| SourceQuery {
        volume_path,
        expected_binding: binding.clone(),
    });
    let observed = offline_environment::observe(budget, selected.as_ref(), args.query_vss)?;
    let mut owner_events = Vec::new();
    let mut owner_error = None;
    let mut owner = None;
    if args.require_offline_owner {
        use n2r_win32::partition_isolation::{PartitionObservationBudget, PartitionSourceBinding};
        let proof_budget = PartitionObservationBudget {
            ram_bytes: workspace - facts_workspace,
            native_layout_bytes: 65536,
            gpt_entry_bytes: 131072,
            read_buffer_bytes: 4096,
        };
        let result = offline_environment::OfflineOwningEnvironment::observe_and_require(
            PartitionSourceBinding {
                storage: binding.context("offline owner requires an exact source binding")?,
            },
            proof_budget,
            &mut owner_events,
        )
        .and_then(|mut actual| {
            actual.require_current(&mut owner_events)?;
            Ok(actual)
        });
        match result {
            Ok(actual) => owner = Some(actual),
            Err(error) => owner_error = Some((error.raw_os_error(), error.to_string())),
        }
    }
    #[derive(Serialize)]
    struct Output<'a> {
        kind: &'static str,
        total_admitted_ram_bytes: u64,
        execution_stack_reservation_bytes: u64,
        binding_input_sha256: Option<&'a str>,
        observation: &'a offline_environment::Observation,
        stdout_destination_owned_by_caller: bool,
        source_or_output_file_writes: u64,
        offline_owner_requested: bool,
        offline_owner_facts: Option<&'a offline_environment::OfflineOwningFacts>,
        offline_owner_error: Option<&'a (Option<i32>, String)>,
        offline_owner_events: &'a [n2r_win32::NativeEvent],
        exported_facts_grant_write_authority: bool,
    }
    let value = Output {
        kind: "lab-offline-environment-observation-v1",
        total_admitted_ram_bytes: args.ram_bytes,
        execution_stack_reservation_bytes: STACKS,
        binding_input_sha256: args.source_binding_sha256.as_deref(),
        observation: &observed,
        stdout_destination_owned_by_caller: true,
        source_or_output_file_writes: 0,
        offline_owner_requested: args.require_offline_owner,
        offline_owner_facts: owner.as_ref().map(|actual| actual.facts()),
        offline_owner_error: owner_error.as_ref(),
        offline_owner_events: &owner_events,
        exported_facts_grant_write_authority: false,
    };
    struct Count(u64);
    impl Write for Count {
        fn write(&mut self, b: &[u8]) -> io::Result<usize> {
            self.0 = self
                .0
                .checked_add(b.len() as u64)
                .ok_or_else(|| io::Error::other("JSON size overflow"))?;
            Ok(b.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let mut count = Count(0);
    serde_json::to_writer(&mut count, &value)?;
    ensure!(
        count
            .0
            .checked_add(1)
            .is_some_and(|n| n <= args.maximum_output_bytes),
        "collected JSON exceeds explicit output budget"
    );
    let stdout = io::stdout();
    let mut output = io::BufWriter::with_capacity(65536, stdout.lock());
    serde_json::to_writer(&mut output, &value)?;
    output.write_all(b"\n")?;
    output.flush()?;
    ensure!(
        !args.require_offline_owner || owner.is_some(),
        "native offline owning environment was not established; inspect the emitted refusal"
    );
    Ok(())
}
