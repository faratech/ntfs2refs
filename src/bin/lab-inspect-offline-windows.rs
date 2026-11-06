//! Read-only metadata planning. No freeze, conversion or raw source writer.
#[cfg(windows)]
fn main()->anyhow::Result<()>{
    std::thread::Builder::new().name("offline-Windows-inspection".into()).stack_size(8<<20)
        .spawn(run)?.join().map_err(|_|anyhow::anyhow!("Windows source inspection panicked"))?
}
#[cfg(not(windows))]
fn main(){eprintln!("offline Windows inspection requires Windows");std::process::exit(1);}
#[cfg(windows)]
fn run()->anyhow::Result<()>{
    use anyhow::{Context,ensure};use clap::Parser;use sha2::{Digest,Sha256};
    use std::{io::Read,fs::OpenOptions,path::PathBuf,os::windows::fs::OpenOptionsExt};
    #[derive(Parser)]struct Args{
        #[arg(long)]binding:PathBuf,#[arg(long)]binding_sha256:String,#[arg(long)]output:PathBuf,
        #[arg(long)]ram_bytes:u64,#[arg(long)]scratch_bytes:u64,
    }
    let args=Args::parse();
    let available=n2r_win32::resource_native::observe_available_resources(args.output.parent().context("output parent absent")?)?;
    ensure!(args.ram_bytes<=available.available_physical_bytes,"total inspector RAM exceeds observed availability");
    let mut file=OpenOptions::new().read(true).share_mode(1).custom_flags(0x0020_0000).open(&args.binding)?;
    let identity=n2r_win32::reference_file::observe_reference_file_handle_with_limit(&file,16384)?;
    ensure!(identity.file_bytes>0&&identity.file_bytes<=16384&&identity.number_of_links==1,"bounded ordinary binding required");
    let mut bytes=Vec::new();(&mut file).take(16385).read_to_end(&mut bytes)?;
    ensure!(bytes.len() as u64==identity.file_bytes&&hex::encode(Sha256::digest(&bytes))==args.binding_sha256,"binding bytes or hash differ");
    ensure!(n2r_win32::reference_file::observe_reference_file_handle_with_limit(&file,16384)?==identity,"binding identity changed");
    let binding=serde_json::from_slice(&bytes)?;
    let ram=args.ram_bytes.checked_sub(64<<20).context("RAM must cover launcher and native observations")?;
    let budget=n2r_win32::tree_resources::ResourceBudget{schema_version:1,ram_bytes:ram,scratch_bytes:args.scratch_bytes,
        page_bytes:4<<20,max_row_bytes:(ram/64).min(args.scratch_bytes/16),retained_index_bytes:ram/4,handle_slots:128};
    let observation=n2r_win32::partition_isolation::PartitionObservationBudget{
        ram_bytes:32<<20,native_layout_bytes:65536,gpt_entry_bytes:16384,read_buffer_bytes:4<<20};
    ntfs2refs::boot_source::inspect(binding,budget,observation,&args.output)
}
