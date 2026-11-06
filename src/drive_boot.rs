//! Build-specific boot compatibility checks. These are routing/preservation
//! requirements; only the existing native source issuer authorizes writes.
use anyhow::{Result,Context,ensure};
use n2r_win32::general_layout::{GeneralDiskBinding,GeneralDiskLayoutProfile};
use sha2::{Digest,Sha256};
use std::{fs::{File,OpenOptions},io::{Read,Seek,SeekFrom},os::windows::fs::{OpenOptionsExt,MetadataExt},path::Path};

pub(super) fn validate(binding:&GeneralDiskBinding)->Result<()> {
    ensure!(binding.layout_profile==GeneralDiskLayoutProfile::OfflineWindows,"offline Windows topology required");
    let root=std::path::PathBuf::from(binding.volume_path()?+"\\Windows");
    let current=n2r_win32::current_windows_directory()?;
    let mut held=Vec::new();
    for relative in ["","System32","System32\\drivers","System32\\config"] {
        let path=root.join(relative);
        let file=OpenOptions::new().access_mode(0x80).share_mode(3).custom_flags(0x0220_0000).open(path)?;
        let meta=file.metadata()?;
        ensure!(meta.is_dir()&&meta.file_attributes()&0x400==0,"offline Windows directories must be ordinary bound directories");
        held.push(file);
    }
    for (relative,expected) in [
        ("System32\\winload.efi","1c1a978448b8e0fc2284c13d6e55fde8bf9827dca432cdc8a9be66c2e729adda"),
        ("System32\\drivers\\refs.sys","3aa5d90958fc582c5f6567d2b970a3a37b3d4d80a4b58b5a8676943b7860d3c4"),
    ] {
        ensure!(hash(&root.join(relative))?==expected,
            "offline Windows {relative} is outside the demonstrated Windows 11 boot profile");
    }
    ensure!(hash(&root.join("System32\\ntoskrnl.exe"))?==hash(&current.join("System32\\ntoskrnl.exe"))?,
        "offline and recovery Windows kernels differ; this boot profile requires matching builds");
    for name in ["SYSTEM","SOFTWARE"] {
        let mut file=ordinary(&root.join("System32\\config").join(name))?;
        let mut magic=[0;4];file.read_exact(&mut magic)?;
        ensure!(magic==*b"regf","offline Windows {name} is not a registry hive");
    }
    println!("Offline Windows boot profile: demonstrated Windows 11 loader/ReFS driver; matching recovery kernel.");
    println!("The running Windows disk remains excluded. EFI, MSR and WinRE partitions are preserved.");
    Ok(())
}
fn ordinary(path:&Path)->Result<File>{
    let file=OpenOptions::new().read(true).share_mode(1).custom_flags(0x0020_0000).open(path)?;
    let meta=file.metadata()?;
    ensure!(meta.is_file()&&meta.len()>0&&meta.file_attributes()&0x400==0,"ordinary offline Windows component required");
    Ok(file)
}
fn hash(path:&Path)->Result<String>{
    let mut file=ordinary(path)?;let before=file.metadata()?;
    ensure!(before.len()<=32<<20,"boot component exceeds the bounded profile");
    let mut magic=[0;2];file.read_exact(&mut magic)?;ensure!(magic==*b"MZ","Windows executable header differs");file.seek(SeekFrom::Start(0))?;
    let mut hash=Sha256::new();let mut buffer=[0;65536];let mut count=0u64;
    loop{let n=file.read(&mut buffer)?;if n==0{break;}count=count.checked_add(n as u64).context("boot hash length overflow")?;ensure!(count<=before.len(),"boot component grew");hash.update(&buffer[..n]);}
    let after=file.metadata()?;
    ensure!(count==before.len()&&after.len()==before.len()&&after.modified()?==before.modified()?,"boot component changed during hashing");
    Ok(hex::encode(hash.finalize()))
}
