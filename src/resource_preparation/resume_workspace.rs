//! Explicit current working-volume selection; never source or replay authority.
use anyhow::{Context,Result,ensure};
use n2r_win32::{discovery::{self,Role},general_layout::GeneralSourceShadowBinding,
    journal_file::GeneralJournalStorageBinding};
use std::{fs::OpenOptions,os::windows::fs::{OpenOptionsExt,MetadataExt},path::{Path,Component}};

pub(crate) fn discover(parent:&Path,pair:&GeneralSourceShadowBinding)->Result<GeneralJournalStorageBinding>{
    ensure!(parent.is_absolute()&&!parent.components().any(|p|matches!(p,Component::CurDir|Component::ParentDir)),
        "resume workspace must be an existing absolute ordinary directory");
    let mut handles=Vec::new();
    for p in parent.ancestors(){
        let file=OpenOptions::new().access_mode(0x80).share_mode(3).custom_flags(0x02200000).open(p)?;
        let meta=file.metadata()?;
        ensure!(meta.is_dir()&&meta.file_attributes()&0x400==0,"resume workspace reparse ancestry refused");
        handles.push(file);
    }
    let file=handles.first().context("workspace handle absent")?;
    let before=n2r_win32::file_storage::file_id_info(file)?;
    let route=n2r_win32::file_storage::final_path_guid(file)?;
    let end=route.find("}\\").context("workspace has no native volume root")?+2;
    let current=discovery::discover(&route[..end],Role::Journal{allow_additional_partitions:true})?;
    ensure!(current.read_only&&current.observed_twice_unchanged&&current.source_write_requests==0
        &&matches!(current.filesystem.as_str(),"NTFS"|"ReFS"),"workspace native discovery is incomplete");
    for data in [&pair.source,&pair.shadow]{
        ensure!(current.binding.disk_number!=data.disk_number
            &&n2r_win32::layout::guid_bytes(&current.binding.identity.disk_guid)?!=n2r_win32::layout::guid_bytes(&data.identity.disk_guid)?
            &&n2r_win32::layout::guid_bytes(&current.binding.volume_guid)?!=n2r_win32::layout::guid_bytes(&data.volume_guid)?,
            "resume workspace aliases the original source or shadow");
    }
    ensure!(n2r_win32::file_storage::file_id_info(file)?==before
        &&n2r_win32::file_storage::final_path_guid(file)?==route,"workspace directory changed during discovery");
    let binding=GeneralJournalStorageBinding{externally_enrolled_disk_unique_id:format!("gpt-{}",
        current.binding.identity.disk_guid.trim_matches(['{','}'])),disk:current.binding,allow_additional_partitions:true};
    binding.validate()?;
    Ok(binding)
}
