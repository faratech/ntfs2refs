//! Explicit post-V4 retirement of a live bounded thin graph. No recovery,
//! source argument, Drop teardown, arbitrary pool route or cleanup retry.
use super::*;

const CLEANUP_METADATA_RESERVE: u64 = 1 << 20;

#[derive(Debug, Serialize)]
pub struct DetachmentObservation {
    pub provider_virtual_disk_id: String,
    pub disk_number: u32,
    pub attempted: bool,
    pub loaded_before: Option<bool>,
    pub loaded_after: Option<bool>,
    pub detached_observed: bool,
}

#[derive(Debug, Serialize)]
pub struct ThinShadowRetirementReceipt {
    pub schema_version: u32,
    pub kind: &'static str,
    pub backing_profile: &'static str,
    pub provider_root: PathBuf,
    pub shadow: GeneralDiskBinding,
    pub pool_unique_id: String,
    pub virtual_disk_unique_id: String,
    pub success: bool,
    pub phase: String,
    pub error: Option<String>,
    pub native_error: Option<i32>,
    pub frozen_shadow_attributes: Option<u64>,
    pub virtual_disk_removed_observed: bool,
    pub pool_removed_observed: bool,
    pub members: Vec<DetachmentObservation>,
    pub carrier: Option<DetachmentObservation>,
    pub carrier_backing_before_retirement: Option<reference_file::ReferenceFileSnapshot>,
    pub carrier_backing_retirement_requested: bool,
    pub carrier_backing_retired_observed: bool,
    pub source_disk_argument_supplied: bool,
    pub source_payload_io_issued: bool,
    pub recovery_files_retired: bool,
    pub automatic_retry_or_fallback: bool,
    pub cleanup_child_ram_is_sampled_not_a_hard_limit: bool,
    pub physical_freed_bytes_or_ram_reduction_measured: bool,
}

#[derive(Serialize)]
struct Input<'a> {
    schema_version: u32,
    nonce: &'a str,
    subsystem: &'a str,
    pool: &'a PoolRoute,
    members: &'a [MemberRoute],
    member_virtual_bytes: u64,
    shadow: &'a GeneralDiskBinding,
    minimum_free_bytes: u64,
    child_ram_bytes: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Reply {
    schema_version: u32,
    kind: String,
    action: String,
    nonce: String,
    success: bool,
    pool_present: bool,
    virtual_disk_present: bool,
    members: Vec<MemberRoute>,
    error: Option<String>,
    sampled_child_working_set_bytes: u64,
}

struct Graph {
    members: [Member; 2],
    carrier: bounded_carrier::BoundedCarrier,
    target: Option<File>,
    root: PathBuf,
    root_handle: File,
    root_file_id: String,
    root_guid_path: String,
    constructor_script: File,
    script_snapshot: reference_file::ReferenceFileSnapshot,
    subsystem: String,
    nonce: String,
    routes: Vec<MemberRoute>,
    pool: PoolRoute,
    budget: Budget,
    shadow: GeneralDiskBinding,
}

fn admission(root: &Path, budget: Budget) -> io::Result<()> {
    ordinary_root(root)?;
    let available = resource_native::observe_available_resources(root)?;
    let ram = budget
        .rust_ram_bytes
        .checked_add(budget.powershell_ram_bytes)
        .ok_or_else(|| invalid("thin cleanup memory admission overflow"))?;
    let space = budget
        .minimum_free_bytes
        .checked_add(CLEANUP_METADATA_RESERVE)
        .ok_or_else(|| invalid("thin cleanup reserve overflow"))?;
    if ram > available.available_physical_bytes || space > available.scratch_available_bytes {
        return Err(invalid(
            "thin cleanup cannot admit metadata/child RAM while preserving host reserve",
        ));
    }
    Ok(())
}

impl Graph {
    fn verify(&self) -> io::Result<()> {
        ordinary_root(&self.root)?;
        if file_storage::file_id_info(&self.root_handle)? != self.root_file_id
            || file_storage::final_path_guid(&self.root_handle)? != self.root_guid_path
        {
            return Err(invalid("thin retirement root identity changed"));
        }
        same_file(&self.script_snapshot, &self.constructor_script)?;
        for member in &self.members {
            member.revalidate()?;
        }
        self.carrier.verify_retirement_identity()?;
        admission(&self.root, self.budget)
    }

    fn run(&self, action: &str) -> io::Result<Reply> {
        self.verify()?;
        let input = Input {
            schema_version: 1,
            nonce: &self.nonce,
            subsystem: &self.subsystem,
            pool: &self.pool,
            members: &self.routes,
            member_virtual_bytes: self.members[0].attachment.created.size,
            shadow: &self.shadow,
            minimum_free_bytes: self.budget.minimum_free_bytes,
            child_ram_bytes: self.budget.powershell_ram_bytes,
        };
        let input_path = self.root.join(format!("retire-{action}-request.json"));
        let output_path = self.root.join(format!("retire-{action}-result.json"));
        let _input = save(&input_path, &input)?;
        let status = Command::new(powershell_executable()?)
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
            ])
            .arg(self.root.join("thin-retirement.ps1"))
            .arg("-Action")
            .arg(action)
            .arg("-InputPath")
            .arg(&input_path)
            .arg("-OutputPath")
            .arg(&output_path)
            .creation_flags(0x0800_0000)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()?;
        let operation = (|| {
            let mut output = OpenOptions::new()
                .read(true)
                .share_mode(1)
                .custom_flags(0x0020_0000)
                .open(&output_path)?;
            let before =
                reference_file::observe_reference_file_handle_with_limit(&output, RESPONSE_BYTES)?;
            let reply: Reply = serde_json::from_reader((&mut output).take(RESPONSE_BYTES))
                .map_err(io::Error::other)?;
            if reference_file::observe_reference_file_handle_with_limit(&output, RESPONSE_BYTES)?
                != before
                || before.number_of_links != 1
                || !status.success()
                || !reply.success
                || reply.schema_version != 1
                || reply.kind != "owned-thin-retirement-native-phase"
                || reply.nonce != self.nonce
                || reply.action != action
                || reply.members != self.routes
                || reply.sampled_child_working_set_bytes > self.budget.powershell_ram_bytes
            {
                return Err(io::Error::other(format!(
                    "thin retirement {action} refused: {}",
                    reply
                        .error
                        .as_deref()
                        .unwrap_or("native child/identity result differs")
                )));
            }
            let expected = match action {
                "observe" => (true, true),
                "remove-vd" => (true, false),
                "remove-pool" => (false, false),
                _ => return Err(invalid("unknown thin retirement action")),
            };
            if (reply.pool_present, reply.virtual_disk_present) != expected {
                return Err(invalid(
                    "thin retirement native absence was not established",
                ));
            }
            Ok(reply)
        })();
        let closing = self.verify();
        match (operation, closing) {
            (Ok(reply), Ok(())) => Ok(reply),
            (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
            (Err(error), Err(closing)) => Err(io::Error::other(format!(
                "{error}; thin retirement closing also failed: {closing}"
            ))),
        }
    }
}

fn detached_observation(member: &Member) -> DetachmentObservation {
    DetachmentObservation {
        provider_virtual_disk_id: guid_text(&member.attachment.created.id),
        disk_number: member.attachment.number,
        attempted: false,
        loaded_before: None,
        loaded_after: None,
        detached_observed: false,
    }
}

fn loaded(attachment: &AttachedDisk) -> io::Result<bool> {
    let bytes = attachment.query(GET_VIRTUAL_DISK_INFO_IS_LOADED)?;
    if bytes.len() < 12 || layout::u32_at(&bytes, 0)? != GET_VIRTUAL_DISK_INFO_IS_LOADED as u32 {
        return Err(invalid("thin retirement loaded-state response differs"));
    }
    match layout::u32_at(&bytes, 8)? {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(invalid("thin retirement loaded-state boolean differs")),
    }
}

fn detach(member: &Member, observation: &mut DetachmentObservation) -> io::Result<()> {
    member.revalidate()?;
    let before = loaded(&member.attachment)?;
    observation.loaded_before = Some(before);
    if !before {
        return Err(invalid(
            "original owned provider was not loaded before retirement",
        ));
    }
    observation.attempted = true;
    // SAFETY: the exact retained constructor-created provider handle. There is
    // one attempt, no alternate open, no source, wildcard or forced detach.
    win(unsafe {
        DetachVirtualDisk(
            member.attachment.created.handle.0,
            DETACH_VIRTUAL_DISK_FLAG_NONE,
            0,
        )
    })?;
    member.attachment.verify_provider()?;
    let after = loaded(&member.attachment)?;
    observation.loaded_after = Some(after);
    if after {
        return Err(invalid(
            "original owned provider remains loaded after retirement",
        ));
    }
    same_file(&member.snapshot, &member.backing)?;
    observation.detached_observed = true;
    Ok(())
}

impl FormattedThinShadow {
    /// Explicitly consume a completed V4 shadow. The caller must first finish
    /// HND/native finalization and release all scoped tree/raw borrowers. Any
    /// failure is observational and leaves converted source/recovery alone.
    pub fn retire_after_successful_v4(self) -> ThinShadowRetirementReceipt {
        let (owner, shadow) = self.into_retirement_parts();
        let mut receipt = ThinShadowRetirementReceipt {
            schema_version: 1,
            kind: "owned-bounded-thin-post-v4-retirement",
            backing_profile: owner.observation.backing_profile,
            provider_root: owner.root.clone(),
            shadow: shadow.clone(),
            pool_unique_id: owner.pool.unique_id.clone(),
            virtual_disk_unique_id: owner.pool.virtual_unique_id.clone(),
            success: false,
            phase: "verify-owned-frozen-graph".into(),
            error: None,
            native_error: None,
            frozen_shadow_attributes: None,
            virtual_disk_removed_observed: false,
            pool_removed_observed: false,
            members: owner._members.iter().map(detached_observation).collect(),
            carrier: None,
            carrier_backing_before_retirement: None,
            carrier_backing_retirement_requested: false,
            carrier_backing_retired_observed: false,
            source_disk_argument_supplied: false,
            source_payload_io_issued: false,
            recovery_files_retired: false,
            automatic_retry_or_fallback: false,
            cleanup_child_ram_is_sampled_not_a_hard_limit: true,
            physical_freed_bytes_or_ram_reduction_measured: false,
        };
        match retire(owner, shadow, &mut receipt) {
            Ok(()) => receipt.success = true,
            Err(error) => {
                receipt.native_error = error.raw_os_error();
                receipt.error = Some(error.to_string());
            }
        }
        receipt
    }
}

fn retire(
    owner: ThinPool,
    shadow: GeneralDiskBinding,
    receipt: &mut ThinShadowRetirementReceipt,
) -> io::Result<()> {
    if owner.carrier.is_none() {
        return Err(invalid(
            "graph retirement currently requires its constructor-owned bounded carrier",
        ));
    }
    if shadow.disk_number != owner.pool.number || shadow.identity.disk_bytes != owner.pool.bytes {
        return Err(invalid(
            "formatted shadow differs from its original thin provider",
        ));
    }
    let native = native_disk(&owner._disk, owner.pool.number, owner.pool.bytes)?;
    shadow.validate_layout(&native.layout)?;
    shadow.validate_alignment(&native.alignment)?;
    let mut events = Vec::new();
    let frozen = native::observe_general_disk_state_readonly(shadow.clone(), &mut events)?;
    receipt.frozen_shadow_attributes = Some(frozen.disk_attributes);
    if frozen.disk_attributes != 3 {
        return Err(invalid("owned thin shadow is not frozen OFFLINE|READ_ONLY"));
    }
    let ThinPool {
        _members,
        _root_handle,
        _script,
        _disk,
        root,
        root_file_id,
        root_guid_path,
        subsystem,
        nonce,
        budget,
        routes,
        pool,
        script_snapshot,
        carrier,
        ..
    } = owner;
    let mut graph = Graph {
        members: _members,
        carrier: carrier.unwrap(),
        target: Some(_disk),
        root,
        root_handle: _root_handle,
        root_file_id,
        root_guid_path,
        constructor_script: _script,
        script_snapshot,
        subsystem,
        nonce,
        routes,
        pool,
        budget,
        shadow,
    };
    graph.verify()?;
    let _retirement_script =
        save_bytes(&graph.root.join("thin-retirement.ps1"), SCRIPT.as_bytes())?;
    graph.run("observe")?;
    let mut privileges = Privileges::enable_for(&["SeManageVolumePrivilege"])?;
    // Close only the retained VD raw handle. Other scoped conversion owners
    // must already have returned; sharing errors from CIM are not bypassed.
    drop(graph.target.take());
    receipt.phase = "remove-exact-owned-virtual-disk".into();
    graph.run("remove-vd")?;
    receipt.virtual_disk_removed_observed = true;
    receipt.phase = "remove-exact-owned-storage-pool".into();
    graph.run("remove-pool")?;
    receipt.pool_removed_observed = true;
    for (index, member) in graph.members.iter().enumerate() {
        receipt.phase = format!("detach-original-member-{index}");
        detach(member, &mut receipt.members[index])?;
    }
    let Graph {
        members, carrier, ..
    } = graph;
    drop(members); // Close detached member provider/backing files inside carrier.
    receipt.phase = "close-carrier-inner-handles".into();
    let carrier = carrier.into_retirement_member()?;
    receipt.carrier = Some(detached_observation(&carrier));
    receipt.phase = "detach-original-bounded-carrier".into();
    detach(&carrier, receipt.carrier.as_mut().unwrap())?;
    privileges.restore()?;
    let Member {
        attachment,
        backing,
        snapshot: identity,
        path,
    } = carrier;
    drop(attachment);
    drop(backing);
    receipt.phase = "open-exact-detached-carrier-backing".into();
    ordinary_root(
        path.parent()
            .ok_or_else(|| invalid("carrier backing parent absent"))?,
    )?;
    let delete = OpenOptions::new()
        .access_mode(0x80 | 0x10000)
        .share_mode(0)
        .custom_flags(0x0020_0000)
        .open(&path)?;
    same_file(&identity, &delete)?;
    receipt.carrier_backing_before_retirement = Some(file_snapshot(&delete)?);
    receipt.phase = "retire-exact-carrier-backing".into();
    file_storage::mark_delete_on_close(&delete)?;
    receipt.carrier_backing_retirement_requested = true;
    drop(delete);
    receipt.phase = "observe-exact-carrier-retired".into();
    match fs::symlink_metadata(&path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
        Ok(_) => return Err(invalid("carrier backing retirement not observed complete")),
    }
    receipt.carrier_backing_retired_observed = true;
    receipt.phase = "complete".into();
    Ok(())
}

const SCRIPT: &str = r#"
param([ValidateSet('observe','remove-vd','remove-pool')][string]$Action,[string]$InputPath,[string]$OutputPath)
Set-StrictMode -Version Latest;$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
function Need([bool]$ok,[string]$message){if(-not$ok){throw $message}}
$request=$null;$reader=$null;$members=@();$success=$false;$failure=$null;$poolPresent=$true;$virtualPresent=$true
try{
 $file=[IO.File]::Open($InputPath,'Open','Read','Read');try{Need ($file.Length-gt0-and$file.Length-le131072) 'Bounded owned retirement input required';$reader=[IO.StreamReader]::new($file,[Text.UTF8Encoding]::new($false,$true));$request=$reader.ReadToEnd()|ConvertFrom-Json}finally{if($null-ne$reader){$reader.Dispose()}else{$file.Dispose()}}
 Need ($request.schema_version-eq1-and$request.members.Count-eq2-and$request.nonce-cmatch'\A[0-9a-f-]{36}\z') 'Exact live graph input required'
 function Sample{Need ((Get-Process -Id $PID).WorkingSet64-le$request.child_ram_bytes) 'Cleanup child sampled RAM share exceeded';Need ((Get-Volume -FilePath $InputPath).SizeRemaining-ge$request.minimum_free_bytes+1048576) 'Cleanup host reserve breached'}
 Sample
 $sub=@(Get-StorageSubSystem -UniqueId $request.subsystem);Need ($sub.Count-eq1-and$sub[0].UniqueId-ceq$request.subsystem-and$sub[0].FriendlyName-like'Windows Storage*') 'Exact storage subsystem changed'
 $allPools=@(Get-StoragePool -StorageSubSystem $sub[0]);Need ($allPools.Count-le4096) 'Storage pool domain exceeds cleanup admission'
 $selected=@($allPools|Where-Object{$_.UniqueId-ceq$request.pool.unique_id-and$_.ObjectId-ceq$request.pool.object_id})
 Need ($selected.Count-eq1-and-not$selected[0].IsPrimordial-and$selected[0].FriendlyName-ceq('n2r-private-pool-'+$request.nonce)) 'Exact owned private pool absent or changed';$pool=$selected[0]
 foreach($pinned in $request.members){$p=@(Get-PhysicalDisk -UniqueId $pinned.unique_id);Need ($p.Count-eq1-and$p[0].UniqueId-ceq$pinned.unique_id-and$p[0].ObjectId-ceq$pinned.object_id-and$p[0].Size-eq$request.member_virtual_bytes-and$p[0].LogicalSectorSize-eq512-and$p[0].PhysicalSectorSize-eq4096) 'Exact constructor-owned physical member changed';$members+=,@{number=[uint32]$pinned.number;unique_id=[string]$p[0].UniqueId;object_id=[string]$p[0].ObjectId}}
 function ExactMembership{$actual=@(Get-PhysicalDisk -StoragePool $pool);Need ($actual.Count-eq2) 'Foreign/missing pool member';foreach($pinned in $request.members){Need (@($actual|Where-Object{$_.UniqueId-ceq$pinned.unique_id-and$_.ObjectId-ceq$pinned.object_id}).Count-eq1) 'Owned pool member association changed'}}
 ExactMembership
 $virtual=@(Get-VirtualDisk -StoragePool $pool)
 if($Action-cne'remove-pool'){
  Need ($virtual.Count-eq1-and$virtual[0].UniqueId-ceq$request.pool.virtual_unique_id-and$virtual[0].ObjectId-ceq$request.pool.virtual_object_id-and$virtual[0].FriendlyName-ceq('n2r-private-thin-'+$request.nonce)-and$virtual[0].ProvisioningType.ToString()-ceq'Thin'-and$virtual[0].Size-eq$request.pool.bytes) 'Exact owned thin virtual disk changed'
  $disk=@(Get-Disk -VirtualDisk $virtual[0]);Need ($disk.Count-eq1-and$disk[0].Number-eq$request.shadow.disk_number-and$disk[0].UniqueId-ceq$request.pool.disk_unique_id-and[guid]$disk[0].Guid-eq[guid]$request.shadow.identity.disk_guid-and$disk[0].Size-eq$request.shadow.identity.disk_bytes-and-not$disk[0].IsBoot-and-not$disk[0].IsSystem-and$disk[0].IsOffline-and$disk[0].IsReadOnly) 'Owned thin disk is not the exact frozen shadow'
 }else{Need ($virtual.Count-eq0) 'Owned pool still contains a virtual disk';$virtualPresent=$false}
 if($Action-ceq'remove-vd'){
  Sample
  Remove-VirtualDisk -InputObject $virtual[0] -Confirm:$false
  Need (@(Get-VirtualDisk -StoragePool $pool).Count-eq0) 'Owned virtual disk removal not observed';$virtualPresent=$false
  ExactMembership
 }
 if($Action-ceq'remove-pool'){
  Sample
  Remove-StoragePool -InputObject $pool -Confirm:$false
  $remaining=@(Get-StoragePool -StorageSubSystem $sub[0]);Need ($remaining.Count-le4096-and@($remaining|Where-Object{$_.UniqueId-ceq$request.pool.unique_id-or$_.ObjectId-ceq$request.pool.object_id}).Count-eq0) 'Owned pool removal not observed';$poolPresent=$false
  foreach($pinned in $request.members){$p=@(Get-PhysicalDisk -UniqueId $pinned.unique_id);Need ($p.Count-eq1-and$p[0].ObjectId-ceq$pinned.object_id) 'Original member disappeared after pool removal';foreach($other in $remaining|Where-Object{-not$_.IsPrimordial}){Need (@(Get-PhysicalDisk -StoragePool $other|Where-Object{$_.UniqueId-ceq$pinned.unique_id}).Count-eq0) 'Original member remains claimed by a pool'}}
 }
 Sample;$success=$true
}catch{$failure=$_.Exception.Message;if($failure.Length-gt2048){$failure=$failure.Substring(0,2048)}}
$working=[uint64](Get-Process -Id $PID).WorkingSet64
$result=@{schema_version=1;kind='owned-thin-retirement-native-phase';action=$Action;nonce=if($null-eq$request){''}else{[string]$request.nonce};success=$success;pool_present=$poolPresent;virtual_disk_present=$virtualPresent;members=@($members);error=$failure;sampled_child_working_set_bytes=$working}
$bytes=[Text.UTF8Encoding]::new($false).GetBytes(($result|ConvertTo-Json -Depth 8 -Compress));Need ($bytes.Length-le131072) 'Retirement native result exceeds bound'
$file=[IO.File]::Open($OutputPath,'CreateNew','Write','Read');try{$file.Write($bytes,0,$bytes.Length);$file.Flush($true)}finally{$file.Dispose()}
if(-not$success){exit 1}
"#;
