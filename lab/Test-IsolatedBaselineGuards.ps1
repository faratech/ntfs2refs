<# Pure synthetic observations and virtual streams only. No VM/device/file/image
   opener, credentials, initialization, formatting, reference import or cleanup. #>
[CmdletBinding()]param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'IsolatedBaselineGuards.psm1') -Force
if (-not ('Ntfs2RefsResearch.IsolatedJournalZero' -as [type])) {
    Add-Type -Path (Join-Path $PSScriptRoot 'guest/IsolatedJournalZero.cs')
}
if (-not ('Ntfs2RefsPureGuards.VirtualZeroStream' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.IO;
namespace Ntfs2RefsPureGuards {
 public sealed class VirtualZeroStream : Stream {
  public long CurrentLength, NonzeroAt = -1, StopAt = -1, Reads, Writes;
  long position; bool closed;
  public VirtualZeroStream(long length) { CurrentLength = length; }
  public override bool CanRead { get { return !closed; } }
  public override bool CanSeek { get { return !closed; } }
  public override bool CanWrite { get { return false; } }
  public override long Length { get { if(closed)throw new ObjectDisposedException("fixture");return CurrentLength; } }
  public override long Position { get { return position; } set { if(value<0)throw new ArgumentOutOfRangeException();position=value; } }
  public override int Read(byte[] buffer,int offset,int count) {
   if(closed)throw new ObjectDisposedException("fixture");
   Reads++; long end=StopAt<0?CurrentLength:Math.Min(CurrentLength,StopAt);
   int n=(int)Math.Min(count,Math.Max(0,end-position));Array.Clear(buffer,offset,n);
   if(NonzeroAt>=position && NonzeroAt<position+n)buffer[offset+(int)(NonzeroAt-position)]=1;
   position+=n;return n;
  }
  public override long Seek(long at,SeekOrigin origin) {
   Position=origin==SeekOrigin.Begin?at:origin==SeekOrigin.Current?position+at:CurrentLength+at;return Position;
  }
  public override void Flush() { throw new InvalidOperationException("Pure fixture must not be flushed."); }
  public override void Write(byte[] b,int o,int n) { Writes++;throw new InvalidOperationException("No writes."); }
  public override void SetLength(long n) { throw new InvalidOperationException("No length setter."); }
  protected override void Dispose(bool disposing) { closed=true;base.Dispose(disposing); }
 }
}
'@
}
$script:checks = 0
function Check([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }; $script:checks++
}
function Reject([scriptblock]$Action, [string]$Message) {
    $refused = $false
    try { & $Action | Out-Null } catch { $refused = $true }
    Check $refused $Message
}
function Clone($Value) { $Value | ConvertTo-Json -Depth 20 | ConvertFrom-Json }
$policy = Get-IsolatedBaselinePolicy
$hostObservation = [pscustomobject]@{
    schema_version=1; kind='isolated-baseline-host-observation'; profile=$policy.profile
    vm=[pscustomobject]@{ id=$policy.vm_id; name=$policy.vm_name; path=$policy.vm_path;
        generation=2; processor_count=4; memory_startup_bytes=8GB; state='Running'; dynamic_memory_enabled=$false;
        network_adapter_count=0; automatic_checkpoints_enabled=$false; checkpoint_count=0;
        tpm_enabled=$true; secure_boot='On'; secure_boot_template='MicrosoftWindows' }
    registered_reference_inventory_complete=$true; disks=@(); registered_references=@()
}
$fakeIds = @($policy.os_vhd_id, $policy.target_vhd_id, $policy.journal_vhd_id)
$fakeFileIds = @($policy.os_file_id, $policy.target_file_id, $policy.journal_file_id)
$roles = @('os', 'target', 'journal')
for ($i=0; $i -lt 3; $i++) {
    $path = $policy.disk_root + '\' + $roles[$i] + '.vhdx'
    $hostObservation.disks += [pscustomobject]@{ role=$roles[$i]; path=$path; file_id=$fakeFileIds[$i]; host_volume_root=$policy.host_volume_root;
        vhd_id=$fakeIds[$i]; virtual_bytes=$(if ($i -eq 2) {8GB} else {64GB}); logical_sector_bytes=512;
        physical_sector_bytes=4096; parent_path=''; reparse_ancestry=$false; hard_link_paths=@($path);
        controller_type='SCSI'; controller_number=0; controller_location=$i }
    $hostObservation.registered_references += [pscustomobject]@{ vm_id=$policy.vm_id; path=$path; host_volume_root=$policy.host_volume_root;
        file_id=$fakeFileIds[$i]; reference_kind='current_attachment'; parent_paths=@();
        controller_type='SCSI'; controller_number=0; controller_location=$i }
}
$raw = [pscustomobject]@{ schema_version=1; kind='isolated-raw-journal-observation'; profile=$policy.profile;
    vm_id=$policy.vm_id; disk_number=2; unique_id=$policy.journal_unique_id; size_bytes=8GB;
    logical_sector_bytes=512; physical_sector_bytes=4096; partition_style='RAW'; partitions=@();
    scsi_port=0;scsi_target_id=0;scsi_lun=2;current_windows_disk_number=0;
    location='Integrated : Adapter 0 : Port 0 : Target 0 : LUN 2';
    disk_guid=''; is_boot=$false; is_system=$false; is_read_only=$false }
$enrollment = [pscustomobject]@{ schema_version=1; kind='isolated-journal-ntfs-enrollment'; profile=$policy.profile;
    vm_id=$policy.vm_id; disk_number=2; unique_id=$policy.journal_unique_id; host_file_id=$policy.journal_file_id;
    size_bytes=8GB; logical_sector_bytes=512; physical_sector_bytes=4096; partition_style='GPT';
    is_boot=$false; is_system=$false; is_offline=$false; is_read_only=$false;
    disk_guid='33333333-3333-3333-3333-333333333333'; partition_guid='44444444-4444-4444-4444-444444444444';
    volume_guid='55555555-5555-5555-5555-555555555555'; partition_number=1; partition_offset=16MB;
    partition_bytes=(8GB-32MB); gpt_type='ebd0a0a2-b9e5-4433-87c0-68b6b72699c7'; filesystem='NTFS';
    allocation_unit_bytes=4096; drive_letter='J';
    access_paths=@('J:\', '\\?\Volume{55555555-5555-5555-5555-555555555555}\') }
$reference = [pscustomobject]@{ schema_version=1; kind='isolated-reference-creation-review'; profile=$policy.profile;
    vm_id=$policy.vm_id; experiment_id=('a'*32); run_id=('b'*32); disk_number=3;
    vhd_path=('J:\ntfs2refs-reference\' + ('a'*32) + '\reference.vhdx');
    persistent_vhd_id='66666666-6666-6666-6666-666666666666'; path_exists=$false; staging_exists=$false;
    staging_directory=($policy.guest_staging_root + '\' + ('b'*32)) }
$plan = [pscustomobject]@{ schema_version=1; kind='isolated-baseline-import-review-plan'; profile=$policy.profile;
    baseline_only=$true; packet_sha256=$policy.packet_sha256; packet_path=($reference.staging_directory+'\reference.packet');
    writer_metadata_pages=0; writer_metadata_bytes=0; writer_payload_writes=0; overlay_inputs=@();
    overlay_inputs_consumed=$false; adopted_file_expected=$false; native_writer_qualified=$false; ntfs_conversion_qualified=$false }

$structure = Assert-IsolatedBaselineStructure $hostObservation
Check ($structure.structural_review_passed -and -not $structure.write_authority) 'Pure structure success must not grant writes.'
$rawReview = Assert-IsolatedRawJournal $hostObservation $raw @()
Check ($rawReview.identity_token -cmatch '\A[0-9a-f]{64}\z' -and -not $rawReview.write_authority -and -not $rawReview.checked_native_origin) 'RAW review scope differs.'
$newJ = Assert-IsolatedJournalEnrollment $hostObservation $enrollment
Check ($newJ.disk_guid -ceq $enrollment.disk_guid -and -not $newJ.write_authority) 'Fresh J: enrollment refused or grants authority.'
$newReference = Assert-IsolatedReferenceBinding $hostObservation $enrollment $reference
Check ($newReference.vhd_path -ceq $reference.vhd_path -and -not $newReference.creation_performed) 'Fresh reference review differs.'
$baseline = Assert-IsolatedBaselineOnlyPlan $hostObservation $enrollment $reference $plan
Check ($baseline.review_plan_only -and -not $baseline.native_write_authority -and -not $baseline.import_performed) 'Baseline review must not execute or grant native authority.'
$nativeReference=[pscustomobject]@{schema_version=1;kind='isolated-reference-native-enrollment';profile=$policy.profile;
    vm_id=$policy.vm_id;persistent_vhd_id=$reference.persistent_vhd_id;vhd_path=$reference.vhd_path;disk_number=3;
    physical_path='\\.\PhysicalDrive3';virtual_bytes=64GB;block_bytes=2MB;logical_sector_bytes=512;physical_sector_bytes=4096;
    vhd_type='Dynamic';parent_path='';initial_backing_bytes=4MB;partition_style='RAW';partitions=@();
    is_boot=$false;is_system=$false;is_offline=$true;is_read_only=$false;backing_volume_guid=$enrollment.volume_guid;
    backing_file_id='0x00000000000000000000000000000077';backing_reparse_ancestry=$false;
    backing_hard_link_paths=@($reference.vhd_path);guest_disks_before=@(0,1,2);guest_disks_after=@(0,1,2,3)}
$observed=Assert-IsolatedReferenceEnrollment $hostObservation $enrollment $reference $nativeReference
Check ($observed.reference_zero_bytes_still_required -eq 64GB -and -not $observed.whole_reference_blankness_verified -and -not $observed.write_authority) 'Reference structural review substituted for full blank scan.'
$unknownNumber=Clone $reference;$unknownNumber.disk_number=$null
$observedNumber=Clone $nativeReference;$observedNumber.disk_number=4;$observedNumber.physical_path='\\.\PhysicalDrive4';$observedNumber.guest_disks_after=@(0,1,2,4)
$discovered=Assert-IsolatedReferenceEnrollment $hostObservation $enrollment $unknownNumber $observedNumber
Check ($discovered.binding.disk_number -eq 4) 'Reference route was guessed before provider enrollment.'
foreach($change in 0..15){
    $bad=Clone $nativeReference
    switch($change){
        0{$bad.physical_path='\\.\PhysicalDrive1'} 1{$bad.persistent_vhd_id=$policy.journal_vhd_id}
        2{$bad.virtual_bytes=8GB} 3{$bad.block_bytes=1MB} 4{$bad.parent_path='J:\foreign.vhdx'}
        5{$bad.is_boot=$true} 6{$bad.is_offline=$false} 7{$bad.partitions=@([pscustomobject]@{number=1})}
        8{$bad.backing_volume_guid=$enrollment.partition_guid} 9{$bad.backing_reparse_ancestry=$true}
        10{$bad.backing_hard_link_paths+= 'J:\alias.vhdx'} 11{$bad.guest_disks_after=@(0,1,2,3,4)}
        12{$bad.vm_id=$policy.old_vm_id}
        13{$bad.backing_file_id='0x'+('0'*32)} 14{$bad.backing_file_id='not-a-file-id'}
        15{$bad.backing_file_id=''}
    }
    Reject {Assert-IsolatedReferenceEnrollment $hostObservation $enrollment $reference $bad} ('Foreign/ambiguous native reference accepted: '+$change)
}

foreach ($change in 0..21) {
    $bad=Clone $hostObservation
    switch ($change) {
        0 {$bad.vm.id=$policy.old_vm_id} 1 {$bad.vm.name='ntfs2refs-win11'}
        2 {$bad.vm.path=$policy.vm_path+'\..'} 3 {$bad.vm.network_adapter_count=1}
        4 {$bad.vm.automatic_checkpoints_enabled=$true} 5 {$bad.vm.secure_boot='Off'}
        6 {$bad.disks[2].file_id='0x00000000000000000000000000000099'}
        7 {$bad.disks[2].vhd_id=$fakeIds[0]} 8 {$bad.disks[2].parent_path='D:\foreign.vhdx'}
        9 {$bad.disks[2].hard_link_paths+= 'D:\alias.vhdx'} 10 {$bad.disks[2].reparse_ancestry=$true}
        11 {$bad.registered_references[2].vm_id=$policy.old_vm_id}
        12 {$bad.registered_references+= (Clone $bad.registered_references[2])}
        13 {$bad.registered_references[2].controller_location=1}
        14 {$bad.registered_references[0].parent_paths=@($policy.journal_path)}
        15 {$bad.registered_reference_inventory_complete=$false}
        16 {$bad.disks[2].virtual_bytes=64GB}
        17 {$bad.disks[2].host_volume_root='\\?\Volume{77777777-7777-7777-7777-777777777777}\'}
        18 {$bad.disks[0].file_id='0x00000000000000000000000000000099';$bad.registered_references[0].file_id=$bad.disks[0].file_id}
        19 {$bad.disks[1].file_id='0x00000000000000000000000000000099';$bad.registered_references[1].file_id=$bad.disks[1].file_id}
        20 {$bad.disks[0].vhd_id='11111111-1111-1111-1111-111111111111'}
        21 {$bad.disks[1].vhd_id='22222222-2222-2222-2222-222222222222'}
    }
    Reject { Assert-IsolatedBaselineStructure $bad } ('Foreign/aliased host accepted: '+$change)
}
# Equal container UUIDs in an unrelated copy do not establish file aliasing.
$unrelated = Clone $hostObservation
$unrelated.registered_references += [pscustomobject]@{ vm_id=$policy.old_vm_id; path='D:\other\journal.vhdx';
    file_id='0x00000000000000000000000000000099'; host_volume_root=$policy.host_volume_root; reference_kind='current_attachment'; parent_paths=@();
    controller_type='SCSI'; controller_number=0; controller_location=2; vhd_id=$policy.journal_vhd_id }
$null=Assert-IsolatedBaselineStructure $unrelated
Check $true 'Copied UUID alone was incorrectly treated as backing alias.'
$otherVolume = Clone $hostObservation
$otherVolume.registered_references += [pscustomobject]@{ vm_id=$policy.old_vm_id; path='E:\other\journal.vhdx';
    file_id=$policy.journal_file_id; host_volume_root='\\?\Volume{77777777-7777-7777-7777-777777777777}\';
    reference_kind='current_attachment'; parent_paths=@(); controller_type='SCSI'; controller_number=0; controller_location=2 }
$null=Assert-IsolatedBaselineStructure $otherVolume
Check $true 'A file ID from another volume was incorrectly treated as an alias.'
foreach ($change in 0..13) {
    $bad=Clone $raw
    switch ($change) {
        0 {$bad.vm_id=$policy.old_vm_id} 1 {$bad.disk_number=1} 2 {$bad.unique_id='wrong'}
        3 {$bad.size_bytes=8GB-512} 4 {$bad.logical_sector_bytes=4096} 5 {$bad.physical_sector_bytes=512}
        6 {$bad.partition_style='GPT'} 7 {$bad.partitions=@([pscustomobject]@{number=1})}
        8 {$bad.is_boot=$true} 9 {$bad.is_system=$true} 10 {$bad.disk_guid=$policy.old_journal_disk_guid}
        11 {$bad.scsi_lun=1} 12 {$bad.location='Adapter 0 : Port 0 : Target 0 : LUN 1'} 13 {$bad.current_windows_disk_number=2}
    }
    Reject { Assert-IsolatedRawJournal $hostObservation $bad @() } ('Foreign/populated RAW journal accepted: '+$change)
}
Reject { Assert-IsolatedRawJournal $hostObservation $raw @([pscustomobject]@{drive_letter='J'}) } 'Occupied J: accepted.'

foreach ($change in 0..10) {
    $bad=Clone $enrollment
    switch ($change) {
        0 {$bad.disk_guid=$policy.old_journal_disk_guid} 1 {$bad.partition_guid=$policy.old_journal_partition_guid}
        2 {$bad.partition_guid=$bad.disk_guid} 3 {$bad.disk_guid=[guid]::Empty.ToString('D')}
        4 {$bad.disk_guid=$policy.imported_disk_guid} 5 {$bad.disk_guid=$policy.journal_vhd_id}
        6 {$bad.access_paths=@('J:\','\\?\Volume{77777777-7777-7777-7777-777777777777}\')}
        7 {$bad.drive_letter='S'} 8 {$bad.is_offline=$true} 9 {$bad.filesystem='ReFS'}
        10 {$bad.partition_offset=1MB}
    }
    Reject { Assert-IsolatedJournalEnrollment $hostObservation $bad } ('Nonfresh/foreign J: enrollment accepted: '+$change)
}
$sharedGuid=Clone $enrollment
$sharedGuid.volume_guid=$sharedGuid.partition_guid
$sharedGuid.access_paths=@('J:\',('\\?\Volume{'+$sharedGuid.partition_guid+'}\'))
$null=Assert-IsolatedJournalEnrollment $hostObservation $sharedGuid
Check $true 'Valid partition/mount-manager GUID equality was refused.'
foreach ($freshness in @([guid]::Empty.ToString('D'), $policy.old_candidate_vhd_id,
    $policy.old_journal_disk_guid, $policy.old_journal_partition_guid,
    $policy.imported_disk_guid, $policy.imported_partition_guid) + $fakeIds) {
    $bad=Clone $reference; $bad.persistent_vhd_id=$freshness
    Reject { Assert-IsolatedReferenceBinding $hostObservation $enrollment $bad } 'Copied/empty/writer VHD identity accepted.'
}
foreach ($change in 0..8) {
    $bad=Clone $reference
    switch ($change) {
        0 {$bad.vm_id=$policy.old_vm_id} 1 {$bad.disk_number=2} 2 {$bad.disk_number=64}
        3 {$bad.path_exists=$true} 4 {$bad.vhd_path=$bad.vhd_path.Replace('J:','C:')}
        5 {$bad.experiment_id='A'*32} 6 {$bad.staging_directory='J:\ntfs2refs\staging'}
        7 {$bad.staging_exists=$true} 8 {$bad.run_id='..'}
    }
    Reject { Assert-IsolatedReferenceBinding $hostObservation $enrollment $bad } ('Foreign/existing reference accepted: '+$change)
}
foreach ($change in 0..10) {
    $bad=Clone $plan
    switch ($change) {
        0 {$bad.baseline_only=$false} 1 {$bad.packet_sha256='0'*64} 2 {$bad.writer_metadata_pages=8}
        3 {$bad.writer_metadata_bytes=131072} 4 {$bad.overlay_inputs=@('final-metadata.cow')}
        5 {$bad.overlay_inputs_consumed=$true} 6 {$bad.adopted_file_expected=$true}
        7 {$bad.writer_payload_writes=1} 8 {$bad.native_writer_qualified=$true}
        9 {$bad.ntfs_conversion_qualified=$true} 10 {$bad.packet_path='J:\reference.packet'}
    }
    Reject { Assert-IsolatedBaselineOnlyPlan $hostObservation $enrollment $reference $bad } ('Writer/noncanonical baseline plan accepted: '+$change)
}

$short=[Ntfs2RefsPureGuards.VirtualZeroStream]::new(512)
$smallProof=[Ntfs2RefsResearch.IsolatedJournalZero]::ScanRange($short,512,$rawReview.identity_token)
Reject { Assert-IsolatedJournalInitializationPlan $hostObservation $raw @() $short $smallProof } 'Small test-range proof authorized initialization review.'
$fake=[pscustomobject]@{CheckedBytes=8GB;RequestedBytes=8GB;IdentityToken=$rawReview.identity_token;IsJournalScope=$true;GrantsWriteAuthority=$false;allZero=$true}
Reject { Assert-IsolatedJournalInitializationPlan $hostObservation $raw @() $short $fake } 'JSON all-zero assertion replaced opaque proof.'
$nonzero=[Ntfs2RefsPureGuards.VirtualZeroStream]::new(512);$nonzero.NonzeroAt=511
Reject {[Ntfs2RefsResearch.IsolatedJournalZero]::ScanRange($nonzero,512,$rawReview.identity_token)} 'Nonzero journal range accepted.'
$incomplete=[Ntfs2RefsPureGuards.VirtualZeroStream]::new(512);$incomplete.StopAt=256
Reject {[Ntfs2RefsResearch.IsolatedJournalZero]::ScanRange($incomplete,512,$rawReview.identity_token)} 'Incomplete zero scan accepted.'
# One RAM-only virtual scan exercises the exact production-size opaque proof.
# The fixture supplies zero chunks; it allocates no 8 GiB buffer or image.
$held=[Ntfs2RefsPureGuards.VirtualZeroStream]::new(8GB)
$proof=[Ntfs2RefsResearch.IsolatedJournalZero]::ScanJournal($held,$rawReview.identity_token)
Check ($proof.CheckedBytes-eq8GB-and$proof.RequestedBytes-eq8GB-and$proof.IsJournalScope-and-not$proof.GrantsWriteAuthority) 'Production proof length/scope differs.'
$initialization=Assert-IsolatedJournalInitializationPlan $hostObservation $raw @() $held $proof
Check ($initialization.review_plan_only-and-not$initialization.initialization_performed-and-not$initialization.write_authority-and-not$initialization.native_handle_origin_verified) 'Initialization plan grants native write authority.'
$other=[Ntfs2RefsPureGuards.VirtualZeroStream]::new(8GB)
Reject {Assert-IsolatedJournalInitializationPlan $hostObservation $raw @() $other $proof} 'Proof replayed against another stream.'
Reject {$proof.AssertCurrent($held,'foreign-identity')} 'Proof identity token replay accepted.'
$held.CurrentLength=8GB-512
Reject {Assert-IsolatedJournalInitializationPlan $hostObservation $raw @() $held $proof} 'Changed held-stream length accepted.'
Check ($held.Writes-eq0-and$short.Writes-eq0-and$nonzero.Writes-eq0-and$incomplete.Writes-eq0) 'Pure scanner/guard wrote a stream.'
$exports=@(Get-Command -Module IsolatedBaselineGuards | Select-Object -ExpandProperty Name)
$expectedExports=@('Get-IsolatedBaselinePolicy','Assert-IsolatedBaselineStructure','Assert-IsolatedRawJournal',
    'Assert-IsolatedJournalInitializationPlan','Assert-IsolatedJournalEnrollment','Assert-IsolatedReferenceBinding',
    'Assert-IsolatedReferenceEnrollment','Assert-IsolatedBaselineOnlyPlan')
Check (@(Compare-Object ($expectedExports|Sort-Object) ($exports|Sort-Object)).Count-eq0) 'Unexpected executable module API exported.'
[pscustomobject]@{checks=$script:checks;passed=$true;fixture='synthetic observations and virtual zero streams';vm_operations=0;device_operations=0;images_created=0;credentials_accessed=0;native_write_authority=$false}
