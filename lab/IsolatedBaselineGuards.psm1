# Pure, case-specific review predicates. This module opens no files/devices,
# obtains no credentials, and contains no VM, initialization, formatting or
# import operations. Observation JSON is not write authority. A live collector
# must independently acquire and retain the actual enrolled resources.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-IsolatedBaselinePolicy {
    [pscustomobject]@{
        schema_version = 1
        profile = 'isolated-reference-baseline-prerequisites-v1'
        vm_id = '8f7fc646-8c9f-41d0-b65a-ecfadccfc36a'
        vm_name = 'ntfs2refs-reference-isolated'
        vm_path = 'D:\code\ntfs2refs\.lab\hyperv\isolated-reference-20261026-review\vm'
        disk_root = 'D:\code\ntfs2refs\.lab\hyperv\isolated-reference-20261026-review\disks'
        journal_path = 'D:\code\ntfs2refs\.lab\hyperv\isolated-reference-20261026-review\disks\journal.vhdx'
        journal_file_id = '0x000000000007c9c40000000000000010'
        os_file_id = '0x000000000007c9c4000000000000000e'
        target_file_id = '0x000000000007c9c4000000000000000f'
        os_vhd_id = 'a95ba3be-96d4-4e6f-995a-d5aff633d768'
        target_vhd_id = '25c491d0-5f1b-4205-9e6f-fd619706c2b5'
        host_volume_root = '\\?\Volume{fcccb0cc-ddbb-46a4-ab61-ab5f91c889ca}\'
        journal_vhd_id = '1f26ac6a-1f02-4989-b5c8-249596f332fc'
        journal_unique_id = '600224806AAC261F021F249596F332FC'
        journal_bytes = [long]8589934592
        packet_sha256 = '585df94c07190bcd3476a596ee870d1c3e60d793d03d9d4d3bd545780f23df5b'
        old_vm_id = 'eebbfd4e-d964-4aaf-a6e6-5603fb9b6c4c'
        old_journal_disk_guid = '04d5194b-f5db-43da-9b02-ed7a54325d56'
        old_journal_partition_guid = '7435ee94-c435-403f-a515-dec1ccd5094e'
        old_candidate_vhd_id = 'a0c231ef-a959-4a6e-8ae2-7d80363eebe6'
        imported_disk_guid = 'b4ab4dbc-6bd7-4199-8e4a-01b828e98584'
        imported_partition_guid = '00c9f113-e0b9-49d8-b031-130aef8ef3fb'
        guest_staging_root = 'C:\ntfs2refs\isolated-baseline'
        write_authority = $false
    }
}

function Assert-IsolatedCondition([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}
function Test-IsolatedBool($Value, [bool]$Expected) {
    ($Value -is [bool]) -and ($Value -eq $Expected)
}
function Test-IsolatedPath($Value, [string]$Expected) {
    ($Value -is [string]) -and $Value.Equals($Expected, [StringComparison]::OrdinalIgnoreCase)
}
function Get-IsolatedGuid($Value) {
    $parsed = [guid]::Empty
    Assert-IsolatedCondition ([guid]::TryParse([string]$Value, [ref]$parsed) -and $parsed -ne [guid]::Empty) 'Nonempty GUID required.'
    $parsed.ToString('D')
}
function Assert-IsolatedHeader($Value, [string]$Kind) {
    $policy = Get-IsolatedBaselinePolicy
    Assert-IsolatedCondition ($Value.schema_version -eq 1 -and $Value.kind -ceq $Kind -and $Value.profile -ceq $policy.profile) 'Versioned isolated prerequisite profile differs.'
}

function Assert-IsolatedBaselineStructure {
    param([Parameter(Mandatory)]$Observation)
    $p = Get-IsolatedBaselinePolicy
    Assert-IsolatedHeader $Observation 'isolated-baseline-host-observation'
    $vm = $Observation.vm
    Assert-IsolatedCondition ((Get-IsolatedGuid $vm.id) -ceq $p.vm_id -and $vm.name -ceq $p.vm_name -and (Test-IsolatedPath $vm.path $p.vm_path)) 'Exact isolated VM endpoint differs; the old win11 manifest is forbidden.'
    Assert-IsolatedCondition ($vm.generation -eq 2 -and $vm.processor_count -eq 4 -and $vm.memory_startup_bytes -eq 8GB -and $vm.state -ceq 'Running' -and (Test-IsolatedBool $vm.dynamic_memory_enabled $false) -and $vm.network_adapter_count -eq 0 -and $vm.checkpoint_count -eq 0 -and (Test-IsolatedBool $vm.automatic_checkpoints_enabled $false)) 'Isolated VM configuration differs.'
    Assert-IsolatedCondition ((Test-IsolatedBool $vm.tpm_enabled $true) -and $vm.secure_boot -ceq 'On' -and $vm.secure_boot_template -ceq 'MicrosoftWindows') 'Existing isolated security configuration must be preserved.'
    Assert-IsolatedCondition (Test-IsolatedBool $Observation.registered_reference_inventory_complete $true) 'Complete registered attachment/ancestry observation required.'
    $disks = @($Observation.disks)
    Assert-IsolatedCondition ($disks.Count -eq 3) 'Exactly three independent enrolled host backings required.'
    $ids = @(); $files = @()
    foreach ($role in @('os', 'target', 'journal')) {
        $matches = @($disks | Where-Object { $_.role -ceq $role })
        Assert-IsolatedCondition ($matches.Count -eq 1) 'Missing or duplicate disk role.'
        $d = $matches[0]
        $slot = switch ($role) { 'os' { 0 } 'target' { 1 } 'journal' { 2 } }
        $expectedPath = $p.disk_root + '\' + $role + '.vhdx'
        Assert-IsolatedCondition ((Test-IsolatedPath $d.path $expectedPath) -and $d.controller_type -ceq 'SCSI' -and $d.controller_number -eq 0 -and $d.controller_location -eq $slot) 'Host backing route or controller differs.'
        Assert-IsolatedCondition ([string]::IsNullOrEmpty([string]$d.parent_path) -and (Test-IsolatedBool $d.reparse_ancestry $false) -and @($d.hard_link_paths).Count -eq 1 -and (Test-IsolatedPath (@($d.hard_link_paths)[0]) $expectedPath)) 'Standalone single-link ordinary host backing required.'
        Assert-IsolatedCondition (Test-IsolatedPath $d.host_volume_root $p.host_volume_root) 'Host file identity must be scoped to the enrolled D: volume GUID.'
        Assert-IsolatedCondition ($d.file_id -is [string] -and $d.file_id -cmatch '\A0x[0-9a-f]{32}\z' -and $d.file_id -cnotin $files) 'Host file identity is absent or aliases another role.'
        $files += $d.file_id
        $vhdId = Get-IsolatedGuid $d.vhd_id
        $expectedFileId = switch ($role) { 'os' {$p.os_file_id} 'target' {$p.target_file_id} 'journal' {$p.journal_file_id} }
        $expectedVhdId = switch ($role) { 'os' {$p.os_vhd_id} 'target' {$p.target_vhd_id} 'journal' {$p.journal_vhd_id} }
        Assert-IsolatedCondition ($d.file_id -ceq $expectedFileId -and $vhdId -ceq $expectedVhdId) 'Recorded host file/container identity changed.'
        Assert-IsolatedCondition ($vhdId -cnotin $ids) 'Three distinct enrolled container identities required.'
        $ids += $vhdId
        $size = if ($role -ceq 'journal') { 8GB } else { 64GB }
        Assert-IsolatedCondition ($d.virtual_bytes -eq $size -and $d.logical_sector_bytes -eq 512 -and $d.physical_sector_bytes -eq 4096) 'Host backing geometry differs.'
        if ($role -ceq 'journal') {
            Assert-IsolatedCondition ($d.file_id -ceq $p.journal_file_id -and $vhdId -ceq $p.journal_vhd_id) 'Exact independent journal file/container identity differs.'
        }
        $owners = @()
        foreach ($reference in @($Observation.registered_references)) {
            foreach ($parent in @($reference.parent_paths)) {
                Assert-IsolatedCondition (-not (Test-IsolatedPath $parent $expectedPath)) 'Enrolled backing is used as another registered parent.'
            }
            $samePath = Test-IsolatedPath $reference.path $expectedPath
            $sameFile = (Test-IsolatedPath $reference.host_volume_root $p.host_volume_root) -and $reference.file_id -ceq $d.file_id
            if ($samePath -or $sameFile) { $owners += $reference }
        }
        Assert-IsolatedCondition ($owners.Count -eq 1) 'Backing does not have exactly one registered current owner.'
        $owner = $owners[0]
        Assert-IsolatedCondition ($owner.reference_kind -ceq 'current_attachment' -and (Get-IsolatedGuid $owner.vm_id) -ceq $p.vm_id -and (Test-IsolatedPath $owner.path $expectedPath) -and (Test-IsolatedPath $owner.host_volume_root $p.host_volume_root) -and $owner.file_id -ceq $d.file_id -and $owner.controller_type -ceq 'SCSI' -and $owner.controller_number -eq 0 -and $owner.controller_location -eq $slot) 'Foreign owner, alias or controller for enrolled backing.'
    }
    [pscustomobject]@{ profile=$p.profile; structural_review_passed=$true; write_authority=$false; copied_vhd_ids=$ids }
}

function Assert-IsolatedRawJournal {
    param([Parameter(Mandatory)]$HostObservation, [Parameter(Mandatory)]$Journal, [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$JVolumes)
    $null = Assert-IsolatedBaselineStructure $HostObservation
    $p = Get-IsolatedBaselinePolicy
    Assert-IsolatedHeader $Journal 'isolated-raw-journal-observation'
    Assert-IsolatedCondition ((Get-IsolatedGuid $Journal.vm_id) -ceq $p.vm_id -and $Journal.disk_number -eq 2 -and $Journal.unique_id -ceq $p.journal_unique_id -and $Journal.size_bytes -eq $p.journal_bytes -and $Journal.logical_sector_bytes -eq 512 -and $Journal.physical_sector_bytes -eq 4096) 'Exact guest journal identity/geometry differs.'
    Assert-IsolatedCondition ($Journal.scsi_port -eq 0 -and $Journal.scsi_target_id -eq 0 -and $Journal.scsi_lun -eq 2 -and
        $Journal.location -match 'Adapter 0 : Port 0 : Target 0 : LUN 2$' -and $Journal.current_windows_disk_number -eq 0) 'Guest SCSI/journal/Windows routes disagree.'
    Assert-IsolatedCondition ($Journal.partition_style -ceq 'RAW' -and @($Journal.partitions).Count -eq 0 -and (Test-IsolatedBool $Journal.is_boot $false) -and (Test-IsolatedBool $Journal.is_system $false) -and (Test-IsolatedBool $Journal.is_read_only $false)) 'Only the uninitialized nonboot journal is eligible for prerequisite review.'
    Assert-IsolatedCondition ($Journal.disk_guid -in @($null, '', [guid]::Empty.ToString('D'))) 'RAW journal unexpectedly carries a GPT identity.'
    Assert-IsolatedCondition ($JVolumes.Count -eq 0) 'J: is occupied or its volume inventory is ambiguous.'
    $material = 'isolated-journal-zero-v1|' + $p.vm_id + '|' + $p.host_volume_root + '|' + $p.journal_file_id + '|' + $p.journal_unique_id + '|8589934592|512|4096'
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $token = [BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($material))).Replace('-', '').ToLowerInvariant() }
    finally { $sha.Dispose() }
    [pscustomobject]@{ profile=$p.profile; identity_token=$token; checked_native_origin=$false; raw_review_passed=$true; write_authority=$false }
}

function Assert-IsolatedJournalInitializationPlan {
    param([Parameter(Mandatory)]$HostObservation, [Parameter(Mandatory)]$Journal,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$JVolumes,
        [Parameter(Mandatory)][IO.Stream]$HeldStream, [Parameter(Mandatory)]$ZeroProof)
    $raw = Assert-IsolatedRawJournal $HostObservation $Journal $JVolumes
    $proofType = 'Ntfs2RefsResearch.ZeroProof' -as [type]
    Assert-IsolatedCondition ($null -ne $proofType -and $ZeroProof.GetType() -eq $proofType) 'Opaque scanner proof required; JSON/allZero flags are not accepted.'
    Assert-IsolatedCondition ($ZeroProof.CheckedBytes -eq 8GB -and $ZeroProof.RequestedBytes -eq 8GB -and (Test-IsolatedBool $ZeroProof.IsJournalScope $true) -and (Test-IsolatedBool $ZeroProof.GrantsWriteAuthority $false) -and $ZeroProof.IdentityToken -ceq $raw.identity_token) 'Complete production-scope journal proof required.'
    $ZeroProof.AssertCurrent($HeldStream, $raw.identity_token)
    [pscustomobject]@{ schema_version=1; kind='isolated-journal-initialization-review-plan'; profile=$raw.profile;
        vm_id=(Get-IsolatedBaselinePolicy).vm_id; disk_number=2; identity_token=$raw.identity_token;
        proposed_drive_letter='J'; proposed_filesystem='NTFS'; proposed_allocation_unit_bytes=4096;
        fresh_gpt_partition_volume_enrollment_required=$true; native_handle_origin_verified=$false;
        review_plan_only=$true; initialization_performed=$false; write_authority=$false }
}

function Assert-IsolatedJournalEnrollment {
    param([Parameter(Mandatory)]$HostObservation, [Parameter(Mandatory)]$Enrollment)
    $structure = Assert-IsolatedBaselineStructure $HostObservation
    $p = Get-IsolatedBaselinePolicy
    Assert-IsolatedHeader $Enrollment 'isolated-journal-ntfs-enrollment'
    Assert-IsolatedCondition ((Get-IsolatedGuid $Enrollment.vm_id) -ceq $p.vm_id -and $Enrollment.disk_number -eq 2 -and $Enrollment.unique_id -ceq $p.journal_unique_id -and $Enrollment.host_file_id -ceq $p.journal_file_id) 'Fresh journal enrollment routes to foreign backing.'
    Assert-IsolatedCondition ($Enrollment.size_bytes -eq 8GB -and $Enrollment.logical_sector_bytes -eq 512 -and $Enrollment.physical_sector_bytes -eq 4096 -and $Enrollment.partition_style -ceq 'GPT' -and (Test-IsolatedBool $Enrollment.is_boot $false) -and (Test-IsolatedBool $Enrollment.is_system $false) -and (Test-IsolatedBool $Enrollment.is_offline $false) -and (Test-IsolatedBool $Enrollment.is_read_only $false)) 'Enrolled journal geometry/state differs.'
    $fresh = @((Get-IsolatedGuid $Enrollment.disk_guid), (Get-IsolatedGuid $Enrollment.partition_guid), (Get-IsolatedGuid $Enrollment.volume_guid))
    $forbidden = @($p.old_journal_disk_guid, $p.old_journal_partition_guid, $p.imported_disk_guid, $p.imported_partition_guid, $p.old_candidate_vhd_id) + @($structure.copied_vhd_ids)
    # Mount Manager may use the GPT partition GUID for the volume path; these
    # are separately observed identities, not required to differ numerically.
    Assert-IsolatedCondition ($fresh[0] -cne $fresh[1] -and @($fresh | Where-Object { $_ -cin $forbidden }).Count -eq 0) 'New J: requires separately enrolled fresh disk, partition and volume GUIDs.'
    Assert-IsolatedCondition ($Enrollment.partition_number -eq 1 -and $Enrollment.partition_offset -eq 16MB -and $Enrollment.partition_bytes -eq (8GB - 32MB) -and $Enrollment.gpt_type -ieq 'ebd0a0a2-b9e5-4433-87c0-68b6b72699c7' -and $Enrollment.filesystem -ceq 'NTFS' -and $Enrollment.allocation_unit_bytes -eq 4096 -and $Enrollment.drive_letter -ceq 'J') 'New J: partition/filesystem profile differs.'
    $root = '\\?\Volume{' + $fresh[2] + '}\'
    Assert-IsolatedCondition (@($Enrollment.access_paths).Count -eq 2 -and @($Enrollment.access_paths | Where-Object { $_ -ceq 'J:\' }).Count -eq 1 -and @($Enrollment.access_paths | Where-Object { $_ -ceq $root }).Count -eq 1) 'Exactly the fresh volume GUID and J: routes must be enrolled.'
    [pscustomobject]@{ profile=$p.profile; vm_id=$p.vm_id; disk_number=2; disk_guid=$fresh[0]; partition_guid=$fresh[1]; volume_guid=$fresh[2]; volume_root=$root; write_authority=$false }
}

function Assert-IsolatedReferenceBinding {
    param([Parameter(Mandatory)]$HostObservation, [Parameter(Mandatory)]$JournalEnrollment, [Parameter(Mandatory)]$Reference)
    $structure = Assert-IsolatedBaselineStructure $HostObservation
    $journal = Assert-IsolatedJournalEnrollment $HostObservation $JournalEnrollment
    $p = Get-IsolatedBaselinePolicy
    Assert-IsolatedHeader $Reference 'isolated-reference-creation-review'
    Assert-IsolatedCondition ((Get-IsolatedGuid $Reference.vm_id) -ceq $p.vm_id -and $Reference.experiment_id -cmatch '\A[0-9a-f]{32}\z' -and $Reference.run_id -cmatch '\A[0-9a-f]{32}\z') 'Fresh isolated experiment/run identity required.'
    $path = 'J:\ntfs2refs-reference\' + $Reference.experiment_id + '\reference.vhdx'
    Assert-IsolatedCondition ((Test-IsolatedPath $Reference.vhd_path $path) -and
        ($null -eq $Reference.disk_number -or ($Reference.disk_number -ge 3 -and $Reference.disk_number -le 63)) -and
        (Test-IsolatedBool $Reference.path_exists $false)) 'Fresh reference backing/path/route differs or already exists.'
    $persistent = Get-IsolatedGuid $Reference.persistent_vhd_id
    Assert-IsolatedCondition ($persistent -cnotin (@($structure.copied_vhd_ids) + @($p.old_candidate_vhd_id,
        $p.old_journal_disk_guid, $p.old_journal_partition_guid, $p.imported_disk_guid, $p.imported_partition_guid,
        $journal.disk_guid, $journal.partition_guid, $journal.volume_guid))) 'Reference VHD identity must be independent of copied disks and prior journal/import identities.'
    $staging = $p.guest_staging_root + '\' + $Reference.run_id
    Assert-IsolatedCondition ((Test-IsolatedPath $Reference.staging_directory $staging) -and (Test-IsolatedBool $Reference.staging_exists $false)) 'Fresh controlled C: staging directory required.'
    [pscustomobject]@{ schema_version=1; profile=$p.profile; vm_id=$p.vm_id; experiment_id=$Reference.experiment_id;
        disk_number=$Reference.disk_number; vhd_path=$path; persistent_vhd_id=$persistent; staging_directory=$staging;
        creation_performed=$false; native_origin_verified=$false; write_authority=$false }
}

function Assert-IsolatedBaselineOnlyPlan {
    param([Parameter(Mandatory)]$HostObservation, [Parameter(Mandatory)]$JournalEnrollment,
        [Parameter(Mandatory)]$Reference, [Parameter(Mandatory)]$Plan)
    $binding = Assert-IsolatedReferenceBinding $HostObservation $JournalEnrollment $Reference
    $p = Get-IsolatedBaselinePolicy
    Assert-IsolatedHeader $Plan 'isolated-baseline-import-review-plan'
    Assert-IsolatedCondition ((Test-IsolatedBool $Plan.baseline_only $true) -and $Plan.packet_sha256 -ceq $p.packet_sha256 -and $Plan.writer_metadata_pages -eq 0 -and $Plan.writer_metadata_bytes -eq 0 -and $Plan.writer_payload_writes -eq 0 -and @($Plan.overlay_inputs).Count -eq 0 -and (Test-IsolatedBool $Plan.overlay_inputs_consumed $false) -and (Test-IsolatedBool $Plan.adopted_file_expected $false)) 'Only the exact unmodified packet with no writer/adoption inputs is permitted for review.'
    Assert-IsolatedCondition ((Test-IsolatedPath $Plan.packet_path ($binding.staging_directory + '\reference.packet')) -and (Test-IsolatedBool $Plan.native_writer_qualified $false) -and (Test-IsolatedBool $Plan.ntfs_conversion_qualified $false)) 'Packet must use controlled C: staging; qualification cannot be supplied by a plan.'
    [pscustomobject]@{ schema_version=1; kind='isolated-baseline-import-review'; profile=$p.profile; binding=$binding;
        packet_path=$Plan.packet_path; packet_sha256=$p.packet_sha256; baseline_only=$true; writer_metadata_pages=0;
        writer_metadata_bytes=0; overlay_inputs_consumed=$false; adopted_file_expected=$false;
        import_performed=$false; review_plan_only=$true; native_write_authority=$false }
}

# Separate post-creation structural review. Requested paths/UUIDs alone never
# establish that the virtual-disk provider attached the intended fresh device.
function Assert-IsolatedReferenceEnrollment {
    param([Parameter(Mandatory)]$HostObservation, [Parameter(Mandatory)]$JournalEnrollment,
        [Parameter(Mandatory)]$CreationReview, [Parameter(Mandatory)]$Observation)
    $expected=Assert-IsolatedReferenceBinding $HostObservation $JournalEnrollment $CreationReview
    $journal=Assert-IsolatedJournalEnrollment $HostObservation $JournalEnrollment
    Assert-IsolatedHeader $Observation 'isolated-reference-native-enrollment'
    Assert-IsolatedCondition ((Get-IsolatedGuid $Observation.vm_id) -ceq $expected.vm_id -and
        (Get-IsolatedGuid $Observation.persistent_vhd_id) -ceq $expected.persistent_vhd_id -and
        (Test-IsolatedPath $Observation.vhd_path $expected.vhd_path) -and
        $Observation.disk_number -ge 3 -and $Observation.disk_number -le 63 -and
        ($null -eq $expected.disk_number -or $Observation.disk_number -eq $expected.disk_number) -and
        $Observation.physical_path -ceq ('\\.\PhysicalDrive'+$Observation.disk_number)) 'Reference provider/device route differs from creation review.'
    Assert-IsolatedCondition ($Observation.virtual_bytes -eq 64GB -and $Observation.block_bytes -eq 2MB -and
        $Observation.logical_sector_bytes -eq 512 -and $Observation.physical_sector_bytes -eq 4096 -and
        $Observation.vhd_type -ceq 'Dynamic' -and [string]::IsNullOrEmpty([string]$Observation.parent_path) -and
        $Observation.initial_backing_bytes -gt 0 -and $Observation.initial_backing_bytes -le 128MB) 'Fresh independent reference geometry/backing differs.'
    Assert-IsolatedCondition ($Observation.partition_style -ceq 'RAW' -and @($Observation.partitions).Count -eq 0 -and
        (Test-IsolatedBool $Observation.is_boot $false) -and (Test-IsolatedBool $Observation.is_system $false) -and
        (Test-IsolatedBool $Observation.is_offline $true) -and $Observation.is_read_only -is [bool]) 'Reference must remain excluded uninitialized storage.'
    Assert-IsolatedCondition ((Get-IsolatedGuid $Observation.backing_volume_guid) -ceq $journal.volume_guid -and
        $Observation.backing_file_id -is [string] -and $Observation.backing_file_id -cmatch '\A0x[0-9a-f]{32}\z' -and
        $Observation.backing_file_id -cne ('0x'+('0'*32)) -and
        (Test-IsolatedBool $Observation.backing_reparse_ancestry $false) -and
        @($Observation.backing_hard_link_paths).Count -eq 1 -and
        (Test-IsolatedPath (@($Observation.backing_hard_link_paths)[0]) $expected.vhd_path)) 'Reference backing is not the independently enrolled ordinary J: file.'
    $before=@($Observation.guest_disks_before | Sort-Object)
    $after=@($Observation.guest_disks_after | Sort-Object)
    Assert-IsolatedCondition (($before -join ',') -ceq '0,1,2' -and
        ($after -join ',') -ceq ((@(0,1,2,$Observation.disk_number) | Sort-Object) -join ',')) 'Reference attachment did not add exactly its one measured device.'
    $enrolled=[pscustomobject]@{experiment_id=$expected.experiment_id;vhd_path=$expected.vhd_path;
        persistent_vhd_id=$expected.persistent_vhd_id;disk_number=$Observation.disk_number}
    [pscustomobject]@{schema_version=1;profile=$expected.profile;vm_id=$expected.vm_id;binding=$enrolled;
        backing_volume_guid=$journal.volume_guid;backing_file_id=$Observation.backing_file_id;
        reference_zero_bytes_still_required=[long]68719476736;whole_reference_blankness_verified=$false;
        native_origin_verified=$false;review_plan_only=$true;write_authority=$false}
}

Export-ModuleMember -Function Get-IsolatedBaselinePolicy, Assert-IsolatedBaselineStructure, Assert-IsolatedRawJournal, Assert-IsolatedJournalInitializationPlan, Assert-IsolatedJournalEnrollment, Assert-IsolatedReferenceBinding, Assert-IsolatedReferenceEnrollment, Assert-IsolatedBaselineOnlyPlan
