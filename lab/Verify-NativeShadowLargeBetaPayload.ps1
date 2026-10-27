# Independent mounted-driver payload readback after a terminal successful run.
# No raw writes, journal replay, task dispatch, reboot or availability changes.
[CmdletBinding()]param([Parameter(Mandatory)][ValidatePattern('^candidate[2-9][0-9]*$')][string]$Candidate,[switch]$StreamingV2)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
Import-Module Hyper-V -ErrorAction Stop
$workspace='D:\code\ntfs2refs'
$betaRoot=Join-Path $workspace $(if($StreamingV2){'.lab\hyperv\streaming-v2-20261027'}else{'.lab\hyperv\shadow-large-beta-20261027'})
$root=Join-Path $betaRoot $Candidate
$dispatch=Get-Content -LiteralPath (Join-Path $root 'dispatch.json') -Raw|ConvertFrom-Json
$fixtureRoot=$betaRoot
if($StreamingV2-and$dispatch.PSObject.Properties.Name-contains'fixture_root'){
    if($dispatch.fixture_root-cnotin@($betaRoot,(Join-Path $betaRoot 'retention8g'))){throw 'Unknown streaming fixture scope.'}
    $fixtureRoot=$dispatch.fixture_root
}
$fixture=Get-Content -LiteralPath (Join-Path $fixtureRoot $(if($StreamingV2){'fixture.json'}else{'guest-fixture.json'})) -Raw
$id=if($StreamingV2){[guid]'2401593c-4b30-472e-9b6d-c9534cbaa599'}else{[guid]'6c4793d2-cdee-468b-bf3b-1c11cae0b501'};$vm=Get-VM -Id $id
$vmName=if($StreamingV2){'ntfs2refs-streaming-v2-20261027'}else{'ntfs2refs-shadow-large-beta-20261027'}
if([guid]$dispatch.vm_id-ne$id-or$vm.Name-cne$vmName-or$vm.State.ToString()-cne'Running'-or
    -not$vm.Path.StartsWith($betaRoot+'\',[StringComparison]::OrdinalIgnoreCase)){throw 'Running owned beta required.'}
$credential=Import-Clixml (Join-Path $workspace '.lab\hyperv\win11\secrets\guest-credential.xml')
$result=Invoke-Command -VMId $id -Credential $credential -ArgumentList $dispatch.task_name,$dispatch.guest_output,$fixture,[bool]$StreamingV2 -ScriptBlock {
    param($Task,$Output,$Fixture,$Streaming);Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
    $taskObject=Get-ScheduledTask -TaskName $Task;$info=Get-ScheduledTaskInfo -TaskName $Task
    if($taskObject.State.ToString()-in@('Running','Queued')-or$info.LastTaskResult-ne0-or
        @(Get-CimInstance Win32_Process|Where-Object {$_.Name-like'ntfs2refs*'}).Count){throw 'Terminal successful conversion required before readback.'}
    $complete=Get-Content -LiteralPath (Join-Path $Output 'result.json') -Raw|ConvertFrom-Json
    if(-not$complete.success-or-not$complete.source_admitted-or-not$complete.rollback_closed){throw 'Completed handoff result required.'}
    $disk=Get-Disk -Number 1;$volume=Get-Volume -DriveLetter F;$partition=Get-Partition -DriveLetter F
    $expectedLabel=if($Streaming){'n2r-stream-source'}else{'n2r-beta-source'}
    $expectedSize=if($Streaming){52GB}else{240GB}
    $expectedGuid=if($Streaming){[guid]'f06075a8-67a2-46b9-8fac-4af4da809617'}else{[guid]'489aced4-be82-4d61-a7a2-cdac24e3ebc3'}
    if($disk.IsOffline-or$disk.IsReadOnly-or$disk.IsBoot-or$disk.IsSystem-or$volume.FileSystem-cne'ReFS'-or
        $volume.FileSystemLabel-cne$expectedLabel-or$volume.AllocationUnitSize-ne4096-or
        $partition.DiskNumber-ne1-or$partition.Offset-ne16MB-or$partition.Size-ne$expectedSize-or
        [guid]$partition.Guid-ne$expectedGuid){throw 'Original converted partition identity/geometry differs.'}
    if($Streaming){
        $request=Get-Content -LiteralPath (Join-Path $Output 'request.json') -Raw|ConvertFrom-Json
        if($request.source_resource_profile-cne'experimental_streaming_tree_v2'){throw 'Streaming profile required.'}
    }
    $expected=ConvertFrom-Json -InputObject $Fixture
    $files=@(foreach($row in $expected.files){
        if(-not([string]$row.path).StartsWith('F:\',[StringComparison]::OrdinalIgnoreCase)){throw 'Fixture path escaped source.'}
        $item=Get-Item -LiteralPath $row.path -Force
        if($item.PSIsContainer-or($item.Attributes-band[IO.FileAttributes]::ReparsePoint)-or$item.Length-ne[long]$row.bytes){throw 'Converted payload size/type differs.'}
        $hash=(Get-FileHash -LiteralPath $row.path -Algorithm SHA256).Hash.ToLowerInvariant()
        if($hash-cne$row.sha256){throw 'Converted payload hash differs.'}
        [pscustomobject]@{path=$row.path;bytes=$item.Length;sha256=$hash}
    })
    [pscustomobject]@{kind=$(if($Streaming){'independent-streaming-v2-native-payload-readback'}else{'independent-large-beta-native-payload-readback'});success=$true;filesystem=$volume.FileSystem;
        label=$volume.FileSystemLabel;allocation_unit_bytes=$volume.AllocationUnitSize;partition_guid=[string]$partition.Guid;
        source_partition_bytes=$partition.Size;files=$files;logical_bytes=($files|Measure-Object bytes -Sum).Sum;
        observer_raw_writes=0;full_semantics_independently_rechecked=$false;observed_utc=[DateTime]::UtcNow.ToString('o')}
}
$path=Join-Path $root ('payload-readback-'+[DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ')+'.json')
$stream=[IO.File]::Open($path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
try{$bytes=[Text.UTF8Encoding]::new($false).GetBytes(($result|ConvertTo-Json -Depth 12));$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
$result|ConvertTo-Json -Depth 10 -Compress
