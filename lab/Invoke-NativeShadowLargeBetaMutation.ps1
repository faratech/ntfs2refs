# Bounded mounted-driver workload on the disposable beta, after successful handoff.
# Creates a fresh run-owned directory; never replays a journal or changes disk availability.
[CmdletBinding()]param([Parameter(Mandatory)][ValidatePattern('^candidate[2-9][0-9]*$')][string]$Candidate)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$workspace='D:\code\ntfs2refs'
$root=Join-Path $workspace ('.lab\hyperv\shadow-large-beta-20261027\'+$Candidate)
if((Get-PSDrive D).Free-lt64GB){throw 'The 64 GiB host reserve is required.'}
# This observer refuses while any converter is active and checks the exact source
# partition, successful closed handoff and all six original payload hashes.
& (Join-Path $PSScriptRoot 'Verify-NativeShadowLargeBetaPayload.ps1') -Candidate $Candidate | Out-Null
$dispatch=Get-Content -LiteralPath (Join-Path $root 'dispatch.json') -Raw|ConvertFrom-Json
$id=[guid]'6c4793d2-cdee-468b-bf3b-1c11cae0b501'
$credential=Import-Clixml (Join-Path $workspace '.lab\hyperv\win11\secrets\guest-credential.xml')
$intent=Join-Path $root 'mutation-intent.json'
$stream=[IO.File]::Open($intent,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
try{
    $bytes=[Text.UTF8Encoding]::new($false).GetBytes((@{run_id=$dispatch.run_id;vm_id=[string]$id;utc=[DateTime]::UtcNow.ToString('o')}|ConvertTo-Json))
    $stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)
}finally{$stream.Dispose()}
$result=Invoke-Command -VMId $id -Credential $credential -ArgumentList $dispatch.run_id,$dispatch.task_name,$dispatch.guest_output -ScriptBlock {
    param($Run,$TaskName,$Output)
    Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
    if($Run-cnotmatch'^[0-9a-f]{32}$'){throw 'Invalid run identity.'}
    $taskObject=Get-ScheduledTask -TaskName $TaskName
    if($taskObject.State.ToString()-in@('Running','Queued')-or(Get-ScheduledTaskInfo -TaskName $TaskName).LastTaskResult-ne0-or
        @(Get-CimInstance Win32_Process|Where-Object {$_.Name-like'ntfs2refs*'}).Count){throw 'Converter must remain terminal.'}
    $complete=Get-Content -LiteralPath (Join-Path $Output 'result.json') -Raw|ConvertFrom-Json
    if(-not$complete.success-or-not$complete.rollback_closed){throw 'Successful closed handoff required.'}
    $partition=Get-Partition -DriveLetter F;$disk=Get-Disk -Number $partition.DiskNumber;$volume=Get-Volume -DriveLetter F
    if($partition.DiskNumber-ne1-or[guid]$partition.Guid-ne[guid]'489aced4-be82-4d61-a7a2-cdac24e3ebc3'-or
        $partition.Offset-ne16MB-or$partition.Size-ne240GB-or$disk.IsBoot-or$disk.IsSystem-or$disk.IsOffline-or$disk.IsReadOnly-or
        $volume.FileSystem-cne'ReFS'-or$volume.AllocationUnitSize-ne4096-or$volume.SizeRemaining-lt64MB){throw 'Converted beta binding differs.'}
    $path='F:\n2r-mutation-'+$Run
    if(Test-Path -LiteralPath $path){throw 'Mutation directory already exists; inspect prior attempt.'}
    New-Item -ItemType Directory -Path $path | Out-Null
    $buffer=New-Object byte[] 65536
    for($i=0;$i-lt$buffer.Length;$i++){$buffer[$i]=[byte](($i*17+29)%251)}
    $file=Join-Path $path 'grow.bin'
    $handle=[IO.File]::Open($file,[IO.FileMode]::CreateNew,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
    try{
        for($i=0;$i-lt256;$i++){$handle.Write($buffer,0,$buffer.Length)}
        $handle.Flush($true)
        if($handle.Length-ne16MB){throw 'Growth length differs.'}
        $handle.SetLength(1MB+17);$handle.Flush($true)
    }finally{$handle.Dispose()}
    $expectedStream=[IO.MemoryStream]::new()
    try{
        for($i=0;$i-lt16;$i++){$expectedStream.Write($buffer,0,$buffer.Length)}
        $expectedStream.Write($buffer,0,17)
        $hasher=[Security.Cryptography.SHA256]::Create()
        try{$expected=([BitConverter]::ToString($hasher.ComputeHash($expectedStream.ToArray()))).Replace('-','').ToLowerInvariant()}finally{$hasher.Dispose()}
    }finally{$expectedStream.Dispose()}
    $renamed=Join-Path $path 'renamed.bin'
    Move-Item -LiteralPath $file -Destination $renamed
    if((Get-FileHash -LiteralPath $renamed -Algorithm SHA256).Hash.ToLowerInvariant()-cne$expected){throw 'Truncate/rename content differs.'}
    for($i=0;$i-lt128;$i++){[IO.File]::WriteAllBytes((Join-Path $path ('entry-{0:d3}.bin'-f$i)),$buffer)}
    if(@(Get-ChildItem -LiteralPath $path -File).Count-ne129){throw 'Directory growth count differs.'}
    foreach($entry in Get-ChildItem -LiteralPath $path -File){
        if($entry.Attributes-band[IO.FileAttributes]::ReparsePoint){throw 'Unexpected reparse object.'}
        Remove-Item -LiteralPath $entry.FullName
    }
    if(@(Get-ChildItem -LiteralPath $path -Force).Count){throw 'Deletion left entries.'}
    Remove-Item -LiteralPath $path
    [pscustomobject]@{kind='native-large-beta-mutation';success=$true;run_id=$Run;created_bytes=24MB;
        operations=@('create','grow-16MiB','truncate-1MiB-plus-17','rename','directory-128-entries','delete');
        truncated_sha256=$expected;last_boot_utc=(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o');
        utc=[DateTime]::UtcNow.ToString('o');reboot_verified=$false;full_semantics_independently_rechecked=$false}
}
$path=Join-Path $root 'mutation-result.json'
$stream=[IO.File]::Open($path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
try{$bytes=[Text.UTF8Encoding]::new($false).GetBytes(($result|ConvertTo-Json -Depth 8));$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
& (Join-Path $PSScriptRoot 'Verify-NativeShadowLargeBetaPayload.ps1') -Candidate $Candidate | Out-Null
$result|ConvertTo-Json -Depth 8 -Compress
