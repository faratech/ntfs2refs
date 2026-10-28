# Read-only collection of the single independently pinned recovered-tree check.
[CmdletBinding()]param([ValidateSet('candidate13')][string]$Candidate='candidate13')
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$workspace='D:\code\ntfs2refs';$root=Join-Path $workspace ('.lab\hyperv\streaming-v2-20261027\'+$Candidate)
$original=Get-Content -LiteralPath (Join-Path $root 'dispatch.json') -Raw|ConvertFrom-Json
$post=Join-Path $root 'recovery-resume\native-postcheck';$d=Get-Content -LiteralPath (Join-Path $post 'dispatch.json') -Raw|ConvertFrom-Json
if([guid]$original.vm_id-ne[guid]'2401593c-4b30-472e-9b6d-c9534cbaa599'-or$d.run_id-cne$original.run_id-or
    $d.task_name-cne('N2R-RecoveredNativeVerify-'+$original.run_id)-or$d.binary_sha256-cne'8f3675076a34bd977245744af702c82d7bf2b6c662e757246b153fcaf6840f9a'){
    throw 'Exact recorded recovered-tree verifier required.'
}
if((Get-VM -Id $original.vm_id).State.ToString()-cne'Running'){throw 'Guest is not running; no start attempted.'}
$credential=Import-Clixml (Join-Path $workspace '.lab\hyperv\win11\secrets\guest-credential.xml')
$s=New-PSSession -VMId $original.vm_id -Credential $credential
try{
    $state=Invoke-Command -Session $s -ArgumentList $d.task_name,$d.binary,$d.guest_output -ScriptBlock {
        param($Task,$Binary,$Output);$ErrorActionPreference='Stop'
        $t=Get-ScheduledTask -TaskName $Task;$i=Get-ScheduledTaskInfo -TaskName $Task
        $all=@(Get-CimInstance Win32_Process|Where-Object {$_.Name-in@('ntfs2refs.exe','ntfs2refs-recover.exe','lab-convert-admitted-tree.exe','lab-verify-general-converted.exe')})
        $terminal=$t.State.ToString()-notin@('Running','Queued')-and$all.Count-eq0-and$i.LastRunTime.Year-ge2000
        $path=Join-Path $Output 'result.json';$bytes=0;$pin=$null
        if($terminal-and(Test-Path -LiteralPath $path)){
            $file=Get-Item -LiteralPath $path
            if($file.PSIsContainer-or($file.Attributes-band[IO.FileAttributes]::ReparsePoint)-or$file.Length-gt16MB){throw 'Bounded ordinary native report required.'}
            $bytes=$file.Length;$pin=(Get-FileHash -LiteralPath $path).Hash.ToLowerInvariant()
        }
        @{terminal=$terminal;state=$t.State.ToString();exit_code=$i.LastTaskResult;process_count=$all.Count;
            report_path=$path;report_bytes=$bytes;report_sha256=$pin;processes=@($all|Where-Object ExecutablePath -eq $Binary|Select-Object ProcessId,ReadTransferCount,WorkingSetSize)}
    }
    if(-not$state.terminal){$state|ConvertTo-Json -Depth 5 -Compress;return}
    if($state.report_bytes-eq0){throw 'Terminal verifier has no report; preserve its failure/logs.'}
    $reportPath=Join-Path $post 'guest-result.json'
    if(Test-Path -LiteralPath $reportPath){
        if((Get-FileHash -LiteralPath $reportPath).Hash.ToLowerInvariant()-cne$state.report_sha256){throw 'Existing archive differs.'}
    }else{Copy-Item -LiteralPath $state.report_path -FromSession $s -Destination $reportPath}
    if((Get-FileHash -LiteralPath $reportPath).Hash.ToLowerInvariant()-cne$state.report_sha256){throw 'Archived native report differs.'}
    $value=Get-Content -LiteralPath $reportPath -Raw|ConvertFrom-Json
    $physical=if($value.PSObject.Properties.Name-contains'retained_physical_positions'){$value.retained_physical_positions}else{$null}
    $passed=$state.exit_code-eq0-and$value.success-and$value.ordinary_tree_verified-and$value.observation_complete-and$null-ne$physical-and
        $physical.original_physical_positions_verified-and$physical.native_whole_stream_hashes_matched
    $result=@{success=$passed;run_id=$d.run_id;vm_id=$original.vm_id;guest_report=$state.report_path;report_sha256=$state.report_sha256;
        exit_code=$state.exit_code;verified_retained_bytes=$(if($null-ne$physical){$physical.verified_bytes}else{$null});report=$value;utc=[DateTime]::UtcNow.ToString('o')}
    $path=Join-Path $post 'result.json'
    if(-not(Test-Path -LiteralPath $path)){
        $stream=[IO.File]::Open($path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
        try{$bytes=[Text.UTF8Encoding]::new($false).GetBytes(($result|ConvertTo-Json -Depth 28));$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
    }
    $result|Select-Object success,run_id,exit_code,report_sha256,verified_retained_bytes|ConvertTo-Json -Compress
    if(-not$passed){throw 'Independent recovered-tree verification failed; preserve state.'}
}finally{Remove-PSSession $s}
