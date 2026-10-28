# Exact beta end-to-end checks using pinned Rust executables. Run phases once,
# in order, only after terminal successful conversion. No recovery replay.
[CmdletBinding()]param(
    [Parameter(Mandatory)][ValidatePattern('^candidate(?:[2-9]|[1-9][0-9]+)$')][string]$Candidate,
    [Parameter(Mandatory)][ValidateSet('BeforeMutation','AfterPreservationBoot','Mutate','AfterMutation','AfterReboot')][string]$Phase,
    [ValidateRange(1,9)][int]$Attempt=1,
    [switch]$StreamingV2,
    [ValidateRange(1,9)][int]$ToolsetVersion=1
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$workspace='D:\code\ntfs2refs'
$root=Join-Path $workspace ($(if($StreamingV2){'.lab\hyperv\streaming-v2-20261027\'}else{'.lab\hyperv\shadow-large-beta-20261027\'})+$Candidate)
if((Get-PSDrive D).Free-lt64GB){throw 'The 64 GiB host reserve is required.'}
if($ToolsetVersion-gt1-and-not$StreamingV2){throw 'Versioned observers require the separate streaming fixture.'}
$toolsRoot=Join-Path $root $(if($ToolsetVersion-eq1){'rust-postcheck-tools'}else{'rust-postcheck-tools-v'+$ToolsetVersion})
$manifest=Get-Content -LiteralPath (Join-Path $toolsRoot 'manifest.json') -Raw|ConvertFrom-Json
$dispatch=Get-Content -LiteralPath (Join-Path $root 'dispatch.json') -Raw|ConvertFrom-Json
$qualified=Join-Path $root $(if($StreamingV2){'terminal-evidence\run'}else{'qualified-observed'})
$requestPin=(Get-FileHash -LiteralPath (Join-Path $qualified 'request.json')).Hash.ToLowerInvariant()
$treePin=(Get-FileHash -LiteralPath (Join-Path $qualified 'expectation.json')).Hash.ToLowerInvariant()
$id=if($StreamingV2){[guid]'2401593c-4b30-472e-9b6d-c9534cbaa599'}else{[guid]'6c4793d2-cdee-468b-bf3b-1c11cae0b501'}
$kind=if($StreamingV2){'streaming-v2-rust-postcheck-tools'}else{'large-beta-rust-postcheck-tools'}
if([guid]$dispatch.vm_id-ne$id-or$manifest.kind-cne$kind){throw 'Fixture/tool enrollment differs.'}
if($StreamingV2-and$manifest.run_id-cne$dispatch.run_id){throw 'Observer manifest run differs.'}
& (Join-Path $PSScriptRoot 'Verify-NativeShadowLargeBetaPayload.ps1') -Candidate $Candidate -StreamingV2:$StreamingV2 | Out-Null
$post=Join-Path $root 'rust-postcheck'
$guestPost=Join-Path $dispatch.guest_stage 'rust-postcheck'
$guestTools=Join-Path $guestPost $(if($ToolsetVersion-eq1){'tools'}else{'tools-v'+$ToolsetVersion})
if($Attempt-gt1-and$Phase-notin@('BeforeMutation','AfterPreservationBoot','AfterMutation','AfterReboot')){throw 'Only read-only verification phases permit fresh observation attempts.'}
$phaseKey=if($Attempt-eq1){$Phase}else{$Phase+'-attempt-'+$Attempt}
if(Test-Path -LiteralPath (Join-Path $post ($Phase+'.json'))){throw 'Phase already completed; inspect its receipt.'}
function Save-NewRecord([string]$Path,$Value){
    $stream=[IO.File]::Open($Path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try{$bytes=[Text.UTF8Encoding]::new($false).GetBytes(($Value|ConvertTo-Json -Depth 28));$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
}
if($Phase-ceq'BeforeMutation'){
    if($Attempt-eq1){
        if(Test-Path -LiteralPath $post){throw 'Fresh postcheck directory required; inspect prior intent.'}
        New-Item -ItemType Directory -Path $post | Out-Null
    }elseif(-not(Test-Path -LiteralPath (Join-Path $post 'BeforeMutation-intent.json'))){throw 'Original read-only observation intent required.'}
}else{
    $previous=switch($Phase){'AfterPreservationBoot'{'BeforeMutation'}'Mutate'{'AfterPreservationBoot'}'AfterMutation'{'Mutate'}'AfterReboot'{'AfterMutation'}}
    $receipt=Get-Content -LiteralPath (Join-Path $post ($previous+'.json')) -Raw|ConvertFrom-Json
    if(-not$receipt.success-or$receipt.run_id-cne$dispatch.run_id){throw 'Successful matching prior phase required.'}
}
$mutation=if($Phase-in@('AfterMutation','AfterReboot')){Get-Content -LiteralPath (Join-Path $post 'Mutate.json') -Raw|ConvertFrom-Json}else{$null}
Save-NewRecord (Join-Path $post ($phaseKey+'-intent.json')) @{phase=$Phase;attempt=$Attempt;run_id=$dispatch.run_id;utc=[DateTime]::UtcNow.ToString('o');tools=$manifest.tools;
    toolset_version=$ToolsetVersion;tools_manifest_sha256=(Get-FileHash -LiteralPath (Join-Path $toolsRoot 'manifest.json')).Hash.ToLowerInvariant()}
$credential=Import-Clixml (Join-Path $workspace '.lab\hyperv\win11\secrets\guest-credential.xml')
$session=New-PSSession -VMId $id -Credential $credential
try{
    if($Phase-ceq'BeforeMutation'){
        $copyRequired=Invoke-Command -Session $session -ArgumentList $guestPost,$guestTools,($Attempt-gt1) -ScriptBlock {
            param($Post,$Tools,$Retry);$ErrorActionPreference='Stop'
            if(-not$Retry-and(Test-Path -LiteralPath $Post)){throw 'Guest postcheck directory exists.'}
            if(Test-Path -LiteralPath $Tools){
                if(-not$Retry){throw 'Guest tool stage exists.'}
                return $false
            }
            New-Item -ItemType Directory -Path $Tools | Out-Null
            $true
        }
        foreach($row in $manifest.tools){
            if($row.name-cnotin@('lab-verify-general-converted.exe','lab-general-refs-mutation.exe')){throw 'Unexpected executable.'}
            $source=Join-Path $toolsRoot $row.name
            if((Get-Item -LiteralPath $source).Length-ne$row.bytes-or(Get-FileHash -LiteralPath $source).Hash.ToLowerInvariant()-cne$row.sha256){throw 'Host executable pin differs.'}
            if($copyRequired){Copy-Item -LiteralPath $source -ToSession $session -Destination (Join-Path $guestTools $row.name)}
        }
    }
    $priorBoot=''
    if($Phase-in@('AfterPreservationBoot','AfterReboot')){
        $value=$receipt.guest_boot_utc
        if($value-is[DateTime]){
            if($value.Kind-eq[DateTimeKind]::Unspecified){throw 'Prior boot has no timezone.'}
            $priorBoot=$value.ToUniversalTime().ToString('o')
        }elseif($value-is[DateTimeOffset]){$priorBoot=$value.UtcDateTime.ToString('o')}
        else{
            if([string]$value-cnotmatch'(Z|[+-][0-9]{2}:[0-9]{2})$'){throw 'Prior boot lacks an explicit timezone.'}
            $priorBoot=[DateTimeOffset]::Parse([string]$value,[Globalization.CultureInfo]::InvariantCulture).UtcDateTime.ToString('o')
        }
    }
    $result=Invoke-Command -Session $session -ArgumentList $Phase,$guestPost,$guestTools,$dispatch.guest_output,$dispatch.run_id,($manifest.tools|ConvertTo-Json -Compress),($mutation|ConvertTo-Json -Depth 28 -Compress),$priorBoot,$requestPin,$treePin,$phaseKey,[bool]$StreamingV2 -ScriptBlock {
        param($PhaseName,$Post,$Tools,$Output,$Run,$ToolJson,$MutationJson,$PriorBoot,$ExpectedRequestPin,$ExpectedTreePin,$ReportKey,$Streaming)
        Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
        $rows=ConvertFrom-Json -InputObject $ToolJson
        foreach($row in $rows){
            $item=Get-Item -LiteralPath (Join-Path $Tools $row.name)
            if($item.PSIsContainer-or($item.Attributes-band[IO.FileAttributes]::ReparsePoint)-or$item.Length-ne$row.bytes-or
                (Get-FileHash -LiteralPath $item.FullName).Hash.ToLowerInvariant()-cne$row.sha256){throw 'Guest executable differs.'}
        }
        if(@(Get-CimInstance Win32_Process|Where-Object {$_.Name-like'ntfs2refs*'-or$_.Name-ceq'lab-convert-admitted-tree.exe'}).Count){throw 'Converter is active.'}
        $complete=Get-Content -LiteralPath (Join-Path $Output 'result.json') -Raw|ConvertFrom-Json
        if(-not$complete.success-or-not$complete.rollback_closed-or-not$complete.source_admitted){throw 'Successful handoff required.'}
        $boot=(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o')
        if($PhaseName-in@('AfterPreservationBoot','AfterReboot')-and[DateTimeOffset]::Parse($boot)-le[DateTimeOffset]::Parse($PriorBoot)){throw 'New boot required.'}
        $request=Join-Path $Output 'request.json';$expectation=Join-Path $Output 'expectation.json'
        $requestPin=(Get-FileHash -LiteralPath $request).Hash.ToLowerInvariant()
        $treePin=(Get-FileHash -LiteralPath $expectation).Hash.ToLowerInvariant()
        if($requestPin-cne$ExpectedRequestPin-or$treePin-cne$ExpectedTreePin){throw 'Qualified request/expectation pins differ.'}
        $requestValue=Get-Content -LiteralPath $request -Raw|ConvertFrom-Json
        if($requestValue.expected_tree_sha256-cne$treePin-or$complete.expected_tree_sha256-cne$treePin){throw 'Expected-tree binding differs.'}
        if($Streaming-and$requestValue.source_resource_profile-cne'experimental_streaming_tree_v2'){throw 'Streaming source profile required.'}
        $report=Join-Path $Post ($ReportKey+'.json')
        $arguments=@('--request',$request,'--request-sha256',$requestPin,'--output',$report)
        if($PhaseName-ceq'Mutate'){
            $binary=Join-Path $Tools 'lab-general-refs-mutation.exe'
            $arguments+=@('--run-id',([guid]::NewGuid().ToString('N')))
            if(-not$Streaming){$arguments+='--experimental-large-beta'}
        }else{
            $binary=Join-Path $Tools 'lab-verify-general-converted.exe'
            $arguments+=@('--expectation',$expectation,'--expectation-sha256',$treePin)
            if($PhaseName-in@('AfterMutation','AfterReboot')){
                $proof=ConvertFrom-Json -InputObject $MutationJson
                $arguments+=@('--mutation-report',$proof.guest_report,'--mutation-report-sha256',$proof.report_sha256)
            }
        }
        $ErrorActionPreference='Continue'
        $log=@(& $binary @arguments 2>&1);$exit=$LASTEXITCODE
        $ErrorActionPreference='Stop'
        $log|Out-String|Set-Content -LiteralPath (Join-Path $Post ($ReportKey+'.log')) -Encoding utf8
        if($exit-ne0){throw ('Native '+$PhaseName+' refused with exit '+$exit+'; output preserved.')}
        $value=Get-Content -LiteralPath $report -Raw|ConvertFrom-Json
        if($PhaseName-ceq'Mutate'){
            if($value.kind-cne'general-refs-mutation-workload'-or$value.request_sha256-cne$requestPin-or
                -not$value.only_new_test_paths_written-or-not$value.mutation_directory_removed){throw 'Mutation report differs.'}
        }elseif(-not$value.success-or-not$value.ordinary_tree_verified-or$value.diagnostic_only-or$value.request_sha256-cne$requestPin){throw 'Strict verification did not pass.'}
        [pscustomobject]@{success=$true;phase=$PhaseName;run_id=$Run;guest_report=$report;report_sha256=(Get-FileHash -LiteralPath $report).Hash.ToLowerInvariant();
            request_sha256=$requestPin;expectation_sha256=$treePin;guest_boot_utc=$boot;report=$value;utc=[DateTime]::UtcNow.ToString('o')}
    }
    Save-NewRecord (Join-Path $post ($phaseKey+'.json')) $result
    if($phaseKey-cne$Phase){Save-NewRecord (Join-Path $post ($Phase+'.json')) $result}
    if($Phase-ceq'AfterMutation'){
        Save-NewRecord (Join-Path $root 'mutation-result.json') @{success=$true;kind=$(if($StreamingV2){'rust-streaming-v2-mutation'}else{'rust-large-beta-mutation'});run_id=$dispatch.run_id;
            mutation_report_sha256=$mutation.report_sha256;strict_after_report_sha256=$result.report_sha256;full_semantics_independently_rechecked=$true}
    }
    [pscustomobject]@{phase=$Phase;success=$result.success;report_sha256=$result.report_sha256;guest_boot_utc=$result.guest_boot_utc}|ConvertTo-Json -Compress
}finally{Remove-PSSession $session}
