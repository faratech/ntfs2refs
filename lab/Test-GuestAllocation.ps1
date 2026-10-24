<# Pure response/guard checks and read-only queries on isolated ordinary files.
   No Hyper-V calls, volume handles, formatter, allocator or disk writes. #>
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$tokens=$null; $errors=$null
$source = Join-Path $PSScriptRoot 'guest\Capture-GuestAllocation.ps1'
$ast = [Management.Automation.Language.Parser]::ParseFile($source,[ref]$tokens,[ref]$errors)
if ($errors.Count) { throw 'Allocation collector parser errors.' }
$literal = $ast.Find({param($node) $node -is [Management.Automation.Language.StringConstantExpressionAst] -and $node.Value.Contains('public static class NativeAllocationEvidence')},$true)
if (-not $literal) { throw 'Production allocation helper not found.' }
if (-not ('Ntfs2Refs.NativeAllocationEvidence' -as [type])) { Add-Type -TypeDefinition $literal.Value }
$definition = $ast.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Assert-AllocationRelativePath'},$false)
Invoke-Expression $definition.Extent.Text
$script:checks=0
function Check([bool]$Value,[string]$Message) { if (-not $Value) { throw $Message }; $script:checks++ }
function Reject([scriptblock]$Action,[string]$Message) { $refused=$false; try { & $Action | Out-Null } catch { $refused=$true }; Check $refused $Message }
function Page([long]$Start,[long[]]$Next,[long[]]$Lcn) {
    $bytes=New-Object byte[] (16+16*$Next.Count)
    [BitConverter]::GetBytes([uint32]$Next.Count).CopyTo($bytes,0)
    [BitConverter]::GetBytes($Start).CopyTo($bytes,8)
    for($i=0;$i -lt $Next.Count;$i++) { [BitConverter]::GetBytes($Next[$i]).CopyTo($bytes,16+16*$i); [BitConverter]::GetBytes($Lcn[$i]).CopyTo($bytes,24+16*$i) }
    ,$bytes
}
foreach($path in @('nonresident.bin','directory\file with spaces.bin','Unicode-file.txt')) { Assert-AllocationRelativePath $path; $script:checks++ }
foreach($path in @('','..\file','a\..\file','.\file','a\\b','\file','C:\file','file:ads','file*','file?','file.','file ','NUL','aux.txt','COM1.bin',('a'+[char]1+'b'))) { Reject { Assert-AllocationRelativePath $path } "Unsafe relative path accepted: $path" }
Check ([Ntfs2Refs.NativeAllocationEvidence]::ValidateLocalPath('D:\ordinary\file.bin') -ceq 'D:\ordinary\file.bin') 'Ordinary canonical path refused.'
foreach($path in @('\\.\PhysicalDrive0','\\?\D:\file','\\server\file','D:\file:ads','D:\..\file','D:\folder\file.','D:\NUL','D:/file','D:\folder\','D:\a\\b')) { Reject { [Ntfs2Refs.NativeAllocationEvidence]::ValidateLocalPath($path) } "Unsafe absolute path accepted: $path" }
$page = Page 0 @(2,5) @(10,-1)
$parsed=[Ntfs2Refs.NativeAllocationEvidence]::ParsePage($page,$page.Length,0,4096)
Check ($parsed.extents.Count -eq 2 -and $parsed.nextVcn -eq 5 -and $parsed.extents[0].startingVcn -eq 0 -and $parsed.extents[0].lcn -eq 10 -and $parsed.extents[1].startingVcn -eq 2 -and $parsed.extents[1].lcn -eq -1) 'Ordinary and native sentinel mappings were changed.'
$nextPage=Page 5 @(9) @(35)
Check (([Ntfs2Refs.NativeAllocationEvidence]::ParsePage($nextPage,$nextPage.Length,5,1)).nextVcn -eq 9) 'Pagination boundary refused.'
Reject { [Ntfs2Refs.NativeAllocationEvidence]::ParsePage($page,15,0,4096) } 'Truncated header accepted.'
Reject { [Ntfs2Refs.NativeAllocationEvidence]::ParsePage($page,$page.Length-1,0,4096) } 'Truncated extent accepted.'
Reject { [Ntfs2Refs.NativeAllocationEvidence]::ParsePage($page,$page.Length+1,0,4096) } 'Beyond-buffer length accepted.'
Reject { [Ntfs2Refs.NativeAllocationEvidence]::ParsePage($page,$page.Length,1,4096) } 'Unexpected rounded starting VCN accepted.'
Reject { [Ntfs2Refs.NativeAllocationEvidence]::ParsePage($page,$page.Length,0,1) } 'Extent limit ignored.'
Reject { [Ntfs2Refs.NativeAllocationEvidence]::ParsePage($page,$page.Length,0,0) } 'Exhausted extent budget accepted.'
foreach($pair in @(@(0,1),@(1,-2),@(2,[long]::MaxValue))) {
    $invalid=Page 0 @([long]$pair[0]) @([long]$pair[1])
    Reject { [Ntfs2Refs.NativeAllocationEvidence]::ParsePage($invalid,$invalid.Length,0,4096) } 'Invalid progression or LCN range accepted.'
}
$emptyPage=Page 0 @() @()
Reject { [Ntfs2Refs.NativeAllocationEvidence]::ParsePage($emptyPage,$emptyPage.Length,0,4096) } 'Zero-progress response accepted.'
$badCount=[byte[]]$page.Clone(); [BitConverter]::GetBytes([uint32]::MaxValue).CopyTo($badCount,0)
Reject { [Ntfs2Refs.NativeAllocationEvidence]::ParsePage($badCount,$badCount.Length,0,4096) } 'Huge native extent count accepted.'
$root=Join-Path (Split-Path $PSScriptRoot -Parent) ('.lab\tests\allocation-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $root | Out-Null
$path=Join-Path $root 'ordinary file.bin'
$payload=New-Object byte[] 1048576
for($i=0;$i -lt $payload.Length;$i++) { $payload[$i]=[byte]($i % 251) }
[IO.File]::WriteAllBytes($path,$payload)
$hash=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
$observation=[Ntfs2Refs.NativeAllocationEvidence]::Collect($path,$payload.Length)
Check ($observation.length -eq $payload.Length -and $observation.sha256 -ceq $hash -and $observation.stableDuringObservation -and $observation.controlCalls -le 32) 'Ordinary native observation lost logical content or exceeded call bound.'
Check ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() -ceq $hash) 'Read-only observation changed ordinary file content.'
Check ($observation.status -in @('mapping-returned','native-error','no-nonresident-mapping-returned') -and ($observation.status -ne 'native-error' -or (-not $observation.complete -and $observation.nativeError -ne 0))) 'Native status was mislabeled as successful.'
Reject { [Ntfs2Refs.NativeAllocationEvidence]::Collect($path,$payload.Length-1) } 'Logical hash budget ignored.'
Reject { [Ntfs2Refs.NativeAllocationEvidence]::Collect($path,-1) } 'Negative logical hash budget accepted.'
Reject { [Ntfs2Refs.NativeAllocationEvidence]::Collect($path,268435457) } 'Maximum logical hash budget ignored.'
Reject { [Ntfs2Refs.NativeAllocationEvidence]::Collect((Join-Path $root 'missing.bin'),1024) } 'Missing input created.'
Check (-not (Test-Path -LiteralPath (Join-Path $root 'missing.bin'))) 'Native query created a missing file.'
Reject { [Ntfs2Refs.NativeAllocationEvidence]::Collect($root,1024) } 'Directory accepted as ordinary file.'
$emptyPath=Join-Path $root 'empty.bin'; [IO.File]::WriteAllBytes($emptyPath,[byte[]]@())
$emptyObservation=[Ntfs2Refs.NativeAllocationEvidence]::Collect($emptyPath,0)
Check ($emptyObservation.length -eq 0 -and $emptyObservation.sha256 -ceq 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' -and $emptyObservation.stableDuringObservation) 'Empty-file observation lost its empty logical hash.'
$writer=New-Object IO.FileStream($path,[IO.FileMode]::Open,[IO.FileAccess]::Write,[IO.FileShare]::ReadWrite)
try { Reject { [Ntfs2Refs.NativeAllocationEvidence]::Collect($path,$payload.Length) } 'Concurrent writable handle accepted.' } finally { $writer.Dispose() }
$link=Join-Path $root 'alias.bin'
New-Item -ItemType SymbolicLink -Path $link -Target $path | Out-Null
Reject { [Ntfs2Refs.NativeAllocationEvidence]::Collect($link,$payload.Length) } 'Symbolic-link file followed.'
$directoryLink=Join-Path $root 'alias-directory'
New-Item -ItemType Junction -Path $directoryLink -Target $root | Out-Null
Reject { [Ntfs2Refs.NativeAllocationEvidence]::Collect((Join-Path $directoryLink 'ordinary file.bin'),$payload.Length) } 'Junction parent followed.'
$reportPath=Join-Path $root 'report.json'
$reportBytes=[Text.Encoding]::UTF8.GetBytes('{"test":true}')
[Ntfs2Refs.NativeAllocationEvidence]::WriteReport($reportPath,$reportBytes)
Check ([IO.File]::ReadAllText($reportPath) -ceq '{"test":true}') 'Create-new report did not preserve the exact bytes.'
Reject { [Ntfs2Refs.NativeAllocationEvidence]::WriteReport($reportPath,$reportBytes) } 'Existing report overwritten.'
Reject { [Ntfs2Refs.NativeAllocationEvidence]::WriteReport((Join-Path $directoryLink 'escaped-report.json'),$reportBytes) } 'Report parent junction followed.'
Check (-not (Test-Path -LiteralPath (Join-Path $root 'escaped-report.json'))) 'Report was created through the refused parent junction.'
Reject { [Ntfs2Refs.NativeAllocationEvidence]::WriteReport((Join-Path $root 'oversize.json'),(New-Object byte[] (8MB+1))) } 'Output byte limit ignored.'
Check ($literal.Value -notmatch 'GENERIC_WRITE|FSCTL_MOVE_FILE|SetFileValidData|FSCTL_SET|WriteFile|PhysicalDrive' -and ([regex]::Matches($literal.Value,'const uint RetrievalPointers = 0x00090073')).Count -eq 1) 'Unexpected native write operation or control identifier.'
"Passed $script:checks allocation checks; native ordinary-file status=$($observation.status), extents=$($observation.extents.Count). No VM or volume handles used. Test files retained at $root"
