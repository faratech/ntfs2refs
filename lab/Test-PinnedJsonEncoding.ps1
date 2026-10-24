<# Real archived inputs plus disposable ordinary files; no VM/device/native calls. #>
[CmdletBinding()]param()
Set-StrictMode -Version Latest;$ErrorActionPreference='Stop';$script:checks=0
function Check([bool]$Value,[string]$Name){if(-not$Value){throw $Name};$script:checks++}
function Reject([scriptblock]$Body,[string]$Name,[string]$Pattern=''){$failure=$null;try{&$Body|Out-Null}catch{$failure=$_.Exception.Message};Check ($null-ne$failure) $Name;if($Pattern){Check ($failure-match$Pattern) ($Name+' reason')}}
$workspace=Split-Path -Parent $PSScriptRoot;$script:labRoot=Join-Path $workspace '.lab'
foreach($spec in @(
 @('scripts/New-LabNativeReconstructRequest.ps1',@('Assert-NGRHash','Assert-NGRPath','Assert-NGRAncestors','Get-NGRSha','Read-NGRPinned','Convert-NGRJson')),
 @('scripts/Invoke-LabNativeReconstruct.ps1',@('Assert-RHHash','Read-RHBytes','Read-RHJson')),
 @('scripts/Invoke-LabConvertedVerification.ps1',@('Assert-CVHash','Read-CVBytes','Read-CVJson')),
 @('lab/Lab.psm1',@('Assert-LabPath'))
)){
 $tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $workspace $spec[0]),[ref]$tokens,[ref]$errors);Check ($errors.Count-eq0) 'Input source parses.'
 foreach($name in $spec[1]){$defs=@($ast.FindAll({param($n)$n-is[Management.Automation.Language.FunctionDefinitionAst]-and$n.Name-ceq$name},$true));Check ($defs.Count-eq1) 'Exact decoder/reader definition.';. ([scriptblock]::Create($defs[0].Extent.Text))}
}
function Decode([string]$Reader,[string]$Path,[string]$Hash){switch($Reader){NGR{Convert-NGRJson (Read-NGRPinned $Path $Hash 2MB)}RH{Read-RHJson $Path $Hash 2MB}CV{Read-CVJson $Path $Hash 2MB}default{throw 'Unknown test reader.'}}}
$readers=@('NGR','RH','CV');$encoding=New-Object Text.UTF8Encoding($false,$true);$bom=[byte[]]@(239,187,191)
$case=Join-Path $labRoot 'hyperv\retained-native-probe\win11-20261024T045526178Z'
$hostPath=Join-Path $case 'host-result.json';$hostHash='f79b8996db0e617da19a2a0b52d854ccc6f82da61f567724cda69f9cce4ab9f8'
$shadowPath=Join-Path $case 'shadow-platform.json';$shadowHash='fd582940e925891350e308f97740f9f04c350b288537773b297724985518abe9'
$original=Read-NGRPinned $shadowPath $shadowHash 1MB
Check ($original.length-eq39219-and$original.bytes[0]-eq239-and$original.bytes[1]-eq187-and$original.bytes[2]-eq191) 'Exact archived BOM regression input.'
$withoutBom=New-Object byte[] ($original.bytes.Length-3);[Array]::Copy($original.bytes,3,$withoutBom,0,$withoutBom.Length);$strippedHash=Get-NGRSha $withoutBom
Check ($strippedHash-cne$shadowHash) 'Removing BOM changes authenticated bytes.'
foreach($reader in $readers){
 $v=Decode $reader $shadowPath $shadowHash;Check ($v.kind-ceq'guest-local-shadow-platform'-and$v.status-ceq'shadow-platform-prepared'-and$v.runId-ceq'94f6256f57424ad69147f58199387ee1') 'Archived BOM shadow parses through real pinned reader.'
 $h=Decode $reader $hostPath $hostHash;Check ($h.status-ceq'native-isolation-and-restart-verified'-and$h.phase-ceq'complete') 'Archived no-BOM successful host parses.'
 Reject {Decode $reader $shadowPath $strippedHash} 'Normalized-byte hash cannot replace original evidence pin.' 'pin|SHA|content differs'
}
Check ((Get-NGRSha $original.bytes)-ceq$shadowHash) 'Decoding did not mutate supplied archived buffer.'
$temp=Join-Path $labRoot ('json-encoding-test-'+[guid]::NewGuid().ToString('N'));New-Item -ItemType Directory -Path $temp|Out-Null
try{
 $value='accent-'+[char]0x00e9+'-mark-'+[char]0xfeff+'-end';$json='{"kind":"fixture","value":"'+$value+'"}';$plain=$encoding.GetBytes($json)
 $cases=@([pscustomobject]@{name='plain';bytes=$plain},[pscustomobject]@{name='bom';bytes=[byte[]]($bom+$plain)},[pscustomobject]@{name='bom-whitespace';bytes=[byte[]]($bom+$encoding.GetBytes(" `r`n"+$json))})
 foreach($item in $cases){$p=Join-Path $temp ($item.name+'.json');[IO.File]::WriteAllBytes($p,$item.bytes);$pin=Get-NGRSha $item.bytes;foreach($reader in $readers){$v=Decode $reader $p $pin;Check ($v.kind-ceq'fixture'-and$v.value-ceq$value) 'Strict UTF8 preserves non-ASCII and embedded U+FEFF data.'};Check ((Get-NGRSha ([IO.File]::ReadAllBytes($p)))-ceq$pin) 'Input file bytes unchanged.'}
 $bad=@(
  [byte[]]($bom+$bom+$plain),[byte[]]($encoding.GetBytes(' ')+$bom+$plain),[byte[]]($bom+$encoding.GetBytes("`r`n")+$bom+$plain),
  [byte[]]@(239,187),[byte[]]@(255),[byte[]]@(128),[byte[]]@(192,175),[byte[]]@(237,160,128),[byte[]]@(244,144,128,128),
  [byte[]]($bom+[byte[]]@(255)),[byte[]]($plain+[byte[]]@(226,130)),
  [byte[]]@(255,254,123,0,125,0),[byte[]]@(254,255,0,123,0,125),$encoding.GetBytes('{"bad":}')
 )
 $i=0;foreach($bytes in $bad){$p=Join-Path $temp ('bad-'+$i+'.json');[IO.File]::WriteAllBytes($p,$bytes);$pin=Get-NGRSha $bytes;foreach($reader in $readers){Reject {Decode $reader $p $pin} 'Malformed UTF8/JSON or extra/displaced BOM refuses.'};$i++}
 $p=Join-Path $temp 'bad-4.json';foreach($reader in $readers){Reject {Decode $reader $p ('0'*64)} 'Raw hash refusal precedes malformed UTF8 decoding.' 'pin|SHA|content differs'}
 # Exercise the full pure generator against all ten archived inputs. Its two
 # create-new outputs live only in this disposable test directory.
 $output=Join-Path $temp 'request.json';$result=& (Join-Path $workspace 'scripts/New-LabNativeReconstructRequest.ps1') -ProbeResultPath $hostPath -ProbeResultSha256 $hostHash -OutputPath $output -Confirm:$false
 Check ($result.Status-ceq'request-created'-and-not$result.ConversionQualified) 'Actual archive derives a request without native operations.'
 foreach($spec in @(@($output,$result.RequestSha256),@(($output+'.pin.json'),$result.PinSha256))){$b=[IO.File]::ReadAllBytes($spec[0]);Check ($b.Length-gt3-and-not($b[0]-eq239-and$b[1]-eq187-and$b[2]-eq191)) 'Production generated output is UTF8 without BOM.';Check ((Get-NGRSha $b)-ceq$spec[1]) 'Production output pin binds exact bytes.';$encoding.GetString($b)|ConvertFrom-Json|Out-Null;$script:checks++}
 $pin=Read-RHJson ($output+'.pin.json') $result.PinSha256;$entry=@($pin.inputs|Where-Object path -CEQ $shadowPath)
 Check ($pin.inputs.Count-eq10-and$entry.Count-eq1-and$entry[0].sha256-ceq$shadowHash-and$entry[0].length-eq39219) 'Generated provenance retains original BOM input hash and length.'
 Reject {& (Join-Path $workspace 'scripts/New-LabNativeReconstructRequest.ps1') -ProbeResultPath $hostPath -ProbeResultSha256 $hostHash -OutputPath $output -Confirm:$false} 'Create-new output protection remains enforced.'
}finally{
 $resolved=[IO.Path]::GetFullPath($temp);$prefix=[IO.Path]::GetFullPath($labRoot).TrimEnd('\')+'\'
 if(-not$resolved.StartsWith($prefix,[StringComparison]::OrdinalIgnoreCase)-or(Split-Path $resolved -Leaf)-cnotmatch'\Ajson-encoding-test-[0-9a-f]{32}\z'){throw 'Unsafe ordinary test cleanup path.'}
 Remove-Item -LiteralPath $resolved -Recurse -Force
}
Check ((Get-FileHash -LiteralPath $shadowPath -Algorithm SHA256).Hash.ToLowerInvariant()-ceq$shadowHash) 'Original shadow artifact remains byte-identical.'
Check ((Get-FileHash -LiteralPath $hostPath -Algorithm SHA256).Hash.ToLowerInvariant()-ceq$hostHash) 'Passed native host record remains byte-identical.'
Write-Output ('PASS: '+$script:checks+' pinned JSON encoding/archive/generator checks; no VM/device calls, only disposable ordinary outputs.')
