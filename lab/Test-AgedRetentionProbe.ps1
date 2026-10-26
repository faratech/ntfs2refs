<# Pure profile/extent refusals; no guest, filesystem fixture or device call. #>
[CmdletBinding()]param()
Set-StrictMode -Version Latest;$ErrorActionPreference='Stop';$checks=0
function Check([bool]$ok,[string]$message){if(-not$ok){throw $message};$script:checks++}
function Refuse([scriptblock]$action,[string]$message){$rejected=$false;try{&$action|Out-Null}catch{$rejected=$true};Check $rejected $message}
$tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'guest/Add-AgedRetentionProbe.ps1'),[ref]$tokens,[ref]$errors)
Check (-not$errors) 'Guest wrapper must parse.'
$commands=@($ast.FindAll({param($n)$n-is[Management.Automation.Language.CommandAst]},$true)|ForEach-Object {$_.GetCommandName()})
foreach($name in @('Remove-Item','Move-Item','Set-Disk','Format-Volume','Mount-VHD','Dismount-VHD','Start-Process','fsutil')){Check ($commands-notcontains$name) ('Forbidden wrapper operation: '+$name)}
$methods=@($ast.FindAll({param($n)$n-is[Management.Automation.Language.InvokeMemberExpressionAst]-and$n.Expression.Extent.Text-ceq'$native'},$true)|ForEach-Object {$_.Member.Value})
Check (($methods-join',')-ceq'ReserveInitializedZeroes,Reserve,CreateProbe,DeleteOwnedReservation,ClosePreserving') 'Native fixture lifecycle differs.'
Add-Type -Path (Join-Path $PSScriptRoot 'guest/NativeAgedRetentionProbe.cs')
$volume='\\?\Volume{11111111-2222-3333-4444-555555555555}\'
[Ntfs2Refs.NativeAgedRetentionProbe]::ValidateInputs(('a'*32),$volume)
Check ([BitConverter]::ToInt64([Ntfs2Refs.NativeAgedRetentionProbe]::AllocationInput(),0)-eq8GB) 'Reservation must be exactly8GiB.'
Refuse {[Ntfs2Refs.NativeAgedRetentionProbe]::ValidateInputs(('A'*32),$volume)} 'Uppercase fixture ID accepted.'
Refuse {[Ntfs2Refs.NativeAgedRetentionProbe]::ValidateInputs(('a'*31),$volume)} 'Short fixture ID accepted.'
Refuse {[Ntfs2Refs.NativeAgedRetentionProbe]::ValidateInputs(('a'*32),'F:\')} 'Drive alias accepted as volume identity.'
Refuse {[Ntfs2Refs.NativeAgedRetentionProbe]::ValidateInputs(('a'*32),'\\?\Volume{00000000-0000-0000-0000-000000000000}\')} 'Empty volume identity accepted.'
function Standard([long]$allocation,[long]$eof){$b=[byte[]]::new(24);[BitConverter]::GetBytes($allocation).CopyTo($b,0);[BitConverter]::GetBytes($eof).CopyTo($b,8);[BitConverter]::GetBytes([uint32]1).CopyTo($b,16);return ,$b}
$reserved=[Ntfs2Refs.NativeAgedRetentionProbe]::ParseStandard((Standard 8GB 0))
Check ($reserved.allocationBytes-eq8GB-and$reserved.eofBytes-eq0) 'Allocation-only EOF0 state differs.'
Refuse {[Ntfs2Refs.NativeAgedRetentionProbe]::ParseStandard((Standard (8GB+4096) 0))} 'Reservation exceeded fixed cap.'
Refuse {[Ntfs2Refs.NativeAgedRetentionProbe]::ParseStandard((Standard 8MB 9MB))} 'Probe EOF exceeded bound.'
function Mapping([long]$lcn){$b=[byte[]]::new(32);[BitConverter]::GetBytes([uint32]1).CopyTo($b,0);[BitConverter]::GetBytes([long]2048).CopyTo($b,16);[BitConverter]::GetBytes($lcn).CopyTo($b,24);return ,$b}
$high=[Ntfs2Refs.NativeAgedRetentionProbe]::ParseRetrieval((Mapping (8GB/4096)),8MB)
Check ([Ntfs2Refs.NativeAgedRetentionProbe]::Suitable($high)) 'Complete high mapping was refused.'
$low=[Ntfs2Refs.NativeAgedRetentionProbe]::ParseRetrieval((Mapping 6408),8MB)
Check (-not[Ntfs2Refs.NativeAgedRetentionProbe]::Suitable($low)) 'Low native placement was reported suitable.'
Refuse {[Ntfs2Refs.NativeAgedRetentionProbe]::ParseRetrieval((Mapping (8GB/4096)),16MB)} 'Unused preallocation was omitted from the complete mapping.'
foreach($case in @('truncated','partial','sparse','outside','count','start')){
 $bad=Mapping (8GB/4096)
 switch($case){'truncated'{$bad=[byte[]]$bad[0..30]};'partial'{[BitConverter]::GetBytes([long]2047).CopyTo($bad,16)};'sparse'{[BitConverter]::GetBytes([long]-1).CopyTo($bad,24)};'outside'{[BitConverter]::GetBytes([long](52GB/4096-1024)).CopyTo($bad,24)};'count'{[BitConverter]::GetBytes([uint32]2).CopyTo($bad,0)};'start'{[BitConverter]::GetBytes([long]1).CopyTo($bad,8)}}
 Refuse {[Ntfs2Refs.NativeAgedRetentionProbe]::ParseRetrieval($bad,8MB)} ('Malformed mapping accepted: '+$case)
}
Check ($ast.ParamBlock.Parameters.Name.VariablePath.UserPath-contains'SequentialZeroReservation') 'Explicit zero-reservation switch is absent.'
Check ([long][Ntfs2Refs.NativeAgedRetentionProbe]::ReservationChunkBytes*[Ntfs2Refs.NativeAgedRetentionProbe]::ReservationWriteCount-eq8GB) 'Sequential write schedule must cover exactly8GiB.'
Check ([Ntfs2Refs.NativeAgedRetentionProbe]::ReservationChunkBytes-eq1MB-and[Ntfs2Refs.NativeAgedRetentionProbe]::ReservationWriteCount-eq8192) 'Sequential writes must be8192 one-MiB chunks.'
$initialized=[Ntfs2Refs.NativeAgedRetentionProbe]::ParseReservationStandard((Standard 8GB 8GB))
[Ntfs2Refs.NativeAgedRetentionProbe]::ValidateReservationSnapshot($initialized,$true)
Check ($initialized.allocationBytes-eq8GB-and$initialized.eofBytes-eq8GB) 'Initialized reservation EOF/allocation differs.'
[Ntfs2Refs.NativeAgedRetentionProbe]::ValidateReservationSnapshot($reserved,$false)
Check ($reserved.eofBytes-eq0) 'Default reservation EOF must remain zero.'
Refuse {[Ntfs2Refs.NativeAgedRetentionProbe]::ValidateReservationSnapshot($initialized,$false)} 'Initialized reservation accepted as allocation-only.'
Refuse {[Ntfs2Refs.NativeAgedRetentionProbe]::ValidateReservationSnapshot($reserved,$true)} 'EOF0 reservation accepted as initialized.'
Refuse {[Ntfs2Refs.NativeAgedRetentionProbe]::ValidateReservationSnapshot([Ntfs2Refs.NativeAgedRetentionProbe]::ParseReservationStandard((Standard (8GB-4096) 8GB)),$true)} 'Short allocation accepted for initialized reservation.'
Refuse {[Ntfs2Refs.NativeAgedRetentionProbe]::ParseReservationStandard((Standard 8GB (8GB+1)))} 'Reservation EOF exceeded cap.'
Refuse {[Ntfs2Refs.NativeAgedRetentionProbe]::ParseStandard((Standard 8GB 8GB))} 'Reservation parser weakened ordinary probe EOF bound.'
$fresh=New-Object Ntfs2Refs.NativeAgedRetentionProbe(('a'*32),$volume,1)
Check ($fresh.Result.reservationMode-ceq'allocation_only'-and$fresh.Result.reservationPayloadBytesWritten-eq0-and$fresh.Result.reservationWriteCalls-eq0) 'Fresh default mode must not claim payload writes.'
[pscustomobject]@{checks=$checks;syntaxValid=$true;allocationCapBytes=8GB;probeBytes=8MB;lowPlacementReportedUnsuitable=$true;vmOperations=0;fixtureFilesCreated=0}
