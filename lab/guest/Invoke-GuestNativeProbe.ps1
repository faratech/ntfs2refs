<# Launch only the pinned native isolation/read probe in the owned guest. #>
[CmdletBinding(SupportsShouldProcess)]
param(
 [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{32}\z')][string]$RunId,
 [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{32}\z')][string]$ProbeId,
 [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$RequestSha256,
 [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$BinarySha256,
 [switch]$Reopen,[switch]$WholePartition,
 [ValidateRange(30,900)][int]$TimeoutSeconds=600
)
Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
function Assert-NativeProbeFields($Value,[string[]]$Names){
 if($null-eq$Value-or@($Value.PSObject.Properties).Count-ne$Names.Count){throw 'Native evidence fields differ.'}
 foreach($name in $Names){if(-not($Value.PSObject.Properties.Name-ccontains$name)){throw 'Native evidence field missing.'}}
}
function Assert-NativeProbeGuid([string]$Text){
 if($Text-cnotmatch '\A(?:[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\})\z'-or[guid]$Text-eq[guid]::Empty){throw 'Native evidence GUID differs.'}
}
function Assert-NativeProbeBinding($Binding,[int]$Number){
 Assert-NativeProbeFields $Binding @('disk_number','volume_guid','identity')
 Assert-NativeProbeFields $Binding.identity @('disk_guid','partition_guid','partition_number','disk_bytes','partition_offset','partition_bytes','logical_sector_bytes','physical_sector_bytes')
 foreach($text in @($Binding.volume_guid,$Binding.identity.disk_guid,$Binding.identity.partition_guid)){Assert-NativeProbeGuid $text}
 $i=$Binding.identity
 if($Binding.disk_number-ne$Number-or$i.partition_number-ne2-or$i.disk_bytes-ne64GB-or$i.partition_offset-ne16MB-or$i.partition_bytes-ne52GB-or$i.logical_sector_bytes-ne512-or$i.physical_sector_bytes-ne4096){throw 'Native evidence geometry differs.'}
}
function Assert-NativeProbeRequest($Request,[string]$ExpectedRunId){
 Assert-NativeProbeFields $Request @('schema_version','experiment_id','fixture_evidence_sha256','target','shadow','retained_offset','source_retained_sha256','shadow_retained_sha256')
 if($Request.schema_version-ne1-or$Request.experiment_id-cne$ExpectedRunId-or$ExpectedRunId-cnotmatch '\A[0-9a-f]{32}\z'){throw 'Native request identity differs.'}
 Assert-NativeProbeBinding $Request.target 1;Assert-NativeProbeBinding $Request.shadow 3
 foreach($name in @('fixture_evidence_sha256','source_retained_sha256','shadow_retained_sha256')){if($Request.$name-cnotmatch '\A[0-9a-f]{64}\z'){throw 'Native request evidence pin differs.'}}
 foreach($field in @('disk_guid','partition_guid')){if([guid]$Request.target.identity.$field-eq[guid]$Request.shadow.identity.$field){throw 'Native disk identities overlap.'}}
 if([guid]$Request.target.volume_guid-eq[guid]$Request.shadow.volume_guid-or$Request.source_retained_sha256-ceq$Request.shadow_retained_sha256-or$Request.retained_offset-lt8GB-or$Request.retained_offset-gt(9GB-65536)-or$Request.retained_offset%4096-ne0){throw 'Native retained range or independence differs.'}
}
function Assert-NativeProbeSame($Expected,$Actual){
 if($null-eq$Expected-or$null-eq$Actual){if($null-ne$Expected-or$null-ne$Actual){throw 'Native evidence null differs.'};return}
 if($Expected-is[pscustomobject]){
  Assert-NativeProbeFields $Actual @($Expected.PSObject.Properties.Name)
  foreach($name in $Expected.PSObject.Properties.Name){Assert-NativeProbeSame $Expected.$name $Actual.$name};return
 }
 if($Expected-is[string]){if($Actual-isnot[string]-or$Expected-cne$Actual){throw 'Native evidence string differs.'};return}
 if($Expected-is[bool]){if($Actual-isnot[bool]-or$Expected-ne$Actual){throw 'Native evidence boolean differs.'};return}
 if($Actual-is[string]-or$Actual-is[bool]-or$Expected-ne$Actual){throw 'Native evidence value differs.'}
}
function Assert-NativeProbeResult($Report,$Request,[bool]$ExpectedReopen,[bool]$ExpectedWhole){
 Assert-NativeProbeRequest $Request $Request.experiment_id
 Assert-NativeProbeFields $Report @('schema_version','kind','request','reopen','success','phase','error','target_snapshot','shadow_snapshot','target_retained_sha256','shadow_retained_sha256','target_partition_sha256','shadow_partition_sha256','target_flush_succeeded','target_bytes_read','shadow_bytes_read','payload_write_requests_issued','conversion_qualified','events')
 Assert-NativeProbeSame $Request $Report.request
 foreach($pair in @(@($Report.success,$true),@($Report.reopen,$ExpectedReopen),@($Report.payload_write_requests_issued,$false),@($Report.conversion_qualified,$false),@($Report.target_flush_succeeded,$true))){if($pair[0]-isnot[bool]-or$pair[0]-ne$pair[1]){throw 'Native completion boolean differs.'}}
 if($Report.schema_version-ne1-or$Report.kind-cne'native-partition-isolation-probe'-or$Report.phase-cne'complete-disks-remain-offline'-or$null-ne$Report.error-or$Report.target_retained_sha256-cne$Request.source_retained_sha256-or$Report.shadow_retained_sha256-cne$Request.shadow_retained_sha256){throw 'Native completion evidence differs.'}
 foreach($role in @('target','shadow')){
  $snapshot=$Report.($role+'_snapshot');Assert-NativeProbeFields $snapshot @('binding','disk_attributes','device','length','alignment','layout');Assert-NativeProbeSame $Request.$role $snapshot.binding
  $attributes=if($role-ceq'target'){1}else{3};if($snapshot.disk_attributes-ne$attributes){throw 'Native persistent isolation differs.'}
  foreach($spec in @(@('device',12,12),@('length',8,8),@('alignment',28,28),@('layout',48,65536))){$bytes=@($snapshot.($spec[0]));if($bytes.Count-lt$spec[1]-or$bytes.Count-gt$spec[2]){throw 'Native snapshot bytes incomplete.'};foreach($b in $bytes){if($null-eq$b-or$b-is[string]-or$b-is[bool]-or$b-lt0-or$b-gt255-or[long]$b-ne$b){throw 'Native snapshot contains a non-byte.'}}}
 }
 $expected=65536L
 if($ExpectedWhole){$expected+=52GB;foreach($hash in @($Report.target_partition_sha256,$Report.shadow_partition_sha256)){if($hash-cnotmatch '\A[0-9a-f]{64}\z'){throw 'Full partition pins absent.'}}}
 elseif($null-ne$Report.target_partition_sha256-or$null-ne$Report.shadow_partition_sha256){throw 'Unexpected full-partition result.'}
 foreach($n in @($Report.target_bytes_read,$Report.shadow_bytes_read)){if($n-is[string]-or$n-is[bool]-or$n-ne$expected){throw 'Raw byte accounting differs.'}}
 if(@($Report.events).Count-lt1-or@($Report.events).Count-gt128){throw 'Native control event bound differs.'}
 foreach($event in $Report.events){Assert-NativeProbeFields $event @('operation','control_code','input','succeeded','native_error','output');if($event.succeeded-isnot[bool]-or-not$event.succeeded-or$null-ne$event.native_error-or$event.operation-isnot[string]-or$event.operation.Length-lt1-or$event.operation.Length-gt128-or@($event.input).Count-gt65536-or@($event.output).Count-gt65536){throw 'Native control evidence incomplete.'}}
}
function Open-NativeProbeInput([string]$Path,[string]$Hash,[long]$Maximum){
 $item=Get-Item -LiteralPath $Path -Force
 if($item.PSIsContainer-or($item.Attributes-band[IO.FileAttributes]::ReparsePoint)-or$item.Length-lt1-or$item.Length-gt$Maximum){throw 'Pinned input shape differs.'}
 $stream=New-Object IO.FileStream($item.FullName,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
 try{if($stream.Length-lt1-or$stream.Length-gt$Maximum){throw 'Pinned input length changed.'};$sha=[Security.Cryptography.SHA256]::Create();try{$actual=[BitConverter]::ToString($sha.ComputeHash($stream)).Replace('-','').ToLowerInvariant()}finally{$sha.Dispose()};if($actual-cne$Hash){throw 'Pinned input hash differs.'};$stream.Position=0;return $stream}catch{$stream.Dispose();throw}
}
function Read-NativeProbeArtifact([string]$Path,[long]$Maximum,[switch]$AllowEmpty){
 $item=Get-Item -LiteralPath $Path -Force
 if($item.PSIsContainer-or($item.Attributes-band[IO.FileAttributes]::ReparsePoint)-or$item.Length-gt$Maximum-or(-not$AllowEmpty-and$item.Length-lt1)){throw 'Native artifact shape or bound differs.'}
 $stream=New-Object IO.FileStream($item.FullName,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
 try{if($stream.Length-gt$Maximum-or(-not$AllowEmpty-and$stream.Length-lt1)){throw 'Native artifact length changed.'};$bytes=New-Object byte[] $stream.Length;$at=0;while($at-lt$bytes.Length){$n=$stream.Read($bytes,$at,$bytes.Length-$at);if($n-le0){throw 'Short native artifact.'};$at+=$n};return ,$bytes}finally{$stream.Dispose()}
}
function Initialize-N2RProcessCapture {
 # Embedded identically in both pinned wrappers: no extra staged dependency.
 # A fresh managed type is required; never reuse an unpinned preloaded runner.
 if('Ntfs2Refs.BoundedLabProcess'-as[type]){throw 'Fresh PowerShell process required for pinned process capture.'}
 Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
namespace Ntfs2Refs {
 public sealed class BoundedLabProcess : IDisposable {
  const int Limit=65536;
  static readonly object Gate=new object();
  static readonly List<BoundedLabProcess> Active=new List<BoundedLabProcess>();
  readonly Process process=new Process();
  Task stdout,stderr;bool complete,disposed;int overflow;
  public int Id { get { return process.Id; } }
  public int ExitCode { get { if(!complete)throw new InvalidOperationException("Completion is unknown.");return process.ExitCode; } }
  public bool OutputLimitExceeded { get { return Interlocked.CompareExchange(ref overflow,0,0)!=0; } }
  public static int RetainedCount { get { lock(Gate)return Active.Count; } }
  async Task Pump(Stream input,FileStream output) {
   byte[] buffer=new byte[4096];int written=0;
   try {
    while(true){int n=await input.ReadAsync(buffer,0,buffer.Length).ConfigureAwait(false);if(n==0)break;
     int keep=Math.Min(n,Limit-written);if(keep>0){await output.WriteAsync(buffer,0,keep).ConfigureAwait(false);written+=keep;}
     if(keep<n)Interlocked.Exchange(ref overflow,1);
    }
   } finally { try { output.Flush(true); } finally { output.Dispose(); } }
  }
  public static BoundedLabProcess Start(string executable,string arguments,string directory,string stdoutPath,string stderrPath) {
   if(!Path.IsPathRooted(executable)||!Path.IsPathRooted(directory)||!Path.IsPathRooted(stdoutPath)||!Path.IsPathRooted(stderrPath)||
      String.Equals(Path.GetFullPath(stdoutPath),Path.GetFullPath(stderrPath),StringComparison.OrdinalIgnoreCase))
    throw new ArgumentException("Absolute distinct process/capture paths required.");
   BoundedLabProcess capture=new BoundedLabProcess();FileStream output=null,error=null;bool started=false;
   try {
    output=new FileStream(stdoutPath,FileMode.CreateNew,FileAccess.Write,FileShare.Read,4096,true);
    error=new FileStream(stderrPath,FileMode.CreateNew,FileAccess.Write,FileShare.Read,4096,true);
    ProcessStartInfo info=capture.process.StartInfo;info.FileName=executable;info.Arguments=arguments;info.WorkingDirectory=directory;
    info.UseShellExecute=false;info.CreateNoWindow=true;info.RedirectStandardOutput=true;info.RedirectStandardError=true;info.RedirectStandardInput=true;
    if(!capture.process.Start())throw new IOException("Managed child start returned false.");started=true;
    // Process.Start owns the native process handle; force its retained access now.
    lock(Gate)Active.Add(capture);
    IntPtr handle=capture.process.Handle;if(handle==IntPtr.Zero)throw new IOException("Started process handle absent.");
    capture.stdout=capture.Pump(capture.process.StandardOutput.BaseStream,output);output=null;
    capture.stderr=capture.Pump(capture.process.StandardError.BaseStream,error);error=null;
    capture.process.StandardInput.Close();
    return capture;
   } catch {
    // After Start, retain the process and any active pumps even if setup failed.
    // There is deliberately no Kill, timed-out Dispose or output-file deletion.
    if(!started){capture.process.Dispose();if(output!=null)output.Dispose();if(error!=null)error.Dispose();}
    throw;
   }
  }
  public bool WaitForExit(int milliseconds) {
   if(disposed)throw new ObjectDisposedException("BoundedLabProcess");
   if(milliseconds<1||milliseconds>7200000)throw new ArgumentOutOfRangeException("milliseconds");
   if(complete)return true;Stopwatch watch=Stopwatch.StartNew();
   if(!process.WaitForExit(milliseconds))return false;
   int left=(int)Math.Max(0,milliseconds-watch.ElapsedMilliseconds);
   if(stdout==null||stderr==null||!Task.WaitAll(new Task[]{stdout,stderr},left))return false;
   complete=true;return true;
  }
  public void Dispose() {
   if(disposed)return;if(!complete)throw new InvalidOperationException("Unknown child/capture completion must be preserved.");
   process.Dispose();disposed=true;lock(Gate)Active.Remove(this);
  }
 }
}
'@
}
function Complete-NativeProbeProcess($Process,$Record,[int]$Seconds){
 if(-not$Process.WaitForExit($Seconds*1000)){throw 'Native probe deadline exceeded; preserve process and branch.'}
 $Record.completionKnown=$true;$Record.exitCode=$Process.ExitCode
 if($null-eq$Record.exitCode-or$Record.exitCode-isnot[int]){throw 'Process exited without a determinate exit code.'}
 if($Process.OutputLimitExceeded){throw 'Native process output exceeded the 64 KiB capture bound; preserved prefixes are incomplete.'}
 if($Record.exitCode-ne0){throw 'Native probe returned failure; inspect preserved probe report.'}
}
if(-not $PSCmdlet.ShouldProcess('exact enrolled target and independent shadow','Run pinned isolation/raw-read probe; leave persistent offline state')){return}
if($env:COMPUTERNAME-cne'N2R-WIN11'-or$env:SystemDrive-cne'C:'){throw 'Exact owned guest required.'}
$root='C:\ntfs2refs\native-probe\'+$RunId+'\'+$ProbeId
foreach($path in @('C:\','C:\ntfs2refs','C:\ntfs2refs\native-probe',('C:\ntfs2refs\native-probe\'+$RunId),$root)){
 $f=Get-Item -LiteralPath $path -Force;if(-not$f.PSIsContainer-or($f.Attributes-band[IO.FileAttributes]::ReparsePoint)){throw 'Ordinary prepared evidence directory required.'}
}
$binary=Join-Path $root 'lab-native-probe.exe';$requestPath=Join-Path $root 'request.json'
if(@(Get-ChildItem -LiteralPath $root -Force).Count-ne2){throw 'Exactly the pinned binary and request must be staged.'}
$binaryPin=$null;$requestPin=$null;$p=$null
function Write-NativeProbeRecord([string]$Name,$Value){
 $bytes=(New-Object Text.UTF8Encoding($false,$true)).GetBytes(($Value|ConvertTo-Json -Depth 8));if($bytes.Length-gt64KB){throw 'Process evidence bound exceeded.'}
 $stream=New-Object IO.FileStream((Join-Path $root $Name),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
 try{$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
}
$arguments=@('--request',$requestPath,'--request-sha256',$RequestSha256,'--output',(Join-Path $root 'probe.json'))
if($Reopen){$arguments+='--reopen'};if($WholePartition){$arguments+='--whole-partition'}
$record=[ordered]@{schemaVersion=1;kind='native-probe-process';runId=$RunId;probeId=$ProbeId;requestSha256=$RequestSha256;binarySha256=$BinarySha256;arguments=$arguments;reopen=[bool]$Reopen;wholePartition=[bool]$WholePartition;createdUtc=[DateTime]::UtcNow.ToString('o');processId=$null;completionKnown=$false;exitCode=$null;status='started';launchAttempted=$false;payloadWriteRequestsIssued=$false;conversionQualified=$false}
Write-NativeProbeRecord 'process-intent.json' $record
try{
 $binaryPin=Open-NativeProbeInput $binary $BinarySha256 16MB;$requestPin=Open-NativeProbeInput $requestPath $RequestSha256 16KB
 $requestBytes=Read-NativeProbeArtifact $requestPath 16KB;$request=(New-Object Text.UTF8Encoding($false,$true)).GetString($requestBytes)|ConvertFrom-Json;Assert-NativeProbeRequest $request $RunId
 Initialize-N2RProcessCapture;$record.launchAttempted=$true
 $p=[Ntfs2Refs.BoundedLabProcess]::Start($binary,($arguments-join' '),$root,(Join-Path $root 'probe.stdout'),(Join-Path $root 'probe.stderr'))
 $record.processId=$p.Id;Write-NativeProbeRecord 'process-started.json' $record
 Complete-NativeProbeProcess $p $record $TimeoutSeconds
 foreach($name in @('probe.stdout','probe.stderr')){Read-NativeProbeArtifact (Join-Path $root $name) 64KB -AllowEmpty|Out-Null}
 $bytes=Read-NativeProbeArtifact (Join-Path $root 'probe.json') 1MB;$r=(New-Object Text.UTF8Encoding($false,$true)).GetString($bytes)|ConvertFrom-Json
 Assert-NativeProbeResult $r $request ([bool]$Reopen) ([bool]$WholePartition)
 $record.status='native-probe-verified-disks-offline'
}catch{$record.status='failed-preserved';$record['error']=$_.Exception.ToString()}
finally{if($requestPin){$requestPin.Dispose()};if($binaryPin){$binaryPin.Dispose()};if($p-and$record.completionKnown){$p.Dispose()};$record['finishedUtc']=[DateTime]::UtcNow.ToString('o');Write-NativeProbeRecord 'process-result.json' $record}
[pscustomobject]@{Status=$record.status;RunId=$RunId;ProbeId=$ProbeId;EvidenceDirectory=$root;OperationCompletionKnown=$record.completionKnown;ConversionQualified=$false}
