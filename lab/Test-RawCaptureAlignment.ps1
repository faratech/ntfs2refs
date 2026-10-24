<# Compile the production capture helper and exercise aligned ReadFile against
   small ordinary files only. No volume/device path, lock, or dismount is used. #>
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$workspace = Split-Path $PSScriptRoot -Parent
$sourcePath = Join-Path $PSScriptRoot 'guest\Capture-RawControl.ps1'
$tokens=$null; $errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($sourcePath,[ref]$tokens,[ref]$errors)
if ($errors.Count) { throw 'Capture script parser errors.' }
$literal=$ast.Find({param($node) $node -is [Management.Automation.Language.StringConstantExpressionAst] -and $node.Value.Contains('public static class NativeControlCapture')},$true)
if (-not $literal) { throw 'Production capture implementation not found.' }
if (-not ('Ntfs2Refs.NativeControlCapture' -as [type])) { Add-Type -TypeDefinition $literal.Value }
if (-not ('Ntfs2Refs.TestReadOnlyFile' -as [type])) {
Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
namespace Ntfs2Refs {
 public static class TestReadOnlyFile {
  [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
  static extern SafeFileHandle CreateFile(string path, uint access, uint share, IntPtr security, uint creation, uint flags, IntPtr template);
  public static SafeFileHandle Open(string path) {
   if (path.StartsWith(@"\\") || !File.Exists(path)) throw new ArgumentException("Expected an existing local ordinary fixture file.");
   var handle=CreateFile(path,0x80000000,1,IntPtr.Zero,3,0x20000000,IntPtr.Zero);
   if (handle.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());
   return handle;
  }
  public static void WriteFixture(string path, int length) {
   if (length<=0 || length>4194304) throw new ArgumentOutOfRangeException("length");
   var bytes=new byte[length]; for(int i=0;i<bytes.Length;i++) bytes[i]=(byte)(i%251);
   using(var output=new FileStream(path,FileMode.CreateNew,FileAccess.Write)) { output.Write(bytes,0,bytes.Length); output.Flush(true); }
  }
 }
}
'@
}
$flags=[Reflection.BindingFlags]'NonPublic,Static'
$copy=[Ntfs2Refs.NativeControlCapture].GetMethod('CopyAligned',$flags)
$geometry=[Ntfs2Refs.NativeControlCapture].GetMethod('ValidateGeometry',$flags)
$align=[Ntfs2Refs.NativeControlCapture].GetMethod('AlignBuffer',$flags)
if (-not $copy -or -not $geometry -or -not $align) { throw 'Missing aligned production helper methods.' }
$testRoot=Join-Path $workspace ('.lab\tests\aligned-capture-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $testRoot | Out-Null
$checks=0
foreach ($sizes in @(@(512,512),@(512,4096),@(4096,4096),@(512,65536))) {
    $logical=[uint32]$sizes[0]; $physical=[uint32]$sizes[1]
    $length=[int](1MB+$physical)
    $source=Join-Path $testRoot ("source-$logical-$physical.bin")
    $partial=Join-Path $testRoot ("copy-$logical-$physical.partial")
    [Ntfs2Refs.TestReadOnlyFile]::WriteFixture($source,$length)
    $beforeHash=(Get-FileHash -LiteralPath $source).Hash
    $handle=[Ntfs2Refs.TestReadOnlyFile]::Open($source)
    try { $copy.Invoke($null,[object[]]@($handle,[string]$partial,$logical,$physical,[int64]$length)) | Out-Null }
    finally { $handle.Dispose() }
    if ((Get-Item -LiteralPath $partial).Length -ne $length -or (Get-FileHash -LiteralPath $partial).Hash -cne $beforeHash -or (Get-FileHash -LiteralPath $source).Hash -cne $beforeHash) { throw 'Aligned read length/hash/source-preservation check failed.' }
    $aligned=[IntPtr]$align.Invoke($null,[object[]]@([IntPtr]0x100003,[int]$physical))
    if ($aligned.ToInt64()%$physical -ne 0 -or $aligned.ToInt64() -lt 0x100003 -or $aligned.ToInt64() -ge (0x100003+$physical)) { throw 'Unmanaged pointer rounding failed.' }
    $checks++
}
foreach ($sizes in @(@(0,4096),@(1000,4096),@(4096,512),@(512,131072),@(512,6000))) {
    $rejected=$false
    try { $geometry.Invoke($null,[object[]]@([uint32]$sizes[0],[uint32]$sizes[1])) | Out-Null } catch { $rejected=$true }
    if (-not $rejected) { throw 'Invalid sector geometry accepted.' }
    $checks++
}
$shortSource=Join-Path $testRoot 'short-source.bin'
[Ntfs2Refs.TestReadOnlyFile]::WriteFixture($shortSource,1MB+4096)
$shortPartial=Join-Path $testRoot 'short.partial'
$handle=[Ntfs2Refs.TestReadOnlyFile]::Open($shortSource)
$rejected=$false
try { $copy.Invoke($null,[object[]]@($handle,[string]$shortPartial,[uint32]512,[uint32]4096,[int64]2MB)) | Out-Null } catch { $rejected=$true } finally { $handle.Dispose() }
if (-not $rejected -or (Get-Item -LiteralPath $shortPartial).Length -ne 1MB) { throw 'Short read did not retain an incomplete partial containing only complete reads.' }
$checks++
$existing=Join-Path $testRoot 'existing.partial'
[IO.File]::WriteAllText($existing,'preserve-existing')
$existingHash=(Get-FileHash -LiteralPath $existing).Hash
$handle=[Ntfs2Refs.TestReadOnlyFile]::Open($shortSource)
$rejected=$false
try { $copy.Invoke($null,[object[]]@($handle,[string]$existing,[uint32]512,[uint32]4096,[int64]1MB)) | Out-Null } catch { $rejected=$true } finally { $handle.Dispose() }
if (-not $rejected -or (Get-FileHash -LiteralPath $existing).Hash -cne $existingHash) { throw 'Existing output was overwritten.' }
$checks++
$rejected=$false
try { [Ntfs2Refs.NativeControlCapture]::Capture('not-a-device',(Join-Path $testRoot 'never-created.partial'),512,4096) } catch { $rejected=$true }
if (-not $rejected -or (Test-Path -LiteralPath (Join-Path $testRoot 'never-created.partial'))) { throw 'Malformed device was not rejected before opening anything.' }
$checks++
"Passed $checks aligned capture fixtures against ordinary files; no physical/volume device calls executed."
