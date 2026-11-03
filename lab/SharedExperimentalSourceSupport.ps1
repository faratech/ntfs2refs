# Definition-only helper for Build-ReleaseCandidate.ps1's explicit experiment
# mode. Every mutating call requires its held exclusive cache lock and literal
# positively owned disposable source root. Never touches old candidate trees.
Set-StrictMode -Version Latest

function Initialize-SharedSourceIdentityApi {
    if('N2RSharedSourceIdentityV2'-as[type]){return}
    $definition=@'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
public static class N2RSharedSourceIdentityV2 {
 [StructLayout(LayoutKind.Sequential)] struct Info {
  public uint Attributes,CreationLow,CreationHigh,AccessLow,AccessHigh,WriteLow,WriteHigh;
  public uint VolumeSerial,SizeHigh,SizeLow,Links,IndexHigh,IndexLow;
 }
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]
 static extern SafeFileHandle CreateFileW(string path,uint access,uint share,IntPtr security,uint disposition,uint flags,IntPtr template);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetFileInformationByHandle(SafeFileHandle file,out Info info);
 [StructLayout(LayoutKind.Sequential)] struct FileIdInfo {
  public ulong VolumeSerial; [MarshalAs(UnmanagedType.ByValArray,SizeConst=16)] public byte[] FileId;
 }
 [StructLayout(LayoutKind.Sequential)] struct Disposition { public byte DeleteFile; }
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetFileInformationByHandleEx(SafeFileHandle file,int kind,out FileIdInfo info,uint bytes);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool SetFileInformationByHandle(SafeFileHandle file,int kind,ref Disposition info,uint bytes);
 static Info Read(SafeFileHandle file) {
  Info info;if(!GetFileInformationByHandle(file,out info))throw new Win32Exception(Marshal.GetLastWin32Error());
  if((info.Attributes&0x400)!=0)throw new InvalidOperationException("Reparse handle refused");return info;
 }
 public static string Id(SafeFileHandle file) {
  Read(file);FileIdInfo info;
  if(!GetFileInformationByHandleEx(file,18,out info,24))throw new Win32Exception(Marshal.GetLastWin32Error());
  return info.VolumeSerial.ToString("X16")+BitConverter.ToString(info.FileId).Replace("-","");
 }
 static SafeFileHandle Open(string path,uint access,uint share,bool directory) {
  SafeFileHandle file=CreateFileW(path,access,share,IntPtr.Zero,3,directory?0x02200000u:0x00200000u,IntPtr.Zero);
  if(file.IsInvalid)throw new Win32Exception(Marshal.GetLastWin32Error());
  try {if(((Read(file).Attributes&0x10)!=0)!=directory)throw new InvalidOperationException("Ordinary handle type differs");return file;}catch{file.Dispose();throw;}
 }
 // FILE_SHARE_READ only: neither deletion/rename nor reparse-write opens can
 // coexist. DELETE access is held only for removable owned child directories.
 public static SafeFileHandle GuardDirectory(string path,bool removable) {return Open(path,0x80u|(removable?0x10000u:0u),1,true);}
 public static SafeFileHandle ObserveDirectory(string path) {return Open(path,0x80,7,true);}
 public static SafeFileHandle ObserveFile(string path) {return Open(path,0x80,7,false);}
 public static SafeFileHandle ReadFile(string path) {return Open(path,0x80000000,1,false);}
 public static SafeFileHandle RemoveFile(string path) {return Open(path,0x80010000,0,false);}
 public static ulong Length(SafeFileHandle file) {Info i=Read(file);return ((ulong)i.SizeHigh<<32)|i.SizeLow;}
 // SDK FILE_DISPOSITION_INFO contains BOOLEAN (one byte), not Win32 BOOL.
 // https://learn.microsoft.com/windows/win32/api/winbase/ns-winbase-file_disposition_info
 public static void MarkDelete(SafeFileHandle file) {
  Read(file);Disposition disposition=new Disposition {DeleteFile=1};
  if(!SetFileInformationByHandle(file,4,ref disposition,1))throw new Win32Exception(Marshal.GetLastWin32Error());
 }
 public static void RequireMissing(string path) {
  using(SafeFileHandle file=CreateFileW(path,0,7,IntPtr.Zero,3,0x02200000,IntPtr.Zero)) {
   if(!file.IsInvalid)throw new InvalidOperationException("Deleted staging entry still exists");
   int error=Marshal.GetLastWin32Error();if(error!=2&&error!=3)throw new Win32Exception(error);
  }
 }
}
'@
    Add-Type -TypeDefinition $definition -Language CSharp -ErrorAction Stop
}

function Get-SharedSourceFullPath([string]$Path) {
    $full=[IO.Path]::GetFullPath($Path)
    if($full.Length-gt[IO.Path]::GetPathRoot($full).Length){$full=$full.TrimEnd('\')}
    return $full
}

function Assert-SharedSourceDirectoryGuard($State,[string]$Path) {
    $full=Get-SharedSourceFullPath $Path
    Need ($null-ne$State.guards-and$State.guard_paths.ContainsKey($full)) 'Directory route must be owned before traversal or mutation.'
    $guard=$State.guard_paths[$full]
    Need (-not$guard.retired-and[N2RSharedSourceIdentityV2]::Id($guard.handle)-ceq$guard.id) 'Held directory identity differs.'
    $current=[N2RSharedSourceIdentityV2]::ObserveDirectory($full)
    try{Need ([N2RSharedSourceIdentityV2]::Id($current)-ceq$guard.id) 'Directory path is no longer the actual held directory.'}finally{$current.Dispose()}
    return $guard
}

function Add-SharedSourceDirectoryGuard($State,[string]$Path,[bool]$Removable=$false) {
    $full=Get-SharedSourceFullPath $Path
    if($State.guard_paths.ContainsKey($full)){return (Assert-SharedSourceDirectoryGuard $State $full)}
    $parent=[IO.DirectoryInfo]::new($full).Parent
    if($null-ne$parent){$null=Assert-SharedSourceDirectoryGuard $State $parent.FullName}
    if($Removable){$null=Assert-SharedSourceScope $State $full}
    $handle=[N2RSharedSourceIdentityV2]::GuardDirectory($full,$Removable)
    try{
        $guard=[pscustomobject]@{path=$full;handle=$handle;id=[N2RSharedSourceIdentityV2]::Id($handle);removable=$Removable;retired=$false}
        $State.guards.Add($guard);$State.guard_paths.Add($full,$guard)
        return $guard
    }catch{$handle.Dispose();throw}
}

function Assert-SharedSourceScope($State,[string]$Path,[bool]$AllowRoot=$false) {
    Need ($null-ne$State.lock-and$State.lock.CanRead-and$State.lock.CanWrite) 'Actual exclusive shared build lock required.'
    Need ($State.workspace-ceq'D:\code\ntfs2refs'-and$State.stage_root-ceq'D:\code\ntfs2refs\target\shared-experiments-staging'-and$State.source-ceq'D:\code\ntfs2refs\target\shared-experiments-staging\source') 'Literal disposable source staging identity differs.'
    $full=[IO.Path]::GetFullPath($Path).TrimEnd('\')
    Need (($AllowRoot-and$full-ceq$State.source)-or$full.StartsWith($State.source+'\',[StringComparison]::OrdinalIgnoreCase)) 'Source staging mutation escaped its positively owned source root.'
    $cursor=$full
    while($cursor-and$cursor.Length-ge$State.stage_root.Length) {
        if(Test-Path -LiteralPath $cursor){$m=Get-Item -LiteralPath $cursor -Force;Need (-not($m.Attributes-band[IO.FileAttributes]::ReparsePoint)) 'Reparse staging ancestry refused.'}
        $next=Split-Path $cursor -Parent;if($next-ceq$cursor){break};$cursor=$next
    }
    return $full
}

function Initialize-SharedExperimentalSource([string]$Workspace,[IO.FileStream]$Lock) {
    $state=[pscustomobject]@{workspace=$Workspace;stage_root='D:\code\ntfs2refs\target\shared-experiments-staging';source='D:\code\ntfs2refs\target\shared-experiments-staging\source';lock=$Lock;owner=$null;guards=[Collections.Generic.List[object]]::new();guard_paths=[Collections.Generic.Dictionary[string,object]]::new([StringComparer]::OrdinalIgnoreCase);inventory_guarded=$false;success_path='D:\code\ntfs2refs\target\shared-experiments-staging\last-successful-build.json'}
    Need ($Workspace-ceq'D:\code\ntfs2refs'-and$null-ne$Lock-and$Lock.CanRead-and$Lock.CanWrite) 'Shared source requires the actual explicit workspace/cache lock.'
    Initialize-SharedSourceIdentityApi
    try{
        # Acquire top-down before the first staging check/create. Keeping every
        # ancestor open without delete/write sharing prevents replacement of a
        # checked directory by a reparse route during subsequent path opens.
        $ancestors=[Collections.Generic.List[string]]::new();$cursor=[IO.DirectoryInfo]::new((Split-Path $state.stage_root -Parent))
        while($null-ne$cursor){$ancestors.Insert(0,$cursor.FullName);$cursor=$cursor.Parent}
        foreach($ancestor in $ancestors){$null=Add-SharedSourceDirectoryGuard $state $ancestor}
        $marker=Join-Path $state.stage_root 'owner.json';$createdStage=$false
        if(-not(Test-Path -LiteralPath $state.stage_root)) {
            $null=Assert-SharedSourceDirectoryGuard $state (Split-Path $state.stage_root -Parent)
            $null=New-Item -ItemType Directory -Path $state.stage_root -ErrorAction Stop
            $createdStage=$true
        }
        $null=Add-SharedSourceDirectoryGuard $state $state.stage_root
        if($createdStage){
            $record=@{schema_version=1;kind='disposable-shared-experimental-source';workspace=$Workspace;source_path=$state.source;lock_path='D:\code\ntfs2refs\target\shared-experiments.build.lock';created_utc=[DateTime]::UtcNow.ToString('o');isolated_release_allowed=$false}
            $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($record|ConvertTo-Json -Depth 8))
            $file=[IO.File]::Open($marker,'CreateNew','Write','Read');try{$file.Write($bytes,0,$bytes.Length);$file.Flush($true)}finally{$file.Dispose()}
        }
        Need (Test-Path -LiteralPath $marker -PathType Leaf) 'Existing staging root has no positive ownership marker; refusing adoption.'
        $pin=PinFile $marker '' 4096
        $reader=[IO.StreamReader]::new($pin.stream,[Text.UTF8Encoding]::new($false,$true),$true,4096,$true)
        try{$owner=$reader.ReadToEnd()|ConvertFrom-Json}finally{$reader.Dispose();$pin.stream.Position=0}
        Need ($owner.schema_version-eq1-and$owner.kind-ceq'disposable-shared-experimental-source'-and$owner.workspace-ceq$Workspace-and$owner.source_path-ceq$state.source-and$owner.lock_path-ceq'D:\code\ntfs2refs\target\shared-experiments.build.lock'-and$owner.isolated_release_allowed-eq$false) 'Disposable staging ownership marker differs.'
        $state.owner=[pscustomobject]@{path=$pin.path;bytes=$pin.bytes;sha256=$pin.sha256;created_utc=$owner.created_utc}
        $null=Assert-SharedSourceScope $state $state.source $true
        if(-not(Test-Path -LiteralPath $state.source)){$null=New-Item -ItemType Directory -Path $state.source -ErrorAction Stop}
        $null=Add-SharedSourceDirectoryGuard $state $state.source
        return $state
    }catch{Close-SharedSourceDirectories $state;throw}
}

function Hold-SharedSourceDirectories($State) {
    Need (-not$State.inventory_guarded) 'Source directory inventory is already guarded.'
    $null=Assert-SharedSourceDirectoryGuard $State $State.source
    $null=Get-SharedSourceInventory $State
    $State.inventory_guarded=$true
}
function Close-SharedSourceDirectories($State) {
    if($null-ne$State-and$null-ne$State.guards){for($i=$State.guards.Count-1;$i-ge0;$i--){$State.guards[$i].handle.Dispose()};$State.guards=$null;$State.guard_paths.Clear()}
}

function Get-SharedSourceInventory($State) {
    $null=Assert-SharedSourceScope $State $State.source $true
    $files=[Collections.Generic.Dictionary[string,object]]::new([StringComparer]::OrdinalIgnoreCase)
    $directories=[Collections.Generic.List[object]]::new();$pending=[Collections.Generic.Queue[string]]::new();$pending.Enqueue($State.source)
    while($pending.Count) {
        $directory=$pending.Dequeue();$null=Assert-SharedSourceScope $State $directory $true
        $null=Assert-SharedSourceDirectoryGuard $State $directory
        foreach($m in Get-ChildItem -LiteralPath $directory -Force -ErrorAction Stop) {
            $full=Assert-SharedSourceScope $State $m.FullName
            Need (-not($m.Attributes-band[IO.FileAttributes]::ReparsePoint)) 'Source staging reparse entry refused.'
            $relative=$full.Substring($State.source.Length+1).Replace('\','/')
            Need ($relative-cmatch'\A[A-Za-z0-9_./-]+\z'-and-not$relative.Contains('..')) 'Unexpected staging source path syntax.'
            if($m-is[IO.DirectoryInfo]){
                $guard=Add-SharedSourceDirectoryGuard $State $full $true
                $directories.Add([pscustomobject]@{path=$full;relative=$relative;id=$guard.id});$pending.Enqueue($full)
            }else{
                Need ($m-is[IO.FileInfo]) 'Source staging ordinary file required.'
                $handle=[N2RSharedSourceIdentityV2]::ObserveFile($full)
                try{$row=[pscustomobject]@{FullName=$full;Length=[N2RSharedSourceIdentityV2]::Length($handle);id=[N2RSharedSourceIdentityV2]::Id($handle)}}finally{$handle.Dispose()}
                Need ($files.TryAdd($relative,$row)) 'Source staging file type/case collision differs.'
            }
            Need ($files.Count-le8192-and$directories.Count-le16384) 'Source staging inventory exceeds original archive bounds.'
        }
    }
    return [pscustomobject]@{files=$files;directories=$directories}
}

function Remove-SharedSourceFile($State,$Row,[bool]$SuccessContract=$false) {
    if($SuccessContract){
        Need ($Row.FullName-ceq$State.success_path-and$State.success_path-ceq(Join-Path $State.stage_root 'last-successful-build.json')) 'Only the exact owned success contract is replaceable outside source.'
    }else{$null=Assert-SharedSourceScope $State $Row.FullName}
    $null=Assert-SharedSourceDirectoryGuard $State (Split-Path $Row.FullName -Parent)
    $handle=[N2RSharedSourceIdentityV2]::RemoveFile($Row.FullName)
    try{
        Need ([N2RSharedSourceIdentityV2]::Id($handle)-ceq$Row.id) 'Staging file entry changed since its actual identity was observed; refusing unlink.'
        # No path-based deletion: the exclusive READ|DELETE open above binds
        # the exact enumerated file, including when it has an outside hardlink.
        [N2RSharedSourceIdentityV2]::MarkDelete($handle)
    }finally{$handle.Dispose()}
    [N2RSharedSourceIdentityV2]::RequireMissing($Row.FullName)
}

function Remove-SharedSourceDirectory($State,$Directory) {
    $null=Assert-SharedSourceScope $State $Directory.path
    $guard=Assert-SharedSourceDirectoryGuard $State $Directory.path
    Need ($guard.removable-and$guard.id-ceq$Directory.id) 'Only an actual held removable source-child directory may be unlinked.'
    Need (@(Get-ChildItem -LiteralPath $guard.path -Force -ErrorAction Stop).Count-eq0) 'Unexpected nonempty obsolete source directory.'
    # This is the same DELETE-capable handle acquired before traversing it.
    # The kernel also refuses deletion if a new child appeared after the check.
    [N2RSharedSourceIdentityV2]::MarkDelete($guard.handle)
    $guard.handle.Dispose();$guard.retired=$true
    $null=$State.guard_paths.Remove($guard.path)
    [N2RSharedSourceIdentityV2]::RequireMissing($guard.path)
}

function Ensure-SharedSourceParent($State,[string]$Path) {
    $full=Assert-SharedSourceScope $State $Path $true
    $null=Assert-SharedSourceDirectoryGuard $State $State.source
    if($full-ceq$State.source){return}
    $cursor=$State.source
    foreach($part in $full.Substring($State.source.Length+1).Split('\')){
        Need ($part-cmatch'\A[A-Za-z0-9_.-]+\z'-and-not$part.Contains('..')) 'Unexpected source directory syntax.'
        $parent=$cursor;$cursor=Join-Path $cursor $part
        $null=Assert-SharedSourceDirectoryGuard $State $parent
        if(-not(Test-Path -LiteralPath $cursor)){$null=New-Item -ItemType Directory -Path $cursor -ErrorAction Stop}
        # Capture before creating/opening any child; OPEN_REPARSE_POINT rejects
        # a route swapped into the just-created name before this open.
        $null=Add-SharedSourceDirectoryGuard $State $cursor $true
    }
}

function Sync-SharedExperimentalSource($State,[string]$ArchiveSource,$Expected,$ArchivePins) {
    Need ($State.inventory_guarded) 'All initial source directories must be guarded before refresh.'
    $null=Assert-SharedSourceScope $State $State.source $true
    $archive=[IO.Path]::GetFullPath($ArchiveSource).TrimEnd('\');Need ($archive-cne$State.source) 'Fresh archived source must remain separate from disposable build source.'
    $inventory=Get-SharedSourceInventory $State
    $caseReset=$false
    foreach($actualName in $inventory.files.Keys){if($Expected.ContainsKey($actualName)-and$actualName-cne$Expected[$actualName].path){$caseReset=$true;break}}
    $expectedDirs=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $expectedDirCase=[Collections.Generic.Dictionary[string,string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach($name in $Expected.Keys) {
        $parent=Split-Path ($name.Replace('/','\')) -Parent
        while($parent){$relative=$parent.Replace('\','/');$null=$expectedDirs.Add($relative);if(-not$expectedDirCase.ContainsKey($relative)){$expectedDirCase.Add($relative,$relative)};$parent=Split-Path $parent -Parent}
    }
    foreach($directory in $inventory.directories){if($expectedDirCase.ContainsKey($directory.relative)-and$directory.relative-cne$expectedDirCase[$directory.relative]){$caseReset=$true;break}}
    $removed=[Collections.Generic.List[string]]::new();$updated=[Collections.Generic.List[string]]::new();$unchanged=0
    foreach($name in @($inventory.files.Keys)) {
        if($caseReset-or-not$Expected.ContainsKey($name)) {
            Remove-SharedSourceFile $State $inventory.files[$name]
            $removed.Add($name)
        }
    }
    # Nonrecursive, deepest-first deletion through the actual held handles.
    foreach($directory in @($inventory.directories|Sort-Object @{Expression={$_.path.Length};Descending=$true})) {
        if($caseReset-or-not$expectedDirs.Contains($directory.relative)) {
            Remove-SharedSourceDirectory $State $directory
        }
    }
    $pins=[Collections.Generic.Dictionary[string,object]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach($row in $ArchivePins){Need ($pins.TryAdd($row.path,$row)) 'Archived source pin collision.'}
    foreach($name in @($Expected.Keys|Sort-Object -CaseSensitive)) {
        $destination=Assert-SharedSourceScope $State (Join-Path $State.source $name)
        $fresh=[IO.Path]::GetFullPath((Join-Path $archive $name));Need ($fresh.StartsWith($archive+'\',[StringComparison]::OrdinalIgnoreCase)) 'Fresh archive source path escaped.'
        $row=$pins[$name];$same=$false
        if(Test-Path -LiteralPath $destination) {
            Need (-not$caseReset-and$inventory.files.ContainsKey($name)) 'Unexpected source leaf appeared after the guarded inventory.'
            $m=$inventory.files[$name]
            $null=Assert-SharedSourceDirectoryGuard $State (Split-Path $destination -Parent)
            $handle=[N2RSharedSourceIdentityV2]::ReadFile($destination)
            $file=$null
            try{
                Need ([N2RSharedSourceIdentityV2]::Id($handle)-ceq$m.id) 'Source entry changed before byte comparison.'
                $file=[IO.FileStream]::new($handle,[IO.FileAccess]::Read,65536,$false)
                if($file.Length-eq$row.bytes){$same=(HashStream $file)-ceq$row.sha256}
            }finally{if($null-ne$file){$file.Dispose()}else{$handle.Dispose()}}
            if(-not$same) {
                # Unlink, never truncate: an outside hard-link alias cannot be
                # modified through this disposable staging directory entry.
                Remove-SharedSourceFile $State $m
            }
        }
        if($same){$unchanged++;continue}
        $parent=Split-Path $destination -Parent;Ensure-SharedSourceParent $State $parent
        $sourceFile=[IO.File]::Open($fresh,'Open','Read','Read');$destinationFile=$null
        try{
            $null=Assert-SharedSourceDirectoryGuard $State $parent
            $destinationFile=[IO.File]::Open($destination,'CreateNew','Write','None')
            $sourceFile.CopyTo($destinationFile,65536);$destinationFile.Flush($true)
        }finally{$sourceFile.Dispose();if($null-ne$destinationFile){$destinationFile.Dispose()}}
        $updated.Add($name)
    }
    $after=Get-SharedSourceInventory $State
    Need ($after.files.Count-eq$Expected.Count) 'Refreshed staging file count differs from exact archive.'
    foreach($name in $Expected.Keys){Need ($after.files.ContainsKey($name)) 'Refreshed staging omitted an archived source.'}
    return [pscustomobject]@{unchanged_files=$unchanged;updated_files=$updated.ToArray();removed_files=$removed.ToArray();unchanged_mtimes_preserved=$true;case_only_tree_reset=$caseReset;refresh_directory_guards_held=$true;removed_entries_same_handle_identity_verified=$true;path_based_deletion_used=$false}
}

function Assert-SharedExperimentalSource($State,$Expected,$HeldSourcePins) {
    Need ($null-ne$State.guards) 'Actual no-delete directory ancestry guards required.'
    foreach($guard in $State.guards){
        if(-not$guard.retired){$null=Assert-SharedSourceDirectoryGuard $State $guard.path}
    }
    $inventory=Get-SharedSourceInventory $State
    Need ($inventory.files.Count-eq$Expected.Count-and$HeldSourcePins.Count-eq$Expected.Count) 'Actual staged build-input inventory differs.'
    $actualNames=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach($name in $inventory.files.Keys){$null=$actualNames.Add($name)}
    $expectedDirs=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach($name in $Expected.Keys){Need ($actualNames.Contains($name)) 'Staging path casing differs from exact committed archive.';$parent=Split-Path ($name.Replace('/','\')) -Parent;while($parent){$null=$expectedDirs.Add($parent.Replace('\','/'));$parent=Split-Path $parent -Parent}}
    Need ($inventory.directories.Count-eq$expectedDirs.Count) 'Staging directory inventory differs from committed archive.'
    foreach($directory in $inventory.directories){Need ($expectedDirs.Contains($directory.relative)) 'Unexpected staging directory/casing.'}
    foreach($pin in $HeldSourcePins) {
        Need ($inventory.files.ContainsKey($pin.relative)-and$Expected.ContainsKey($pin.relative)) 'Unexpected/missing held staging source.'
        $pin.stream.Position=0;$actual=HashStream $pin.stream;$pin.stream.Position=0
        Need ($pin.stream.Length-eq$pin.bytes-and$actual-ceq$pin.sha256) 'Held stable source bytes changed during experimental build.'
        Need ([N2RSharedSourceIdentityV2]::Id($pin.stream.SafeFileHandle)-ceq$pin.file_id) 'Held stable source file ID changed.'
        $current=[IO.File]::Open($pin.path,'Open','Read','Read')
        try{Need ([N2RSharedSourceIdentityV2]::Id($current.SafeFileHandle)-ceq$pin.file_id) 'Current source path is not the exact held file.'}finally{$current.Dispose()}
    }
}

function Get-SharedSourceSuccessfulContract($State) {
    $null=Assert-SharedSourceDirectoryGuard $State $State.stage_root
    if(-not(Test-Path -LiteralPath $State.success_path)){return $null}
    $handle=[N2RSharedSourceIdentityV2]::ReadFile($State.success_path)
    $file=$null;$reader=$null
    try{
        $length=[N2RSharedSourceIdentityV2]::Length($handle)
        Need ($length-gt0-and$length-le16384) 'Bounded successful staging contract required.'
        $file=[IO.FileStream]::new($handle,[IO.FileAccess]::Read,4096,$false)
        $reader=[IO.StreamReader]::new($file,[Text.UTF8Encoding]::new($false,$true))
        $value=$reader.ReadToEnd()|ConvertFrom-Json
    }finally{if($null-ne$reader){$reader.Dispose()};if($null-ne$file){$file.Dispose()}else{$handle.Dispose()}}
    Need ($value.schema_version-eq1-and$value.kind-ceq'successful-shared-source-contract'-and$value.source_path-ceq$State.source-and$value.target_path-ceq'D:\code\ntfs2refs\target\shared-experiments'-and$value.contract_sha256-cmatch'\A[0-9a-f]{64}\z') 'Successful source contract differs.'
    return $value.contract_sha256
}
function Save-SharedSourceSuccessfulContract($State,[string]$Contract,[string]$Commit,[string]$Manifest,[string]$ManifestSha) {
    $null=Assert-SharedSourceScope $State $State.source $true
    Need ($State.success_path-ceq(Join-Path $State.stage_root 'last-successful-build.json')-and$Contract-cmatch'\A[0-9a-f]{64}\z') 'Literal successful contract path/pin required.'
    $null=Assert-SharedSourceDirectoryGuard $State $State.stage_root
    if(Test-Path -LiteralPath $State.success_path){
        $handle=[N2RSharedSourceIdentityV2]::ObserveFile($State.success_path)
        try{$old=[pscustomobject]@{FullName=$State.success_path;id=[N2RSharedSourceIdentityV2]::Id($handle)}}finally{$handle.Dispose()}
        Remove-SharedSourceFile $State $old $true
    }
    $value=@{schema_version=1;kind='successful-shared-source-contract';source_path=$State.source;target_path='D:\code\ntfs2refs\target\shared-experiments';contract_sha256=$Contract;source_commit=$Commit;manifest_path=$Manifest;manifest_sha256=$ManifestSha;utc=[DateTime]::UtcNow.ToString('o')}
    $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($value|ConvertTo-Json -Depth 8));$file=[IO.File]::Open($State.success_path,'CreateNew','Write','Read')
    try{$file.Write($bytes,0,$bytes.Length);$file.Flush($true)}finally{$file.Dispose()}
}

function Read-SharedSourceJsonPin($Pin) {
    $Pin.stream.Position=0
    $reader=[IO.StreamReader]::new($Pin.stream,[Text.UTF8Encoding]::new($false,$true),$true,4096,$true)
    try{return ($reader.ReadToEnd()|ConvertFrom-Json)}finally{$reader.Dispose();$Pin.stream.Position=0}
}

function Ensure-SharedExperimentalCargoTag($State,$Baseline) {
    $null=Assert-SharedSourceDirectoryGuard $State $State.source
    $target='D:\code\ntfs2refs\target\shared-experiments'
    Need ($State.workspace-ceq'D:\code\ntfs2refs'-and$null-ne$State.lock-and$State.lock.CanRead-and$State.lock.CanWrite) 'Actual fixed cache lock/workspace required before Cargo tag enrollment.'
    # The guarded source and target share the already-held target-directory
    # ancestry. The actual target handle is held before any tag check/create.
    $targetGuard=Add-SharedSourceDirectoryGuard $State $target
    $null=Assert-SharedSourceDirectoryGuard $State $target
    $seedPath='D:\code\ntfs2refs\.lab\development\shared-experiment-cache-seed.json'
    $seedPin=PinFile $seedPath 'ea9d0c96f2c517614d28a9d6d7dcac760c03bd55ec9c402b8e679f961bcca349' 4KB
    $seed=Read-SharedSourceJsonPin $seedPin
    $original='D:\code\ntfs2refs\.lab\development\release-candidates\ra6d68d2-cache'
    Need ($seed.source-ceq($original+'\target')-and$seed.destination-ceq$target-and$seed.operation-ceq'same-volume move of generated Cargo target only'-and$seed.source_commit-ceq'a6d68d2488cadc6f5efd0cd7e0c3d98dceac3496'-and$seed.manifest_sha256-ceq'b8cbb6e104bb563fa953a8a0ea261c8df238374ab0043eb1bbbfa721f69a945b'-and$seed.binary_sha256-ceq'e660b31cd4f1e5e28b60c78b95f93ef3a493b80bf187f37fe0f2280b6240a256'-and$seed.bytes-eq388066812) 'Exact historical generated-cache move receipt required; arbitrary target adoption refused.'
    $manifestPin=PinFile ($original+'\manifest.json') $seed.manifest_sha256 1MB
    $manifest=Read-SharedSourceJsonPin $manifestPin
    $seedBins=@($manifest.binaries|Where-Object {$_.name-ceq'lab-observe-resource-source'-and$_.path-ceq'bin/lab-observe-resource-source.exe'-and$_.sha256-ceq$seed.binary_sha256-and$_.bytes-eq3395072})
    Need ($manifest.schema_version-eq1-and$manifest.kind-ceq'clean-committed-source-release-candidate'-and$manifest.source_commit-ceq$seed.source_commit-and$seedBins.Count-eq1-and$manifest.archive.path-ceq'source.zip'-and$manifest.archive.sha256-ceq'a91f03a4cbdc6986f6429930f31f58ab09737cce4d29f52b532997251cd00fcb') 'Preserved source/manifest provenance of the generated target differs.'
    $binaryPin=PinFile ($original+'\bin\lab-observe-resource-source.exe') $seed.binary_sha256 64MB
    Need ($binaryPin.bytes-eq$seedBins[0].bytes) 'Preserved seed executable length differs.'
    $archivePin=PinFile ($original+'\source.zip') $manifest.archive.sha256 64MB
    Need ($archivePin.bytes-eq$manifest.archive.bytes) 'Preserved seed source archive length differs.'
    $baselinePath='D:\code\ntfs2refs\.lab\development\shared-experimental-target-baseline.json'
    Need ($Baseline.path-ceq$baselinePath-and$Baseline.sha256-cmatch'\A[0-9a-f]{64}\z') 'Already validated original cache baseline pin required.'
    $baselinePin=PinFile $baselinePath $Baseline.sha256 4KB
    $record=Read-SharedSourceJsonPin $baselinePin
    Need ($record.schema_version-eq1-and$record.kind-ceq'shared-experimental-cargo-target-baseline'-and$record.workspace-ceq$State.workspace-and$record.shared_target-ceq$target-and$record.initial_bytes-eq$Baseline.initial_bytes-and$record.initial_bytes-ge$seed.bytes-and$record.maximum_actual_bytes-eq329374052988-and$record.minimum_host_free_bytes-eq17179869184-and$record.epoch_reset-eq$false) 'Existing target baseline/epoch differs; no baseline reset or generic cache adoption allowed.'
    # Exact standard Cargo tag; this supplements historical ownership proof,
    # rather than treating the tag itself as authorization for a directory.
    # Cargo's explicit-target validation: rust-lang/cargo PR16712.
    $tagPath=Join-Path $target 'CACHEDIR.TAG'
    $tagText="Signature: 8a477f597d28d172789f06886806bc55`n# This file is a cache directory tag created by cargo.`n# For information about cache directory tags see https://bford.info/cachedir/`n"
    $tagBytes=[Text.UTF8Encoding]::new($false).GetBytes($tagText)
    $hash=[Security.Cryptography.SHA256]::Create();try{$tagSha=[Convert]::ToHexString($hash.ComputeHash($tagBytes)).ToLowerInvariant()}finally{$hash.Dispose()}
    $created=$false
    $null=Assert-SharedSourceDirectoryGuard $State $target
    if(-not(Test-Path -LiteralPath $tagPath)){
        $file=[IO.File]::Open($tagPath,'CreateNew','Write','None')
        try{$file.Write($tagBytes,0,$tagBytes.Length);$file.Flush($true);$created=$true}finally{$file.Dispose()}
    }
    # OPEN_REPARSE_POINT and the retained parent route bind the exact ordinary
    # tag. Existing invalid tags are refused without deletion or overwriting.
    $handle=[N2RSharedSourceIdentityV2]::ReadFile($tagPath);$file=$null;$retained=$false
    try{
        $file=[IO.FileStream]::new($handle,[IO.FileAccess]::Read,4096,$false)
        Need ($file.Length-eq$tagBytes.Length-and(HashStream $file)-ceq$tagSha) 'Existing/created Cargo cache tag differs from exact standard bytes; refusing cleanup.'
        $file.Position=0;$tagId=[N2RSharedSourceIdentityV2]::Id($handle)
        $held.Add($file);$retained=$true
    }finally{if(-not$retained){if($null-ne$file){$file.Dispose()}else{$handle.Dispose()}}}
    $null=Assert-SharedSourceDirectoryGuard $State $target
    return [pscustomobject]@{target_path=$target;target_file_id=$targetGuard.id;target_ancestry_no_delete_write_guards_held=$true;tag_path=$tagPath;tag_sha256=$tagSha;tag_bytes=$tagBytes.Length;tag_file_id=$tagId;created_new=$created;created_new_tag_flushed=$created;tag_readback_verified=$true;existing_invalid_tag_overwritten=$false;seed_receipt_sha256=$seedPin.sha256;seed_manifest_sha256=$manifestPin.sha256;seed_binary_sha256=$binaryPin.sha256;seed_source_archive_sha256=$archivePin.sha256;baseline_sha256=$baselinePin.sha256;historical_provenance_only=$true;current_cache_contents_fully_rehashed=$false;epoch_reset=$false;cleanup_scope=@('ntfs2refs','n2r-win32')}
}
