#Requires -Version 7.2
# Builds only a fresh, explicit committed source archive. Does not run the
# produced tools, tests, guests, disks or recovery. Qualification is separate.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{40}\z')][string]$SourceCommit,
    [Parameter(Mandatory)][string]$OutputDirectory,
    [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$ExpectedCargoLockSha256,
    [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$ExpectedCargoSha256,
    [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$ExpectedRustcSha256,
    [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$ExpectedRustupSha256,
    [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$ExpectedGitSha256,
    [ValidatePattern('\A(?:[0-9a-f]{64})?\z')][string]$ExpectedCargoHomeConfigSha256 = '',
    [string]$RustupPath = (Join-Path $env:USERPROFILE '.cargo\bin\rustup.exe'),
    [ValidateRange(1073741824,17179869184)][long]$MaximumWorkingBytes = 4294967296,
    [ValidateRange(1,16)][int]$Jobs = 4
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$workspace = [IO.Path]::GetFullPath((Split-Path $PSScriptRoot -Parent)).TrimEnd('\')
$labRoot = Join-Path $workspace '.lab'
$allowedRoot = Join-Path $labRoot 'development\release-candidates'
$targetTriple = 'x86_64-pc-windows-msvc'
$sourcePaths = @('Cargo.toml','Cargo.lock','rust-toolchain.toml','.cargo/config.toml','src','crates/n2r-win32/Cargo.toml','crates/n2r-win32/src','evidence/qualification-registry.json')
$binaries = @('ntfs2refs','lab-selected-marker-native','lab-convert-native-composite','lab-recover-native-composite','lab-content-digest','lab-managed-shadow','lab-inspect-paged-metadata')
$held = [Collections.Generic.List[IO.FileStream]]::new()
$commands = [Collections.Generic.List[object]]::new()
$created = $false
$root = $null
$childEnvironment = @{}

function Need([bool]$Condition,[string]$Message) { if (-not $Condition) { throw $Message } }
function Ordinary([string]$Path,[bool]$Directory) {
    $item = Get-Item -LiteralPath $Path -Force
    Need ($item.PSIsContainer -eq $Directory) 'Ordinary path type differs.'
    $cursor = $item
    while ($null -ne $cursor) {
        Need (-not ($cursor.Attributes -band [IO.FileAttributes]::ReparsePoint)) 'Reparse ancestry refused.'
        $cursor = if ($cursor -is [IO.DirectoryInfo]) { $cursor.Parent } else { $cursor.Directory }
    }
    return $item
}
function HashStream([IO.Stream]$Stream) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return [Convert]::ToHexString($sha.ComputeHash($Stream)).ToLowerInvariant() } finally { $sha.Dispose() }
}
function PinFile([string]$Path,[string]$Expected='',[long]$Maximum=67108864) {
    $item = Ordinary $Path $false
    Need ($item.Length -ge 0 -and $item.Length -le $Maximum) 'File length exceeds its build-input bound.'
    $file = [IO.File]::Open($item.FullName,'Open','Read','Read'); $held.Add($file)
    $sha = HashStream $file; $file.Position = 0
    Need ($file.Length -eq $item.Length -and (-not $Expected -or $sha -ceq $Expected)) 'Held build-input SHA or length differs.'
    return [pscustomobject]@{path=$item.FullName;bytes=$file.Length;sha256=$sha;stream=$file}
}
function WriteRecord([string]$Name,$Value) {
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes(($Value | ConvertTo-Json -Depth 20))
    Need ($bytes.Length -le 4MB) 'Build receipt exceeds its bound.'
    $file = [IO.File]::Open((Join-Path $root $Name),'CreateNew','Write','Read')
    try { $file.Write($bytes,0,$bytes.Length); $file.Flush($true) } finally { $file.Dispose() }
}
function MissingWorkingEntry($Failure,[string]$Path) {
    # Only a positively missing, previously enumerated child of this fresh
    # candidate may disappear during a running compiler's resource estimate.
    if (-not $Path.StartsWith($root+'\',[StringComparison]::OrdinalIgnoreCase)) { return $false }
    $missing = $false; $exception = $Failure.Exception
    while ($null -ne $exception) {
        if ($exception -is [IO.FileNotFoundException] -or $exception -is [IO.DirectoryNotFoundException]) { $missing = $true }
        $exception = $exception.InnerException
    }
    if ($Failure.Exception -is [Management.Automation.ItemNotFoundException] -and $Failure.FullyQualifiedErrorId -like 'PathNotFound,*') { $missing = $true }
    if (-not $missing) { return $false }
    try { $null = Get-Item -LiteralPath $Path -Force -ErrorAction Stop; return $false } catch {
        $exception = $_.Exception
        while ($null -ne $exception) {
            if ($exception -is [IO.FileNotFoundException] -or $exception -is [IO.DirectoryNotFoundException]) { return $true }
            $exception = $exception.InnerException
        }
        return ($_.Exception -is [Management.Automation.ItemNotFoundException] -and $_.FullyQualifiedErrorId -like 'PathNotFound,*')
    }
}
function DirectoryBytes([string]$Path,[switch]$AllowTransient) {
    Need ($Path -ceq $root) 'Resource scans are confined to this fresh candidate.'
    $queue = [Collections.Generic.Queue[string]]::new(); $queue.Enqueue($Path)
    $bytes = [long]0; $count = 0
    while ($queue.Count) {
        $directory = $queue.Dequeue()
        try {
            $current = Get-Item -LiteralPath $directory -Force -ErrorAction Stop
            Need ($current.PSIsContainer -and -not ($current.Attributes -band [IO.FileAttributes]::ReparsePoint)) 'Resource scan directory changed type or became a reparse point.'
            $items = @(Get-ChildItem -LiteralPath $directory -Force -ErrorAction Stop)
        } catch {
            if ($AllowTransient -and (MissingWorkingEntry $_ $directory)) { continue }
            throw
        }
        foreach ($item in $items) {
            $count++; Need ($count -le 100000) 'Build storage inventory exceeds its entry bound.'
            try {
                Need (-not ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) 'Reparse entry in build storage refused.'
                if ($item.PSIsContainer) { $queue.Enqueue($item.FullName) } else {
                    $length = [long]$item.Length
                    Need ($bytes -le [long]::MaxValue-$length) 'Storage byte accounting overflow.'
                    $bytes += $length
                }
            } catch {
                if ($AllowTransient -and (MissingWorkingEntry $_ $item.FullName)) { continue }
                throw
            }
        }
    }
    return $bytes
}
function SmallTool([string]$Tool,[string[]]$Arguments) {
    $lines = @(& $Tool @Arguments 2>&1); $code = $LASTEXITCODE
    Need ($code -eq 0) 'Read-only build-tool query failed.'
    $text = ($lines -join "`n").Trim()
    Need ([Text.Encoding]::UTF8.GetByteCount($text) -le 1MB) 'Build-tool query exceeds its bound.'
    return $text
}
function RunOwned([string]$Name,[string]$Tool,[string[]]$Arguments,[string]$WorkingDirectory) {
    $outPath = Join-Path $root ($Name+'.stdout.log'); $errPath = Join-Path $root ($Name+'.stderr.log')
    $stdout = [IO.File]::Open($outPath,'CreateNew','Write','Read'); $stderr = [IO.File]::Open($errPath,'CreateNew','Write','Read')
    $process = [Diagnostics.Process]::new(); $started = $false; $outDrain = $null; $errDrain = $null
    $info = [Diagnostics.ProcessStartInfo]::new($Tool)
    $info.UseShellExecute = $false; $info.CreateNoWindow = $true
    $info.WorkingDirectory = $WorkingDirectory; $info.RedirectStandardOutput = $true; $info.RedirectStandardError = $true
    foreach ($argument in $Arguments) { $info.ArgumentList.Add($argument) }
    foreach ($key in @($info.Environment.Keys | Where-Object { $_ -match '\A(CARGO_|RUST)' })) { $null = $info.Environment.Remove($key) }
    foreach ($key in $childEnvironment.Keys) { $info.Environment[$key] = $childEnvironment[$key] }
    $process.StartInfo = $info
    try {
        $started = $process.Start(); Need $started 'Build child did not start.'
        $birth = $process.StartTime.ToUniversalTime().ToString('o')
        $outDrain = $process.StandardOutput.BaseStream.CopyToAsync($stdout,65536)
        $errDrain = $process.StandardError.BaseStream.CopyToAsync($stderr,65536)
        while (-not $process.WaitForExit(2000)) {
            Need ((DirectoryBytes $root -AllowTransient) -le $MaximumWorkingBytes) 'Candidate exceeded its reserved working-space budget.'
            Need ($stdout.Length+$stderr.Length -le 16MB) 'Build logs exceeded their shared bound.'
            Need ([IO.DriveInfo]::new([IO.Path]::GetPathRoot($root)).AvailableFreeSpace -ge $configuration.Settings.minimumHostFreeBytes) 'Build breached host free-space reserve.'
        }
        $null = [Threading.Tasks.Task]::WhenAll($outDrain,$errDrain).GetAwaiter().GetResult()
        $stdout.Flush($true); $stderr.Flush($true)
        $record = [pscustomobject]@{name=$Name;tool=$Tool;arguments=$Arguments;working_directory=$WorkingDirectory;pid=$process.Id;birth_utc=$birth;exit_code=$process.ExitCode;stdout=(Split-Path $outPath -Leaf);stderr=(Split-Path $errPath -Leaf)}
        $commands.Add($record)
        Need ($process.ExitCode -eq 0) 'Candidate command failed; retained logs and failure receipt contain its result.'
        Need ($stdout.Length+$stderr.Length -le 16MB -and (DirectoryBytes $root) -le $MaximumWorkingBytes) 'Candidate final log/storage budget exceeded.'
    } finally {
        if ($started -and -not $process.HasExited) { $process.Kill($true); $process.WaitForExit() }
        if ($started) {
            if ($null -ne $outDrain) { $null = $outDrain.GetAwaiter().GetResult() }
            if ($null -ne $errDrain) { $null = $errDrain.GetAwaiter().GetResult() }
        }
        $process.Dispose(); $stdout.Dispose(); $stderr.Dispose()
    }
}

try {
    Need ($IsWindows) 'Windows x64 release candidate builder required.'
    Need ([IO.Path]::IsPathRooted($OutputDirectory) -and -not $OutputDirectory.Contains('..')) 'Fresh absolute output directory required.'
    $root = [IO.Path]::GetFullPath($OutputDirectory).TrimEnd('\')
    Need ($root.StartsWith($allowedRoot+'\',[StringComparison]::OrdinalIgnoreCase) -and -not (Test-Path -LiteralPath $root)) 'Output must be a fresh child of .lab/development/release-candidates.'
    $cursor = Split-Path $root -Parent
    while (-not (Test-Path -LiteralPath $cursor)) { $cursor = Split-Path $cursor -Parent }
    $null = Ordinary $cursor $true
    $gitPath = (Get-Command git -CommandType Application | Select-Object -First 1).Source
    $git = PinFile $gitPath $ExpectedGitSha256
    $rustup = PinFile ([IO.Path]::GetFullPath($RustupPath)) $ExpectedRustupSha256
    $gitBase = @('--no-replace-objects','-C',$workspace)
    Need ((SmallTool $gitPath ($gitBase+@('rev-parse','--show-object-format'))) -ceq 'sha1') 'Explicit SHA-1 Git commit identity required.'
    Need ((SmallTool $gitPath ($gitBase+@('rev-parse','--verify',($SourceCommit+'^{commit}')))) -ceq $SourceCommit) 'Source commit identity differs.'
    $tree = SmallTool $gitPath ($gitBase+@('rev-parse',($SourceCommit+'^{tree}')))
    $listing = SmallTool $gitPath ($gitBase+@('-c','core.quotePath=false','ls-tree','-r','--format=%(objectmode) %(objecttype) %(objectname)%x09%(path)',$SourceCommit,'--')+$sourcePaths)
    $expected = [Collections.Generic.Dictionary[string,object]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($line in ($listing -split "`n")) {
        Need ($line -cmatch '\A(100644|100755) blob ([0-9a-f]{40})\t([A-Za-z0-9_./-]+)\z') 'Only ordinary tracked build inputs with safe Windows paths may be archived.'
        $name = $Matches[3]; $blob = $Matches[2]
        $embeddedRegistry = $name -ceq 'evidence/qualification-registry.json'
        Need (-not $name.Contains('..') -and $name -notmatch '(^|/)(secrets|\.env)(/|\.|$)' -and ($name -cmatch '\.(rs|toml|lock)\z' -or $embeddedRegistry)) 'Non-source or secret build path refused.'
        Need ($expected.TryAdd($name,[pscustomobject]@{path=$name;git_blob=$blob})) 'Case-colliding archived paths refused.'
    }
    Need ($expected.Count -gt 0 -and $expected.Count -le 8192) 'Committed build file inventory exceeds its bound.'
    foreach ($required in @('Cargo.toml','Cargo.lock','rust-toolchain.toml','.cargo/config.toml','src/main.rs','crates/n2r-win32/Cargo.toml','evidence/qualification-registry.json')) { Need ($expected.ContainsKey($required)) 'Required committed build input is absent.' }
    Import-Module (Join-Path $PSScriptRoot 'Lab.psm1') -Force
    $configuration = Get-LabConfiguration -WorkspaceRoot $workspace
    $capacity = Get-LabCapacity -Configuration $configuration
    # Preserve the configured Hyper-V lab epoch. The additional candidate
    # reservation and host-volume free-space floor include this fresh output;
    # unrelated .lab research trees are not candidate build inputs.
    Assert-LabCapacity -Capacity $capacity -AdditionalBytes $MaximumWorkingBytes
    $null = New-Item -ItemType Directory -Path $root -ErrorAction Stop; $created = $true
    $source = Join-Path $root 'source'; $target = Join-Path $root 'target'; $temporary = Join-Path $root 'tmp'
    foreach ($path in @($source,$target,$temporary,(Join-Path $root 'bin'))) { $null = New-Item -ItemType Directory -Path $path -ErrorAction Stop }
    WriteRecord 'intent.json' @{schema_version=1;kind='committed-source-candidate-build-intent';source_commit=$SourceCommit;source_tree=$tree;source_paths=$sourcePaths;expected_cargo_lock_sha256=$ExpectedCargoLockSha256;maximum_working_bytes=$MaximumWorkingBytes;capacity=$capacity;unit_tests_requested=$false;native_tools_invoked=$false;qualification_inherited=$false}
    $zipPath = Join-Path $root 'source.zip'
    RunOwned 'git-archive' $gitPath ($gitBase+@('archive','--format=zip',('--output='+$zipPath),$SourceCommit,'--')+$sourcePaths) $workspace
    $archive = PinFile $zipPath '' 64MB
    $zip = [IO.Compression.ZipArchive]::new($archive.stream,[IO.Compression.ZipArchiveMode]::Read,$true)
    $expanded = [long]0; $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    try {
        Need ($zip.Entries.Count -le 16384) 'Source archive entry count exceeds its bound.'
        foreach ($entry in $zip.Entries) {
            $name = $entry.FullName
            Need ($name -cmatch '\A[A-Za-z0-9_./-]+\z' -and -not $name.Contains('..') -and -not $name.StartsWith('/')) 'Unsafe source archive path refused.'
            $destination = [IO.Path]::GetFullPath((Join-Path $source $name))
            Need ($destination.StartsWith($source+'\',[StringComparison]::OrdinalIgnoreCase)) 'Archive path escaped source directory.'
            if ($name.EndsWith('/')) { $null = New-Item -ItemType Directory -Path $destination -Force; continue }
            Need ($expected.ContainsKey($name) -and $seen.Add($name) -and $entry.Length -le 16MB) 'Unexpected, duplicate or oversize archive source file.'
            $expanded += $entry.Length; Need ($expanded -le 128MB) 'Expanded source exceeds its128MiB bound.'
            $null = New-Item -ItemType Directory -Path (Split-Path $destination -Parent) -Force
            $inputStream = $entry.Open(); $outputStream = [IO.File]::Open($destination,'CreateNew','Write','None')
            try { $inputStream.CopyTo($outputStream,65536); $outputStream.Flush($true) } finally { $inputStream.Dispose(); $outputStream.Dispose() }
        }
    } finally { $zip.Dispose() }
    Need ($seen.Count -eq $expected.Count) 'Git archive omitted committed source inputs.'
    $sourcePins = [Collections.Generic.List[object]]::new()
    foreach ($name in @($expected.Keys | Sort-Object -CaseSensitive)) {
        $pin = PinFile (Join-Path $source $name) '' 16MB
        $sha1 = [Security.Cryptography.SHA1]::Create()
        try {
            $header = [Text.Encoding]::ASCII.GetBytes(('blob '+$pin.bytes+[char]0))
            $null = $sha1.TransformBlock($header,0,$header.Length,$null,0)
            $buffer = [byte[]]::new(65536)
            while (($count = $pin.stream.Read($buffer,0,$buffer.Length)) -gt 0) { $null = $sha1.TransformBlock($buffer,0,$count,$null,0) }
            $null = $sha1.TransformFinalBlock([byte[]]::new(0),0,0)
            Need ([Convert]::ToHexString($sha1.Hash).ToLowerInvariant() -ceq $expected[$name].git_blob) 'Archive bytes differ from the exact committed Git blob.'
        } finally { $sha1.Dispose(); $pin.stream.Position = 0 }
        $sourcePins.Add([pscustomobject]@{path=$name;bytes=$pin.bytes;sha256=$pin.sha256;git_blob=$expected[$name].git_blob})
    }
    $lock = @($sourcePins | Where-Object path -CEQ 'Cargo.lock')[0]
    Need ($lock.sha256 -ceq $ExpectedCargoLockSha256) 'Committed Cargo.lock differs from its supplied pin.'
    $toolchainText = [IO.File]::ReadAllText((Join-Path $source 'rust-toolchain.toml'))
    Need ($toolchainText -cmatch '(?m)^channel\s*=\s*"([0-9]+\.[0-9]+\.[0-9]+)"\s*$') 'Exact committed Rust release channel required.'
    $channel = $Matches[1]
    $cargoPath = SmallTool $rustup.path @('which','--toolchain',$channel,'cargo')
    $rustcPath = SmallTool $rustup.path @('which','--toolchain',$channel,'rustc')
    $cargo = PinFile $cargoPath $ExpectedCargoSha256
    $rustc = PinFile $rustcPath $ExpectedRustcSha256
    $rustcVersion = SmallTool $rustc.path @('--version','--verbose')
    $cargoVersion = SmallTool $cargo.path @('--version','--verbose')
    Need ($rustcVersion -cmatch ('(?m)^release: '+[regex]::Escape($channel)+'$') -and $rustcVersion -cmatch '(?m)^host: x86_64-pc-windows-msvc$') 'Pinned Rust compiler release/host differs from committed toolchain.'
    # Cargo discovers ancestor configuration from its working directory, not
    # --manifest-path. Run outside the checkout and supply the held committed
    # config explicitly. Any Cargo-home configuration needs its separate
    # caller-supplied pin and held handle; its contents never enter a receipt.
    $cargoDirectory = [Environment]::SystemDirectory
    $null = Ordinary $cargoDirectory $true
    $configCursor = [IO.DirectoryInfo]::new($cargoDirectory)
    while ($null -ne $configCursor) {
        foreach ($leaf in @('.cargo\config','.cargo\config.toml')) { Need (-not (Test-Path -LiteralPath (Join-Path $configCursor.FullName $leaf))) 'Unpinned ancestor Cargo configuration refused.' }
        $configCursor = $configCursor.Parent
    }
    $cargoHome = if ($env:CARGO_HOME) { [IO.Path]::GetFullPath($env:CARGO_HOME) } else { Join-Path $env:USERPROFILE '.cargo' }
    $null = Ordinary $cargoHome $true
    $homeConfigs = @(@('config','config.toml') | ForEach-Object { Join-Path $cargoHome $_ } | Where-Object { Test-Path -LiteralPath $_ })
    Need ($homeConfigs.Count -le 1) 'Ambiguous legacy and TOML Cargo-home configurations refused.'
    $cargoHomeConfig = $null
    if ($homeConfigs.Count -eq 1) {
        Need ($ExpectedCargoHomeConfigSha256 -cmatch '\A[0-9a-f]{64}\z') 'Existing Cargo-home configuration requires its explicit SHA-256 pin.'
        $homeConfigPin = PinFile $homeConfigs[0] $ExpectedCargoHomeConfigSha256 1MB
        $cargoHomeConfig = @{path=$homeConfigPin.path;bytes=$homeConfigPin.bytes;sha256=$homeConfigPin.sha256;handle_held_during_build=$true;contents_included_in_receipt=$false}
    } else {
        Need ([string]::IsNullOrEmpty($ExpectedCargoHomeConfigSha256)) 'Cargo-home configuration pin supplied while no configuration exists.'
    }
    $childEnvironment = @{CARGO_HOME=$cargoHome;CARGO_TARGET_DIR=$target;CARGO_INCREMENTAL='0';RUSTC=$rustc.path;RUSTUP_TOOLCHAIN=$channel;RUSTC_WRAPPER='';RUSTC_WORKSPACE_WRAPPER='';TEMP=$temporary;TMP=$temporary}
    $arguments = @('--config',(Join-Path $source '.cargo\config.toml'),'build','--manifest-path',(Join-Path $source 'Cargo.toml'),'--release','--locked','--offline','--target',$targetTriple,'--target-dir',$target,'--jobs',[string]$Jobs)
    foreach ($binary in $binaries) { $arguments += @('--bin',$binary) }
    RunOwned 'cargo-build' $cargo.path $arguments $cargoDirectory
    $binaryPins = [Collections.Generic.List[object]]::new()
    foreach ($binary in $binaries) {
        $pin = PinFile (Join-Path $target ($targetTriple+'\release\'+$binary+'.exe')) '' 64MB
        $destination = Join-Path $root ('bin\'+$binary+'.exe')
        $outputStream = [IO.File]::Open($destination,'CreateNew','Write','Read')
        try { $pin.stream.CopyTo($outputStream,65536); $outputStream.Flush($true) } finally { $outputStream.Dispose(); $pin.stream.Position = 0 }
        Need ((Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash.ToLowerInvariant() -ceq $pin.sha256) 'Candidate executable copy changed.'
        $binaryPins.Add([pscustomobject]@{name=$binary;path=('bin/'+$binary+'.exe');bytes=$pin.bytes;sha256=$pin.sha256})
    }
    foreach ($pin in $held) { $pin.Position = 0 }
    $finalBytes = DirectoryBytes $root
    Need ($finalBytes -le $MaximumWorkingBytes) 'Final candidate exceeds its working-space budget.'
    WriteRecord 'manifest.json' @{schema_version=1;kind='clean-committed-source-release-candidate';created_utc=[DateTime]::UtcNow.ToString('o');source_commit=$SourceCommit;source_tree=$tree;archive=@{path='source.zip';bytes=$archive.bytes;sha256=$archive.sha256};source_files=$sourcePins.ToArray();cargo_lock_sha256=$lock.sha256;toolchain_channel=$channel;target=$targetTriple;cargo_home_configuration=$cargoHomeConfig;tools=@(@{name='git';path=$git.path;bytes=$git.bytes;sha256=$git.sha256},@{name='rustup';path=$rustup.path;bytes=$rustup.bytes;sha256=$rustup.sha256},@{name='cargo';path=$cargo.path;bytes=$cargo.bytes;sha256=$cargo.sha256;version=$cargoVersion},@{name='rustc';path=$rustc.path;bytes=$rustc.bytes;sha256=$rustc.sha256;version=$rustcVersion});commands=$commands.ToArray();binaries=$binaryPins.ToArray();builder_sha256=(Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash.ToLowerInvariant();maximum_working_bytes=$MaximumWorkingBytes;observed_working_bytes_before_manifest=$finalBytes;resource_guard='periodic process-tree stop; not a filesystem quota';working_tree_inputs_used=$false;source_input_handles_held_during_build=$true;locked_dependencies=$true;offline_build=$true;unit_tests_run=$false;native_tools_invoked=$false;qualification_inherited=$false;stable_release=$false;native_marker_qualified=$false;power_loss_qualified=$false;reproducible_build_verified=$false}
    [pscustomobject]@{output_directory=$root;manifest_sha256=(Get-FileHash -LiteralPath (Join-Path $root 'manifest.json') -Algorithm SHA256).Hash.ToLowerInvariant();source_commit=$SourceCommit;binaries=$binaryPins.Count;stable_release=$false;qualification_inherited=$false} | ConvertTo-Json
} catch {
    if ($created) { WriteRecord 'build-failed.json' @{schema_version=1;kind='committed-source-candidate-build-failure';source_commit=$SourceCommit;error=$_.Exception.Message;commands=$commands.ToArray();retained_for_review=$true;unit_tests_run=$false;native_tools_invoked=$false;qualification_inherited=$false} }
    throw
} finally {
    for ($i=$held.Count-1; $i -ge 0; $i--) { $held[$i].Dispose() }
}
