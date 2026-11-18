<#
.SYNOPSIS
Builds the release of the version in Cargo.toml: the ZIP, its SHA-256 file,
the source archive and the notes.

.DESCRIPTION
A release is what this script makes from a clean checkout of a tagged commit:

  ntfs2refs-<version>-windows-x64.zip
      ntfs2refs.exe, lab-volume-manifest.exe, capabilities.json (what this
      executable says it admits), README.md, the guide, the feature matrix,
      the recovery matrix, and RELEASE-NOTES.md
  ntfs2refs-<version>-windows-x64.zip.sha256
  ntfs2refs-<version>-source.zip          (git archive of the commit)
  RELEASE-NOTES.md                        (also inside the ZIP)

The notes are generated: the version, the commit, the toolchain, the SHA-256
of both executables, what `ntfs2refs capabilities` reports as not carried
over, refused and not shown, and the two matrices by reference. Nothing in
them is typed by hand, so they cannot say more than the tree does.

It refuses a tree with uncommitted changes, a version that is not the one the
executable reports, and (unless -AllowUntagged) a commit without the tag of
that version. It publishes nothing: pushing the tag and `gh release create`
are the owner's steps, and the last lines it prints are those commands.

-ComparedWith <dir> names the executables the lab's final pass ran. They were
built from the same sources at another moment, so they differ from this build
in the linker's time stamps and in nothing else; the script checks exactly
that and says so in the notes.
#>
[CmdletBinding()]
param(
    # Where the release is written; a new directory.
    [string]$Output,
    # Build a commit that does not carry the version's tag (a rehearsal).
    [switch]$AllowUntagged,
    # A directory with the ntfs2refs.exe and lab-volume-manifest.exe that the
    # lab ran: this build has to equal them apart from the linker's stamps.
    [string]$ComparedWith
)
$ErrorActionPreference = 'Stop'; Set-StrictMode -Version Latest
$workspace = Split-Path -Parent $PSScriptRoot

# The parts of a PE file that hold the moment it was linked, as (offset,
# length) pairs: the COFF time stamp, the checksum, and for each debug
# directory entry its own time stamp and the CodeView record's signature and
# age. Everything outside them has to be equal in two builds of one source.
function Get-LinkStampRanges([byte[]]$bytes) {
    $pe = [BitConverter]::ToInt32($bytes, 0x3c)
    if ([Text.Encoding]::ASCII.GetString($bytes, $pe, 4) -ne "PE`0`0") { throw 'not a PE file' }
    $ranges = New-Object System.Collections.Generic.List[object]
    $ranges.Add(@(($pe + 8), 4))
    $optional = $pe + 24
    $magic = [BitConverter]::ToUInt16($bytes, $optional)
    if ($magic -ne 0x20b) { throw 'not a PE32+ file' }
    $ranges.Add(@(($optional + 64), 4))
    $sections = [BitConverter]::ToUInt16($bytes, $pe + 6)
    $sectionTable = $optional + [BitConverter]::ToUInt16($bytes, $pe + 20)
    $toFile = {
        param([uint32]$rva)
        for ($i = 0; $i -lt $sections; $i++) {
            $at = $sectionTable + 40 * $i
            $virtualSize = [BitConverter]::ToUInt32($bytes, $at + 8); $virtual = [BitConverter]::ToUInt32($bytes, $at + 12)
            $rawSize = [BitConverter]::ToUInt32($bytes, $at + 16); $raw = [BitConverter]::ToUInt32($bytes, $at + 20)
            if ($rva -ge $virtual -and $rva -lt $virtual + [Math]::Max($virtualSize, $rawSize)) { return [int]($rva - $virtual + $raw) }
        }
        throw "RVA $rva is in no section"
    }
    $debugRva = [BitConverter]::ToUInt32($bytes, $optional + 112 + 8 * 6); $debugSize = [BitConverter]::ToUInt32($bytes, $optional + 112 + 8 * 6 + 4)
    if ($debugSize) {
        $debug = & $toFile $debugRva
        for ($entry = 0; $entry -lt $debugSize / 28; $entry++) {
            $at = $debug + 28 * $entry
            $ranges.Add(@(($at + 4), 4))
            $type = [BitConverter]::ToUInt32($bytes, $at + 12); $length = [BitConverter]::ToUInt32($bytes, $at + 16); $pointer = [BitConverter]::ToInt32($bytes, $at + 24)
            # CodeView (2): 'RSDS', a GUID and an age. The others are records
            # the linker derives from the link itself (16 is a hash of it).
            if ($type -eq 2 -and $length -ge 24) { $ranges.Add(@(($pointer + 4), 20)) }
            elseif ($type -in 13, 14, 16, 20) { $ranges.Add(@($pointer, [int]$length)) }
        }
    }
    , $ranges
}
function Compare-ApartFromLinkStamps([string]$left, [string]$right) {
    $a = [IO.File]::ReadAllBytes($left); $b = [IO.File]::ReadAllBytes($right)
    if ($a.Length -ne $b.Length) { return "the files differ in length ($($a.Length) and $($b.Length) bytes)" }
    $skip = New-Object bool[] $a.Length
    foreach ($range in (Get-LinkStampRanges $a)) { for ($i = 0; $i -lt $range[1]; $i++) { $skip[$range[0] + $i] = $true } }
    $stamps = 0
    for ($i = 0; $i -lt $a.Length; $i++) {
        if ($a[$i] -ne $b[$i]) { if ($skip[$i]) { $stamps++ } else { return "byte $i differs outside the linker's stamps" } }
    }
    "equal apart from $stamps bytes of the linker's stamps"
}

Push-Location $workspace
try {
    $version = [regex]::Match((Get-Content -Raw -LiteralPath 'Cargo.toml'), '(?m)^version\s*=\s*"([^"]+)"').Groups[1].Value
    if (-not $version) { throw 'Cargo.toml has no version' }
    if (-not $Output) { $Output = Join-Path $workspace ".lab\release\$version" }
    if (Test-Path -LiteralPath $Output) { throw "$Output already exists; a release is built once into a new directory" }
    $dirty = @(& git status --porcelain)
    if ($dirty) { throw "the working tree has uncommitted changes ($($dirty.Count) paths); a release is built from a commit" }
    $commit = (& git rev-parse HEAD).Trim()
    $tags = @(& git tag --points-at HEAD)
    $tagged = $tags -contains $version
    if (-not $tagged -and -not $AllowUntagged) { throw "commit $commit does not carry the tag '$version' (its tags: $($tags -join ', ')); tag it, or use -AllowUntagged for a rehearsal" }

    $tool = { param($name) $path = Join-Path $env:USERPROFILE ".cargo\bin\$name.exe"; if (Test-Path -LiteralPath $path) { $path } else { $name } }
    & (& $tool 'cargo') build --locked --release --bin ntfs2refs --bin ntfs2refs-recovery --bin lab-volume-manifest
    if ($LASTEXITCODE -ne 0) { throw "cargo build failed (exit $LASTEXITCODE)" }
    $binaries = 'ntfs2refs.exe', 'ntfs2refs-recovery.exe', 'lab-volume-manifest.exe' | ForEach-Object { Join-Path $workspace "target\release\$_" }
    $reported = (& $binaries[0] --version).Trim()
    if ($reported -ne "ntfs2refs $version") { throw "the executable reports '$reported', not 'ntfs2refs $version'" }
    $capabilities = (& $binaries[0] capabilities) -join "`n"
    if ($LASTEXITCODE -ne 0) { throw 'ntfs2refs capabilities failed' }
    $reportedCapabilities = $capabilities | ConvertFrom-Json
    if ($reportedCapabilities.tool_version -ne $version) { throw "capabilities reports version '$($reportedCapabilities.tool_version)', not '$version'" }

    $compared = @()
    if ($ComparedWith) {
        foreach ($binary in $binaries) {
            $other = Join-Path $ComparedWith (Split-Path -Leaf $binary)
            if (-not (Test-Path -LiteralPath $other)) { throw "$other does not exist" }
            $result = Compare-ApartFromLinkStamps $binary $other
            if ($result -notlike 'equal apart from*') { throw "$(Split-Path -Leaf $binary) is not the build in ${ComparedWith}: $result" }
            $compared += [pscustomobject]@{ name = Split-Path -Leaf $binary; result = $result; sha256 = (Get-FileHash -LiteralPath $other -Algorithm SHA256).Hash.ToLowerInvariant() }
        }
    }

    $null = New-Item -ItemType Directory -Path $Output
    $stage = Join-Path $Output "ntfs2refs-$version-windows-x64"
    $null = New-Item -ItemType Directory -Path $stage, (Join-Path $stage 'docs')
    Copy-Item -LiteralPath $binaries -Destination $stage
    [IO.File]::WriteAllText((Join-Path $stage 'capabilities.json'), $capabilities, [Text.UTF8Encoding]::new($false))
    Copy-Item -LiteralPath 'README.md' -Destination $stage
    if (Test-Path -LiteralPath 'LICENSE') { Copy-Item -LiteralPath 'LICENSE' -Destination $stage }
    foreach ($document in 'cli-workflow.md', 'feature-matrix.md', 'recovery-matrix.md') { Copy-Item -LiteralPath (Join-Path 'docs' $document) -Destination (Join-Path $stage 'docs') }

    $hash = { param($path) (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() }
    $notes = New-Object System.Collections.Generic.List[string]
    $notes.Add("# ntfs2refs $version")
    $notes.Add('')
    $notes.Add("Built by ``lab\New-Release.ps1`` from commit ``$commit``$(if (-not $tagged) { ' (not tagged: a rehearsal)' }) with $((& (& $tool 'rustc') --version).Trim()).")
    $notes.Add('')
    $notes.Add('| File | SHA-256 |')
    $notes.Add('|---|---|')
    foreach ($binary in $binaries) { $notes.Add("| ``$(Split-Path -Leaf $binary)`` | ``$(& $hash $binary)`` |") }
    $notes.Add('')
    if ($compared) {
        $notes.Add('The lab ran an earlier build of the same sources. Each executable here was compared with it byte for byte:')
        $notes.Add('')
        foreach ($item in $compared) { $notes.Add("- ``$($item.name)``: $($item.result) (the lab's build: ``$($item.sha256)``).") }
        $notes.Add('')
    }
    $notes.Add('## What this executable admits')
    $notes.Add('')
    $notes.Add("``capabilities.json`` in this archive is the output of ``ntfs2refs capabilities`` (schema $($reportedCapabilities.schema_version)). In short:")
    $notes.Add('')
    $notes.Add("- Windows build $($reportedCapabilities.windows_builds.minimum_build) or later; conversions were run on builds $(@($reportedCapabilities.windows_builds.confirmed_builds) -join ' and ').")
    $notes.Add("- ReFS clusters of $(@($reportedCapabilities.target.refs_cluster_bytes) -join ' or ') bytes for a data volume; $($reportedCapabilities.target.refs_version).")
    $notes.Add("- A data volume: $($reportedCapabilities.data_volume.disk_layout).")
    $notes.Add("- An installed Windows that is not running: $(@($reportedCapabilities.qualified_boot_profiles | ForEach-Object { $_.id }) -join ', ').")
    $notes.Add('')
    $notes.Add('Not carried over:')
    $notes.Add('')
    foreach ($item in $reportedCapabilities.data_volume.not_carried_over) { $notes.Add("- $($item.what): $($item.why).") }
    $notes.Add('')
    $notes.Add('Refused before anything is written:')
    $notes.Add('')
    foreach ($item in $reportedCapabilities.data_volume.refused_by_name) { $notes.Add("- $($item.what)$(if ($item.PSObject.Properties['remedy']) { ". To do: $($item.remedy)" }).") }
    $notes.Add('')
    $notes.Add('## What was shown, and what was not')
    $notes.Add('')
    $notes.Add("``$($reportedCapabilities.lab_evidence.feature_matrix)`` lists every NTFS feature with what a conversion does with it and the lab case that shows it; ``$($reportedCapabilities.lab_evidence.recovery_matrix)`` lists every point at which a conversion was interrupted and how each recovery ended. ``$($reportedCapabilities.lab_evidence.guide)`` is the operating and recovery guide.")
    $notes.Add('')
    $notes.Add('Not shown:')
    $notes.Add('')
    foreach ($item in $reportedCapabilities.lab_evidence.not_shown) { $notes.Add("- $item.") }
    [IO.File]::WriteAllLines((Join-Path $stage 'RELEASE-NOTES.md'), $notes, [Text.UTF8Encoding]::new($false))
    Copy-Item -LiteralPath (Join-Path $stage 'RELEASE-NOTES.md') -Destination $Output

    $zip = Join-Path $Output "ntfs2refs-$version-windows-x64.zip"
    Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $zip
    [IO.File]::WriteAllText("$zip.sha256", "$(& $hash $zip)  $(Split-Path -Leaf $zip)`n", [Text.UTF8Encoding]::new($false))
    $source = Join-Path $Output "ntfs2refs-$version-source.zip"
    & git archive --format=zip "--output=$source" $commit
    if ($LASTEXITCODE -ne 0) { throw 'git archive failed' }
    Remove-Item -LiteralPath $stage -Recurse -Force
    "release $version of commit $commit written to $Output"
    Get-ChildItem -LiteralPath $Output | ForEach-Object { '  {0,12:N0}  {1}' -f $_.Length, $_.Name }
    ''
    'To publish it (the owner''s step):'
    "  git push origin $version"
    "  gh release create $version --prerelease --title `"ntfs2refs $version`" --notes-file `"$(Join-Path $Output 'RELEASE-NOTES.md')`" `"$zip`" `"$zip.sha256`""
} finally { Pop-Location }
