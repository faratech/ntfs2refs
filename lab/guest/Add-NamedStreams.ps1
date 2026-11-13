<#
.SYNOPSIS
  Shapes a lab source volume: adds files and a directory that carry named
  data streams, which a freshly installed Windows volume does not have.

.DESCRIPTION
  Run in the control OS against the mounted NTFS source, before the source is
  listed and converted (the harness's -ShapeSource). Everything is created
  under one new directory at the root of the source. Prints one JSON line
  saying what was made.
#>
[CmdletBinding()]
param([Parameter(Mandatory)][string]$SourceLetter)
$ErrorActionPreference = 'Stop'
$root = "${SourceLetter}:\n2r-shape-named-streams"
if (Test-Path -LiteralPath $root) { throw "$root already exists" }
$null = New-Item -ItemType Directory -Path $root

# A file with two streams beside its data, one of them empty.
$plain = Join-Path $root 'report.txt'
Set-Content -LiteralPath $plain -Value 'unnamed data stream' -Encoding ASCII
Set-Content -LiteralPath $plain -Stream 'notes' -Value 'a named stream of a few bytes' -Encoding ASCII
Set-Content -LiteralPath $plain -Stream 'Zone.Identifier' -Value "[ZoneTransfer]`r`nZoneId=3" -Encoding ASCII
# (Streams are written through the provider: .NET Framework's file classes
# refuse a path with a stream name in it.)
Set-Content -LiteralPath $plain -Stream 'empty' -Value ([byte[]]@()) -Encoding Byte

# A stream larger than a cluster, with content that is not all one byte.
$large = Join-Path $root 'archive.bin'
[IO.File]::WriteAllBytes($large, [byte[]](1..200))
$bytes = [byte[]]::new(300000); for ($i = 0; $i -lt $bytes.Length; $i++) { $bytes[$i] = [byte](($i * 31 + 7) -band 0xff) }
Set-Content -LiteralPath $large -Stream 'payload' -Value $bytes -Encoding Byte

# Names outside ASCII (spelled by code point: Windows PowerShell reads a
# script without a byte-order mark as ANSI), on a file whose unnamed stream
# is empty.
$named = Join-Path $root ('Bericht f' + [char]0xFC + 'r M' + [char]0xE4 + 'rz.txt')
$only = [IO.File]::Open($named, 'Create'); $only.Dispose()
Set-Content -LiteralPath $named -Stream ([char]0xDC + 'bersicht') -Value 'stream on a file with a non-ASCII name' -Encoding ASCII

# A stream on a directory is not made here: the converter refuses that at
# admission ("directory data streams exceed the profile"), which is a
# separate shape, Add-DirectoryStream.ps1.

$streams = @(Get-ChildItem -LiteralPath $root -Force | ForEach-Object { Get-Item -LiteralPath $_.FullName -Stream * } | Where-Object Stream -NE ':$DATA')
[ordered]@{ kind = 'source-shape-v1'; shape = 'named-streams'; root = $root; objects = @(Get-ChildItem -LiteralPath $root -Force).Count
    named_streams = $streams.Count; named_stream_bytes = ($streams | Measure-Object Length -Sum).Sum } | ConvertTo-Json -Compress
