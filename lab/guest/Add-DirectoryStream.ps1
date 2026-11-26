<#
.SYNOPSIS
  Shapes a lab source volume with a directory that carries a named data
  stream.

.DESCRIPTION
  The converter carries it over as the same directory's named stream on
  ReFS (ds3-dirstream-minimal and ds3-dirstream-lived-in showed the
  data-volume case). Run through the harness's -ShapeSource.
#>
[CmdletBinding()]
param([Parameter(Mandatory)][string]$SourceLetter)
$ErrorActionPreference = 'Stop'
$root = "${SourceLetter}:\n2r-shape-directory-stream"
if (Test-Path -LiteralPath $root) { throw "$root already exists" }
$null = New-Item -ItemType Directory -Path $root
$directory = Join-Path $root 'folder with a stream'
$null = New-Item -ItemType Directory -Path $directory
Set-Content -LiteralPath $directory -Stream 'about' -Value 'a stream on a directory' -Encoding ASCII
[ordered]@{ kind = 'source-shape-v1'; shape = 'directory-stream'; root = $root; directory = $directory } | ConvertTo-Json -Compress
