<#
.SYNOPSIS
  Shapes a lab source volume with one thing the converter does not admit: a
  directory that carries a named data stream.

.DESCRIPTION
  For checking the refusal, not a conversion: the source must be refused at
  admission, before anything is written, with a message that names the
  directory and the reason. Run through the harness's -ShapeSource.
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
