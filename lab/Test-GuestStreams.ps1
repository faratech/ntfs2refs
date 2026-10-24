<# Exercise the production read-only stream helper on ordinary lab files. #>
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$tokens = $null; $errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'guest\Capture-GuestEvidence.ps1'), [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw 'Evidence parser errors.' }
$literal = $ast.Find({ param($node) $node -is [Management.Automation.Language.StringConstantExpressionAst] -and $node.Value.Contains('public static class NativeEvidenceStreams') }, $true)
if (-not $literal) { throw 'Production stream reader not found.' }
if (-not ('Ntfs2Refs.NativeEvidenceStreams' -as [type])) { Add-Type -TypeDefinition $literal.Value }
$root = Join-Path (Split-Path $PSScriptRoot -Parent) ('.lab\tests\guest-streams-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $root | Out-Null
$path = Join-Path $root 'file with spaces.bin'
[IO.File]::WriteAllBytes($path, [byte[]](0..255))
$before = (Get-FileHash -LiteralPath $path).Hash
Set-Content -LiteralPath $path -Stream named -Value 'alternate-stream' -Encoding UTF8 -NoNewline
$checks = 0
foreach ($entry in @(Get-Item -LiteralPath $path -Stream *)) {
    $streamPath = if ($entry.Stream -eq ':$DATA') { $path } else { $path + ':' + $entry.Stream }
    $stream = [Ntfs2Refs.NativeEvidenceStreams]::OpenRead($streamPath)
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $hash = [BitConverter]::ToString($sha.ComputeHash($stream)).Replace('-','') } finally { $sha.Dispose(); $stream.Dispose() }
    $bytes = if ($entry.Stream -eq ':$DATA') { [IO.File]::ReadAllBytes($path) } else { [byte[]](Get-Content -LiteralPath $path -Stream named -Encoding Byte) }
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $expected = [BitConverter]::ToString($sha.ComputeHash([byte[]]$bytes)).Replace('-','') } finally { $sha.Dispose() }
    if ($hash -cne $expected -or $entry.Length -ne $bytes.Length) { throw 'Native stream hash/length differs from provider bytes.' }
    $checks++
}
if ($checks -ne 2 -or (Get-FileHash -LiteralPath $path).Hash -cne $before) { throw 'Both streams must be observed without changing unnamed data.' }
$rejected = $false
try { $unexpected = [Ntfs2Refs.NativeEvidenceStreams]::OpenRead($path + ':absent'); $unexpected.Dispose() } catch { $rejected = $true }
if (-not $rejected) { throw 'Missing stream must fail without creation.' }
if (@(Get-Item -LiteralPath $path -Stream *).Count -ne 2) { throw 'Read-only probe created a stream.' }
'Passed 3 guest stream checks: unnamed/named hashes and missing-stream refusal; ordinary files only.'
