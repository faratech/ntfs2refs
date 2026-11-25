#Requires -Version 7.2
param(
    [Parameter(Mandatory)][string]$Archive,
    [Parameter(Mandatory)][string]$Candidate,
    [Parameter(Mandatory)][string]$Qualification
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$archivePath = (Resolve-Path -LiteralPath $Archive).ProviderPath
$distribution = Split-Path -Parent $archivePath
$identity = Get-Content -LiteralPath (Join-Path $Candidate 'candidate.json') -Raw | ConvertFrom-Json -AsHashtable
$hashes = $identity.hashes
foreach ($name in 'QUALIFICATION.json', 'QUALIFICATION.md') {
    $approved = Join-Path $Qualification $name
    $published = Join-Path $distribution $name
    $hashes[$name] = (Get-FileHash -LiteralPath $approved -Algorithm SHA256).Hash.ToLowerInvariant()
    if ((Get-FileHash -LiteralPath $published -Algorithm SHA256).Hash.ToLowerInvariant() -cne $hashes[$name]) {
        throw "Published qualification file differs for $name"
    }
}

$zip = [IO.Compression.ZipFile]::OpenRead($archivePath)
try {
    foreach ($name in $hashes.Keys) {
        # Windows treats case variants as the same path on extraction.
        $entries = @($zip.Entries | Where-Object FullName -ieq $name)
        if ($entries.Count -ne 1 -or $entries[0].FullName -cne $name) {
            throw "Expected one ZIP entry named $name"
        }
        $stream = $entries[0].Open()
        try {
            if ((Get-FileHash -InputStream $stream -Algorithm SHA256).Hash.ToLowerInvariant() -cne $hashes[$name]) {
                throw "ZIP entry differs for $name"
            }
        } finally { $stream.Dispose() }
    }
} finally { $zip.Dispose() }
