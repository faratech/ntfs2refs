#Requires -Version 7.2
param(
    [Parameter(Mandatory)][string]$Archive,
    [Parameter(Mandatory)][string]$Candidate,
    [Parameter(Mandatory)][string]$Qualification
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$source = Join-Path $PSScriptRoot '../..'
. "$source/lab/ReleaseArchiveDocuments.ps1"

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
foreach ($name in Get-ReleaseArchiveSourceDocuments $source) {
    $hashes[$name] = (Get-FileHash -LiteralPath (Join-Path $source $name) -Algorithm SHA256).Hash.ToLowerInvariant()
}
foreach ($name in 'RELEASE-NOTES.md', 'capabilities.json') {
    $hashes[$name] = (Get-FileHash -LiteralPath (Join-Path $distribution $name) -Algorithm SHA256).Hash.ToLowerInvariant()
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
    $extra = @($zip.Entries | Where-Object { $_.FullName -cnotin $hashes.Keys })
    if ($extra.Count) { throw "Unexpected ZIP entry: $($extra[0].FullName)" }
} finally { $zip.Dispose() }

$archiveHash = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
$checksum = Get-Content -LiteralPath "$archivePath.sha256" -Raw
if ($checksum.TrimEnd("`r", "`n") -cne "$archiveHash  $(Split-Path -Leaf $archivePath)") {
    throw 'Published archive checksum differs from the verified ZIP'
}
