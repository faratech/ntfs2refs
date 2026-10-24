<# Compare exported JSON evidence only. Never opens an image, volume or VM.
   Passing hashes establish agreement for captured fixture streams only. #>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$InspectionPath,
    [Parameter(Mandatory)][string]$NativeEvidencePath,
    [Parameter(Mandatory)][string]$OutputPath,
    [string]$CaptureRecordPath
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-RequiredField($Object, [string]$Name) {
    if ($null -eq $Object -or $null -eq $Object.PSObject.Properties[$Name]) { throw "Missing JSON field: $Name" }
    $Object.$Name
}
function Get-RequiredArray($Object, [string]$Name) {
    if ($null -eq $Object -or $null -eq $Object.PSObject.Properties[$Name] -or $Object.$Name -isnot [array]) { throw "Missing or non-array JSON field: $Name" }
    $Object.$Name
}
function Get-UnsignedInteger($Value, [string]$Label, [uint64]$Maximum = [uint64]::MaxValue) {
    $text = [string]$Value; [uint64]$number = 0
    if ($text -cnotmatch '^(0|[1-9][0-9]*)$' -or -not [uint64]::TryParse($text, [ref]$number) -or $number -gt $Maximum) { throw "Invalid unsigned integer: $Label" }
    $number
}
function Get-LocalJsonPath([string]$Path, [switch]$Existing) {
    try { $full = [IO.Path]::GetFullPath($Path) } catch { throw 'Only ordinary local .json paths are accepted.' }
    if ($full -notmatch '^[A-Za-z]:\\' -or $full.Substring(2).Contains(':') -or [IO.Path]::GetExtension($full) -ine '.json') { throw 'Only ordinary local .json paths are accepted.' }
    $check = if ($Existing) { $full } else { [IO.Path]::GetDirectoryName($full) }
    while ($check) {
        $item = Get-Item -LiteralPath $check -Force -ErrorAction Stop
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'JSON paths must not contain reparse points.' }
        if ($check -ceq $full -and $Existing -and $item.PSIsContainer) { throw 'JSON input must be a regular file.' }
        $parent = [IO.Path]::GetDirectoryName($check.TrimEnd('\'))
        if ($parent -ceq $check) { break }
        $check = $parent
    }
    $full
}
function Read-JsonEvidence([string]$Path) {
    $full = Get-LocalJsonPath $Path -Existing
    $file = [IO.File]::Open($full, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
        if ($file.Length -le 0 -or $file.Length -gt 128MB) { throw 'JSON input is empty or exceeds the 128 MiB comparison limit.' }
        $sha = [Security.Cryptography.SHA256]::Create()
        try { $hash = [BitConverter]::ToString($sha.ComputeHash($file)).Replace('-', '').ToLowerInvariant() } finally { $sha.Dispose() }
        $file.Position = 0
        $reader = [IO.StreamReader]::new($file, [Text.UTF8Encoding]::new($false, $true), $true, 65536, $true)
        try { $json = $reader.ReadToEnd() | ConvertFrom-Json } finally { $reader.Dispose() }
        [pscustomobject]@{ path = $full; length = $file.Length; sha256 = $hash; json = $json }
    } finally { $file.Dispose() }
}
function Get-FileReference([string]$FileId) {
    if ($FileId -cnotmatch '^0x[0-9a-fA-F]{1,32}$') { throw 'Native NTFS file ID is missing or malformed.' }
    $hex = $FileId.Substring(2).PadLeft(32, '0')
    if ($hex.Substring(0, 16) -cne '0000000000000000') { throw 'Native NTFS file ID has nonzero high 64 bits.' }
    $reference = [uint64]::Parse($hex.Substring(16), [Globalization.NumberStyles]::HexNumber, [Globalization.CultureInfo]::InvariantCulture)
    $number = $reference -band [uint64]281474976710655
    $sequence = [uint64]($reference -shr 48)
    [pscustomobject]@{ canonical = '0x' + $hex.ToLowerInvariant(); record = $number; sequence = $sequence; key = ('{0}:{1}' -f $number, $sequence) }
}
function Get-NameUnits([string]$Name) { ,([uint16[]]@($Name.ToCharArray() | ForEach-Object { [uint16]$_ })) }
function Get-UnitKey($Units) {
    if ($null -eq $Units) { return '' }
    if (@($Units).Count -gt 255) { throw 'NTFS stream name exceeds 255 UTF-16 units.' }
    $parts = foreach ($unit in @($Units)) { '{0:x4}' -f (Get-UnsignedInteger $unit 'stream UTF-16 unit' 65535) }
    $parts -join ''
}
function Get-Hash([object]$Value, [string]$Label) {
    if ($Value -isnot [string] -or $Value -cnotmatch '^[0-9a-fA-F]{64}$') { throw "Invalid SHA-256: $Label" }
    $Value.ToLowerInvariant()
}
function Get-FixturePath($Path) {
    if ($Path -isnot [string]) { throw 'Native path must be a string.' }
    if (-not $Path.StartsWith('fixtures\', [StringComparison]::OrdinalIgnoreCase)) { return $null }
    if ($Path.Contains('/') -or $Path.Contains(':') -or $Path.Contains([char]0) -or @($Path.Split('\') | Where-Object { $_ -eq '' -or $_ -eq '.' -or $_ -eq '..' }).Count) { throw 'Fixture path is not a normalized relative path.' }
    $Path
}
function Get-AggregateStatus($Streams) {
    $statuses = @($Streams | ForEach-Object { $_.status })
    if ($statuses -contains 'mismatch') { return 'mismatch' }
    if ($statuses -contains 'missing') { return 'missing' }
    if ($statuses -contains 'unsupported') { return 'unsupported' }
    if ($statuses.Count -eq 0) { return 'unsupported' }
    'matched'
}
function Assert-CaptureProvenance($Capture, $Inspection, $Native, $Details) {
    if ((Get-RequiredField $Capture 'schemaVersion') -ne 1 -or (Get-RequiredField $Capture 'status') -cne 'complete' -or (Get-RequiredField $Capture 'fileSystem') -cne 'NTFS') { throw 'Capture record must be a complete NTFS capture.' }
    $source = Get-RequiredField $Inspection 'source'
    $length = Get-UnsignedInteger (Get-RequiredField $Capture 'length') 'capture length'
    if ($length -eq 0 -or $length -ne (Get-UnsignedInteger (Get-RequiredField $source 'length') 'inspection source length') -or (Get-Hash (Get-RequiredField $Capture 'sha256') 'capture') -cne (Get-Hash (Get-RequiredField $source 'sha256') 'inspection source')) { throw 'Capture length or SHA-256 differs from the inspected source.' }
    $target = Get-RequiredField $Capture 'target'; $nativeTarget = Get-RequiredField $Native 'diskIdentity'
    if ((Get-RequiredField $target 'schemaVersion') -ne 1 -or (Get-RequiredField $nativeTarget 'schemaVersion') -ne 1 -or (Get-RequiredField $target 'role') -cne 'target' -or (Get-RequiredField $nativeTarget 'role') -cne 'target') { throw 'Capture and native evidence must identify the target role.' }
    foreach ($field in @('uniqueId','serialNumber','location','enrolledUtc')) {
        $captured = Get-RequiredField $target $field; $observed = Get-RequiredField $nativeTarget $field
        if ($captured -isnot [string] -or $observed -isnot [string] -or -not [string]::Equals($captured, $observed, [StringComparison]::Ordinal) -or ($field -ne 'serialNumber' -and [string]::IsNullOrWhiteSpace($captured))) { throw "Capture target identity differs from native evidence: $field" }
    }
    foreach ($identity in @($target, $nativeTarget)) {
        $available = Get-RequiredField $identity 'serialNumberAvailable'
        if ($available -isnot [bool] -or $available -ne (-not [string]::IsNullOrWhiteSpace([string]$identity.serialNumber))) { throw 'Capture/native serial availability is inconsistent.' }
    }
    $targetSize = Get-UnsignedInteger (Get-RequiredField $target 'sizeBytes') 'capture target size'
    if ($targetSize -ne (Get-UnsignedInteger (Get-RequiredField $nativeTarget 'sizeBytes') 'native target size')) { throw 'Capture target size differs from native evidence.' }
    $offset = Get-UnsignedInteger (Get-RequiredField $Capture 'partitionOffset') 'partition offset'
    $logical = Get-UnsignedInteger (Get-RequiredField $Capture 'logicalSectorSize') 'capture logical sector' 4096
    $physical = Get-UnsignedInteger (Get-RequiredField $Capture 'physicalSectorSize') 'capture physical sector' 65536
    $alignment = Get-UnsignedInteger (Get-RequiredField $Capture 'ioBufferAlignment') 'capture buffer alignment' 65536
    $allocation = Get-UnsignedInteger (Get-RequiredField $Capture 'allocationUnitSize') 'capture allocation unit' 2097152
    if ($logical -lt 512 -or ($logical -band ($logical - 1)) -ne 0 -or $physical -lt $logical -or ($physical -band ($physical - 1)) -ne 0 -or $alignment -ne $physical -or $allocation -lt $logical -or ($allocation -band ($allocation - 1)) -ne 0) { throw 'Capture sector/allocation/alignment geometry is invalid.' }
    if ($length -gt $targetSize -or $offset -eq 0 -or $offset -gt ($targetSize - $length) -or $offset % $physical -ne 0 -or $length % $physical -ne 0) { throw 'Captured partition bounds or alignment are inconsistent with the target.' }
    $geometry = Get-RequiredField $Details 'geometry'
    $sector = Get-UnsignedInteger (Get-RequiredField $geometry 'bytes_per_sector') 'inspection sector size'
    $cluster = Get-UnsignedInteger (Get-RequiredField $geometry 'cluster_size') 'inspection cluster size'
    $sectorsPerCluster = Get-UnsignedInteger (Get-RequiredField $geometry 'sectors_per_cluster') 'inspection sectors per cluster'
    $totalSectors = Get-UnsignedInteger (Get-RequiredField $geometry 'total_sectors') 'inspection total sectors'
    $volumeSize = Get-UnsignedInteger (Get-RequiredField $geometry 'volume_size') 'inspection volume size'
    if ($sector -ne $logical -or $cluster -ne $allocation -or [decimal]$sector * [decimal]$sectorsPerCluster -ne [decimal]$cluster -or [decimal]$totalSectors * [decimal]$sector -ne [decimal]$volumeSize -or $volumeSize -gt $length -or ($length - $volumeSize) -notin @(0, $logical)) { throw 'Capture geometry differs from inspected NTFS geometry.' }
    [pscustomobject]@{ sourceSha256 = $Capture.sha256; sourceLength = $length; targetUniqueId = $target.uniqueId; partitionOffset = $offset; logicalSectorSize = $logical; physicalSectorSize = $physical; allocationUnitSize = $allocation; geometryConsistent = $true; targetIdentityMatched = $true }
}

$inspectionInput = Read-JsonEvidence $InspectionPath
$nativeInput = Read-JsonEvidence $NativeEvidencePath
$inspection = $inspectionInput.json; $native = $nativeInput.json
if ((Get-RequiredField $inspection 'schema_version') -ne 1 -or (Get-RequiredField $native 'schemaVersion') -ne 1) { throw 'Unsupported inspection or native evidence schema.' }
$filesystem = Get-RequiredField $inspection 'filesystem'
if ((Get-RequiredField $filesystem 'filesystem') -cne 'Ntfs') { throw 'Comparison requires an NTFS inspection report.' }
$details = Get-RequiredField $filesystem 'details'
if ((Get-RequiredField $details 'schema_version') -ne 1) { throw 'Unsupported NTFS details schema.' }
$filesystemProof = [Collections.Generic.List[string]]::new()
$filesystemLimitations = [Collections.Generic.List[string]]::new()
$captureInput = $null; $captureVerification = $null
if ($CaptureRecordPath) {
    $captureInput = Read-JsonEvidence $CaptureRecordPath
    $captureVerification = Assert-CaptureProvenance $captureInput.json $inspection $native $details
    $filesystemProof.Add('complete_capture_sidecar_bound_to_source_and_native_target')
}
if ($native.PSObject.Properties['fileSystem']) {
    if ($native.fileSystem -cne 'NTFS') { throw 'Structured native filesystem disagrees with NTFS evidence.' }
    $filesystemProof.Add('structured_native_volume_filesystem')
    if ($native.PSObject.Properties['allocationUnitSize']) {
        $allocation = Get-UnsignedInteger $native.allocationUnitSize 'native allocation unit'
        if ($allocation -ne (Get-UnsignedInteger (Get-RequiredField (Get-RequiredField $details 'geometry') 'cluster_size') 'inspection cluster size')) { throw 'Structured native allocation unit differs from inspected NTFS geometry.' }
    }
}
$commands = Get-RequiredField $native 'nativeCommandResults'; $volumeInfo = Get-RequiredField $commands 'volumeInfo'
$nativeInfo = [string](Get-RequiredField $volumeInfo 'output')
$nativeFs = [regex]::Matches($nativeInfo, '(?m)^\s*File System Name\s*:\s*([^\r\n]+)\r?$')
$nativeVolumeInfoExitCode = Get-RequiredField $volumeInfo 'exitCode'
if ($nativeInfo.Length -gt 128KB) { throw 'Native volume information exceeds its text bound.' }
if ($nativeVolumeInfoExitCode -eq 0) {
    if ($nativeFs.Count -ne 1 -or $nativeFs[0].Groups[1].Value.Trim() -cne 'NTFS') { throw 'Successful native command must contain unambiguous English NTFS volume information.' }
    $filesystemProof.Add('successful_native_fsutil_volume_information')
} else {
    if (@($nativeFs | Where-Object { $_.Groups[1].Value.Trim() -cne 'NTFS' }).Count) { throw 'Failed native command contains a conflicting filesystem observation.' }
    $filesystemLimitations.Add("Native fsutil volume information failed (exit $nativeVolumeInfoExitCode); retained as a capture limitation. Filesystem proof comes from the recorded structured/capture evidence.")
}
if ($filesystemProof.Count -eq 0) { throw 'At least one native NTFS filesystem proof is required; the fsutil query did not succeed.' }
$nativeFailures = @(Get-RequiredArray $native 'failures'); $nativeLimitations = @(Get-RequiredArray $native 'limitations')
$nativeEnumerationSucceeded = Get-RequiredField $native 'nativeEnumerationSucceeded'
if ($nativeEnumerationSucceeded -isnot [bool]) { throw 'nativeEnumerationSucceeded must be boolean.' }
$files = @(Get-RequiredArray $details 'files'); $nativeFiles = @(Get-RequiredArray $native 'files')
if ($files.Count -gt 1000000 -or $nativeFiles.Count -gt 250000) { throw 'File count exceeds comparison limits.' }
$byReference = [Collections.Generic.Dictionary[string, object]]::new([StringComparer]::Ordinal)
$byRecord = [Collections.Generic.Dictionary[string, object]]::new([StringComparer]::Ordinal)
foreach ($file in $files) {
    $number = Get-UnsignedInteger (Get-RequiredField $file 'record_number') 'MFT record number' 281474976710655
    $sequence = Get-UnsignedInteger (Get-RequiredField $file 'sequence_number') 'MFT sequence number' 65535
    $key = '{0}:{1}' -f $number, $sequence
    if ($byRecord.ContainsKey([string]$number)) { throw 'Inspection contains duplicate MFT record numbers.' }
    $byReference.Add($key, $file); $byRecord.Add([string]$number, $file)
}
$comparisons = [Collections.Generic.List[object]]::new()
$paths = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
$identities = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
$nativeStreamCount = 0; $matchedStreamCount = 0; $extraInspectorStreams = 0; $excludedEntries = 0; $comparisonRows = 0
foreach ($nativeFile in $nativeFiles) {
    $path = Get-FixturePath (Get-RequiredField $nativeFile 'path')
    if ($null -eq $path) { continue }
    if (-not $paths.Add($path)) { throw 'Native evidence contains duplicate fixture paths.' }
    $directory = Get-RequiredField $nativeFile 'directory'; $reparse = Get-RequiredField $nativeFile 'reparse'
    if ($directory -isnot [bool] -or $reparse -isnot [bool]) { throw 'Native directory/reparse fields must be boolean.' }
    $entry = [ordered]@{ path = $path; fileId = (Get-RequiredField $nativeFile 'fileId'); recordNumber = $null; sequenceNumber = $null; status = 'unsupported'; reason = $null; streams = @() }
    $nativeStreams = @(Get-RequiredArray $nativeFile 'streams')
    if ($directory -or $reparse) {
        if ($nativeStreams.Count) { throw 'Native directory/reparse record unexpectedly contains stream hashes.' }
        $entry.reason = if ($directory) { 'directory_not_compared' } else { 'reparse_payload_not_compared' }
        $excludedEntries++; $comparisons.Add([pscustomobject]$entry); continue
    }
    $nativeStreamCount += $nativeStreams.Count
    $reference = $null; $file = $null
    try { $reference = Get-FileReference ([string]$entry.fileId) } catch { $entry.reason = $_.Exception.Message }
    if ($reference) {
        $entry.recordNumber = $reference.record; $entry.sequenceNumber = $reference.sequence
        [void]$identities.Add($reference.key)
        if ($byReference.ContainsKey($reference.key)) { $file = $byReference[$reference.key] }
        elseif ($byRecord.ContainsKey([string]$reference.record)) { $entry.status = 'mismatch'; $entry.reason = 'sequence_number_changed' }
        else { $entry.status = 'missing'; $entry.reason = 'file_reference_missing_from_inspection' }
    }
    $inspectorStreams = [Collections.Generic.Dictionary[string, object]]::new([StringComparer]::Ordinal)
    if ($file) {
        if ((Get-RequiredField $file 'is_directory') -or (Get-RequiredField $file 'is_metadata') -or (Get-RequiredField $file 'base_file_reference') -ne 0) {
            $entry.reason = 'inspection_record_is_not_a_regular_fixture_base_file'; $file = $null
        } else {
            foreach ($stream in @(Get-RequiredArray $file 'streams')) {
                $key = Get-UnitKey @(Get-RequiredArray $stream 'name_utf16')
                if ($inspectorStreams.ContainsKey($key)) { throw 'Inspection contains ambiguous duplicate stream names for a fixture file.' }
                $inspectorStreams.Add($key, $stream)
            }
        }
    }
    $results = [Collections.Generic.List[object]]::new()
    $seenNames = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($nativeStream in $nativeStreams) {
        $name = Get-RequiredField $nativeStream 'name'
        if ($name -isnot [string] -or $name.Length -eq 0) { throw 'Native stream name is missing.' }
        $normalizedName = if ($name -ceq ':$DATA') { '' } else { $name }
        $units = Get-NameUnits $normalizedName; $key = Get-UnitKey $units
        if (-not $seenNames.Add($key)) { throw 'Native evidence contains duplicate stream names for a fixture path.' }
        $length = Get-UnsignedInteger (Get-RequiredField $nativeStream 'length') 'native stream length'
        $hash = Get-Hash (Get-RequiredField $nativeStream 'sha256') 'native stream'
        $result = [ordered]@{ nativeName = $name; nameUtf16 = $units; nativeLength = $length; nativeSha256 = $hash; inspectionLength = $null; inspectionSha256 = $null; inspectionHashStatus = $null; status = $entry.status; reason = $entry.reason }
        if ($file) {
            if (-not $inspectorStreams.ContainsKey($key)) { $result.status = 'missing'; $result.reason = 'stream_missing_from_inspection' }
            else {
                $stream = $inspectorStreams[$key]
                $result.inspectionLength = Get-UnsignedInteger (Get-RequiredField $stream 'logical_size') 'inspection stream length'
                $hashStatus = if ($stream.PSObject.Properties['logical_hash_status']) { [string]$stream.logical_hash_status } else { 'not_computed' }
                $result.inspectionHashStatus = $hashStatus
                if ($hashStatus -cne 'complete') { $result.status = 'unsupported'; $result.reason = 'logical_hash_unavailable' }
                else {
                    $result.inspectionSha256 = Get-Hash (Get-RequiredField $stream 'logical_sha256') 'inspection logical stream'
                    if ($result.inspectionLength -ne $length -or $result.inspectionSha256 -cne $hash) { $result.status = 'mismatch'; $result.reason = 'logical_length_or_sha256_differs' }
                    else { $result.status = 'matched'; $result.reason = $null; $matchedStreamCount++ }
                }
            }
        }
        if (++$comparisonRows -gt 250000) { throw 'Stream comparison exceeds the 250000-row limit.' }
        $results.Add([pscustomobject]$result)
    }
    if ($file) {
        foreach ($key in $inspectorStreams.Keys) {
            if (-not $seenNames.Contains($key)) {
                $stream = $inspectorStreams[$key]; $extraInspectorStreams++
                if (++$comparisonRows -gt 250000) { throw 'Stream comparison exceeds the 250000-row limit.' }
                $results.Add([pscustomobject]@{ nativeName = $null; nameUtf16 = $stream.name_utf16; nativeLength = $null; nativeSha256 = $null; inspectionLength = $stream.logical_size; inspectionSha256 = $null; inspectionHashStatus = $null; status = 'missing'; reason = 'stream_missing_from_native_capture' })
            }
        }
    }
    $entry.streams = $results.ToArray()
    if ($results.Count) { $entry.status = Get-AggregateStatus $entry.streams }
    elseif (-not $entry.reason) { $entry.reason = 'native_fixture_has_no_captured_streams' }
    $comparisons.Add([pscustomobject]$entry)
}
$regularComparisons = @($comparisons | Where-Object { $_.reason -notin @('directory_not_compared', 'reparse_payload_not_compared') })
$allPassed = $nativeStreamCount -gt 0 -and $matchedStreamCount -eq $nativeStreamCount -and $extraInspectorStreams -eq 0 -and @($regularComparisons | Where-Object status -cne 'matched').Count -eq 0
$result = [pscustomobject]@{
    schemaVersion = 1; purpose = 'native-ntfs-fixture-logical-stream-comparison'; comparedUtc = [DateTime]::UtcNow.ToString('o')
    inspectionJson = [pscustomobject]@{ path = $inspectionInput.path; length = $inspectionInput.length; sha256 = $inspectionInput.sha256 }
    nativeEvidenceJson = [pscustomobject]@{ path = $nativeInput.path; length = $nativeInput.length; sha256 = $nativeInput.sha256 }
    captureRecordJson = $(if ($captureInput) { [pscustomobject]@{ path = $captureInput.path; length = $captureInput.length; sha256 = $captureInput.sha256 } } else { $null })
    captureVerification = $captureVerification; filesystemProof = $filesystemProof.ToArray(); nativeVolumeInfoExitCode = $nativeVolumeInfoExitCode
    inspectedSource = (Get-RequiredField $inspection 'source'); scope = 'Captured regular file streams beneath fixtures\; exact file reference and UTF-16 stream name'
    nativeFixtureStreamCount = $nativeStreamCount; matchedStreamCount = $matchedStreamCount; extraInspectorStreamCount = $extraInspectorStreams
    fixturePathCount = $comparisons.Count; distinctRegularFileIdentityCount = $identities.Count; excludedFixtureEntryCount = $excludedEntries
    allComparedHashesPassed = [bool]$allPassed; nativeEnumerationSucceeded = $nativeEnumerationSucceeded
    nativeFailures = $nativeFailures; nativeLimitations = $nativeLimitations; files = $comparisons.ToArray()
    limitations = @('Only captured fixture DATA lengths and hashes are compared. Native failures may leave files or streams unobserved.', 'Hard-link paths share an identity; directory membership, link counts, ACLs, timestamps, reparse data, EAs and protected metadata are not validated.', 'JSON provenance identifies supplied reports. A verified capture sidecar binds the reported image hash/length and target identity; this command does not read images or independently establish crash consistency.') + $filesystemLimitations.ToArray()
    metadataValidated = $false; inventoryValidated = $false; conversionValidated = $false; bootValidated = $false
}
$outputFull = Get-LocalJsonPath $OutputPath
$output = [IO.File]::Open($outputFull, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
try {
    $writer = [IO.StreamWriter]::new($output, [Text.UTF8Encoding]::new($false), 65536, $true)
    try { $writer.Write(($result | ConvertTo-Json -Depth 20)); $writer.Flush(); $output.Flush($true) } finally { $writer.Dispose() }
} finally { $output.Dispose() }
$result
