<# Synthetic JSON files only; no image, VM, guest, disk or provider operations. #>
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$workspace = Split-Path $PSScriptRoot -Parent
$compareScript = Join-Path $workspace 'scripts\Compare-LabNtfsStreams.ps1'
$testRoot = Join-Path $workspace ('.lab\tests\stream-comparison-' + [guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($testRoot)
$script:checks = 0
function Assert-Check([bool]$Condition, [string]$Message) { if (-not $Condition) { throw $Message } }
function Write-NewJson([string]$Path, $Value) {
    $output = [IO.File]::Open($Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try {
        $writer = [IO.StreamWriter]::new($output, [Text.UTF8Encoding]::new($false))
        try { $writer.Write(($Value | ConvertTo-Json -Depth 15)) } finally { $writer.Dispose() }
    } finally { $output.Dispose() }
}
function Reset-Fixtures {
    $script:captureRecord = $null
    $script:inspection = [pscustomobject]@{
        schema_version = 1; source = [pscustomobject]@{ path = 'never-open-this.raw'; length = 1GB; sha256 = ('c' * 64) }
        filesystem = [pscustomobject]@{ filesystem = 'Ntfs'; details = [pscustomobject]@{
            schema_version = 1; inventory_complete = $false; files = @([pscustomobject]@{
                record_number = 16; sequence_number = 1; is_directory = $false; is_metadata = $false; base_file_reference = 0
                streams = @([pscustomobject]@{ name = ''; name_utf16 = @(); logical_size = 17; logical_sha256 = ('a' * 64); logical_hash_status = 'complete' })
            })
        } }
    }
    $script:native = [pscustomobject]@{
        schemaVersion = 1; nativeCommandResults = [pscustomobject]@{ volumeInfo = [pscustomobject]@{ exitCode = 0; output = "Volume Name : test`r`nFile System Name : NTFS`r`n" } }
        failures = @(); limitations = @('Captured limitation retained verbatim.'); nativeEnumerationSucceeded = $true
        files = @([pscustomobject]@{ path = 'fixtures\file.txt'; fileId = '0x00000000000000000001000000000010'; directory = $false; reparse = $false; streams = @([pscustomobject]@{ name = ':$DATA'; length = 17; sha256 = ('a' * 64) }) })
    }
    $script:inspection.filesystem.details | Add-Member -NotePropertyName geometry -NotePropertyValue ([pscustomobject]@{ bytes_per_sector = 512; sectors_per_cluster = 8; cluster_size = 4096; total_sectors = 2097151; volume_size = 1073741312 })
    $script:native | Add-Member -NotePropertyName diskIdentity -NotePropertyValue ([pscustomobject]@{ schemaVersion = 1; role = 'target'; uniqueId = 'mock-target'; serialNumber = ''; serialNumberAvailable = $false; sizeBytes = 64GB; location = 'mock-SCSI-LUN-1'; enrolledUtc = '2026-10-23T21:17:20Z' })
}
function New-CaptureRecord {
    [pscustomobject]@{
        schemaVersion = 1; status = 'complete'; fileSystem = 'NTFS'; imagePath = 'E:\native-control\control.raw'; length = 1GB; sha256 = ('c' * 64)
        allocationUnitSize = 4096; partitionOffset = 16MB; logicalSectorSize = 512; physicalSectorSize = 4096; ioBufferAlignment = 4096
        target = ($script:native.diskIdentity | ConvertTo-Json | ConvertFrom-Json)
    }
}
function Use-FailedNativeVolumeInfo {
    $script:native.nativeCommandResults.volumeInfo.exitCode = 1
    $script:native.nativeCommandResults.volumeInfo.output = 'Error 3: The system cannot find the path specified.'
    $script:native.failures = @('Native volume information failed: exit 1; Error 3: The system cannot find the path specified.')
    $script:native.nativeEnumerationSucceeded = $false
}
function Invoke-Case([string]$Name, [scriptblock]$Mutate, [scriptblock]$Check, [string]$ExpectedError) {
    Reset-Fixtures
    & $Mutate
    $prefix = Join-Path $testRoot ([string]$script:checks)
    $inspectionFile = $prefix + '-inspect.json'; $nativeFile = $prefix + '-native.json'; $outputFile = $prefix + '-comparison.json'
    Write-NewJson $inspectionFile $script:inspection; Write-NewJson $nativeFile $script:native
    $inspectionHash = (Get-FileHash -LiteralPath $inspectionFile).Hash
    $nativeHash = (Get-FileHash -LiteralPath $nativeFile).Hash
    $arguments = @{ InspectionPath = $inspectionFile; NativeEvidencePath = $nativeFile; OutputPath = $outputFile }
    $captureFile = $null; $captureHash = $null
    if ($script:captureRecord) {
        $captureFile = $prefix + '-capture.json'; Write-NewJson $captureFile $script:captureRecord
        $captureHash = (Get-FileHash -LiteralPath $captureFile).Hash; $arguments.CaptureRecordPath = $captureFile
    }
    $caught = $null; $result = $null
    try { $result = & $compareScript @arguments } catch { $caught = $_ }
    if ($ExpectedError) {
        Assert-Check ($null -ne $caught -and $caught.Exception.Message -match $ExpectedError) "Expected $ExpectedError; got $caught"
        Assert-Check (-not [IO.File]::Exists($outputFile)) 'Rejected input created a comparison report.'
    } else {
        if ($caught) { throw $caught }
        $persisted = [IO.File]::ReadAllText($outputFile) | ConvertFrom-Json
        Assert-Check ($persisted.inspectionJson.sha256 -ieq $inspectionHash -and $persisted.nativeEvidenceJson.sha256 -ieq $nativeHash) 'Input provenance hashes differ.'
        if ($captureFile) { Assert-Check ($persisted.captureRecordJson.sha256 -ieq $captureHash -and $result.captureVerification.targetIdentityMatched -and $result.captureVerification.geometryConsistent) 'Capture provenance was not retained.' }
        Assert-Check (-not $result.metadataValidated -and -not $result.inventoryValidated -and -not $result.conversionValidated -and -not $result.bootValidated) 'Comparison overclaimed qualification.'
        & $Check $result
    }
    Assert-Check ((Get-FileHash -LiteralPath $inspectionFile).Hash -ceq $inspectionHash -and (Get-FileHash -LiteralPath $nativeFile).Hash -ceq $nativeHash) 'Input JSON changed.'
    if ($captureFile) { Assert-Check ((Get-FileHash -LiteralPath $captureFile).Hash -ceq $captureHash) 'Capture sidecar changed.' }
    $script:checks++; "PASS $Name"
}

Invoke-Case 'Exact unnamed stream matches and preserves limitations' {} {
    param($result)
    Assert-Check ($result.allComparedHashesPassed -and $result.matchedStreamCount -eq 1 -and $result.files[0].status -ceq 'matched') 'Exact stream did not match.'
    Assert-Check ($result.files[0].streams[0].nameUtf16.Count -eq 0) 'Unnamed DATA was not normalized to empty UTF-16.'
    Assert-Check ($result.nativeLimitations[0] -ceq 'Captured limitation retained verbatim.') 'Native limitations lost.'
}
Invoke-Case 'Hardlink aliases compare against the same full file reference' {
    $alias = $script:native.files[0] | ConvertTo-Json -Depth 5 | ConvertFrom-Json
    $alias.path = 'fixtures\alias.txt'; $script:native.files += $alias
} {
    param($result)
    Assert-Check ($result.allComparedHashesPassed -and $result.fixturePathCount -eq 2 -and $result.distinctRegularFileIdentityCount -eq 1 -and $result.matchedStreamCount -eq 2) 'Hardlink identity or paths were collapsed incorrectly.'
}
Invoke-Case 'Sequence change is a mismatch even when record number matches' {
    $script:native.files[0].fileId = '0x00000000000000000002000000000010'
} {
    param($result)
    Assert-Check (-not $result.allComparedHashesPassed -and $result.files[0].status -ceq 'mismatch' -and $result.files[0].reason -ceq 'sequence_number_changed') 'Reused MFT record matched.'
}
Invoke-Case 'Unsigned high sequence bits remain exact' {
    $script:inspection.filesystem.details.files[0].sequence_number = 65535
    $script:native.files[0].fileId = '0x0000000000000000ffff000000000010'
} { param($result) Assert-Check ($result.allComparedHashesPassed -and $result.files[0].sequenceNumber -eq 65535) 'Unsigned file reference lost precision.' }
Invoke-Case 'Nonzero high 64 bits are explicitly unmatched' {
    $script:native.files[0].fileId = '0x00000000000000010001000000000010'
} { param($result) Assert-Check (-not $result.allComparedHashesPassed -and $result.files[0].status -ceq 'unsupported' -and $result.files[0].reason -match 'high 64 bits') 'ReFS-style file ID accepted.' }
Invoke-Case 'Missing native file ID is retained as unsupported' {
    $script:native.files[0].fileId = $null
} { param($result) Assert-Check (-not $result.allComparedHashesPassed -and $result.files.Count -eq 1 -and $result.files[0].streams[0].status -ceq 'unsupported') 'Missing ID was silently skipped.' }
Invoke-Case 'Missing inspected file is retained as missing' {
    $script:inspection.filesystem.details.files = @()
} { param($result) Assert-Check (-not $result.allComparedHashesPassed -and $result.files[0].status -ceq 'missing') 'Missing file matched.' }
Invoke-Case 'Hash mismatch is reported' {
    $script:native.files[0].streams[0].sha256 = ('b' * 64)
} { param($result) Assert-Check (-not $result.allComparedHashesPassed -and $result.files[0].streams[0].status -ceq 'mismatch') 'Hash mismatch passed.' }
Invoke-Case 'Logical length mismatch is reported' {
    $script:native.files[0].streams[0].length = 18
} { param($result) Assert-Check (-not $result.allComparedHashesPassed -and $result.files[0].streams[0].status -ceq 'mismatch') 'Length mismatch passed.' }
Invoke-Case 'Unsupported logical hash cannot use resident digest as a substitute' {
    $stream = $script:inspection.filesystem.details.files[0].streams[0]
    $stream.logical_hash_status = 'unsupported_attribute_list'; $stream.logical_sha256 = $null
    $stream | Add-Member -NotePropertyName resident_sha256 -NotePropertyValue ('a' * 64)
} { param($result) Assert-Check (-not $result.allComparedHashesPassed -and $result.files[0].streams[0].status -ceq 'unsupported') 'Unsupported hash passed.' }
Invoke-Case 'Missing inspector stream is reported' {
    $script:inspection.filesystem.details.files[0].streams = @()
} { param($result) Assert-Check (-not $result.allComparedHashesPassed -and $result.files[0].streams[0].reason -ceq 'stream_missing_from_inspection') 'Missing inspector stream passed.' }
Invoke-Case 'Missing native stream is reported including extra inspector content' {
    $script:native.files[0].streams = @()
} { param($result) Assert-Check (-not $result.allComparedHashesPassed -and $result.extraInspectorStreamCount -eq 1 -and $result.files[0].streams[0].reason -ceq 'stream_missing_from_native_capture') 'Missing native stream passed.' }
Invoke-Case 'Raw UTF-16 names take precedence over lossy inspector display name' {
    $name = [string][char]0x03a9 + [char]0xd83d + [char]0xde00
    $script:native.files[0].streams[0].name = $name
    $stream = $script:inspection.filesystem.details.files[0].streams[0]
    $stream.name = 'deliberately different display'; $stream.name_utf16 = @(0x03a9, 0xd83d, 0xde00)
} { param($result) Assert-Check $result.allComparedHashesPassed 'Exact UTF-16 name did not match.' }
Invoke-Case 'Unicode canonical equivalence is not silently normalized' {
    $script:native.files[0].streams[0].name = 'e' + [char]0x0301
    $script:inspection.filesystem.details.files[0].streams[0].name_utf16 = @(0x00e9)
} { param($result) Assert-Check (-not $result.allComparedHashesPassed -and $result.files[0].status -ceq 'missing') 'Distinct UTF-16 names were normalized.' }
Invoke-Case 'Only exact colon DATA sentinel normalizes to unnamed' {
    $script:native.files[0].streams[0].name = '$DATA'
} { param($result) Assert-Check (-not $result.allComparedHashesPassed -and $result.files[0].status -ceq 'missing') 'Named DATA was treated as unnamed.' }
Invoke-Case 'Native failures remain explicit without claiming metadata coverage' {
    $script:native.failures = @('Cannot read SACL: F:\fixtures\file.txt', 'Cannot enumerate F:\System Volume Information: denied')
    $script:native.nativeEnumerationSucceeded = $false
} {
    param($result)
    Assert-Check ($result.allComparedHashesPassed -and -not $result.nativeEnumerationSucceeded -and $result.nativeFailures.Count -eq 2) 'Captured hash result or native failures were obscured.'
    Assert-Check ($result.nativeFailures[0] -ceq 'Cannot read SACL: F:\fixtures\file.txt') 'Native failure text changed.'
}
Invoke-Case 'Protected metadata paths outside fixtures are not compared' {
    $outside = $script:native.files[0] | ConvertTo-Json -Depth 5 | ConvertFrom-Json
    $outside.path = 'System Volume Information\protected'; $outside.fileId = $null
    $script:native.files += $outside
} { param($result) Assert-Check ($result.allComparedHashesPassed -and $result.fixturePathCount -eq 1 -and $result.nativeFixtureStreamCount -eq 1) 'Comparison escaped fixture scope.' }
Invoke-Case 'No captured fixture streams is not a vacuous success' {
    $script:native.files = @()
} { param($result) Assert-Check (-not $result.allComparedHashesPassed -and $result.nativeFixtureStreamCount -eq 0) 'Empty comparison passed.' }
Invoke-Case 'Reparse fixture without native streams is explicitly excluded' {
    $link = $script:native.files[0] | ConvertTo-Json -Depth 5 | ConvertFrom-Json
    $link.path = 'fixtures\link'; $link.reparse = $true; $link.streams = @()
    $script:native.files += $link
} { param($result) Assert-Check ($result.allComparedHashesPassed -and $result.excludedFixtureEntryCount -eq 1 -and $result.files[1].reason -ceq 'reparse_payload_not_compared') 'Reparse payload qualification was implied.' }
Invoke-Case 'Reparse record cannot hide claimed native streams' {
    $script:native.files[0].reparse = $true
} {} 'directory/reparse record unexpectedly contains'
Invoke-Case 'ReFS inspection refused' { $script:inspection.filesystem.filesystem = 'Refs' } {} 'requires an NTFS inspection'
Invoke-Case 'ReFS native volume refused' { $script:native.nativeCommandResults.volumeInfo.output = 'File System Name : ReFS' } {} 'unambiguous English NTFS'
Invoke-Case 'Failed native volume command without another proof refused' { $script:native.nativeCommandResults.volumeInfo.exitCode = 1 } {} 'native NTFS filesystem proof'
Invoke-Case 'Ambiguous native filesystem observations refused' { $script:native.nativeCommandResults.volumeInfo.output += 'File System Name : ReFS' } {} 'unambiguous English NTFS'
Invoke-Case 'Structured native NTFS field agrees with legacy observation' {
    $script:native | Add-Member -NotePropertyName fileSystem -NotePropertyValue 'NTFS'
} { param($result) Assert-Check $result.allComparedHashesPassed 'Structured NTFS evidence refused.' }
Invoke-Case 'Structured native filesystem disagreement refused' {
    $script:native | Add-Member -NotePropertyName fileSystem -NotePropertyValue 'ReFS'
} {} 'Structured native filesystem disagrees'
Invoke-Case 'Fixture traversal refused' { $script:native.files[0].path = 'fixtures\..\protected.txt' } {} 'normalized relative path'
Invoke-Case 'Duplicate native fixture paths refused' { $script:native.files += $script:native.files[0] } {} 'duplicate fixture paths'
Invoke-Case 'Duplicate inspector records refused' { $script:inspection.filesystem.details.files += $script:inspection.filesystem.details.files[0] } {} 'duplicate MFT record'
Invoke-Case 'Duplicate raw stream names refused' {
    $script:inspection.filesystem.details.files[0].streams += $script:inspection.filesystem.details.files[0].streams[0]
} {} 'duplicate stream names'
Invoke-Case 'Complete status requires a full valid digest' { $script:inspection.filesystem.details.files[0].streams[0].logical_sha256 = $null } {} 'Invalid SHA-256'
Invoke-Case 'Malformed UTF-16 unit refused' { $script:inspection.filesystem.details.files[0].streams[0].name_utf16 = @(65536) } {} 'Invalid unsigned integer'
Invoke-Case 'Legacy hashless stream stays unsupported' {
    $stream = $script:inspection.filesystem.details.files[0].streams[0]
    $stream.PSObject.Properties.Remove('logical_hash_status'); $stream.PSObject.Properties.Remove('logical_sha256')
} { param($result) Assert-Check (-not $result.allComparedHashesPassed -and $result.files[0].streams[0].inspectionHashStatus -ceq 'not_computed') 'Legacy stream was assumed complete.' }

Invoke-Case 'Structured native filesystem permits comparison after fsutil failure' {
    Use-FailedNativeVolumeInfo
    $script:native | Add-Member -NotePropertyName fileSystem -NotePropertyValue 'NTFS'
    $script:native | Add-Member -NotePropertyName allocationUnitSize -NotePropertyValue 4096
} {
    param($result)
    Assert-Check ($result.allComparedHashesPassed -and $result.nativeVolumeInfoExitCode -eq 1 -and -not $result.nativeEnumerationSucceeded -and $result.nativeFailures.Count -eq 1) 'Structured proof concealed native failure or blocked valid captured hashes.'
    Assert-Check ($result.filesystemProof -contains 'structured_native_volume_filesystem' -and @($result.limitations | Where-Object { $_ -match 'fsutil volume information failed' }).Count -eq 1) 'Failed query limitation or structured proof was lost.'
}
Invoke-Case 'Bound complete capture permits legacy comparison after fsutil failure' {
    Use-FailedNativeVolumeInfo; $script:captureRecord = New-CaptureRecord
} {
    param($result)
    Assert-Check ($result.allComparedHashesPassed -and $result.captureVerification.sourceLength -eq 1GB -and $result.captureVerification.sourceSha256 -ceq ('c' * 64)) 'Bound legacy capture did not permit exact stream comparison.'
    Assert-Check ($result.filesystemProof -contains 'complete_capture_sidecar_bound_to_source_and_native_target') 'Capture proof is missing.'
}
Invoke-Case 'Capture permits an exact declared-volume length without backup-sector tail' {
    Use-FailedNativeVolumeInfo; $script:captureRecord = New-CaptureRecord
    $script:inspection.filesystem.details.geometry.volume_size = 1GB
    $script:inspection.filesystem.details.geometry.total_sectors = 2097152
} { param($result) Assert-Check $result.allComparedHashesPassed 'Exact geometry was refused.' }
Invoke-Case 'Incomplete capture refused' {
    Use-FailedNativeVolumeInfo; $script:captureRecord = New-CaptureRecord; $script:captureRecord.status = 'partial'
} {} 'complete NTFS capture'
Invoke-Case 'ReFS capture refused despite NTFS inspection' {
    Use-FailedNativeVolumeInfo; $script:captureRecord = New-CaptureRecord; $script:captureRecord.fileSystem = 'ReFS'
} {} 'complete NTFS capture'
Invoke-Case 'Capture hash mismatch refused' {
    Use-FailedNativeVolumeInfo; $script:captureRecord = New-CaptureRecord; $script:captureRecord.sha256 = ('b' * 64)
} {} 'Capture length or SHA-256 differs'
Invoke-Case 'Capture length mismatch refused' {
    Use-FailedNativeVolumeInfo; $script:captureRecord = New-CaptureRecord; $script:captureRecord.length = 512MB
} {} 'Capture length or SHA-256 differs'
foreach ($identityField in @('uniqueId','serialNumber','location','enrolledUtc')) {
    Invoke-Case "Capture $identityField identity change refused" {
        Use-FailedNativeVolumeInfo; $script:captureRecord = New-CaptureRecord; $script:captureRecord.target.$identityField = 'changed'
    } {} 'Capture target identity differs'
}
Invoke-Case 'Capture target size mismatch refused' {
    Use-FailedNativeVolumeInfo; $script:captureRecord = New-CaptureRecord; $script:captureRecord.target.sizeBytes = 8GB
} {} 'Capture target size differs'
Invoke-Case 'Capture journal role refused' {
    Use-FailedNativeVolumeInfo; $script:captureRecord = New-CaptureRecord; $script:captureRecord.target.role = 'journal'
} {} 'target role'
Invoke-Case 'Capture serial availability inconsistency refused' {
    Use-FailedNativeVolumeInfo; $script:captureRecord = New-CaptureRecord; $script:captureRecord.target.serialNumberAvailable = $true
} {} 'serial availability is inconsistent'
foreach ($geometryField in @('logicalSectorSize','allocationUnitSize')) {
    Invoke-Case "Capture $geometryField disagreement refused" {
        Use-FailedNativeVolumeInfo; $script:captureRecord = New-CaptureRecord; $script:captureRecord.$geometryField *= 2
    } {} 'Capture geometry differs'
}
Invoke-Case 'Capture physical alignment disagreement refused' {
    Use-FailedNativeVolumeInfo; $script:captureRecord = New-CaptureRecord; $script:captureRecord.ioBufferAlignment = 512
} {} 'alignment geometry is invalid'
Invoke-Case 'Capture partition outside target refused' {
    Use-FailedNativeVolumeInfo; $script:captureRecord = New-CaptureRecord; $script:captureRecord.partitionOffset = 64GB
} {} 'partition bounds or alignment'
Invoke-Case 'Capture partition offset misalignment refused' {
    Use-FailedNativeVolumeInfo; $script:captureRecord = New-CaptureRecord; $script:captureRecord.partitionOffset += 1
} {} 'partition bounds or alignment'
Invoke-Case 'Inconsistent inspector volume geometry refused' {
    Use-FailedNativeVolumeInfo; $script:captureRecord = New-CaptureRecord; $script:inspection.filesystem.details.geometry.volume_size -= 1
} {} 'Capture geometry differs'
Invoke-Case 'Capture proof cannot override successful conflicting native filesystem' {
    $script:captureRecord = New-CaptureRecord; $script:native.nativeCommandResults.volumeInfo.output = 'File System Name : ReFS'
} {} 'unambiguous English NTFS'
Invoke-Case 'Capture proof cannot override failed conflicting native filesystem observation' {
    Use-FailedNativeVolumeInfo; $script:captureRecord = New-CaptureRecord; $script:native.nativeCommandResults.volumeInfo.output = 'File System Name : ReFS'
} {} 'conflicting filesystem observation'
Invoke-Case 'Capture proof cannot override structured filesystem disagreement' {
    Use-FailedNativeVolumeInfo; $script:captureRecord = New-CaptureRecord
    $script:native | Add-Member -NotePropertyName fileSystem -NotePropertyValue 'ReFS'
} {} 'Structured native filesystem disagrees'
Invoke-Case 'Structured native cluster geometry mismatch refused' {
    Use-FailedNativeVolumeInfo
    $script:native | Add-Member -NotePropertyName fileSystem -NotePropertyValue 'NTFS'
    $script:native | Add-Member -NotePropertyName allocationUnitSize -NotePropertyValue 65536
} {} 'Structured native allocation unit differs'

Reset-Fixtures
$source = Join-Path $testRoot 'overwrite-inspection.json'; $nativeSource = Join-Path $testRoot 'overwrite-native.json'; $existing = Join-Path $testRoot 'existing.json'
Write-NewJson $source $script:inspection; Write-NewJson $nativeSource $script:native; Write-NewJson $existing ([pscustomobject]@{ preserve = 'existing output' })
$before = (Get-FileHash -LiteralPath $existing).Hash; $caught = $null
try { & $compareScript -InspectionPath $source -NativeEvidencePath $nativeSource -OutputPath $existing | Out-Null } catch { $caught = $_ }
Assert-Check ($null -ne $caught -and (Get-FileHash -LiteralPath $existing).Hash -ceq $before) 'Existing output was overwritten.'
$script:checks++; 'PASS Existing output uses CreateNew and remains unchanged'
$before = (Get-FileHash -LiteralPath $source).Hash; $caught = $null
try { & $compareScript -InspectionPath $source -NativeEvidencePath $nativeSource -OutputPath $source | Out-Null } catch { $caught = $_ }
Assert-Check ($null -ne $caught -and (Get-FileHash -LiteralPath $source).Hash -ceq $before) 'Input path was overwritten as output.'
$script:checks++; 'PASS Input cannot be reused as output'
$directoryInput = Join-Path $testRoot 'directory.json'; [void][IO.Directory]::CreateDirectory($directoryInput)
$caught = $null
try { & $compareScript -InspectionPath $directoryInput -NativeEvidencePath $nativeSource -OutputPath (Join-Path $testRoot 'refused-directory.json') | Out-Null } catch { $caught = $_ }
Assert-Check ($null -ne $caught -and $caught.Exception.Message -match 'regular file') 'Directory input was accepted.'
$script:checks++; 'PASS Directory input refused'
foreach ($invalidPath in @('C:\not-opened.raw', '\\.\PhysicalDrive0', '\\?\C:\not-opened.json', 'C:\not-opened.json:stream')) {
    $caught = $null
    try { & $compareScript -InspectionPath $invalidPath -NativeEvidencePath $nativeSource -OutputPath (Join-Path $testRoot 'refused-path.json') | Out-Null } catch { $caught = $_ }
    Assert-Check ($null -ne $caught -and $caught.Exception.Message -match 'ordinary local .json') 'Non-JSON/device/ADS path was accepted.'
    $script:checks++
}
$tokens = $null; $parseErrors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($compareScript, [ref]$tokens, [ref]$parseErrors)
Assert-Check ($parseErrors.Count -eq 0) 'Comparison script parser errors.'
$forbidden = @($ast.FindAll({ param($node) $node -is [Management.Automation.Language.CommandAst] -and $node.GetCommandName() -in @('Get-Disk', 'Get-Volume', 'Get-VM', 'Invoke-Command', 'Start-Process', 'Add-Type', 'Set-Content', 'Remove-Item') }, $true))
Assert-Check ($forbidden.Count -eq 0) 'Comparison script gained an image, provider, overwrite or external command.'
$script:checks++
"Passed $script:checks NTFS stream comparison checks. Only synthetic local JSON files were read or created."
