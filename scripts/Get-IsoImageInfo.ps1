<# Read WIM metadata through binary stdout without mounting/extracting the ISO.
WIM layout: https://github.com/ebiggers/wimlib/blob/master/include/wimlib/header.h #>
[CmdletBinding()]
param([Parameter(Mandatory)][string]$IsoPath, [switch]$PassThru)
$ErrorActionPreference = 'Stop'
$iso = Get-Item -LiteralPath $IsoPath
if ($iso.Extension -ne '.iso' -or $iso.PSIsContainer -or $iso.FullName.Contains('"')) { throw 'A completed local ISO is required.' }
$sevenZip = @('C:\Program Files\7-Zip\7z.exe','C:\Program Files (x86)\7-Zip\7z.exe') | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
if (-not $sevenZip) { throw '7-Zip is required for unprivileged ISO inspection.' }
$listing = & $sevenZip l '-slt' '--' $iso.FullName 'sources\install.wim' 'sources\install.esd' 2>&1
if ($LASTEXITCODE -ne 0) { throw '7-Zip could not read the ISO.' }
$imagePath = if (@($listing | Where-Object { $_ -eq 'Path = sources\install.wim' }).Count) { 'sources\install.wim' } elseif (@($listing | Where-Object { $_ -eq 'Path = sources\install.esd' }).Count) { 'sources\install.esd' } else { throw 'No single install.wim/install.esd found.' }
$start = New-Object Diagnostics.ProcessStartInfo
$start.FileName = $sevenZip
$start.Arguments = 'e -so -bd -bb0 -- "' + $iso.FullName + '" "' + $imagePath + '"'
$start.UseShellExecute = $false
$start.CreateNoWindow = $true
$start.RedirectStandardOutput = $true
$start.RedirectStandardError = $true
$process = New-Object Diagnostics.Process
$process.StartInfo = $start
$started = $false
function Read-ExactBytes([IO.Stream]$Stream, [byte[]]$Buffer, [int]$Count) {
    $read = 0
    while ($read -lt $Count) {
        $n = $Stream.Read($Buffer, $read, $Count - $read)
        if ($n -eq 0) { throw 'Unexpected end of WIM stream.' }
        $read += $n
    }
}
try {
    $started = $process.Start()
    $errors = $process.StandardError.ReadToEndAsync()
    $stream = $process.StandardOutput.BaseStream
    $header = New-Object byte[] 208
    Read-ExactBytes $stream $header 208
    if ([Text.Encoding]::ASCII.GetString($header,0,8) -ne "MSWIM`0`0`0" -or [BitConverter]::ToUInt32($header,8) -ne 208) { throw 'Unexpected WIM header.' }
    if ([BitConverter]::ToUInt16($header,42) -ne 1) { throw 'Split WIMs are not supported.' }
    $resourceSize = [BitConverter]::ToUInt64($header,72) -band [uint64]72057594037927935
    $resourceOffset = [BitConverter]::ToUInt64($header,80)
    if (($header[79] -band 20) -or $resourceSize -ne [BitConverter]::ToUInt64($header,88)) { throw 'Compressed WIM XML requires a full WIM reader.' }
    if ($resourceSize -lt 2 -or $resourceSize -gt 16777216 -or $resourceOffset -lt 208 -or $resourceOffset -gt [uint64]$iso.Length -or $resourceSize -gt ([uint64]$iso.Length - $resourceOffset)) { throw 'Invalid WIM XML bounds.' }
    $buffer = New-Object byte[] 1048576
    $remaining = [int64]$resourceOffset - 208
    while ($remaining -gt 0) {
        $count = [int][Math]::Min($remaining, $buffer.Length)
        Read-ExactBytes $stream $buffer $count
        $remaining -= $count
    }
    $xmlBytes = New-Object byte[] ([int]$resourceSize)
    Read-ExactBytes $stream $xmlBytes $xmlBytes.Length
    $settings = New-Object Xml.XmlReaderSettings
    $settings.DtdProcessing = [Xml.DtdProcessing]::Prohibit
    $settings.XmlResolver = $null
    $xmlStream = New-Object IO.MemoryStream(,$xmlBytes)
    $reader = $null
    try {
        $reader = [Xml.XmlReader]::Create($xmlStream, $settings)
        $xml = New-Object Xml.XmlDocument
        $xml.XmlResolver = $null
        $xml.Load($reader)
        $images = @($xml.WIM.IMAGE | ForEach-Object {
            [pscustomobject]@{ index = [int]$_.INDEX; name = [string]$_.NAME; edition = [string]$_.WINDOWS.EDITIONID; installationType = [string]$_.WINDOWS.INSTALLATIONTYPE; architecture = [string]$_.WINDOWS.ARCH; version = "$($_.WINDOWS.VERSION.MAJOR).$($_.WINDOWS.VERSION.MINOR).$($_.WINDOWS.VERSION.BUILD).$($_.WINDOWS.VERSION.SPBUILD)" }
        })
    } finally { if ($reader) { $reader.Dispose() }; $xmlStream.Dispose() }
    $result = [pscustomobject]@{ schemaVersion = 1; isoPath = $iso.FullName; imagePath = $imagePath; images = $images }
    if ($PassThru) { $result } else { $result | ConvertTo-Json -Depth 5 }
} finally {
    if ($started -and -not $process.HasExited) { $process.Kill(); $process.WaitForExit() }
    $process.Dispose()
}
