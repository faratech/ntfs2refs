<# Reads an offline Windows volume (mounted in the control OS) and reports the
   things that would stop it booting after an in-place change of file system.
   It writes nothing to the source: registry hives are copied out and the
   copies are loaded. Output is one JSON object on stdout.

   -SourceLetter  drive letter of the offline Windows volume, for example D #>
param([Parameter(Mandatory)][string]$SourceLetter)
$ErrorActionPreference = 'Stop'; Set-StrictMode -Version Latest
$root = "${SourceLetter}:\"
$findings = [System.Collections.Generic.List[string]]::new()
$result = [ordered]@{ source = $root; findings = $findings }

# A hibernated or fast-startup session would be resumed against a volume
# whose file system it no longer describes.
$hiber = Join-Path $root 'hiberfil.sys'
if (Test-Path -LiteralPath $hiber) {
    $stream = [IO.File]::Open($hiber, 'Open', 'Read', 'ReadWrite')
    try { $head = [byte[]]::new(4); $null = $stream.Read($head, 0, 4) } finally { $stream.Dispose() }
    $signature = [Text.Encoding]::ASCII.GetString($head)
    $result.hiberfil = [ordered]@{ bytes = (Get-Item -LiteralPath $hiber -Force).Length; signature = ($head | ForEach-Object { '{0:x2}' -f $_ }) -join '' }
    if ($signature -match '^(HIBR|hibr|WAKE|wake)$') { $findings.Add("hiberfil.sys holds a resumable session (signature $signature)") }
} else { $result.hiberfil = $null }

foreach ($name in 'pagefile.sys', 'swapfile.sys') {
    $path = Join-Path $root $name
    $result[$name] = if (Test-Path -LiteralPath $path) { (Get-Item -LiteralPath $path -Force).Length } else { $null }
}

# Boot-start and system-start drivers named through an 8.3 path depend on the
# short-name links existing before the file system that provides them is up.
$copy = Join-Path $env:TEMP ("n2r-system-{0}.hiv" -f [guid]::NewGuid().ToString('N'))
Copy-Item -LiteralPath (Join-Path $root 'Windows\System32\config\SYSTEM') -Destination $copy
$mount = 'N2R_SOURCE_SYSTEM'
$null = & reg.exe load "HKLM\$mount" $copy 2>&1
try {
    $select = Get-ItemProperty -LiteralPath "HKLM:\$mount\Select"
    $control = 'ControlSet{0:D3}' -f $select.Current
    $result.control_set = $control
    $early = foreach ($service in Get-ChildItem -LiteralPath "HKLM:\$mount\$control\Services") {
        $properties = Get-ItemProperty -LiteralPath $service.PSPath
        if ($properties.PSObject.Properties['Start'] -and $properties.Start -le 1 -and $properties.PSObject.Properties['ImagePath']) {
            [pscustomobject]@{ name = $service.PSChildName; start = $properties.Start; image = [string]$properties.ImagePath }
        }
    }
    $result.early_drivers = @($early).Count
    $short = @($early | Where-Object { $_.image -match '~\d' })
    $result.early_drivers_with_short_paths = @($short | ForEach-Object { "$($_.name): $($_.image)" })
    if ($short.Count) { $findings.Add("$($short.Count) boot/system-start drivers are named through 8.3 paths") }
    $file_systems = @($early | Where-Object { $_.name -match '^(refs|refsv1|ntfs|fastfat|wof|fileinfo|bindflt|wcifs|cldflt)$' } | ForEach-Object { "$($_.name)=$($_.start)" })
    $result.file_system_drivers = $file_systems
    if (-not ($early | Where-Object name -EQ 'refs')) { $findings.Add('the ReFS driver is not a boot-start driver in this installation') }
    $session = Get-ItemProperty -LiteralPath "HKLM:\$mount\$control\Control\Session Manager"
    $result.boot_execute = @($session.BootExecute)
    $power = Get-ItemProperty -LiteralPath "HKLM:\$mount\$control\Control\Session Manager\Power" -ErrorAction SilentlyContinue
    $result.fast_startup = if ($power -and $power.PSObject.Properties['HiberbootEnabled']) { $power.HiberbootEnabled } else { $null }
} finally {
    [GC]::Collect(); [GC]::WaitForPendingFinalizers()
    $null = & reg.exe unload "HKLM\$mount" 2>&1
    Remove-Item -LiteralPath $copy -Force -ErrorAction SilentlyContinue
    Get-ChildItem -LiteralPath $env:TEMP -Filter ((Split-Path -Leaf $copy) + '*') -Force -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
}

$result.ready = ($findings.Count -eq 0)
$result | ConvertTo-Json -Depth 6
