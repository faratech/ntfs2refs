<# Build an isolated research program against, without modifying, the pinned
   GPL engine checkout under ignored .lab. No Cargo/product integration. #>
[CmdletBinding()]
param([string]$VsDevCmd='C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\Common7\Tools\VsDevCmd.bat')
Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
$root=Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$engine=Join-Path $root '.lab/research/refsnt';$pin='bdde6875b47a7370f5f98dd1d6b1a3e19278ca2a'
$actual=(& git -C $engine rev-parse HEAD).Trim();if($LASTEXITCODE-or$actual-cne$pin){throw 'Pinned external engine revision required.'}
$changed=@(& git -C $engine status --porcelain);if($LASTEXITCODE-or$changed.Count){throw 'External engine checkout must remain unmodified.'}
if(-not(Test-Path -LiteralPath $VsDevCmd)){throw 'MSVC environment script unavailable.'}
$output=Join-Path $root ('.lab/research/refsnt-strict-'+[DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ'))
New-Item -ItemType Directory -Path $output|Out-Null
$relative=@('src/rfssup.c','src/rfsupcase.c','src/rfsvol.c','src/rfstree.c','src/rfsfile.c','src/rfsv1.c','src/rfsalloc.c','src/rfswrite.c','src/rfscommit.c','src/rfsops.c','src/rfsshim.c','fmt/rfsmk1.c')
$sources=@($relative|ForEach-Object {Join-Path $engine $_})+@((Join-Path $PSScriptRoot 'strict_image.c'),(Join-Path $PSScriptRoot 'adopt_existing.c'))
$compat=Join-Path $PSScriptRoot 'msvc-compat.h';$executable=Join-Path $output 'adopt-existing.exe'
foreach($path in @($sources)+@($compat,$VsDevCmd,$output)){if($path-match'["\r\n&|<>^%!]'){throw 'Build paths contain unsupported command-shell characters.'}}
$contract=Join-Path $output 'backend-contract.exe'
$command=@('@echo off',('call "'+$VsDevCmd+'" -arch=x64 -host_arch=x64 >nul'),'if errorlevel 1 exit /b %errorlevel%',
 ('cl /nologo /O2 /W4 /TC /D_CRT_SECURE_NO_WARNINGS /FI"'+$compat+'" /I"'+(Join-Path $engine 'src')+'" /I"'+(Join-Path $engine 'fmt')+'" '+(($sources|ForEach-Object {'"'+$_+'"'})-join' ')+' /Fe:"'+$executable+'" /link bcrypt.lib'),
 'if errorlevel 1 exit /b %errorlevel%',
 ('cl /nologo /O2 /W4 /TC /D_CRT_SECURE_NO_WARNINGS "'+(Join-Path $PSScriptRoot 'strict_image.c')+'" "'+(Join-Path $PSScriptRoot 'backend_contract.c')+'" /Fe:"'+$contract+'" /link bcrypt.lib'))
$script=Join-Path $output 'build.cmd';[IO.File]::WriteAllLines($script,$command,[Text.ASCIIEncoding]::new())
Push-Location $output
try{& cmd.exe /d /c $script 2>&1|Tee-Object -FilePath (Join-Path $output 'build.log');$code=$LASTEXITCODE}finally{Pop-Location}
if($code){throw ('Strict research build failed: '+$code)}
$manifest=[ordered]@{schemaVersion=1;kind='isolated-refsnt-strict-build';upstreamRepository='https://github.com/ages2001/REFSNT';upstreamCommit=$pin;upstreamLicense='GPL-3.0';productIntegration=$false;executable=$executable;executableSha256=(Get-FileHash -LiteralPath $executable).Hash.ToLowerInvariant();contractExecutable=$contract;contractExecutableSha256=(Get-FileHash -LiteralPath $contract).Hash.ToLowerInvariant();sources=@(($sources+@((Join-Path $PSScriptRoot 'strict_image.h'),(Join-Path $PSScriptRoot 'backend_contract.c'),$compat))|ForEach-Object {[ordered]@{path=$_;sha256=(Get-FileHash -LiteralPath $_).Hash.ToLowerInvariant()}});builtUtc=[DateTime]::UtcNow.ToString('o')}
$manifest|ConvertTo-Json -Depth 8|Set-Content -LiteralPath (Join-Path $output 'provenance.json') -Encoding utf8
[pscustomobject]@{buildDirectory=$output;executable=$executable;sha256=$manifest.executableSha256}
