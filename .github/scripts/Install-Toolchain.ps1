<#
Installs the toolchain rust-toolchain.toml pins, on a hosted Windows runner,
and refuses one that is not the x64 MSVC host. Every workflow starts with it,
so a change of the pinned version is made in one file.
#>
param([string[]]$Components = @())
$ErrorActionPreference = 'Stop'; Set-StrictMode -Version Latest
$pinned = [regex]::Match((Get-Content -Raw -LiteralPath 'rust-toolchain.toml'), '(?m)^channel\s*=\s*"([^"]+)"').Groups[1].Value
if (-not $pinned) { throw 'rust-toolchain.toml names no channel' }
$toolchain = "$pinned-x86_64-pc-windows-msvc"
$arguments = @('toolchain', 'install', $toolchain, '--profile', 'minimal')
foreach ($component in $Components) { $arguments += @('--component', $component) }
& rustup @arguments
if ($LASTEXITCODE -ne 0) { throw "rustup toolchain install $toolchain failed ($LASTEXITCODE)" }
& rustup override set $toolchain
if ($LASTEXITCODE -ne 0) { throw "rustup override set $toolchain failed ($LASTEXITCODE)" }
$compiler = @(& rustc -vV)
$compiler
if ($compiler -notcontains 'host: x86_64-pc-windows-msvc') { throw 'the x64 MSVC host is required' }
if (-not ($compiler | Where-Object { $_ -eq "release: $pinned" })) { throw "rustc is not $pinned" }
"RUSTUP_TOOLCHAIN=$toolchain" | Out-File -FilePath $env:GITHUB_ENV -Append -Encoding utf8
