<#
Installs the pinned native Windows MSVC toolchain for the requested runner
architecture. Release workflows and x64 CI use the default.
#>
param(
    [string[]]$Components = @(),
    [ValidateSet('x86_64', 'aarch64')][string]$HostArchitecture = 'x86_64'
)
$ErrorActionPreference = 'Stop'; Set-StrictMode -Version Latest
$pinned = [regex]::Match((Get-Content -Raw -LiteralPath 'rust-toolchain.toml'), '(?m)^channel\s*=\s*"([^"]+)"').Groups[1].Value
if (-not $pinned) { throw 'rust-toolchain.toml names no channel' }
$nativeHost = "$HostArchitecture-pc-windows-msvc"
$toolchain = "$pinned-$nativeHost"
$arguments = @('toolchain', 'install', $toolchain, '--profile', 'minimal')
foreach ($component in $Components) { $arguments += @('--component', $component) }
& rustup @arguments
if ($LASTEXITCODE -ne 0) { throw "rustup toolchain install $toolchain failed ($LASTEXITCODE)" }
& rustup override set $toolchain
if ($LASTEXITCODE -ne 0) { throw "rustup override set $toolchain failed ($LASTEXITCODE)" }
$compiler = @(& rustc -vV)
$compiler
if ($compiler -notcontains "host: $nativeHost") { throw "expected the $nativeHost compiler host" }
if (-not ($compiler | Where-Object { $_ -eq "release: $pinned" })) { throw "rustc is not $pinned" }
"RUSTUP_TOOLCHAIN=$toolchain" | Out-File -FilePath $env:GITHUB_ENV -Append -Encoding utf8
