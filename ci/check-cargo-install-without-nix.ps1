param([string]$Version = '')
$ErrorActionPreference = 'Stop'
Set-Location (Join-Path $PSScriptRoot '..')

if (Get-Command nix -ErrorAction SilentlyContinue) {
    throw 'This installation check requires a host without Nix'
}
$metadata = cargo metadata --locked --no-deps --format-version 1 | ConvertFrom-Json
if ($LASTEXITCODE -ne 0) { throw 'Cargo metadata failed' }
$package = @($metadata.packages | Where-Object name -eq narjar)
if ($package.Count -ne 1) { throw 'Expected one Narjar package' }
$expectedVersion = $package[0].version
$installRoot = Join-Path $PWD 'target/cargo-install'
$buildRoot = Join-Path $PWD 'target/cargo-install-build'
$options = @('--locked', '--root', $installRoot, '--target-dir', $buildRoot)

if ($Version) {
    if ($Version -ne $expectedVersion) { throw 'Requested and packaged versions differ' }
    cargo install @options --registry crates-io --version "=$Version" narjar
} else {
    cargo package --locked --no-verify --package narjar
    if ($LASTEXITCODE -ne 0) { throw 'Cargo packaging failed' }
    $archive = "target/package/narjar-$expectedVersion.crate"
    tar -xzf $archive -C target/package
    if ($LASTEXITCODE -ne 0) { throw 'Cargo archive extraction failed' }
    cargo install @options --path "target/package/narjar-$expectedVersion"
}
if ($LASTEXITCODE -ne 0) { throw 'Cargo installation failed' }

$executable = Join-Path $installRoot 'bin/narjar.exe'
$versionOutput = & $executable --version
if ($LASTEXITCODE -ne 0 -or $versionOutput -ne "narjar $expectedVersion") {
    throw 'Installed executable has the wrong version'
}
& (Join-Path $PSScriptRoot 'check-windows-filesystem.ps1') -NarjarExecutable $executable -Fixture installed
