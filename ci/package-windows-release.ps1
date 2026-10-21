param([string]$Executable = 'target/cargo-install/bin/narjar.exe')
$ErrorActionPreference = 'Stop'

$metadata = cargo metadata --locked --no-deps --format-version 1 | ConvertFrom-Json
if ($LASTEXITCODE -ne 0) { throw 'Cargo metadata failed' }
$package = @($metadata.packages | Where-Object name -eq narjar)
if ($package.Count -ne 1) { throw 'Expected one Narjar package' }
$version = $package[0].version
$bundleName = "narjar-v$version-x86_64-pc-windows-msvc"
$directory = New-Item -ItemType Directory -Path target/windows-release -Force
$archive = Join-Path $directory "$bundleName.zip"
$timestamp = git show -s --format=%ct HEAD
if ($LASTEXITCODE -ne 0) { throw 'Cannot identify the release timestamp' }
$timestamp = [DateTimeOffset]::FromUnixTimeSeconds([long]$timestamp)
$files = [ordered]@{
    'LICENSE-APACHE' = (Resolve-Path LICENSE-APACHE).Path
    'LICENSE-MIT' = (Resolve-Path LICENSE-MIT).Path
    'README.md' = (Resolve-Path README.md).Path
    'narjar.exe' = (Resolve-Path $Executable).Path
}

$zip = [IO.Compression.ZipFile]::Open($archive, [IO.Compression.ZipArchiveMode]::Create)
try {
    foreach ($file in $files.GetEnumerator()) {
        $entry = [IO.Compression.ZipFileExtensions]::CreateEntryFromFile(
            $zip, $file.Value, "$bundleName/$($file.Key)", [IO.Compression.CompressionLevel]::Optimal
        )
        $entry.LastWriteTime = $timestamp
    }
} finally {
    $zip.Dispose()
}

$extracted = Join-Path $PWD 'target/windows-release-smoke'
Expand-Archive -LiteralPath $archive -DestinationPath $extracted
$installed = Join-Path $extracted "$bundleName/narjar.exe"
if ((Get-FileHash $installed).Hash -ne (Get-FileHash $Executable).Hash) {
    throw 'Archived executable differs from the verified Cargo installation'
}
$versionOutput = & $installed --version
if ($LASTEXITCODE -ne 0 -or $versionOutput -ne "narjar $version") {
    throw 'Archived executable has the wrong version'
}
Get-FileHash $archive -Algorithm SHA256
