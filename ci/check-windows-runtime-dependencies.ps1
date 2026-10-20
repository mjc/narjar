param([Parameter(Mandatory)][string]$Executable)
$ErrorActionPreference = 'Stop'

$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio/Installer/vswhere.exe'
$installation = & $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if ($LASTEXITCODE -ne 0 -or -not $installation) { throw 'Missing MSVC inspection tools' }
$dumpbin = Get-ChildItem "$installation/VC/Tools/MSVC/*/bin/Hostx64/x64/dumpbin.exe" |
    Sort-Object FullName | Select-Object -Last 1
if (-not $dumpbin) { throw 'Missing dumpbin.exe' }
$report = & $dumpbin.FullName /dependents $Executable
if ($LASTEXITCODE -ne 0) { throw 'PE import inspection failed' }
$report | Tee-Object -FilePath 'target/cargo-install-linkage.txt'
$imports = @($report | ForEach-Object {
    if ($_ -match '^\s+([^\s]+\.dll)\s*$') { $Matches[1] }
})
if ($imports.Count -eq 0) { throw 'PE import inspection found no runtime libraries' }

# Windows API contracts need not have a matching on-disk DLL. Other imports
# must resolve from Windows itself, not the compiler or the build directory.
foreach ($library in $imports) {
    if ($library -notmatch '^(api-ms-win-|ext-ms-win-)' -and
        -not (Test-Path (Join-Path "$env:SystemRoot/System32" $library) -PathType Leaf)) {
        throw "Installed executable requires an extra runtime DLL: $library"
    }
    if ($library -match '(sqlite|libssl|libcrypto|libgcc|libstdc\+\+)') {
        throw "Unexpected application runtime dependency: $library"
    }
}
