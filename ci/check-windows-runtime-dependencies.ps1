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

# API contracts need not have matching files. Other imports are Windows DLLs
# or the documented Microsoft Visual C++ runtime, never build-directory DLLs.
# LAN discovery enumerates network interfaces through Windows IP Helper.
$systemLibraries = @('kernel32.dll', 'advapi32.dll', 'ws2_32.dll', 'ntdll.dll', 'bcryptprimitives.dll', 'bcrypt.dll', 'iphlpapi.dll')
$vcRuntime = @('vcruntime140.dll', 'vcruntime140_1.dll')
foreach ($library in $imports) {
    if ($library -match '^(api-ms-win-|ext-ms-win-)[a-z0-9-]+\.dll$') {
        continue
    }
    if ($library -notin $systemLibraries -and $library -notin $vcRuntime) {
        throw "Undeclared runtime DLL: $library"
    }
    if (-not (Test-Path (Join-Path "$env:SystemRoot/System32" $library) -PathType Leaf)) {
        throw "Runtime DLL is not installed: $library"
    }
}
