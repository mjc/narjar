$ErrorActionPreference = 'Stop'
$probeRoot = Join-Path $env:GITHUB_WORKSPACE 'target/windows-filesystem-probe'
New-Item -ItemType Directory -Path $probeRoot -Force | Out-Null
$executable = Join-Path $probeRoot 'probe.exe'
rustc --edition 2024 ci/windows-filesystem-probe.rs -o $executable
if ($LASTEXITCODE -ne 0) { throw 'Windows filesystem probe compilation failed' }

$accountName = 'NarjarFsProbe'
$password = ConvertTo-SecureString ('Aa9!' + [guid]::NewGuid().ToString('N')) -AsPlainText -Force
$account = New-LocalUser -Name $accountName -Password $password -AccountNeverExpires
try {
    Add-LocalGroupMember -SID 'S-1-5-32-545' -Member $account.SID
    $volume = Get-Volume -FilePath $probeRoot
    Write-Output "Filesystem: $($volume.FileSystemType)"
    if ($volume.FileSystemType -ne 'NTFS') { throw 'Probe requires local NTFS' }
    $acl = Get-Acl $probeRoot
    $rule = [System.Security.AccessControl.FileSystemAccessRule]::new(
        $account.SID, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
    $acl.AddAccessRule($rule)
    Set-Acl -Path $probeRoot -AclObject $acl

    $childScript = Join-Path $probeRoot 'run.ps1'
    @'
param([string]$Root)
$ErrorActionPreference = 'Stop'
$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [System.Security.Principal.WindowsPrincipal]::new($identity)
if ($principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Probe must run without administrator membership'
}
Write-Output "Account: $($identity.Name); SID: $($identity.User); administrator: false"
Write-Output "OS: $([System.Environment]::OSVersion.VersionString)"
& (Join-Path $Root 'probe.exe') $Root
if ($LASTEXITCODE -ne 0) { throw "Filesystem probe failed: $LASTEXITCODE" }
'@ | Set-Content -Path $childScript
    $credential = [System.Management.Automation.PSCredential]::new(
        "$env:COMPUTERNAME\$accountName", $password)
    $stdout = Join-Path $probeRoot 'stdout.log'
    $stderr = Join-Path $probeRoot 'stderr.log'
    $process = Start-Process -FilePath (Join-Path $PSHOME 'pwsh.exe') `
        -Credential $credential -LoadUserProfile -Wait -PassThru `
        -WorkingDirectory $probeRoot `
        -ArgumentList "-NoProfile -File `"$childScript`" -Root `"$probeRoot`"" `
        -RedirectStandardOutput $stdout -RedirectStandardError $stderr
    Get-Content $stdout
    Get-Content $stderr
    if ($process.ExitCode -ne 0) { throw "Standard-account probe failed: $($process.ExitCode)" }
} finally {
    Remove-LocalUser -SID $account.SID
}
