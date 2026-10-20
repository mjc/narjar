param([Parameter(Mandatory)][string]$Executable, [Parameter(Mandatory)][string]$Root)
$ErrorActionPreference = 'Stop'

# Use only the installed Windows runtime while exercising the copied executable.
$env:PATH = "$env:SystemRoot\System32;$env:SystemRoot"

function Invoke-Narjar {
    param([Parameter(ValueFromRemainingArguments)][string[]]$Arguments)
    & $Executable @Arguments
    if ($LASTEXITCODE -ne 0) { throw "narjar $($Arguments[0]) failed: $LASTEXITCODE" }
}

$cache = Join-Path $Root 'application cache é'
Invoke-Narjar --version
Invoke-Narjar --help | Out-Null
Invoke-Narjar init --data-dir $cache
Invoke-Narjar doctor --data-dir $cache --json
Invoke-Narjar init --data-dir $cache

$token = Invoke-Narjar token create --data-dir $cache --scope write --name smoke
if ($token -notmatch '^[0-9a-f]{64}$') { throw 'Token creation did not return a 32-byte secret' }
$stored = Get-Content (Join-Path $cache 'auth/write.tokens') -Raw
if ($stored.Contains($token)) { throw 'Token file contains the plaintext token' }
Invoke-Narjar token revoke --data-dir $cache --scope write --name smoke

$setupCache = Join-Path $Root 'setup cache é'
$credentials = Join-Path $Root 'setup credentials é'
Invoke-Narjar setup --yes --data-dir $setupCache --credentials-dir $credentials --private-read | Out-Null
Invoke-Narjar doctor --data-dir $setupCache --json
foreach ($file in 'producer.sec', 'producer.pub', 'read.token', 'write.token', 'narjar.netrc') {
    if (-not (Test-Path (Join-Path $credentials $file) -PathType Leaf)) {
        throw "Setup did not create $file"
    }
}
Write-Output 'Native application lifecycle succeeded without administrator rights or developer tools on PATH'
