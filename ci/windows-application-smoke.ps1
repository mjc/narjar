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

$setupCache = Join-Path $Root "setup cache é's‘’‚‛;Write-Output injected;#"
$credentials = Join-Path $Root "setup credentials é's"
$summary = Invoke-Narjar setup --yes --data-dir $setupCache --credentials-dir $credentials --private-read | Out-String
$lines = $summary -split '\r?\n'
$serveCommand = ($lines | Where-Object { $_.StartsWith('start the cache: ') }).Substring('start the cache: '.Length)
$printedData = ($lines | Where-Object { $_.StartsWith('data directory: ') }).Substring('data directory: '.Length)
$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseInput($serveCommand, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count -ne 0) { throw "Setup printed an invalid PowerShell command: $serveCommand" }
$command = $ast.Find({ param($node) $node -is [System.Management.Automation.Language.CommandAst] }, $false)
$commandCount = $ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.CommandAst] }, $true).Count
if ($commandCount -ne 1 -or
    $command.CommandElements.Count -ne 8 -or $command.CommandElements[3].Value -ne $printedData) {
    $diagnostic = @{
        command = $serveCommand
        commandCount = $commandCount
        elements = @($command.CommandElements | ForEach-Object { $_.Extent.Text })
        expectedPath = $printedData
        actualPath = $command.CommandElements[3].Value
    } | ConvertTo-Json -Compress
    throw "Setup command did not preserve its literal argument: $diagnostic"
}
Invoke-Narjar doctor --data-dir $setupCache --json
foreach ($file in 'producer.sec', 'producer.pub', 'read.token', 'write.token', 'narjar.netrc') {
    if (-not (Test-Path (Join-Path $credentials $file) -PathType Leaf)) {
        throw "Setup did not create $file"
    }
}
Write-Output 'Native application lifecycle succeeded without administrator rights or developer tools on PATH'

$tests = Join-Path $Root 'application-tests.exe'
if (Test-Path $tests -PathType Leaf) {
    $env:NARJAR_TEST_EXECUTABLE = $Executable
    $env:TEMP = Join-Path $Root 'test-temporary-files'
    $env:TMP = $env:TEMP
    New-Item -ItemType Directory -Path $env:TEMP -Force | Out-Null
    foreach ($test in @(
        'nix_cache_info_get_and_head_match_contract',
        'nar_get_supports_ranges_and_head_ignores_them',
        'xz_narinfo_is_published_as_the_canonical_raw_pair',
        'zstd_narinfo_is_published_as_the_canonical_raw_pair',
        'configured_compressed_egress_is_independent_of_ingress_encoding',
        'online_gc_uses_the_running_flat_daemon_without_interrupting_cache_reads',
        'gc_deletes_a_shared_nar_only_after_the_last_narinfo',
        'interrupted_gc_deletion_is_recovered_before_serving_shared_payloads'
    )) {
        $name = "cli_tests::$test"
        $listed = & $tests --list --exact $name
        if ($LASTEXITCODE -ne 0 -or "$name`: test" -notin $listed) {
            throw "Missing standard-account acceptance test: $name"
        }
        & $tests --exact $name --nocapture
        if ($LASTEXITCODE -ne 0) { throw "Standard-account acceptance failed: $name" }
    }
}
