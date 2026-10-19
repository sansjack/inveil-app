# Tests for install.ps1 against local fixture releases. No network, no Pester.
# A stand-in for inveil.exe records every execution in FAKE_MARKER, so the tests can prove that nothing from the
# download directory runs before the signed manifest has been verified.
# Needs an OpenSSL 3 that verifies Ed25519 (Git for Windows ships one), the same requirement as the installer.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$isWindowsHost = $env:OS -eq 'Windows_NT'
$installer = Join-Path $PSScriptRoot 'install.ps1'
$powershell = (Get-Process -Id $PID).Path
$root = Join-Path ([IO.Path]::GetTempPath()) "inveil-install-test-$([guid]::NewGuid().ToString('N'))"
New-Item -ItemType Directory -Path $root | Out-Null
$script:failures = 0

function Assert-Test([string]$Name, [bool]$Condition) {
    if ($Condition) {
        Write-Output "ok   $Name"
    } else {
        Write-Output "FAIL $Name"
        $script:failures++
    }
}

function Find-TestOpenSsl {
    $candidates = @($env:INVEIL_OPENSSL, '/opt/homebrew/opt/openssl@3/bin/openssl', 'openssl', 'openssl.exe',
        (Join-Path $env:ProgramFiles 'Git\usr\bin\openssl.exe'))
    foreach ($candidate in $candidates) {
        if (-not $candidate) { continue }
        $command = Get-Command $candidate -ErrorAction SilentlyContinue
        if ($command -and ((& $command.Source version) -match '^OpenSSL [3-9]')) { return $command.Source }
    }
    throw 'install.test.ps1 needs OpenSSL 3 (set INVEIL_OPENSSL)'
}

function ConvertTo-FileUrl([string]$Path) {
    return ([Uri]('file:///' + $Path.TrimStart('/').Replace('\', '/'))).AbsoluteUri
}

function Invoke-Installer([string[]]$Arguments, [hashtable]$Environment = @{}) {
    $saved = @{}
    foreach ($name in $Environment.Keys) {
        $saved[$name] = [Environment]::GetEnvironmentVariable($name)
        [Environment]::SetEnvironmentVariable($name, $Environment[$name])
    }
    try {
        $output = & $powershell -NoProfile -ExecutionPolicy Bypass -File $installer @Arguments 2>&1 | Out-String
        return [pscustomobject]@{ ExitCode = $LASTEXITCODE; Output = $output }
    } finally {
        foreach ($name in $saved.Keys) { [Environment]::SetEnvironmentVariable($name, $saved[$name]) }
    }
}

function Add-TestKey([string]$Name) {
    $pem = Join-Path $root "$Name.pem"
    & $openSsl genpkey -algorithm ed25519 -out $pem 2>$null
    $der = Join-Path $root "$Name.der"
    & $openSsl pkey -in $pem -pubout -outform DER -out $der 2>$null
    $bytes = [IO.File]::ReadAllBytes($der)
    $script:publicKeys[$Name] = [Convert]::ToBase64String($bytes[($bytes.Length - 32)..($bytes.Length - 1)])
}

function Get-Signature([string]$KeyName, [byte[]]$Message) {
    $messagePath = Join-Path $root 'message'
    $signaturePath = Join-Path $root 'signature'
    [IO.File]::WriteAllBytes($messagePath, $Message)
    & $openSsl pkeyutl -sign -rawin -inkey (Join-Path $root "$KeyName.pem") -in $messagePath -out $signaturePath
    return [Convert]::ToBase64String([IO.File]::ReadAllBytes($signaturePath))
}

function Add-Release {
    param([string]$Directory, [string]$Version, [string]$ManifestChannel = 'stable', [int64]$ExpiresAt = 4102444800,
        [int]$Threshold = 2, [string[]]$Signers = @('alpha=alpha', 'beta=beta'), [string]$SignedPayload = '')
    New-Item -ItemType Directory -Path $Directory -Force | Out-Null
    $binaryPath = Join-Path $Directory $binaryName
    Copy-Item $fakeExe $binaryPath
    [IO.File]::AppendAllText($binaryPath, "`n# build $Version")
    $payload = @{
        schema = 1; channel = $ManifestChannel; version = $Version; published_at = 1; expires_at = $ExpiresAt
        threshold = $Threshold
        artifacts = @{ $targetName = @{
            url = "https://example.invalid/$binaryName"
            sha256 = (Get-FileHash -Algorithm SHA256 $binaryPath).Hash.ToLowerInvariant()
            size = (Get-Item $binaryPath).Length } }
    } | ConvertTo-Json -Depth 5
    $payload += "`n"
    $signedText = if ($SignedPayload) { $SignedPayload } else { $payload }
    $message = [byte[]]([Text.Encoding]::ASCII.GetBytes("inveil-update-v1`0") + [Text.Encoding]::UTF8.GetBytes($signedText))
    $signatures = @()
    foreach ($signer in $Signers) {
        $keyId, $keyName = $signer -split '=', 2
        $signatures += @{ key_id = $keyId; signature = (Get-Signature $keyName $message) }
    }
    $envelope = @{ payload = $payload; signatures = $signatures } | ConvertTo-Json -Depth 5
    [IO.File]::WriteAllText((Join-Path $Directory 'update-manifest.json.sig'), $envelope, (New-Object Text.UTF8Encoding $false))
}

function Test-Rejected([string]$Name, [string]$Message, [string]$Directory, [string[]]$Arguments = @()) {
    Clear-Content $env:FAKE_MARKER
    $installDir = Join-Path $root "rejected-$([guid]::NewGuid().ToString('N'))\bin"
    $result = Invoke-Installer $Arguments @{ INVEIL_INSTALL_BASE_URL = (ConvertTo-FileUrl $Directory); INVEIL_INSTALL_DIR = $installDir }
    $executedFromDownload = (Get-Content $env:FAKE_MARKER -Raw) -match 'inveil-install-'
    Assert-Test $Name (
        $result.ExitCode -ne 0 -and $result.Output -match [regex]::Escape($Message) -and
        -not (Test-Path (Join-Path $installDir 'inveil.exe')) -and -not $executedFromDownload)
}

try {
    $openSsl = Find-TestOpenSsl
    $env:INVEIL_OPENSSL = $openSsl
    $architecture = if ($env:PROCESSOR_ARCHITEW6432) { $env:PROCESSOR_ARCHITEW6432 } else { $env:PROCESSOR_ARCHITECTURE }
    $arch = if ($architecture -eq 'ARM64') { 'aarch64' } else { 'x86_64' }
    $targetName = "windows-$arch"
    $binaryName = "inveil-$targetName.exe"

    $script:publicKeys = @{}
    foreach ($name in 'alpha', 'beta', 'gamma', 'mallory') { Add-TestKey $name }
    $keysTwo = "alpha=$($publicKeys['alpha']) beta=$($publicKeys['beta'])"

    $fakeExe = Join-Path $root 'fake-inveil.exe'
    if ($isWindowsHost) {
        $source = @'
using System;
using System.IO;
public static class FakeInveil {
    public static int Main(string[] args) {
        string marker = Environment.GetEnvironmentVariable("FAKE_MARKER");
        if (marker != null) { File.AppendAllText(marker, Environment.GetCommandLineArgs()[0] + " " + string.Join(" ", args) + "\n"); }
        string log = Environment.GetEnvironmentVariable("FAKE_INVEIL_LOG");
        string version = Environment.GetEnvironmentVariable("FAKE_INVEIL_VERSION") ?? "9.9.9";
        if (args.Length > 0 && args[0] == "--version") { Console.WriteLine("inveil " + version); return 0; }
        if (log != null) {
            File.AppendAllText(log, string.Join(" ", args) + "\n");
            if (args.Length > 2 && args[0] == "enroll" && args[2] == "-") {
                File.AppendAllText(log, "bundle-body " + Console.In.ReadToEnd() + "\n");
            }
        }
        if (args.Length > 0 && args[0] == "verify" && Environment.GetEnvironmentVariable("FAKE_VERIFY_FAIL") == "1") { return 1; }
        return 0;
    }
}
'@
        $sourcePath = Join-Path $root 'fake.cs'
        Set-Content -Path $sourcePath -Value $source
        $csc = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
        & $csc /nologo /out:$fakeExe $sourcePath | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'could not compile the stand-in inveil.exe' }
    } else {
        $shim = @'
#!/bin/sh
echo "$0 $*" >>"${FAKE_MARKER:-/dev/null}"
case "$1" in
  --version) echo "inveil ${FAKE_INVEIL_VERSION:-9.9.9}" ;;
  verify) echo "verify $*" >>"$FAKE_INVEIL_LOG"; [ -z "${FAKE_VERIFY_FAIL:-}" ] || exit 1 ;;
  enroll) echo "enroll $*" >>"$FAKE_INVEIL_LOG"; echo "bundle-body $(cat)" >>"$FAKE_INVEIL_LOG" ;;
  *) echo "$*" >>"$FAKE_INVEIL_LOG" ;;
esac
'@
        [IO.File]::WriteAllText($fakeExe, $shim)
        & chmod +x $fakeExe
    }

    $env:INVEIL_INSTALL_TESTING = '1'
    $env:INVEIL_UPDATE_PUBLIC_KEYS = $keysTwo
    $env:FAKE_MARKER = Join-Path $root 'marker'
    $env:FAKE_INVEIL_LOG = Join-Path $root 'log'
    Set-Content $env:FAKE_MARKER ''
    Set-Content $env:FAKE_INVEIL_LOG ''

    $release = Join-Path $root 'release'
    Add-Release $release '9.9.9'
    $releaseUrl = (ConvertTo-FileUrl $release)
    $env:INVEIL_INSTALL_BASE_URL = $releaseUrl

    $env:INVEIL_INSTALL_DIR = Join-Path $root 'dry\bin'
    $result = Invoke-Installer @('-DryRun')
    Assert-Test 'dry run prints the plan and the key fingerprint without touching disk' (
        $result.ExitCode -eq 0 -and $result.Output -match 'dry-run' -and $result.Output -match 'sha256:' -and -not (Test-Path $env:INVEIL_INSTALL_DIR))
    $rawHash = [BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash([Convert]::FromBase64String($publicKeys['alpha']))).Replace('-', '').ToLowerInvariant()
    Assert-Test 'prints the sha256 of the raw public key bytes' ($result.Output -match "sha256:$rawHash")

    $installDir = Join-Path $root 'ok\bin'
    $env:INVEIL_INSTALL_DIR = $installDir
    $result = Invoke-Installer @()
    Assert-Test 'installs a release signed by two pinned keys' ($result.ExitCode -eq 0 -and (Test-Path (Join-Path $installDir 'inveil.exe')))
    if ($result.ExitCode -ne 0) { Write-Output $result.Output }
    $log = Get-Content $env:FAKE_INVEIL_LOG -Raw
    Assert-Test 'still runs inveil verify as a second check' ($log -match '--role update' -and $log -match '--pinned-key alpha=' -and $log -match '--artifact')
    $result = Invoke-Installer @()
    Assert-Test 're-running with the same release is a no-op' (
        $result.ExitCode -eq 0 -and $result.Output -match 'already up to date' -and -not (Test-Path (Join-Path $installDir 'inveil.exe.prev')))

    $upgrade = Join-Path $root 'upgrade'
    Add-Release $upgrade '9.9.10'
    $result = Invoke-Installer @() @{ INVEIL_INSTALL_BASE_URL = (ConvertTo-FileUrl $upgrade) }
    Assert-Test 'upgrade keeps inveil.exe.prev' ($result.ExitCode -eq 0 -and (Test-Path (Join-Path $installDir 'inveil.exe.prev')))

    $forged = Join-Path $root 'forged'
    $original = (Get-Content (Join-Path $release 'update-manifest.json.sig') -Raw | ConvertFrom-Json).payload
    Add-Release $forged '9.9.9' -SignedPayload ($original -replace '9\.9\.9', '9.9.8')
    Test-Rejected 'rejects a forged manifest whose signatures cover a different payload' 'valid signature' $forged

    $tampered = Join-Path $root 'tampered'
    Add-Release $tampered '9.9.9'
    [IO.File]::AppendAllText((Join-Path $tampered $binaryName), 'evil')
    Set-Content (Join-Path $tampered 'SHA256SUMS') "$((Get-FileHash -Algorithm SHA256 (Join-Path $tampered $binaryName)).Hash.ToLowerInvariant())  $binaryName"
    Test-Rejected 'rejects a tampered binary even with a matching forged SHA256SUMS' 'mismatch' $tampered

    $single = Join-Path $root 'single'
    Add-Release $single '9.9.9' -Threshold 1 -Signers @('alpha=alpha')
    Test-Rejected 'rejects a single-signature manifest when two are required' '1 valid signature' $single

    $duplicate = Join-Path $root 'duplicate'
    Add-Release $duplicate '9.9.9' -Signers @('alpha=alpha', 'dup=alpha')
    $env:INVEIL_UPDATE_PUBLIC_KEYS = "$keysTwo dup=$($publicKeys['alpha'])"
    Test-Rejected 'counts one public key once even under two key ids' '1 valid signature' $duplicate
    $env:INVEIL_UPDATE_PUBLIC_KEYS = $keysTwo

    $wrongKey = Join-Path $root 'wrong-key'
    Add-Release $wrongKey '9.9.9' -Signers @('alpha=mallory', 'beta=gamma')
    Test-Rejected 'rejects signatures made by keys that are not pinned' 'valid signature' $wrongKey

    $expired = Join-Path $root 'expired'
    Add-Release $expired '9.9.9' -ExpiresAt 1000000000
    Test-Rejected 'rejects an expired manifest' 'expired' $expired

    $wrongChannel = Join-Path $root 'wrong-channel'
    Add-Release $wrongChannel '9.9.9' -ManifestChannel beta
    Test-Rejected 'rejects a manifest for another channel' 'channel' $wrongChannel

    $older = Join-Path $root 'older'
    Add-Release $older '9.0.0'
    $env:INVEIL_INSTALL_DIR = Join-Path $root 'older-install\bin'
    Invoke-Installer @() | Out-Null
    $result = Invoke-Installer @() @{ INVEIL_INSTALL_BASE_URL = (ConvertTo-FileUrl $older) }
    Assert-Test 'refuses a version older than the installed one' ($result.ExitCode -ne 0 -and $result.Output -match 'refusing to downgrade')
    $result = Invoke-Installer @('-Version', '9.0.0') @{ INVEIL_INSTALL_BASE_URL = (ConvertTo-FileUrl $older) }
    Assert-Test 'installs an older version when -Version pins it' ($result.ExitCode -eq 0)
    $result = Invoke-Installer @('-Version', '9.1.0') @{ INVEIL_INSTALL_BASE_URL = (ConvertTo-FileUrl $older) }
    Assert-Test '-Version must match the signed manifest version' ($result.ExitCode -ne 0)

    Test-Rejected 'refuses a manifest older than -MinVersion on a fresh install' 'older than -MinVersion' $older @('-MinVersion', '9.5.0')
    $env:INVEIL_INSTALL_DIR = Join-Path $root 'min-version\bin'
    $result = Invoke-Installer @('-MinVersion', '9.0.0') @{ INVEIL_INSTALL_BASE_URL = (ConvertTo-FileUrl $older) }
    Assert-Test 'accepts a manifest at -MinVersion' ($result.ExitCode -eq 0)

    $result = Invoke-Installer @('-DryRun') @{ INVEIL_INSTALL_TESTING = ''; INVEIL_UPDATE_PUBLIC_KEYS = 'evil=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='; INVEIL_INSTALL_BASE_URL = $releaseUrl }
    Assert-Test 'ignores the testing overrides unless INVEIL_INSTALL_TESTING=1' ($result.ExitCode -ne 0 -and $result.Output -match 'no update public keys are pinned')

    $env:INVEIL_INSTALL_DIR = Join-Path $root 'enroll\bin'
    $token = 'tok_ABC-123_secret'
    $backend = @('-Enroll', '-BackendUrl', 'https://backend.example.com', '-PinnedKey', "policy=$($publicKeys['gamma'])")
    Set-Content $env:FAKE_INVEIL_LOG ''
    $result = Invoke-Installer $backend @{ INVEIL_ENROLL_TOKEN = $token }
    $log = Get-Content $env:FAKE_INVEIL_LOG -Raw
    Assert-Test 'enrolls with the token on standard input, then installs the service' (
        $result.ExitCode -eq 0 -and $log -match 'enroll --bundle -' -and $log -match "`"enrollment_token`":\s*`"$token`"" -and $log -match '(?m)^install')
    $argvLines = (Get-Content $env:FAKE_INVEIL_LOG) | Where-Object { $_ -notlike 'bundle-body*' }
    $bodyLine = (Get-Content $env:FAKE_INVEIL_LOG | Where-Object { $_ -like 'bundle-body *' } | Select-Object -First 1)
    $bundle = ($bodyLine -replace '^bundle-body ', '') | ConvertFrom-Json
    Assert-Test 'the enrollment bundle carries min_signatures >= 2 by default' ([int]$bundle.update.min_signatures -ge 2)
    Assert-Test 'the enrollment bundle carries the signed feed_url (.json.sig)' ("$($bundle.update.feed_url)" -match '^https://.+\.json\.sig$')
    Assert-Test 'the enrollment bundle starts the updater in install mode' ("$($bundle.update.mode)" -eq 'install')
    Assert-Test 'the enrollment bundle still pins the update keys' (@($bundle.update.keys).Count -eq 2)
    Assert-Test 'the token never appears in any argv' (-not ($argvLines -match $token) -and -not ((Get-Content $env:FAKE_MARKER -Raw) -match $token))
    Assert-Test 'the installer never prints the token' (-not ($result.Output -match $token))
    foreach ($case in @(
            @('https://backend.example.com', $true), @('http://localhost', $true), @('http://localhost:8080/base', $true),
            @('http://127.0.0.1:9000', $true), @('http://[::1]:9000', $true),
            @('http://localhost:1@evil.com', $false), @('http://localhost@evil.com/', $false),
            @('http://127.0.0.1:80@evil.com', $false), @('https://user:pass@backend.example.com', $false),
            @('http://localhost.evil.com', $false), @('http://evil.com/localhost', $false),
            @('http://backend.example.com', $false), @('ftp://localhost', $false))) {
        $urlResult = Invoke-Installer @('-Enroll', '-DryRun', '-BackendUrl', $case[0], '-PinnedKey', "policy=$($publicKeys['gamma'])") @{ INVEIL_ENROLL_TOKEN = 'tok' }
        Assert-Test "backend url $($case[0]) is $(if ($case[1]) { 'accepted' } else { 'rejected' })" (($urlResult.ExitCode -eq 0) -eq $case[1])
    }
    $result = Invoke-Installer @('-Enroll')
    Assert-Test '-Enroll needs INVEIL_ENROLL_TOKEN' ($result.ExitCode -ne 0)

    Set-Content $env:FAKE_INVEIL_LOG ''
    $result = Invoke-Installer @('-Enroll', '-NoEnroll') @{ INVEIL_ENROLL_TOKEN = 'tok' }
    Assert-Test '-NoEnroll skips enrollment' ($result.ExitCode -eq 0 -and -not ((Get-Content $env:FAKE_INVEIL_LOG -Raw) -match 'enroll'))

    $result = Invoke-Installer @('-Uninstall')
    Assert-Test '-Uninstall removes the binary' (
        $result.ExitCode -eq 0 -and -not (Test-Path (Join-Path $env:INVEIL_INSTALL_DIR 'inveil.exe')))

    $env:INVEIL_INSTALL_DIR = Join-Path $root 'refuse\bin'
    $result = Invoke-Installer @() @{ INVEIL_INSTALL_BASE_URL = 'http://example.com/releases' }
    Assert-Test 'refuses plain http' ($result.ExitCode -ne 0)
    $result = Invoke-Installer @() @{ INVEIL_UPDATE_PUBLIC_KEYS = '' }
    Assert-Test 'refuses to run without pinned update keys' ($result.ExitCode -ne 0)
    $result = Invoke-Installer $backend @{ INVEIL_ENROLL_TOKEN = 'bad token";' }
    Assert-Test 'rejects a token that could break the bundle JSON' ($result.ExitCode -ne 0)
    $result = Invoke-Installer @('-Channel', 'beta')
    Assert-Test 'beta channel requires -Version' ($result.ExitCode -ne 0)
} finally {
    Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
}

if ($script:failures -gt 0) {
    Write-Output "$script:failures test(s) failed"
    exit 1
}
Write-Output 'all install.ps1 tests passed'
# The last installer call fails on purpose; without this its exit code would become the script's.
exit 0
