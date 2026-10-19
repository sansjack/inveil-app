<#
.SYNOPSIS
inveil installer for Windows (per-user, no administrator rights needed).

.DESCRIPTION
Verification order (nothing downloaded is executed until step 4 has passed):
  1. Download the signed manifest (update-manifest.json.sig: payload plus signatures).
  2. Verify each Ed25519 signature over "inveil-update-v1\0" || payload with an OpenSSL 3 binary
     (`openssl pkeyutl -verify -rawin`) against the keys pinned in this script. At least MIN_SIGNATURES distinct
     pinned keys must have signed. Then check expiry, channel and that the version is not older than the installed one.
  3. Download the binary and compare its SHA-256 and size with the signed manifest entry for this machine.
  4. Only now run `inveil verify` from the downloaded binary as a second check, then install.

Limits, stated plainly:
  * Windows PowerShell 5.1 and PowerShell 7 have no built-in Ed25519 verification (System.Security.Cryptography
    offers none; this was checked against the documentation, not on every .NET build), and Windows does not ship
    OpenSSL. The script therefore needs an OpenSSL 3 binary: Git for Windows includes one
    (C:\Program Files\Git\usr\bin\openssl.exe), as does `winget install ShiningLight.OpenSSL.Light`. Every candidate
    is self-tested against an RFC 8032 vector. If none works the script refuses to install; it never falls back to
    executing unverified code.
  * The pinned keys come from this script. If the host that served this script is compromised, so are the keys;
    compare the printed fingerprints (sha256 of the raw 32-byte public key) with the release notes.
  * Revoked key ids in the manifest are not evaluated here; the threshold of distinct keys is the protection.
  * Expiry is checked against the local clock, and an older manifest that has not expired yet is a valid signed
    manifest, so a fresh install (nothing installed to compare with) can be served an older release by whoever
    controls the download path. The installer cannot know the newest release by itself. Pass -MinVersion <x.y.z>
    (the newest version you know of, e.g. from the release notes or your MDM policy) to refuse anything older.
    Once installed, the updater's persisted high-water mark closes this gap.
  * -Bundle <file> hands the file to `inveil enroll` as is. The file contains the one-time enrollment token and is
    left on disk where you put it; delete it after enrolling. The token path (INVEIL_ENROLL_TOKEN) uses stdin.
  * This script has been written against the same logic as install.sh but could not be executed on Windows while
    it was written; scripts/install.test.ps1 must be run on a Windows runner (CI does this).

Run it as a script block so you can pass parameters; nothing but this script is ever evaluated. GitHub serves release
assets as application/octet-stream, so .Content is a byte array and has to be decoded first (a host that serves the
script as text already returns a string; leave out the GetString there):

    $script = [Text.Encoding]::UTF8.GetString((Invoke-WebRequest -UseBasicParsing https://github.com/sansjack/inveil-app/releases/latest/download/install.ps1).Content)
    & ([scriptblock]::Create($script)) -NoEnroll

Enrollment: set the one-time token in $env:INVEIL_ENROLL_TOKEN and pass -Enroll. The token is read, removed from
the environment immediately, and handed to `inveil enroll --bundle -` on standard input. It is never on a command
line or in a file. Or use -Bundle <file>.

Hosting this script (templated by .github/scripts/render-installers.sh; values are single-quoted and may not
contain quotes, backslashes, `$`, backticks or newlines):
  $UpdatePublicKeys          required. Whitespace-separated "<key_id>=<base64 Ed25519 public key>" entries.
  $MinSignatures             optional, default 2. A value below 2 is refused unless -AllowSingleSignature is
                             given, which exists for self-hosters with a single update key.
  $DefaultBackendUrl / $DefaultBackendPinnedKeys  optional; the latter are the policy keys, not the update keys.
Unfilled placeholders are ignored.

Environment: INVEIL_ENROLL_TOKEN, INVEIL_INSTALL_DIR (default %LOCALAPPDATA%\Programs\inveil), INVEIL_OPENSSL
(path of an OpenSSL 3 binary). INVEIL_INSTALL_TESTING=1 (tests only) additionally enables
INVEIL_UPDATE_PUBLIC_KEYS, INVEIL_INSTALL_BASE_URL, INVEIL_MIN_SIGNATURES and file:// URLs; they are ignored
otherwise so a stray variable cannot replace the pinned keys.

.PARAMETER Enroll
Enroll this device using the token in $env:INVEIL_ENROLL_TOKEN.
.PARAMETER Bundle
Path to an enrollment.json file, instead of a token.
.PARAMETER BackendUrl
Backend for -Enroll (https, or loopback http).
.PARAMETER PinnedKey
Policy public key for -Enroll as "<key_id>=<base64>"; repeatable.
.PARAMETER NoEnroll
Install the binary only, ignore any enrollment options.
.PARAMETER Version
Install exactly this release; also permits installing an older version.
.PARAMETER MinVersion
Refuse a signed manifest older than this version (a "latest known version" hint).
.PARAMETER Channel
stable (default) or beta; beta requires -Version.
.PARAMETER AllowSingleSignature
Accept a script templated with MinSignatures below 2 (self-hosters with one update key).
.PARAMETER Uninstall
Run `inveil uninstall` and remove the installed binary.
.PARAMETER DryRun
Print what would happen without downloading or changing anything.
#>
[CmdletBinding()]
param(
    [switch]$Enroll,
    [string]$Bundle,
    [string]$BackendUrl,
    [string[]]$PinnedKey = @(),
    [switch]$NoEnroll,
    [string]$Version,
    [string]$MinVersion,
    [ValidateSet('stable', 'beta')]
    [string]$Channel = 'stable',
    [switch]$AllowSingleSignature,
    [switch]$Uninstall,
    [switch]$DryRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$UpdatePublicKeys = '@@UPDATE_PUBLIC_KEYS@@'
$MinSignatures = '@@MIN_SIGNATURES@@'
$DefaultBackendUrl = '@@BACKEND_URL@@'
$DefaultBackendPinnedKeys = '@@BACKEND_PINNED_KEYS@@'
$GitHubReleasesUrl = 'https://github.com/sansjack/inveil-app/releases'

# Everything lives in this function and the last line calls it, so a truncated download runs nothing.
function Invoke-InveilInstall {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'Interactive installer output.')]
    param(
        [switch]$Enroll,
        [string]$Bundle,
        [string]$BackendUrl,
        [string[]]$PinnedKey = @(),
        [switch]$NoEnroll,
        [string]$Version,
        [string]$MinVersion,
        [string]$Channel = 'stable',
        [switch]$AllowSingleSignature,
        [switch]$Uninstall,
        [switch]$DryRun
    )

    $defaultMinSignatures = 2
    $maxSignatures = 16
    $manifestSchema = 1
    $maxManifestBytes = 1MB
    $maxBinaryBytes = 256MB
    $maxRedirects = 5
    $selfTestKey = 'PUAXw+hDiVqStwqnTRt+vJyYLM8uxJaMwM1V8Sr0Zgw='
    $selfTestSignature = 'kqAJqfDUyrhyDoILX2QlQKKye1QWUD+Ps3YiI+vbadoIWsHkPhWZbkWPNhPQ8R2MOHsurrQwKu6wDSkWErsMAA=='
    $testing = $env:INVEIL_INSTALL_TESTING -eq '1'

    function Test-Placeholder([string]$Value) {
        return $Value -match '^@@.*@@$'
    }

    function Get-FileSha256([string]$Path) {
        return (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant()
    }

    function Get-BytesSha256([byte[]]$Bytes) {
        $hash = [Security.Cryptography.SHA256]::Create().ComputeHash($Bytes)
        return (($hash | ForEach-Object { $_.ToString('x2') }) -join '')
    }

    function ConvertTo-KeyList([string]$Name, [string[]]$Entries) {
        $keys = @()
        foreach ($entry in $Entries) {
            foreach ($item in ($entry -split '\s+' | Where-Object { $_ })) {
                if ($item -notmatch '^([A-Za-z0-9._-]+)=([A-Za-z0-9+/=]+)$') {
                    throw "$Name entry '$item' is not <key_id>=<base64 public key>"
                }
                $keys += [pscustomobject]@{ key_id = $Matches[1]; public_key = $Matches[2]; entry = $item }
            }
        }
        if ($keys.Count -eq 0) { throw "$Name is empty" }
        return , $keys
    }

    function Get-Download([string]$Url, [string]$Destination, [long]$MaxBytes) {
        if ($Url -like 'file://*') {
            if (-not $testing) { throw 'file:// URLs are only allowed when INVEIL_INSTALL_TESTING=1' }
            Copy-Item -LiteralPath ([Uri]$Url).LocalPath -Destination $Destination
            return
        }
        # Redirects are followed by hand so that an https URL can never be downgraded to http.
        $current = [Uri]$Url
        for ($hop = 0; $hop -le $maxRedirects; $hop++) {
            if ($current.Scheme -ne 'https') { throw "only https:// URLs are allowed: $current" }
            $request = [Net.HttpWebRequest]::Create($current)
            $request.AllowAutoRedirect = $false
            $request.UserAgent = 'inveil-install'
            $request.Timeout = 60000
            $response = $request.GetResponse()
            try {
                $status = [int]$response.StatusCode
                if ($status -ge 300 -and $status -lt 400) {
                    $location = $response.Headers['Location']
                    if (-not $location) { throw "redirect without a Location header from $current" }
                    $current = New-Object Uri $current, $location
                    continue
                }
                if ($response.ContentLength -gt $MaxBytes) { throw "$current is larger than $MaxBytes bytes" }
                $source = $response.GetResponseStream()
                $output = [IO.File]::Create($Destination)
                try {
                    $buffer = New-Object byte[] 81920
                    $total = 0L
                    while (($read = $source.Read($buffer, 0, $buffer.Length)) -gt 0) {
                        $total += $read
                        if ($total -gt $MaxBytes) { throw "$current is larger than $MaxBytes bytes" }
                        $output.Write($buffer, 0, $read)
                    }
                } finally {
                    $output.Dispose()
                    $source.Dispose()
                }
                return
            } finally {
                $response.Close()
            }
        }
        throw "too many redirects fetching $Url"
    }

    function Invoke-Inveil([string]$Executable, [string[]]$Arguments, [string]$Failure) {
        & $Executable @Arguments
        if ($LASTEXITCODE -ne 0) { throw $Failure }
    }

    function Test-Ed25519([string]$OpenSsl, [string]$KeyBase64, [string]$SignatureBase64, [string]$MessagePath) {
        $ErrorActionPreference = 'Continue'
        try {
            $key = [Convert]::FromBase64String($KeyBase64)
            $signature = [Convert]::FromBase64String($SignatureBase64)
        } catch {
            return $false
        }
        if ($key.Length -ne 32 -or $signature.Length -ne 64) { return $false }
        # SubjectPublicKeyInfo header for Ed25519 (RFC 8410) followed by the raw key.
        $header = [byte[]](0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00)
        $derPath = Join-Path $workDir 'verify.der'
        $signaturePath = Join-Path $workDir 'verify.sig'
        [IO.File]::WriteAllBytes($derPath, [byte[]]($header + $key))
        [IO.File]::WriteAllBytes($signaturePath, $signature)
        & $OpenSsl pkeyutl -verify -pubin -inkey $derPath -keyform DER -rawin -in $MessagePath -sigfile $signaturePath 2>&1 | Out-Null
        return ($LASTEXITCODE -eq 0)
    }

    function Find-OpenSsl {
        $candidates = @($env:INVEIL_OPENSSL)
        $onPath = Get-Command openssl.exe -ErrorAction SilentlyContinue
        if ($onPath) { $candidates += $onPath.Source }
        foreach ($root in @($env:ProgramFiles, ${env:ProgramFiles(x86)})) {
            if (-not $root) { continue }
            $candidates += (Join-Path $root 'Git\usr\bin\openssl.exe')
            $candidates += (Join-Path $root 'Git\mingw64\bin\openssl.exe')
            $candidates += (Join-Path $root 'OpenSSL-Win64\bin\openssl.exe')
            $candidates += (Join-Path $root 'OpenSSL\bin\openssl.exe')
        }
        $right = Join-Path $workDir 'selftest-message'
        $wrong = Join-Path $workDir 'selftest-wrong-message'
        [IO.File]::WriteAllBytes($right, [byte[]](0x72))
        [IO.File]::WriteAllBytes($wrong, [byte[]](0x78))
        foreach ($candidate in $candidates) {
            if (-not $candidate -or -not (Test-Path -LiteralPath $candidate -PathType Leaf)) { continue }
            if ((Test-Ed25519 $candidate $selfTestKey $selfTestSignature $right) -and
                -not (Test-Ed25519 $candidate $selfTestKey $selfTestSignature $wrong)) {
                return $candidate
            }
        }
        return $null
    }

    function Compare-Version([string]$Left, [string]$Right) {
        $pattern = '^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?$'
        if ($Left -notmatch $pattern) { throw "invalid version $Left" }
        $leftParts = @([int64]$Matches[1], [int64]$Matches[2], [int64]$Matches[3])
        $leftPre = if ($Matches[4]) { $Matches[4] } else { '' }
        if ($Right -notmatch $pattern) { throw "invalid version $Right" }
        $rightParts = @([int64]$Matches[1], [int64]$Matches[2], [int64]$Matches[3])
        $rightPre = if ($Matches[4]) { $Matches[4] } else { '' }
        for ($i = 0; $i -lt 3; $i++) {
            if ($leftParts[$i] -ne $rightParts[$i]) { return [Math]::Sign($leftParts[$i] - $rightParts[$i]) }
        }
        if ($leftPre -eq $rightPre) { return 0 }
        if (-not $leftPre) { return 1 }
        if (-not $rightPre) { return -1 }
        $leftIds = $leftPre -split '\.'
        $rightIds = $rightPre -split '\.'
        for ($i = 0; $i -lt [Math]::Max($leftIds.Count, $rightIds.Count); $i++) {
            if ($i -ge $leftIds.Count) { return -1 }
            if ($i -ge $rightIds.Count) { return 1 }
            if ($leftIds[$i] -ceq $rightIds[$i]) { continue }
            $leftNumeric = $leftIds[$i] -match '^\d+$'
            $rightNumeric = $rightIds[$i] -match '^\d+$'
            if ($leftNumeric -and $rightNumeric) { return [Math]::Sign([int64]$leftIds[$i] - [int64]$rightIds[$i]) }
            if ($leftNumeric) { return -1 }
            if ($rightNumeric) { return 1 }
            return [Math]::Sign([string]::CompareOrdinal($leftIds[$i], $rightIds[$i]))
        }
        return 0
    }

    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

    $enrollToken = $env:INVEIL_ENROLL_TOKEN
    Remove-Item Env:\INVEIL_ENROLL_TOKEN -ErrorAction SilentlyContinue

    if ($enrollToken -and $Bundle) { throw 'use either INVEIL_ENROLL_TOKEN or -Bundle, not both' }
    if ($Enroll -and -not $enrollToken -and -not $Bundle) {
        throw '-Enroll needs the token in the INVEIL_ENROLL_TOKEN environment variable (or use -Bundle <file>)'
    }
    if ($Version -and $Version -notmatch '^v?\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$') { throw 'invalid -Version' }
    $releaseVersion = if ($Version) { $Version.TrimStart('v') } else { '' }
    if ($MinVersion -and $MinVersion -notmatch '^v?\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$') { throw 'invalid -MinVersion' }
    $minimumVersion = if ($MinVersion) { $MinVersion.TrimStart('v') } else { '' }

    $updateKeysText = $UpdatePublicKeys
    $minSignaturesText = $MinSignatures
    $baseUrl = ''
    if ($testing) {
        Write-Host 'WARNING: INVEIL_INSTALL_TESTING=1, pinned keys and download location may be overridden. Never use this for a real install.'
        if ($env:INVEIL_UPDATE_PUBLIC_KEYS) { $updateKeysText = $env:INVEIL_UPDATE_PUBLIC_KEYS }
        if ($env:INVEIL_MIN_SIGNATURES) { $minSignaturesText = $env:INVEIL_MIN_SIGNATURES }
        if ($env:INVEIL_INSTALL_BASE_URL) { $baseUrl = $env:INVEIL_INSTALL_BASE_URL }
    }
    if (Test-Placeholder $updateKeysText) {
        throw 'no update public keys are pinned in this script ($UpdatePublicKeys); refusing to install unverified software'
    }
    $updateKeys = ConvertTo-KeyList 'UpdatePublicKeys' @($updateKeysText)
    if (Test-Placeholder $minSignaturesText) { $minSignaturesText = "$defaultMinSignatures" }
    if ($minSignaturesText -notmatch '^\d+$' -or [int]$minSignaturesText -lt 1) { throw 'MinSignatures must be a number of at least 1' }
    $minSignatures = [int]$minSignaturesText
    if ($minSignatures -lt $defaultMinSignatures -and -not $AllowSingleSignature) {
        throw "this script accepts a manifest with fewer than $defaultMinSignatures signatures; that is only for self-hosters with one update key. Pass -AllowSingleSignature if that is what you intend"
    }

    $architecture = if ($env:PROCESSOR_ARCHITEW6432) { $env:PROCESSOR_ARCHITEW6432 } else { $env:PROCESSOR_ARCHITECTURE }
    $arch = switch ($architecture) {
        'AMD64' { 'x86_64' }
        'ARM64' { 'aarch64' }
        default { throw "unsupported CPU architecture: $architecture (supported: x86_64, aarch64)" }
    }
    $targetName = "windows-$arch"
    $binaryName = "inveil-$targetName.exe"
    $manifestName = if ($Channel -eq 'beta') { 'update-manifest-beta.json.sig' } else { 'update-manifest.json.sig' }

    $installDir = if ($env:INVEIL_INSTALL_DIR) { $env:INVEIL_INSTALL_DIR } else { Join-Path $env:LOCALAPPDATA 'Programs\inveil' }
    $target = Join-Path $installDir 'inveil.exe'

    if (-not $baseUrl) {
        if ($releaseVersion) {
            $baseUrl = "$GitHubReleasesUrl/download/v$releaseVersion"
        } elseif ($Channel -eq 'beta') {
            throw 'the beta channel is published on pre-releases; pass -Version <x.y.z-rc.N>'
        } else {
            $baseUrl = "$GitHubReleasesUrl/latest/download"
        }
    }
    $baseUrl = $baseUrl.TrimEnd('/')
    # The updater's feed is always the https GitHub URL, even when tests redirect the download location.
    $feedUrl = if ($Channel -eq 'beta') { "$GitHubReleasesUrl/download/v$releaseVersion/$manifestName" } else { "$GitHubReleasesUrl/latest/download/$manifestName" }

    $backendUrlValue = $BackendUrl
    if (-not $backendUrlValue -and -not (Test-Placeholder $DefaultBackendUrl)) { $backendUrlValue = $DefaultBackendUrl }
    $backendKeyEntries = @($PinnedKey)
    if ($backendKeyEntries.Count -eq 0 -and -not (Test-Placeholder $DefaultBackendPinnedKeys)) {
        $backendKeyEntries = @($DefaultBackendPinnedKeys)
    }

    $enrolling = (-not $NoEnroll) -and ($enrollToken -or $Bundle)
    $backendKeys = @()
    if ($enrolling -and $enrollToken) {
        if (-not $backendUrlValue) { throw '-Enroll needs -BackendUrl' }
        if ($backendKeyEntries.Count -eq 0) { throw '-Enroll needs at least one -PinnedKey' }
        $backendKeys = ConvertTo-KeyList '-PinnedKey' $backendKeyEntries
        # Parsed, not pattern-matched: userinfo or an odd authority (http://localhost:1@evil.com) is refused.
        $parsedUrl = $null
        if (-not [Uri]::TryCreate($backendUrlValue, [UriKind]::Absolute, [ref]$parsedUrl) -or $parsedUrl.UserInfo -or
            $backendUrlValue -match '^[A-Za-z]+://[^/?#]*@') {
            throw '-BackendUrl must be https:// (or loopback http://) without userinfo'
        }
        $loopbackHosts = @('localhost', '127.0.0.1', '[::1]')
        if ($parsedUrl.Scheme -ne 'https' -and -not ($parsedUrl.Scheme -eq 'http' -and $loopbackHosts -contains $parsedUrl.Host)) {
            throw '-BackendUrl must be https:// (or loopback http://)'
        }
        if ($enrollToken -notmatch '^[A-Za-z0-9_-]+$') { throw "the enrollment token must contain only letters, digits, '-' and '_'" }
    }
    if ($enrolling -and $Bundle -and -not (Test-Path -LiteralPath $Bundle -PathType Leaf)) {
        throw "bundle file not found: $Bundle"
    }

    Write-Host "inveil installer: windows/$arch, channel $Channel, install dir $installDir"
    Write-Host 'Pinned update keys (SHA-256 of the raw 32-byte public key; compare with the release notes or MDM policy):'
    $distinctKeys = @{}
    foreach ($key in $updateKeys) {
        try { $raw = [Convert]::FromBase64String($key.public_key) } catch { throw "public key for '$($key.key_id)' is not valid base64" }
        if ($raw.Length -ne 32) { throw "public key for '$($key.key_id)' is not 32 bytes" }
        $distinctKeys[[BitConverter]::ToString($raw)] = $true
        Write-Host "  $($key.key_id)  sha256:$(Get-BytesSha256 $raw)"
    }
    Write-Host "Signatures required: at least $minSignatures distinct pinned keys (the manifest may raise this)."
    if ($distinctKeys.Count -lt $minSignatures) {
        throw "only $($distinctKeys.Count) distinct key(s) are pinned but $minSignatures signatures are required"
    }

    if ($Uninstall) {
        if ($DryRun) {
            Write-Host "[dry-run] would run '$target uninstall' and remove $target"
            return
        }
        if (Test-Path -LiteralPath $target) {
            Invoke-Inveil $target @('uninstall') 'inveil uninstall failed'
        } else {
            Write-Host "No inveil binary at $target; skipping service removal."
        }
        Remove-Item -LiteralPath $target, "$target.prev", "$target.new" -Force -ErrorAction SilentlyContinue
        Write-Host "Removed $target. Enrollment data and credential store entries are removed by 'inveil uninstall'."
        return
    }

    if ($DryRun) {
        Write-Host "[dry-run] would download $baseUrl/$manifestName and verify its signatures with OpenSSL before anything else"
        Write-Host "[dry-run] would download $baseUrl/$binaryName and check its SHA-256 and size against the signed manifest"
        Write-Host "[dry-run] would then run 'inveil verify --role update' from the checked binary and install $target"
        if ($enrolling) {
            Write-Host "[dry-run] would run 'inveil enroll --bundle -' (token on stdin) then 'inveil install'"
        } else {
            Write-Host '[dry-run] would not enroll'
        }
        return
    }

    $workDir = Join-Path ([IO.Path]::GetTempPath()) "inveil-install-$([guid]::NewGuid().ToString('N'))"
    New-Item -ItemType Directory -Path $workDir | Out-Null
    try {
        $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        & icacls.exe $workDir /inheritance:r /grant:r "*${sid}:(OI)(CI)F" | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'could not restrict the temporary directory to the current user' }

        $openSsl = Find-OpenSsl
        if (-not $openSsl) {
            throw 'no OpenSSL 3 that can verify Ed25519 signatures was found, so the signed manifest cannot be checked before running anything. Install one (Git for Windows includes it; or winget install ShiningLight.OpenSSL.Light) or set INVEIL_OPENSSL to its path, then re-run. Nothing was downloaded or installed.'
        }

        $downloadedManifest = Join-Path $workDir $manifestName
        Get-Download "$baseUrl/$manifestName" $downloadedManifest $maxManifestBytes

        $envelope = Get-Content -LiteralPath $downloadedManifest -Raw -Encoding UTF8 | ConvertFrom-Json
        if (-not $envelope.PSObject.Properties['payload'] -or $envelope.payload -isnot [string]) { throw 'the manifest envelope has no payload' }
        $payloadBytes = [Text.Encoding]::UTF8.GetBytes($envelope.payload)
        $messagePath = Join-Path $workDir 'signed-message'
        [IO.File]::WriteAllBytes($messagePath, [byte[]]([Text.Encoding]::ASCII.GetBytes("inveil-update-v1`0") + $payloadBytes))

        $validKeys = @{}
        $signatures = @()
        if ($envelope.PSObject.Properties['signatures']) { $signatures = @($envelope.signatures) | Select-Object -First $maxSignatures }
        foreach ($entry in $signatures) {
            if (-not $entry -or $entry -isnot [pscustomobject]) { continue }
            if (-not $entry.PSObject.Properties['key_id'] -or -not $entry.PSObject.Properties['signature']) { continue }
            if ($entry.signature -isnot [string] -or $entry.signature -notmatch '^[A-Za-z0-9+/=]+$') { continue }
            foreach ($key in ($updateKeys | Where-Object { $_.key_id -ceq $entry.key_id })) {
                if (Test-Ed25519 $openSsl $key.public_key $entry.signature $messagePath) {
                    $validKeys[[BitConverter]::ToString([Convert]::FromBase64String($key.public_key))] = $true
                }
            }
        }

        $manifest = $envelope.payload | ConvertFrom-Json
        $manifestThreshold = 0
        if (-not $manifest.PSObject.Properties['threshold'] -or -not [int]::TryParse("$($manifest.threshold)", [ref]$manifestThreshold)) {
            throw 'the signed manifest has no valid threshold'
        }
        $required = [Math]::Max($minSignatures, $manifestThreshold)
        if ($validKeys.Count -lt $required) {
            throw "manifest has $($validKeys.Count) valid signature(s) from distinct pinned keys, $required required; nothing was installed"
        }
        Write-Host "Manifest signature check passed: $($validKeys.Count) distinct pinned key(s) signed (required $required)."

        if ($manifest.schema -ne $manifestSchema) { throw 'unsupported manifest schema' }
        if ($manifest.channel -cne $Channel) { throw "the manifest is for channel '$($manifest.channel)', not '$Channel'" }
        $now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
        if ([int64]$manifest.expires_at -le $now) { throw 'the signed manifest has expired; ask the publisher for a new release' }

        $manifestVersion = "$($manifest.version)"
        if ($manifestVersion -notmatch '^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$') { throw 'the signed manifest has an invalid version' }
        if ($minimumVersion -and (Compare-Version $manifestVersion $minimumVersion) -lt 0) {
            throw "the signed manifest is for $manifestVersion, older than -MinVersion $minimumVersion; nothing was installed"
        }
        if ($releaseVersion) {
            if ($manifestVersion -cne $releaseVersion) { throw "asked for $releaseVersion but the manifest is for $manifestVersion" }
        } elseif (Test-Path -LiteralPath $target) {
            $reported = (& $target --version 2>$null | Select-Object -First 1)
            if ("$reported" -notmatch '^inveil (\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?)') {
                throw "cannot determine the installed version; pass -Version $manifestVersion to install it explicitly"
            }
            if ((Compare-Version $manifestVersion $Matches[1]) -lt 0) {
                throw "refusing to downgrade from $($Matches[1]) to $manifestVersion; pass -Version $manifestVersion to do it deliberately"
            }
        }

        $entry = $manifest.artifacts.PSObject.Properties[$targetName]
        if (-not $entry) { throw "the signed manifest has no binary for $targetName" }
        $expectedSha = "$($entry.Value.sha256)"
        $expectedSize = [int64]$entry.Value.size
        if ($expectedSha -notmatch '^[0-9a-f]{64}$') { throw "the signed manifest has no SHA-256 for $targetName" }
        if ($expectedSize -le 0 -or $expectedSize -gt $maxBinaryBytes) { throw "the signed size for $targetName is not plausible" }

        $downloadedBinary = Join-Path $workDir $binaryName
        Get-Download "$baseUrl/$binaryName" $downloadedBinary $maxBinaryBytes
        if ((Get-Item -LiteralPath $downloadedBinary).Length -ne $expectedSize) {
            throw "size mismatch for $binaryName (signed manifest says $expectedSize bytes); nothing was installed"
        }
        $actual = Get-FileSha256 $downloadedBinary
        if ($expectedSha -ne $actual) {
            throw "SHA-256 mismatch for $binaryName (signed manifest says $expectedSha, got $actual); nothing was installed"
        }
        Write-Host "Binary matches the signed manifest: sha256 $actual, $expectedSize bytes."

        $verifyArguments = @('verify', '--role', 'update')
        foreach ($key in $updateKeys) { $verifyArguments += @('--pinned-key', $key.entry) }
        $verifyArguments += @('--artifact', $downloadedBinary, $downloadedManifest)
        Invoke-Inveil $downloadedBinary $verifyArguments 'inveil verify rejected the manifest; nothing was installed'
        Write-Host 'inveil verify agrees (second check).'

        New-Item -ItemType Directory -Path $installDir -Force | Out-Null
        if ((Test-Path -LiteralPath $target) -and ((Get-FileSha256 $target) -eq $actual)) {
            Write-Host "inveil $target is already up to date."
        } else {
            $staged = "$target.new"
            Copy-Item -LiteralPath $downloadedBinary -Destination $staged -Force
            if (Test-Path -LiteralPath $target) {
                # A running exe can be renamed but not overwritten.
                Remove-Item -LiteralPath "$target.prev" -Force -ErrorAction SilentlyContinue
                Move-Item -LiteralPath $target -Destination "$target.prev" -Force
                Write-Host "Kept the previous binary as $target.prev"
            }
            Move-Item -LiteralPath $staged -Destination $target -Force
            if ((Get-FileSha256 $target) -ne $actual) { throw 'installed file does not match the verified download' }
            Write-Host "Installed $target"
        }

        if ($enrolling) {
            if ($Bundle) {
                Invoke-Inveil $target @('enroll', '--bundle', $Bundle) 'inveil enroll failed'
            } else {
                $toEntries = { param($keys) @($keys | ForEach-Object { @{ key_id = $_.key_id; public_key = $_.public_key } }) }
                $bundleBody = @{
                    backend_url      = $backendUrlValue
                    pinned_keys      = @(& $toEntries $backendKeys)
                    enrollment_token = $enrollToken
                    auth             = @{ mode = 'enrolled' }
                    update           = @{ keys = @(& $toEntries $updateKeys); min_signatures = $minSignatures; feed_url = $feedUrl }
                } | ConvertTo-Json -Depth 5 -Compress
                $bundleBody | & $target enroll --bundle -
                if ($LASTEXITCODE -ne 0) { throw 'inveil enroll failed (this needs an inveil that reads --bundle - from standard input)' }
            }
            Invoke-Inveil $target @('install') 'inveil install failed'
            Write-Host 'Enrolled this device and installed the background service.'
            if ($Bundle) {
                Write-Host "Note: $Bundle still contains the one-time enrollment token. Delete it now."
            } else {
                Write-Host 'The one-time enrollment token went to inveil on standard input: it was never on a command line or written to disk by this script.'
            }
        } else {
            Write-Host "Not enrolled. Next: run 'inveil init' then 'inveil install', or re-run this script with -Enroll."
        }

        $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
        if (-not $userPath -or (($userPath -split ';') -notcontains $installDir)) {
            Write-Host "Note: $installDir is not on your PATH."
        }
        Write-Host 'To uninstall: re-run this script with -Uninstall'
    } finally {
        Remove-Item -LiteralPath $workDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Invoke-InveilInstall @PSBoundParameters
