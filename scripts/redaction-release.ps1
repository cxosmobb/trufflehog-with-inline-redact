[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{40}$')][string]$SourceSha,
    [Parameter(Mandatory)][string]$OutputDirectory
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if (-not [Environment]::Is64BitOperatingSystem -or $env:OS -ne 'Windows_NT') {
    throw 'Release packaging requires 64-bit Windows'
}
if ($env:CGO_ENABLED -ne '0') { throw 'Release packaging requires CGO_ENABLED=0' }
$sourceRoot = Split-Path -Parent $PSScriptRoot
$resolvedOutput = [IO.Path]::GetFullPath($OutputDirectory)
if (Test-Path -LiteralPath $resolvedOutput) { throw 'Output directory must not already exist' }
$null = New-Item -ItemType Directory -Path $resolvedOutput
$packageRoot = Join-Path $resolvedOutput 'package'
$null = New-Item -ItemType Directory -Path $packageRoot
$executable = Join-Path $packageRoot 'trufflehog.exe'
$wrapper = Join-Path $packageRoot 'trufflehog-redact.exe'
Push-Location $sourceRoot
try {
    $actualSha = (& git rev-parse HEAD).Trim()
    if ($LASTEXITCODE -ne 0 -or $actualSha -ne $SourceSha) { throw 'Source revision mismatch' }
    $env:GOOS = 'windows'
    $env:GOARCH = 'amd64'
    & go build -mod=readonly -p 2 -trimpath -buildvcs=false '-ldflags=-s -w' -o $executable .
    if ($LASTEXITCODE -ne 0) { throw 'Full Windows TruffleHog build failed' }
    & go build -mod=readonly -p 2 -trimpath -buildvcs=false '-ldflags=-s -w' -o $wrapper ./cmd/trufflehog-redact
    if ($LASTEXITCODE -ne 0) { throw 'Windows compatibility wrapper build failed' }
    $goVersion = (& go version).Trim()
    if ($LASTEXITCODE -ne 0) { throw 'Cannot record Go version' }
} finally {
    Pop-Location
}

function Invoke-ReleaseCommand([string]$Program, [string]$InputText, [string[]]$Options = @()) {
    $start = [Diagnostics.ProcessStartInfo]::new($Program)
    $start.UseShellExecute = $false
    $start.RedirectStandardInput = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $start.StandardInputEncoding = [Text.UTF8Encoding]::new($false)
    $start.StandardOutputEncoding = [Text.UTF8Encoding]::new($false)
    $start.StandardErrorEncoding = [Text.UTF8Encoding]::new($false)
    foreach ($option in $Options) { $start.ArgumentList.Add($option) }
    $process = [Diagnostics.Process]::Start($start)
    try {
        $outputTask = $process.StandardOutput.ReadToEndAsync()
        $errorTask = $process.StandardError.ReadToEndAsync()
        $process.StandardInput.Write($InputText)
        $process.StandardInput.Close()
        if (-not $process.WaitForExit(120000)) {
            $process.Kill($true)
            throw 'Release smoke test timed out'
        }
        $output = $outputTask.GetAwaiter().GetResult()
        $diagnostics = $errorTask.GetAwaiter().GetResult()
        if ($process.ExitCode -ne 0) { throw 'Release executable rejected the synthetic smoke input' }
        return @{ Output = $output; Diagnostics = $diagnostics }
    } finally {
        $process.Dispose()
    }
}

function Read-ReleaseFindings([string]$OutputText) {
    try {
        foreach ($line in ($OutputText -split '\r?\n')) {
            if (-not [string]::IsNullOrWhiteSpace($line)) { ConvertFrom-Json -InputObject $line }
        }
    } catch {
        throw 'Full TruffleHog did not produce valid JSON findings'
    }
}

# Deterministic synthetic credentials only; never print source or captured output.
# Synthetic: ghp_ + first36hex(SHA256("trufflehog-native-inline-redaction-synthetic-fixture")).
$secret = 'ghp_732e944dd9bca8079d5304a4d30f05e15e24'
$source = 'const githubToken = "' + $secret + '"; // preserve' + "`r`n"
$expected = 'const githubToken = "REDACTED"; // preserve' + "`r`n"
foreach ($inputText in @($source, $expected)) {
    $result = Invoke-ReleaseCommand $wrapper $inputText
    if ($result.Output -cne $expected -or $result.Diagnostics.Length -ne 0) {
        throw 'Windows compatibility wrapper failed exact redaction or second-pass idempotence'
    }
}
$helpResult = Invoke-ReleaseCommand $wrapper '' @('--help')
if (($helpResult.Output + $helpResult.Diagnostics) -notmatch '--?in-place') {
    throw 'Windows compatibility wrapper did not provide command help'
}
$helpResult = Invoke-ReleaseCommand $executable '' @('--help')
$helpText = ($helpResult.Output + $helpResult.Diagnostics).Replace('--[no-]', '--')
foreach ($option in @('--json', '--no-verification', '--in-place', 'filesystem', 'github', 'git', 's3')) {
    if (-not $helpText.Contains($option)) { throw 'Full TruffleHog help lost an original command or expected flag' }
}
foreach ($entry in @(@('git', '--since-commit'), @('filesystem', '--include-paths'))) {
    $helpResult = Invoke-ReleaseCommand $executable '' @($entry[0], '--help')
    if (-not ($helpResult.Output + $helpResult.Diagnostics).Contains($entry[1])) {
        throw 'Full TruffleHog source command help lost an original flag'
    }
}

# Query the original file object without changing security settings or privileges.
Add-Type -TypeDefinition @"
using System;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
public static class InlineRedactorReleaseIdentity {
    [StructLayout(LayoutKind.Sequential, Pack = 4)]
    private struct FileInformation {
        public uint Attributes;
        public long CreationTime, LastAccessTime, LastWriteTime;
        public uint VolumeSerial, SizeHigh, SizeLow, NumberOfLinks, IndexHigh, IndexLow;
    }
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetFileInformationByHandle(SafeFileHandle handle, out FileInformation info);
    public static string Read(string path) {
        using (var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete)) {
            FileInformation info;
            if (!GetFileInformationByHandle(file.SafeFileHandle, out info))
                throw new IOException("Cannot inspect release smoke file identity");
            return info.VolumeSerial.ToString("x8") + info.IndexHigh.ToString("x8") + info.IndexLow.ToString("x8");
        }
    }
}
"@
$smokeRoot = Join-Path $resolvedOutput 'in-place-smoke'
$nestedRoot = Join-Path $smokeRoot 'nested'
$first = Join-Path $smokeRoot 'first.go'
$second = Join-Path $nestedRoot 'second.go'
$null = New-Item -ItemType Directory -Path $nestedRoot
$encoding = [Text.UTF8Encoding]::new($false)
try {
    [IO.File]::WriteAllText($first, $source, $encoding)
    [IO.File]::WriteAllText($second, $source.Replace('// preserve', '// nested'), $encoding)
    $identities = @{}
    foreach ($path in @($first, $second)) { $identities[$path] = [InlineRedactorReleaseIdentity]::Read($path) }
    $ordinary = Invoke-ReleaseCommand $executable '' @('--no-update', '--no-verification', '--log-level=-1', '--json', '--include-detectors=Github', 'filesystem', $smokeRoot)
    $findings = @(Read-ReleaseFindings $ordinary.Output)
    if (@($findings | Where-Object { $_.DetectorName -eq 'Github' -and $_.Raw -eq $secret }).Count -lt 1) {
        throw 'Full TruffleHog did not retain ordinary offline JSON findings'
    }
    foreach ($path in @($first, $second)) {
        $wanted = if ($path -eq $first) { $source } else { $source.Replace('// preserve', '// nested') }
        if ([Convert]::ToBase64String([IO.File]::ReadAllBytes($path)) -cne [Convert]::ToBase64String($encoding.GetBytes($wanted))) {
            throw 'Ordinary TruffleHog scanning unexpectedly changed source'
        }
    }
    foreach ($pass in 1..2) {
        $result = Invoke-ReleaseCommand $executable '' @('--no-update', '--no-verification', '--log-level=-1', '--json', 'filesystem', '--in-place', $smokeRoot)
        $findings = @(Read-ReleaseFindings $result.Output)
        if ($pass -eq 1 -and @($findings | Where-Object { $_.DetectorName -eq 'Github' -and $_.Raw -eq $secret }).Count -lt 1) {
            throw 'Native Windows in-place scan did not retain original JSON findings'
        }
        if ($pass -eq 2 -and $findings.Count -ne 0) {
            throw 'Native Windows in-place second pass reported residual findings'
        }
        foreach ($path in @($first, $second)) {
            $wanted = if ($path -eq $first) { $expected } else { $expected.Replace('// preserve', '// nested') }
            if ([Convert]::ToBase64String([IO.File]::ReadAllBytes($path)) -cne [Convert]::ToBase64String($encoding.GetBytes($wanted))) {
                throw 'Native Windows in-place smoke test changed unrelated source or missed a credential'
            }
            if ([InlineRedactorReleaseIdentity]::Read($path) -cne $identities[$path]) {
                throw 'Native Windows in-place smoke test replaced the original file object'
            }
        }
        if (@(Get-ChildItem -LiteralPath $smokeRoot -Recurse -Filter '.trufflehog-redact-*' -Force).Count -ne 0) {
            throw 'Native Windows in-place smoke test left staging files'
        }
    }
} finally {
    # Explicit files/directories only; no recursive cleanup of computed paths.
    foreach ($path in @($first, $second, $nestedRoot, $smokeRoot)) {
        if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path }
    }
}

Copy-Item -LiteralPath (Join-Path $sourceRoot 'LICENSE') -Destination (Join-Path $packageRoot 'LICENSE')
$usage = @"
TruffleHog with inline source redaction for Windows x64
Source commit: $SourceSha

trufflehog.exe retains the original TruffleHog commands, flags and output formats.
Without --in-place, it performs ordinary TruffleHog scanning. Add --in-place to
filesystem scans to replace detected sensitive source strings with REDACTED.
The normal scan prints its original findings before redaction; protect that
output because it can contain credentials. Use --no-verification for an offline
scan. The separate redaction pass is always offline and includes expired and
unverified candidates, regardless of reporting filters. Public IDs and source
surroundings are preserved. Check the exit code before downstream access.

PowerShell, from this extracted folder:
  .\trufflehog.exe --help
  .\trufflehog.exe --no-update --no-verification filesystem --in-place C:\path\to\private-import
  if (`$LASTEXITCODE -ne 0) { throw 'Redaction failed; do not scan the import' }

Ordinary scan, preserving upstream JSON output and leaving files unchanged:
  .\trufflehog.exe --no-update --no-verification --json filesystem C:\path\to\source

For a local repository, pass its working-tree folder to filesystem --in-place.
Remote sources and historical commits cannot be rewritten with --in-place.
The companion trufflehog-redact.exe remains available for compatibility and
buffered stream redaction (cmd.exe preserves stdin/stdout bytes):
  trufflehog-redact.exe < original.go > redacted.go
  if errorlevel 1 exit /b 1

Run Windows --in-place as a standard user on a private NTFS import that your
account can read and write. Administrator access and SeSecurityPrivilege are
not required. The existing file object and its security descriptor are retained;
no privileges are enabled. Hard-linked, read-only and locked changed files block
the batch before writes begin. Controlled failures attempt to restore original
bytes; abrupt termination or power loss can leave a partially written file or
batch. Keep a separate original copy if recovery is required. Do not run the
downstream scanner unless redaction succeeds; keep the import private until then.

ZIP checksum: verify SHA256SUMS from the same GitHub Release before use.
PowerShell: Get-FileHash .\trufflehog-redact-windows-amd64-$SourceSha.zip -Algorithm SHA256
Builds are unsigned. Only file contents are redacted, not metadata or Git history.
Archives and containers must be extracted first. Detection is not a guarantee
that every possible secret is recognized. Ambiguous mappings block source edits.

Full usage and limitations:
https://github.com/cxosmobb/trufflehog-with-inline-redact/blob/$SourceSha/docs/source-redaction.md
"@
[IO.File]::WriteAllText((Join-Path $packageRoot 'README.txt'), $usage + "`n", $encoding)
$metadata = "Source commit: $SourceSha`nToolchain: $goVersion`nTarget: windows/amd64`nCGO_ENABLED: 0`nSmoke tests: upstream command help; ordinary offline JSON detection without source edits; native in-place original JSON findings; directory edits; idempotence; original file identities; compatibility stream redaction`n"
[IO.File]::WriteAllText((Join-Path $packageRoot 'BUILD.txt'), $metadata, $encoding)
$assetName = "trufflehog-redact-windows-amd64-$SourceSha.zip"
$assetPath = Join-Path $resolvedOutput $assetName
Compress-Archive -LiteralPath @(
    $executable,
    $wrapper,
    (Join-Path $packageRoot 'LICENSE'),
    (Join-Path $packageRoot 'README.txt'),
    (Join-Path $packageRoot 'BUILD.txt')
) -DestinationPath $assetPath -CompressionLevel Optimal
$hash = (Get-FileHash -LiteralPath $assetPath -Algorithm SHA256).Hash.ToLowerInvariant()
[IO.File]::WriteAllText((Join-Path $resolvedOutput 'SHA256SUMS'), "$hash  $assetName`n", [Text.ASCIIEncoding]::new())
Write-Output 'Windows full TruffleHog and wrapper builds, ordinary scanning, native in-place directory redaction, idempotence, file identity, stream redaction and help checks passed.'
