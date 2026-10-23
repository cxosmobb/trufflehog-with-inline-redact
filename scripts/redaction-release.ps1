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
$executable = Join-Path $packageRoot 'trufflehog-redact.exe'
Push-Location $sourceRoot
try {
    $actualSha = (& git rev-parse HEAD).Trim()
    if ($LASTEXITCODE -ne 0 -or $actualSha -ne $SourceSha) { throw 'Source revision mismatch' }
    $env:GOOS = 'windows'
    $env:GOARCH = 'amd64'
    & go build -mod=readonly -p 2 -trimpath -buildvcs=false '-ldflags=-s -w' -o $executable ./cmd/trufflehog-redact
    if ($LASTEXITCODE -ne 0) { throw 'Windows release build failed' }
    $goVersion = (& go version).Trim()
    if ($LASTEXITCODE -ne 0) { throw 'Cannot record Go version' }
} finally {
    Pop-Location
}

function Invoke-Redactor([string]$InputText, [string[]]$Options = @()) {
    $start = [Diagnostics.ProcessStartInfo]::new($executable)
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

# Deterministic synthetic credentials only; never print source or captured output.
$source = 'const githubToken = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"; // preserve' + "`r`n"
$expected = 'const githubToken = "REDACTED"; // preserve' + "`r`n"
foreach ($inputText in @($source, $expected)) {
    $result = Invoke-Redactor $inputText
    if ($result.Output -cne $expected -or $result.Diagnostics.Length -ne 0) {
        throw 'Windows executable failed exact redaction or second-pass idempotence'
    }
}
$helpResult = Invoke-Redactor '' @('--help')
if ($helpResult.Output.Length -ne 0 -or -not $helpResult.Diagnostics.Contains('--in-place')) {
    # Go flag help uses one leading dash even when both spellings are accepted.
    if ($helpResult.Output.Length -ne 0 -or -not $helpResult.Diagnostics.Contains('-in-place')) {
        throw 'Windows executable did not provide command help'
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
    foreach ($pass in 1..2) {
        $result = Invoke-Redactor '' @('--in-place', $smokeRoot)
        if ($result.Output.Length -ne 0 -or $result.Diagnostics.Length -ne 0) {
            throw 'Windows in-place smoke test produced unexpected output'
        }
        foreach ($path in @($first, $second)) {
            $wanted = if ($path -eq $first) { $expected } else { $expected.Replace('// preserve', '// nested') }
            if ([Convert]::ToBase64String([IO.File]::ReadAllBytes($path)) -cne [Convert]::ToBase64String($encoding.GetBytes($wanted))) {
                throw 'Windows in-place smoke test changed unrelated source or missed a credential'
            }
            if ([InlineRedactorReleaseIdentity]::Read($path) -cne $identities[$path]) {
                throw 'Windows in-place smoke test replaced the original file object'
            }
        }
        if (@(Get-ChildItem -LiteralPath $smokeRoot -Recurse -Filter '.trufflehog-redact-*' -Force).Count -ne 0) {
            throw 'Windows in-place smoke test left staging files'
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
TruffleHog inline source redactor for Windows x64
Source commit: $SourceSha

This executable replaces detected sensitive source strings with REDACTED.
It scans offline, including expired and unverified candidates. Public IDs and
surrounding source are preserved. Always check its exit code before allowing a
downstream scanner to access the processed files.

PowerShell, from this extracted folder:
  .\trufflehog-redact.exe --help
  .\trufflehog-redact.exe --in-place C:\path\to\private-import
  if (`$LASTEXITCODE -ne 0) { throw 'Redaction failed; do not scan the import' }

One stream (cmd.exe preserves stdin/stdout bytes):
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
Builds are unsigned. Only file contents are scanned, not metadata or Git history.
Archives and containers must be extracted first. Detection is not a guarantee
that every possible secret is recognized. Ambiguous mappings withhold output.

Full usage and limitations:
https://github.com/cxosmobb/trufflehog-with-inline-redact/blob/$SourceSha/docs/source-redaction.md
"@
$encoding = [Text.UTF8Encoding]::new($false)
[IO.File]::WriteAllText((Join-Path $packageRoot 'README.txt'), $usage + "`n", $encoding)
$metadata = "Source commit: $SourceSha`nToolchain: $goVersion`nTarget: windows/amd64`nCGO_ENABLED: 0`nSmoke tests: exact source redaction; idempotence; help; two-file in-place directory; original file identities`n"
[IO.File]::WriteAllText((Join-Path $packageRoot 'BUILD.txt'), $metadata, $encoding)
$assetName = "trufflehog-redact-windows-amd64-$SourceSha.zip"
$assetPath = Join-Path $resolvedOutput $assetName
Compress-Archive -LiteralPath @(
    $executable,
    (Join-Path $packageRoot 'LICENSE'),
    (Join-Path $packageRoot 'README.txt'),
    (Join-Path $packageRoot 'BUILD.txt')
) -DestinationPath $assetPath -CompressionLevel Optimal
$hash = (Get-FileHash -LiteralPath $assetPath -Algorithm SHA256).Hash.ToLowerInvariant()
[IO.File]::WriteAllText((Join-Path $resolvedOutput 'SHA256SUMS'), "$hash  $assetName`n", [Text.ASCIIEncoding]::new())
Write-Output 'Windows x64 release build, exact stream and in-place directory redaction, idempotence, file identity, and help checks passed.'
