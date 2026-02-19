<#
.SYNOPSIS
    Signs build artifacts (DLLs, EXE, MSI) with an Authenticode certificate.

.DESCRIPTION
    Uses signtool.exe to sign GruppenMFA build artifacts with SHA-256.
    Supports two modes:
      1. PFX file + password (local builds / CI with secret file)
      2. Certificate thumbprint from Windows certificate store (CI with imported cert)

    Use -Phase to control what gets signed:
      "binaries" - Sign DLLs and EXE only (run BEFORE building the MSI)
      "msi"      - Sign the MSI only (run AFTER building the MSI)
      "all"      - Sign everything in order (for local builds where MSI already exists)

.PARAMETER PfxPath
    Path to the .pfx certificate file.

.PARAMETER PfxPassword
    Password for the .pfx file.

.PARAMETER Thumbprint
    SHA-1 thumbprint of a certificate already imported into the Windows cert store.

.PARAMETER TimestampServer
    RFC 3161 timestamp server URL. Defaults to DigiCert.

.PARAMETER Configuration
    Build configuration (Release or Debug). Defaults to Release.

.PARAMETER Platform
    Build platform. Defaults to x64.

.PARAMETER SolutionDir
    Root of the repository. Defaults to the parent of this script's directory.

.PARAMETER Phase
    What to sign: "binaries", "msi", or "all" (default).

.EXAMPLE
    # Local: sign everything after a full build
    .\Sign-Artifacts.ps1 -PfxPath "C:\certs\gruppen.pfx" -PfxPassword "mypass"

.EXAMPLE
    # CI: sign binaries before MSI packaging
    .\Sign-Artifacts.ps1 -PfxPath cert.pfx -PfxPassword pw -Phase binaries

.EXAMPLE
    # CI: sign MSI after packaging
    .\Sign-Artifacts.ps1 -PfxPath cert.pfx -PfxPassword pw -Phase msi
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$PfxPath,

    [Parameter(Mandatory = $false)]
    [string]$PfxPassword,

    [Parameter(Mandatory = $false)]
    [string]$Thumbprint,

    [Parameter(Mandatory = $false)]
    [string]$TimestampServer = "http://timestamp.digicert.com",

    [Parameter(Mandatory = $false)]
    [string]$Configuration = "Release",

    [Parameter(Mandatory = $false)]
    [string]$Platform = "x64",

    [Parameter(Mandatory = $false)]
    [string]$SolutionDir,

    [Parameter(Mandatory = $false)]
    [ValidateSet("all", "binaries", "msi")]
    [string]$Phase = "all"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ── Resolve paths ────────────────────────────────────────────────────────────

if (-not $SolutionDir) {
    $SolutionDir = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    if (-not $SolutionDir) {
        $SolutionDir = Split-Path -Parent $PSCommandPath | Split-Path -Parent
    }
}

# Normalize
$SolutionDir = (Resolve-Path $SolutionDir).Path

Write-Host "Solution dir : $SolutionDir"
Write-Host "Configuration: $Configuration"
Write-Host "Platform     : $Platform"
Write-Host "Phase        : $Phase"

# ── Locate signtool.exe ──────────────────────────────────────────────────────

function Find-SignTool {
    # Try Windows SDK paths (newest first)
    $sdkPaths = @(
        "${env:ProgramFiles(x86)}\Windows Kits\10\bin",
        "${env:ProgramFiles}\Windows Kits\10\bin"
    )

    foreach ($sdk in $sdkPaths) {
        if (Test-Path $sdk) {
            $versions = Get-ChildItem $sdk -Directory | Where-Object { $_.Name -match '^\d' } |
                Sort-Object Name -Descending
            foreach ($ver in $versions) {
                $candidate = Join-Path $ver.FullName "x64\signtool.exe"
                if (Test-Path $candidate) { return $candidate }
            }
        }
    }

    # Try PATH
    $inPath = Get-Command signtool.exe -ErrorAction SilentlyContinue
    if ($inPath) { return $inPath.Source }

    throw "signtool.exe not found. Install Windows SDK or add signtool to PATH."
}

$signtool = Find-SignTool
Write-Host "Using signtool: $signtool"

# ── Validate signing parameters ─────────────────────────────────────────────

if (-not $PfxPath -and -not $Thumbprint) {
    throw "You must provide either -PfxPath or -Thumbprint."
}

if ($PfxPath -and -not (Test-Path $PfxPath)) {
    throw "PFX file not found: $PfxPath"
}

# ── Build signtool arguments ────────────────────────────────────────────────

function Get-SignArgs {
    param([string]$FilePath)

    $signArgs = @("sign", "/fd", "sha256", "/tr", $TimestampServer, "/td", "sha256")

    if ($PfxPath) {
        $signArgs += @("/f", $PfxPath)
        if ($PfxPassword) {
            $signArgs += @("/p", $PfxPassword)
        }
    }
    else {
        $signArgs += @("/sha1", $Thumbprint)
    }

    $signArgs += $FilePath
    return $signArgs
}

# ── Sign a single file ──────────────────────────────────────────────────────

function Sign-File {
    param([string]$FilePath)

    if (-not (Test-Path $FilePath)) {
        Write-Host "  SKIP (not found): $FilePath" -ForegroundColor Yellow
        return $false
    }

    $signArgs = Get-SignArgs $FilePath
    Write-Host "  Signing: $FilePath"

    # Mask password in log output
    if ($PfxPassword) {
        $logArgs = $signArgs -replace [regex]::Escape($PfxPassword), "***"
    } else {
        $logArgs = $signArgs
    }
    Write-Host "    signtool $($logArgs -join ' ')" -ForegroundColor DarkGray

    & $signtool @signArgs
    if ($LASTEXITCODE -ne 0) {
        throw "signtool failed for: $FilePath (exit code $LASTEXITCODE)"
    }

    # Verify signature
    & $signtool verify /pa /v $FilePath | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Host "  WARNING: Signature verification failed for $FilePath" -ForegroundColor Yellow
    }
    else {
        Write-Host "  OK: Signature verified" -ForegroundColor Green
    }

    return $true
}

# ── Phase: binaries (DLLs + EXE) ────────────────────────────────────────────

if ($Phase -eq "all" -or $Phase -eq "binaries") {
    Write-Host ""
    Write-Host "=== Signing binaries (DLLs + EXE) ===" -ForegroundColor Cyan

    $artifacts = @(
        (Join-Path $SolutionDir "CredentialProvider\bin\$Platform\$Configuration\GruppenMFACredentialProvider.dll"),
        (Join-Path $SolutionDir "CredentialProviderFilter\bin\$Platform\$Configuration\GruppenMFACredentialProviderFilter.dll"),
        (Join-Path $SolutionDir "AgentService\publish\GruppenMFA.AgentService.exe")
    )

    $signed = 0
    foreach ($file in $artifacts) {
        if (Sign-File $file) { $signed++ }
    }

    Write-Host ""
    Write-Host "Signed $signed binaries." -ForegroundColor Green
}

# ── Phase: MSI ───────────────────────────────────────────────────────────────

if ($Phase -eq "all" -or $Phase -eq "msi") {
    Write-Host ""
    Write-Host "=== Signing MSI installer ===" -ForegroundColor Cyan

    $msiDir = Join-Path $SolutionDir "WiXSetup\bin\$Platform\$Configuration"
    $msiFiles = Get-ChildItem $msiDir -Filter "*.msi" -Recurse -ErrorAction SilentlyContinue

    if ($msiFiles) {
        foreach ($msi in $msiFiles) {
            Sign-File $msi.FullName | Out-Null
        }
    }
    else {
        Write-Host "  No MSI files found at: $msiDir" -ForegroundColor Yellow
    }
}

Write-Host ""
Write-Host "=== Code signing complete ($Phase) ===" -ForegroundColor Green
