<#
.SYNOPSIS
    Signs build artifacts (DLLs, EXE, MSI) with an Authenticode certificate.

.DESCRIPTION
    Uses signtool.exe to sign all GruppenMFA build artifacts with SHA-256.
    Supports two modes:
      1. PFX file + password (local builds / CI with secret file)
      2. Certificate thumbprint from Windows certificate store (CI with imported cert)

    The script signs individual binaries first, then the MSI (which embeds them).
    This order is important: if you sign the MSI first and then the binaries,
    the MSI signature becomes invalid.

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

.EXAMPLE
    # Sign with PFX file
    .\Sign-Artifacts.ps1 -PfxPath "C:\certs\gruppen.pfx" -PfxPassword "mypass"

.EXAMPLE
    # Sign with certificate from store (CI)
    .\Sign-Artifacts.ps1 -Thumbprint "A1B2C3D4..."
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
    [string]$SolutionDir
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

    $args = @("sign", "/fd", "sha256", "/tr", $TimestampServer, "/td", "sha256")

    if ($PfxPath) {
        $args += @("/f", $PfxPath)
        if ($PfxPassword) {
            $args += @("/p", $PfxPassword)
        }
    }
    else {
        $args += @("/sha1", $Thumbprint)
    }

    $args += $FilePath
    return $args
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
    $logArgs = $signArgs -replace [regex]::Escape($PfxPassword), "***"
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

# ── Collect artifacts ────────────────────────────────────────────────────────

Write-Host ""
Write-Host "=== Collecting artifacts to sign ===" -ForegroundColor Cyan

$artifacts = @()

# 1. Credential Provider DLL
$cpDll = Join-Path $SolutionDir "CredentialProvider\bin\$Platform\$Configuration\GruppenMFACredentialProvider.dll"
$artifacts += $cpDll

# 2. Credential Provider Filter DLL
$cpfDll = Join-Path $SolutionDir "CredentialProviderFilter\bin\$Platform\$Configuration\GruppenMFACredentialProviderFilter.dll"
$artifacts += $cpfDll

# 3. Agent Service EXE
$agentExe = Join-Path $SolutionDir "AgentService\publish\GruppenMFA.AgentService.exe"
$artifacts += $agentExe

Write-Host ""
Write-Host "=== Signing binaries (DLLs + EXE) ===" -ForegroundColor Cyan

$signed = 0
foreach ($file in $artifacts) {
    if (Sign-File $file) { $signed++ }
}

Write-Host ""
Write-Host "Signed $signed binaries." -ForegroundColor Green

# 4. MSI (must be signed AFTER binaries are signed and embedded)
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

Write-Host ""
Write-Host "=== Code signing complete ===" -ForegroundColor Green
