# PathTrial installer for Windows x86_64.
# Downloads a release archive, verifies its SHA-256, and copies pathtrial.exe.
# It does not change firewall, DNS, routes, or the user PATH.

$ErrorActionPreference = "Stop"

$Repo = "gaochenyang666-droid/PathTrial"
$Version = if ($env:PATHTRIAL_VERSION) { $env:PATHTRIAL_VERSION } else { "v1.5.0-rc.1" }
$BaseUrl = if ($env:PATHTRIAL_BASE_URL) { $env:PATHTRIAL_BASE_URL } else { "https://github.com/$Repo/releases/download/$Version" }
$InstallDir = if ($env:PATHTRIAL_INSTALL_DIR) { $env:PATHTRIAL_INSTALL_DIR } else { Join-Path $env:LOCALAPPDATA "PathTrial" }

if ($env:PROCESSOR_ARCHITECTURE -ne "AMD64") {
    throw "unsupported architecture $($env:PROCESSOR_ARCHITECTURE); the published Windows archive is x86_64"
}

$Target = "x86_64-pc-windows-msvc"
$Asset = "pathtrial-$Target.tar.gz"
$Temp = Join-Path ([System.IO.Path]::GetTempPath()) ("pathtrial-install-" + [guid]::NewGuid().ToString("n"))
New-Item -ItemType Directory -Path $Temp | Out-Null

function Get-FileSha256([string]$Path) {
    return (Get-FileHash -Algorithm SHA256 -Path $Path).Hash.ToLowerInvariant()
}

try {
    Write-Output "Downloading PathTrial $Version for $Target..."
    $Archive = Join-Path $Temp $Asset
    $ChecksumFile = "$Archive.sha256"
    Invoke-WebRequest -Uri "$BaseUrl/$Asset" -OutFile $Archive -UseBasicParsing
    Invoke-WebRequest -Uri "$BaseUrl/$Asset.sha256" -OutFile $ChecksumFile -UseBasicParsing
    $Expected = (Get-Content -Raw $ChecksumFile).Trim().Split()[0].ToLowerInvariant()
    $Actual = Get-FileSha256 $Archive
    if (-not $Expected -or $Expected -ne $Actual) {
        throw "SHA-256 verification failed for $Asset"
    }
    tar -xzf $Archive -C $Temp
    $Binary = Get-ChildItem -Path $Temp -Recurse -Filter "pathtrial.exe" | Select-Object -First 1
    if (-not $Binary) {
        throw "the release archive did not contain pathtrial.exe"
    }
    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    $Destination = Join-Path $InstallDir "pathtrial.exe"
    Copy-Item -Force $Binary.FullName $Destination
    Write-Output "Installed $Destination"
    Write-Output "Add this directory to PATH if needed:"
    Write-Output "  $InstallDir"
    & $Destination --version
}
finally {
    Remove-Item -Recurse -Force $Temp
}
