# Windows release check.
# When the published archive exists, download it, verify SHA-256, and run
# --version. When it does not exist yet, say so and only self-check the
# checksum comparison. A missing asset is not a successful download.

$ErrorActionPreference = "Stop"

$Repo = "gaochenyang666-droid/PathTrial"
$Version = if ($env:PATHTRIAL_VERSION) { $env:PATHTRIAL_VERSION } else { "v1.5.0-rc.2" }
$BaseUrl = "https://github.com/$Repo/releases/download/$Version"
$Asset = "pathtrial-x86_64-pc-windows-msvc.tar.gz"
$AssetUrl = "$BaseUrl/$Asset"

function Get-FileSha256([string]$Path) {
    return (Get-FileHash -Algorithm SHA256 -Path $Path).Hash.ToLowerInvariant()
}

$Sample = Join-Path ([System.IO.Path]::GetTempPath()) ("pathtrial-sha-" + [guid]::NewGuid().ToString("n"))
Set-Content -Path $Sample -Value "pathtrial" -NoNewline -Encoding ascii
$SampleHash = Get-FileSha256 $Sample
$SampleChecksum = "$Sample.sha256"
Set-Content -Path $SampleChecksum -Value "$SampleHash  sample" -Encoding ascii
$ReadBack = (Get-Content -Raw $SampleChecksum).Trim().Split()[0].ToLowerInvariant()
if ($ReadBack -ne $SampleHash) {
    throw "local SHA-256 self-check failed"
}
Remove-Item $Sample, $SampleChecksum
Write-Output "local SHA-256 self-check passed"

try {
    $Head = Invoke-WebRequest -Method Head -Uri $AssetUrl -UseBasicParsing
    if ($Head.StatusCode -ge 400) {
        throw "status $($Head.StatusCode)"
    }
}
catch {
    Write-Output "windows_published_asset=absent"
    Write-Output "version=$Version"
    Write-Output "url=$AssetUrl"
    Write-Output "SKIP: this is not a successful download verification. The published release has no Windows archive yet."
    exit 0
}

$Temp = Join-Path ([System.IO.Path]::GetTempPath()) ("pathtrial-verify-" + [guid]::NewGuid().ToString("n"))
New-Item -ItemType Directory -Path $Temp | Out-Null
try {
    $Archive = Join-Path $Temp $Asset
    Invoke-WebRequest -Uri $AssetUrl -OutFile $Archive -UseBasicParsing
    Invoke-WebRequest -Uri "$AssetUrl.sha256" -OutFile "$Archive.sha256" -UseBasicParsing
    $Expected = (Get-Content -Raw "$Archive.sha256").Trim().Split()[0].ToLowerInvariant()
    $Actual = Get-FileSha256 $Archive
    if ($Expected -ne $Actual) {
        throw "SHA-256 verification failed for $Asset"
    }
    tar -xzf $Archive -C $Temp
    $Binary = Get-ChildItem -Path $Temp -Recurse -Filter "pathtrial.exe" | Select-Object -First 1
    if (-not $Binary) {
        throw "archive did not contain pathtrial.exe"
    }
    $VersionText = & $Binary.FullName --version
    $ExpectedVersion = $Version.TrimStart("v")
    if ($VersionText.Trim() -ne "pathtrial $ExpectedVersion") {
        throw "unexpected version output: $VersionText"
    }
    Write-Output "windows_published_asset=present"
    Write-Output "Installed version: $VersionText"
    Write-Output "Asset SHA-256: $Actual"
}
finally {
    Remove-Item -Recurse -Force $Temp
}
