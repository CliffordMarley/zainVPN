<#
.SYNOPSIS
  Builds zainvpn.exe and the one-file installer for friends (dist\zainVPN-Setup.exe).

.DESCRIPTION
  The coordinator address, network name and password are baked into the installer
  as defaults, so friends only pick a nickname. Values not given on the command
  line are read from build.config.json (copy build.config.example.json).

.EXAMPLE
  .\build.ps1 -Server 1.2.3.4 -Network blur -Password secret

.EXAMPLE
  .\build.ps1 -SkipInstaller -ServerBinaries

.EXAMPLE
  .\build.ps1 -WhatIf
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$Server,
    [string]$Network,
    [string]$Password,
    [string]$Name,
    [string]$Version,
    [switch]$SkipInstaller,
    [switch]$ServerBinaries
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = $PSScriptRoot
$buildDir = Join-Path $root 'build'
$distDir = Join-Path $root 'dist'

function Write-Step([string]$msg) { Write-Host "==> $msg" -ForegroundColor Cyan }

# Find-Tool returns $name from PATH, else the first existing candidate, else $null.
function Find-Tool([string]$name, [string[]]$candidates) {
    $cmd = Get-Command $name -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($cmd) { return $cmd.Path }
    foreach ($c in $candidates) {
        if ($c -and (Test-Path -LiteralPath $c -PathType Leaf)) { return $c }
    }
    return $null
}

function Find-Iscc {
    $candidates = @(
        "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe",
        "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
        "$env:ProgramFiles\Inno Setup 6\ISCC.exe"
    )
    foreach ($key in 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Inno Setup 6_is1',
                     'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Inno Setup 6_is1',
                     'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Inno Setup 6_is1') {
        $item = Get-ItemProperty -LiteralPath $key -ErrorAction SilentlyContinue
        if ($item -and $item.PSObject.Properties['InstallLocation'] -and $item.InstallLocation) {
            $candidates += Join-Path $item.InstallLocation 'ISCC.exe'
        }
    }
    return Find-Tool 'ISCC.exe' $candidates
}

# Invoke-GoBuild cross-compiles $pkg with CGO off, restoring GOOS/GOARCH/CGO_ENABLED afterwards.
function Invoke-GoBuild([string]$goos, [string]$goarch, [string]$out, [string]$pkg) {
    if (-not $PSCmdlet.ShouldProcess($out, "go build $pkg ($goos/$goarch)")) { return }
    $saved = @{}
    foreach ($k in 'GOOS', 'GOARCH', 'CGO_ENABLED') { $saved[$k] = [Environment]::GetEnvironmentVariable($k, 'Process') }
    try {
        $env:GOOS = $goos
        $env:GOARCH = $goarch
        $env:CGO_ENABLED = '0'
        & $go -C $root build -trimpath -ldflags "-s -w -X main.version=$exeVersion" -o $out $pkg
        if ($LASTEXITCODE -ne 0) { throw "go build $pkg ($goos/$goarch) failed with exit code $LASTEXITCODE" }
    } finally {
        foreach ($k in $saved.Keys) { [Environment]::SetEnvironmentVariable($k, $saved[$k], 'Process') }
    }
}

# Find-ServerPackage picks the coordinator's main package under cmd\.
function Find-ServerPackage {
    $dirs = @(Get-ChildItem -LiteralPath (Join-Path $root 'cmd') -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -ne 'zainvpn' -and (Get-ChildItem -LiteralPath $_.FullName -Filter *.go -File) })
    $pick = @($dirs | Where-Object { $_.Name -match 'server|coord' })
    if ($pick.Count -eq 0) { $pick = $dirs }
    if ($pick.Count -ne 1) {
        throw "Can't tell which cmd\ package is the coordinator (found: $(($dirs | ForEach-Object Name) -join ', '))"
    }
    return $pick[0].Name
}

# ConvertTo-IssString escapes $s for a Pascal single-quoted string in the installer
# script. ISCC's command line can't carry a double quote, so " becomes '#34'.
function ConvertTo-IssString([string]$label, [string]$s) {
    if ($s -match '[\x00-\x1f]') { throw "$label contains a control character" }
    return $s.Replace("'", "''").Replace('"', "'#34'")
}

# --- settings -----------------------------------------------------------------

$configPath = Join-Path $root 'build.config.json'
if (Test-Path -LiteralPath $configPath) {
    try {
        $json = Get-Content -LiteralPath $configPath -Raw -Encoding UTF8 | ConvertFrom-Json
    } catch {
        throw "build.config.json is not valid JSON: $_"
    }
    $cfg = @{}
    foreach ($p in $json.PSObject.Properties) { $cfg[$p.Name] = [string]$p.Value }
    foreach ($key in 'Server', 'Network', 'Password', 'Name') {
        if (-not $PSBoundParameters.ContainsKey($key) -and $cfg.ContainsKey($key)) {
            Set-Variable -Name $key -Value $cfg[$key]
        }
    }
}
$Server = "$Server".Trim()
$Network = "$Network".Trim()
$Name = "$Name".Trim()

if (-not $Version) {
    $describe = $null
    if (Get-Command git -CommandType Application -ErrorAction SilentlyContinue) {
        $eap = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        try {
            $describe = & git -C $root describe --tags --always --dirty 2>$null | Select-Object -First 1
            if ($LASTEXITCODE -ne 0) { $describe = $null }
        } finally {
            $ErrorActionPreference = $eap
        }
    }
    $Version = if ($describe) { "$describe".Trim() } else { '0.1.0' }
}
$exeVersion = $Version
if ($exeVersion -notmatch '^[0-9A-Za-z._+-]+$') {
    throw "Version '$exeVersion' may only contain letters, digits and . _ + -"
}
# Inno Setup needs a numeric x.y[.z[.w]] version; take it from a tag like v1.2.3-4-gabc.
$appVersion = '0.1.0'
if ($exeVersion -match '^v?(\d{1,5}(?:\.\d{1,5}){1,3})(?:[-+].*)?$' -and
    -not ($Matches[1].Split('.') | Where-Object { [int]$_ -gt 65535 })) {
    $appVersion = $Matches[1]
}

# --- tools ----------------------------------------------------------------------

$go = Find-Tool 'go.exe' @("$env:LOCALAPPDATA\Programs\go\bin\go.exe", 'C:\Program Files\Go\bin\go.exe')
if (-not $go) { throw 'Go not found on PATH or in the usual places. Install it from https://go.dev/dl/' }

$iscc = $null
if (-not $SkipInstaller) {
    $iscc = Find-Iscc
    if (-not $iscc) { throw 'Inno Setup 6 (ISCC.exe) not found. Install it with: winget install JRSoftware.InnoSetup' }
}

if (-not (Test-Path -Path (Join-Path $root 'cmd\zainvpn\*.go'))) {
    if (-not $WhatIfPreference) { throw "No Go sources in $(Join-Path $root 'cmd\zainvpn')" }
    Write-Warning 'cmd\zainvpn has no Go sources yet'
}

Write-Step "zainvpn $exeVersion (installer version $appVersion)"
Write-Host "    go:   $go"
if ($iscc) { Write-Host "    iscc: $iscc" }

# --- build ----------------------------------------------------------------------

New-Item -ItemType Directory -Force -Path $buildDir | Out-Null

Write-Step 'Building build\zainvpn.exe (windows/amd64)'
Invoke-GoBuild 'windows' 'amd64' (Join-Path $buildDir 'zainvpn.exe') './cmd/zainvpn'
Copy-Item -LiteralPath (Join-Path $root 'third_party\wintun\amd64\wintun.dll') -Destination $buildDir -Force

if ($ServerBinaries) {
    $pkg = Find-ServerPackage
    $serverDir = Join-Path $distDir 'server'
    New-Item -ItemType Directory -Force -Path $serverDir | Out-Null
    foreach ($arch in 'amd64', 'arm64') {
        Write-Step "Building dist\server\$pkg-linux-$arch"
        Invoke-GoBuild 'linux' $arch (Join-Path $serverDir "$pkg-linux-$arch") "./cmd/$pkg"
    }
}

if ($SkipInstaller) {
    Write-Step 'Skipping the installer (-SkipInstaller)'
    return
}

$missing = @('Server', 'Network', 'Password' | Where-Object { -not (Get-Variable -Name $_ -ValueOnly) })
if ($missing) {
    Write-Warning ("No {0} given (parameters or build.config.json): the installer will have empty fields for friends to fill in." -f ($missing -join '/'))
}
$pwInfo = if ($Password) { "set, $($Password.Length) chars" } else { 'empty' }
Write-Step "Building the installer (server '$Server', network '$Network', password $pwInfo)"

$isccArgs = @(
    '/Qp',
    "/DAppVersion=$appVersion",
    "/DDefServer=$(ConvertTo-IssString 'Server' $Server)",
    "/DDefNetwork=$(ConvertTo-IssString 'Network' $Network)",
    "/DDefPassword=$(ConvertTo-IssString 'Password' $Password)",
    "/DDefName=$(ConvertTo-IssString 'Name' $Name)",
    "/DSourceDir=$buildDir",
    "/DOutputDir=$distDir",
    (Join-Path $root 'installer\zainvpn.iss')
)
$setup = Join-Path $distDir 'zainVPN-Setup.exe'
if (-not $PSCmdlet.ShouldProcess($setup, 'ISCC installer\zainvpn.iss')) { return }
& $iscc @isccArgs
if ($LASTEXITCODE -ne 0) { throw "ISCC failed with exit code $LASTEXITCODE" }
if (-not (Test-Path -LiteralPath $setup)) { throw "ISCC succeeded but $setup is missing" }

$size = (Get-Item -LiteralPath $setup).Length / 1MB
Write-Host ''
Write-Host ('Installer: {0} ({1:N1} MB)' -f $setup, $size) -ForegroundColor Green
Write-Host ('SHA-256:   {0}' -f (Get-FileHash -LiteralPath $setup -Algorithm SHA256).Hash)
if ($Password) {
    Write-Warning "Anyone with this installer can join network '$Network': it contains the password. Share it only with friends."
}
