<#
.SYNOPSIS
  Builds zainvpn.exe, zainvpn-app.exe and the installer for friends (dist\zainVPN-Setup.exe).

.DESCRIPTION
  The installer only contains the coordinator address (nothing secret); friends
  join networks with invite codes. deploy.sh builds the same installer on the
  server, so you only need this script for local testing. Values not given on
  the command line are read from build.config.json (copy build.config.example.json).
  Needs Go and NSIS (makensis): winget install GoLang.Go NSIS.NSIS

.EXAMPLE
  .\build.ps1 -Server 1.2.3.4

.EXAMPLE
  .\build.ps1 -Server 1.2.3.4 -Publish
  Also uploads the installer to the coordinator dashboard (http://1.2.3.4:21958 unless
  -DashboardUrl is given), where friends download it from the sign-in page. Asks for
  the admin password unless -AdminPassword or build.config.json provides it.

.EXAMPLE
  .\build.ps1 -SkipInstaller -ServerBinaries

.EXAMPLE
  .\build.ps1 -WhatIf
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$Server,
    [string]$Version,
    [switch]$SkipInstaller,
    [switch]$ServerBinaries,
    [switch]$Publish,
    [string]$DashboardUrl,
    [string]$AdminPassword
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

function Find-Makensis {
    $candidates = @(
        "${env:ProgramFiles(x86)}\NSIS\makensis.exe",
        "$env:ProgramFiles\NSIS\makensis.exe"
    )
    $candidates += Get-ChildItem -Path "$env:LOCALAPPDATA\Programs" -Filter makensis.exe -Recurse -Depth 2 -ErrorAction SilentlyContinue |
        Select-Object -ExpandProperty FullName
    return Find-Tool 'makensis.exe' $candidates
}

# Invoke-GoBuild cross-compiles $pkg with CGO off, restoring GOOS/GOARCH/CGO_ENABLED afterwards.
function Invoke-GoBuild([string]$goos, [string]$goarch, [string]$out, [string]$pkg, [string]$extraLdflags = '') {
    if (-not $PSCmdlet.ShouldProcess($out, "go build $pkg ($goos/$goarch)")) { return }
    $saved = @{}
    foreach ($k in 'GOOS', 'GOARCH', 'CGO_ENABLED') { $saved[$k] = [Environment]::GetEnvironmentVariable($k, 'Process') }
    try {
        $env:GOOS = $goos
        $env:GOARCH = $goarch
        $env:CGO_ENABLED = '0'
        & $go -C $root build -trimpath -ldflags "-s -w $extraLdflags -X main.version=$exeVersion" -o $out $pkg
        if ($LASTEXITCODE -ne 0) { throw "go build $pkg ($goos/$goarch) failed with exit code $LASTEXITCODE" }
    } finally {
        foreach ($k in $saved.Keys) { [Environment]::SetEnvironmentVariable($k, $saved[$k], 'Process') }
    }
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
    foreach ($key in 'Server', 'DashboardUrl', 'AdminPassword') {
        if (-not $PSBoundParameters.ContainsKey($key) -and $cfg.ContainsKey($key)) {
            Set-Variable -Name $key -Value $cfg[$key]
        }
    }
}
$Server = "$Server".Trim()
if ($Server -match '["\x00-\x1f]') { throw 'Server contains a quote or control character' }

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
# The installer needs a numeric x.y.z version; take it from a tag like v1.2.3-4-gabc.
$appVersion = '0.1.0'
if ($exeVersion -match '^v?(\d{1,5}\.\d{1,5}\.\d{1,5})(?:[-+].*)?$') {
    $appVersion = $Matches[1]
}

# --- tools ----------------------------------------------------------------------

$go = Find-Tool 'go.exe' @("$env:LOCALAPPDATA\Programs\go\bin\go.exe", 'C:\Program Files\Go\bin\go.exe')
if (-not $go) { throw 'Go not found on PATH or in the usual places. Install it from https://go.dev/dl/' }

$makensis = $null
if (-not $SkipInstaller) {
    $makensis = Find-Makensis
    if (-not $makensis) { throw 'NSIS (makensis.exe) not found. Install it with: winget install NSIS.NSIS' }
}

Write-Step "zainvpn $exeVersion (installer version $appVersion)"
Write-Host "    go:       $go"
if ($makensis) { Write-Host "    makensis: $makensis" }

# --- build ----------------------------------------------------------------------
# Icons/manifests come from cmd\*\rsrc_windows_amd64.syso, generated from
# installer\winres\*.json with: go run github.com/tc-hib/go-winres@v0.3.3 make --in installer\winres\<exe>.json --out cmd\<exe>\rsrc

New-Item -ItemType Directory -Force -Path $buildDir | Out-Null

Write-Step 'Building build\zainvpn.exe and build\zainvpn-app.exe (windows/amd64)'
Invoke-GoBuild 'windows' 'amd64' (Join-Path $buildDir 'zainvpn.exe') './cmd/zainvpn'
Invoke-GoBuild 'windows' 'amd64' (Join-Path $buildDir 'zainvpn-app.exe') './cmd/zainvpn-app' '-H windowsgui'
Copy-Item -LiteralPath (Join-Path $root 'third_party\wintun\amd64\wintun.dll') -Destination $buildDir -Force

if ($ServerBinaries) {
    $serverDir = Join-Path $distDir 'server'
    New-Item -ItemType Directory -Force -Path $serverDir | Out-Null
    foreach ($arch in 'amd64', 'arm64') {
        Write-Step "Building dist\server\zainvpn-server-linux-$arch"
        Invoke-GoBuild 'linux' $arch (Join-Path $serverDir "zainvpn-server-linux-$arch") './cmd/zainvpn-server'
    }
}

if ($SkipInstaller) {
    if ($Publish) { throw '-Publish needs the installer; drop -SkipInstaller' }
    Write-Step 'Skipping the installer (-SkipInstaller)'
    return
}

if (-not $Server) {
    Write-Warning 'No -Server given (parameter or build.config.json): friends will have to type the coordinator address.'
}
Write-Step "Building the installer (coordinator '$Server')"
New-Item -ItemType Directory -Force -Path $distDir | Out-Null
$setup = Join-Path $distDir 'zainVPN-Setup.exe'
if (-not $PSCmdlet.ShouldProcess($setup, 'makensis installer\zainvpn.nsi')) { return }
& $makensis /V2 "/DVERSION=$appVersion" "/DSERVER=$Server" "/DSRC=$buildDir" "/DOUT=$setup" (Join-Path $root 'installer\zainvpn.nsi')
if ($LASTEXITCODE -ne 0) { throw "makensis failed with exit code $LASTEXITCODE" }
if (-not (Test-Path -LiteralPath $setup)) { throw "makensis succeeded but $setup is missing" }

$size = (Get-Item -LiteralPath $setup).Length / 1MB
Write-Host ''
Write-Host ('Installer: {0} ({1:N1} MB)' -f $setup, $size) -ForegroundColor Green
Write-Host ('SHA-256:   {0}' -f (Get-FileHash -LiteralPath $setup -Algorithm SHA256).Hash)
Write-Host 'It only contains the coordinator address, so it is safe to share; friends join with an invite code.'

if ($Publish) {
    if (-not $DashboardUrl) {
        if (-not $Server) { throw '-Publish needs -DashboardUrl or -Server' }
        $DashboardUrl = 'http://{0}:21958' -f ($Server -replace ':\d+$', '')
    }
    $DashboardUrl = $DashboardUrl.TrimEnd('/')
    if (-not $AdminPassword) {
        $secure = Read-Host -AsSecureString "Admin password for $DashboardUrl"
        $AdminPassword = [Runtime.InteropServices.Marshal]::PtrToStringBSTR([Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure))
    }
    Write-Step "Publishing the installer to $DashboardUrl"
    if ($PSCmdlet.ShouldProcess("$DashboardUrl/api/installer", 'upload installer')) {
        try {
            Invoke-WebRequest -UseBasicParsing -Method Put -Uri "$DashboardUrl/api/installer" -InFile $setup `
                -ContentType 'application/octet-stream' -Headers @{ Authorization = "Bearer $AdminPassword" } -TimeoutSec 600 | Out-Null
        } catch {
            $detail = if ($_.ErrorDetails -and $_.ErrorDetails.Message) { " $($_.ErrorDetails.Message)" } else { '' }
            throw "Upload to $DashboardUrl failed: $($_.Exception.Message)$detail"
        }
        Write-Host "Published. Send your friends this link: $DashboardUrl/" -ForegroundColor Green
    }
}
