#Requires -Version 5.0
<#
.SYNOPSIS
  Download the pre-built honeypot binary that matches this Windows machine.

.DESCRIPTION
  Looks up the GitHub Release tagged "nightly" (published on every push to
  main) and downloads honeypot-windows-<arch>.exe. Falls back to GitHub
  Actions artifacts via the `gh` CLI when --From actions is set, or when
  the release is missing (PR builds).

.EXAMPLE
  .\install.ps1
  $env:GITHUB_REPO = 'owner/name'; .\install.ps1
  .\install.ps1 -Repo owner/name -Output .\honeypot.exe
  .\install.ps1 -From actions -Pr 42
#>
[CmdletBinding()]
param(
  [string]$Repo = $(if ($env:GITHUB_REPO) { $env:GITHUB_REPO } elseif ($env:GITHUB_REPOSITORY) { $env:GITHUB_REPOSITORY } else { '' }),
  [ValidateSet('', 'release', 'actions')]
  [string]$From = '',
  [string]$Tag = 'nightly',
  [string]$Pr = '',
  [string]$RunId = '',
  [string]$Output = '',
  [string]$Dir = '.'
)

$ErrorActionPreference = 'Stop'

function Write-Log([string]$Message) {
  Write-Host "==> $Message"
}

function Get-GitHubRepoFromRemote {
  try {
    $url = git remote get-url origin 2>$null
    if (-not $url) { return $null }
    $url = $url.Trim().TrimEnd('/').TrimEnd('.git')
    if ($url -match 'github\.com[:/](.+?/.+)$') { return $Matches[1] }
  } catch {}
  return $null
}

function Get-AuthHeaders {
  $token = $env:GITHUB_TOKEN
  if (-not $token) { $token = $env:GH_TOKEN }
  $h = @{
    'Accept'                 = 'application/vnd.github+json'
    'X-GitHub-Api-Version'   = '2022-11-28'
    'User-Agent'             = 'honeypot-install'
  }
  if ($token) { $h['Authorization'] = "Bearer $token" }
  return $h
}

function Get-Target {
  $arch = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString().ToLowerInvariant()
  switch ($arch) {
    'x64'   { $goarch = 'amd64' }
    'arm64' { $goarch = 'arm64' }
    default {
      # Windows PowerShell 5.x fallback
      if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { $goarch = 'arm64' }
      else { $goarch = 'amd64' }
    }
  }
  return @{ Os = 'windows'; Arch = $goarch }
}

if (-not $Repo) { $Repo = Get-GitHubRepoFromRemote }
if (-not $Repo) {
  throw "Could not determine GitHub repo. Pass -Repo owner/name or set GITHUB_REPO."
}

$target = Get-Target
$asset = "honeypot-$($target.Os)-$($target.Arch).exe"
$artifactName = "honeypot-$($target.Os)-$($target.Arch)"

if (-not (Test-Path -LiteralPath $Dir)) {
  New-Item -ItemType Directory -Path $Dir | Out-Null
}
$Dir = (Resolve-Path $Dir).Path
if (-not $Output) { $Output = Join-Path $Dir 'honeypot.exe' }

Write-Log "target  : $($target.Os)/$($target.Arch)"
Write-Log "repo    : $Repo"
Write-Log "asset   : $asset"
Write-Log "output  : $Output"

$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("honeypot-dl-" + [guid]::NewGuid().ToString('n'))
New-Item -ItemType Directory -Path $tmp | Out-Null
try {
  $got = $false

  if ($From -eq '' -or $From -eq 'release') {
    try {
      $headers = Get-AuthHeaders
      $api = if ($Tag -eq 'latest') {
        "https://api.github.com/repos/$Repo/releases/latest"
      } else {
        "https://api.github.com/repos/$Repo/releases/tags/$Tag"
      }
      Write-Log "looking up release $Tag on $Repo"
      $rel = Invoke-RestMethod -Uri $api -Headers $headers
      $item = $rel.assets | Where-Object { $_.name -eq $asset } | Select-Object -First 1
      if (-not $item) { throw "asset $asset not in release $Tag" }
      Write-Log "downloading $($item.browser_download_url)"
      $outFile = Join-Path $tmp $asset
      Invoke-WebRequest -Uri $item.browser_download_url -Headers $headers -OutFile $outFile -UseBasicParsing
      $got = $true
    } catch {
      if ($From -eq 'release') { throw }
      Write-Log "release download failed ($($_.Exception.Message)); falling back to Actions artifacts"
    }
  }

  if (-not $got) {
    if (-not (Get-Command gh -ErrorAction SilentlyContinue)) {
      throw "the GitHub CLI (gh) is required for Actions artifacts. Install it from https://cli.github.com/"
    }
    $rid = $RunId
    if (-not $rid -and $Pr) {
      Write-Log "resolving latest successful run for PR #$Pr"
      $branch = gh pr view $Pr --repo $Repo --json headRefName -q .headRefName
      $rid = gh run list --repo $Repo --branch $branch --workflow go-honeypot.yml --status success --limit 1 --json databaseId -q '.[0].databaseId'
    }
    if (-not $rid) {
      Write-Log "resolving latest successful run on main"
      $rid = gh run list --repo $Repo --branch main --workflow go-honeypot.yml --status success --limit 1 --json databaseId -q '.[0].databaseId'
    }
    if (-not $rid) { throw "no successful workflow run found for $Repo" }
    Write-Log "downloading artifact $artifactName from run $rid"
    gh run download $rid --repo $Repo --name $artifactName --dir $tmp
    $found = Get-ChildItem -Path $tmp -Recurse -File -Filter 'honeypot-windows-*' | Select-Object -First 1
    if (-not $found) { throw "artifact $artifactName did not contain $asset" }
    if ($found.FullName -ne (Join-Path $tmp $asset)) {
      Copy-Item $found.FullName (Join-Path $tmp $asset) -Force
    }
    $got = $true
  }

  if (-not $got) { throw "could not fetch $asset from $Repo" }

  $parent = Split-Path -Parent $Output
  if ($parent -and -not (Test-Path $parent)) {
    New-Item -ItemType Directory -Path $parent | Out-Null
  }
  Copy-Item (Join-Path $tmp $asset) $Output -Force
  Write-Log "installed $Output"
  Write-Log "run it with:  $Output"
} finally {
  Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}
