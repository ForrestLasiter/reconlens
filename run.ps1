<#
.SYNOPSIS
  Windows runner for ReconLens (Docker Desktop or WSL-backed Docker).

.DESCRIPTION
  Builds the image and runs the container with the correct mounts + env,
  avoiding the single-file bind-mount footgun. Mirrors run.sh for Linux/WSL.

.EXAMPLE
  .\run.ps1              # build (if needed) + run in the foreground
  .\run.ps1 -Rebuild     # force a rebuild first
  .\run.ps1 -Detach      # run in the background
#>
param(
  [switch]$Rebuild,
  [switch]$Detach
)

$ErrorActionPreference = "Stop"
Set-Location -Path $PSScriptRoot

$Image = "reconlens:latest"
$Name  = "reconlens"
$Port  = 8077

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
  Write-Error "docker not found on PATH. Install Docker Desktop or enable WSL Docker integration."
}

if (-not (Test-Path "scope.yaml")) {
  Write-Host "[*] No scope.yaml found - creating one from scope.example.yaml" -ForegroundColor Cyan
  Copy-Item scope.example.yaml scope.yaml
}

# Refuse to run against the shipped placeholders (example.com is a real,
# third-party IANA domain - scanning it is not authorized).
if (Select-String -Path scope.yaml -Pattern '^\s*-\s*(example\.com|vpn\.example\.org)\s*$' -Quiet) {
  Write-Host "!! scope.yaml still contains placeholder targets." -ForegroundColor Yellow
  Write-Host "   Edit scope.yaml and list only the domain(s)/IP(s) YOU own, then re-run."
  Write-Host "   (ReconLens will only scan what you explicitly list.)"
  exit 1
}

New-Item -ItemType Directory -Force -Path "data" | Out-Null

$haveImage = docker image inspect $Image 2>$null
if ($Rebuild -or -not $haveImage) {
  Write-Host "[*] building $Image ..." -ForegroundColor Cyan
  docker build -t $Image .
  if ($LASTEXITCODE -ne 0) { Write-Error "build failed" }
}

docker rm -f $Name 2>$null | Out-Null

# Docker on Windows wants forward-slash host paths; ${PWD} works in Docker Desktop.
$cwd = (Get-Location).Path -replace '\\','/'
$detachArg = if ($Detach) { "-d" } else { "" }

Write-Host "[*] starting ReconLens on http://localhost:$Port" -ForegroundColor Green
$dockerArgs = @(
  "run","--rm"
) + @($detachArg | Where-Object { $_ }) + @(
  "--name",$Name,
  "-p","$Port`:8077",
  "-e","RECONLENS_SCOPE=/app/scope.yaml",
  "-e","RECONLENS_DB=/app/data/reconlens.db",
  "-v","$cwd/scope.yaml:/app/scope.yaml:ro",
  "-v","$cwd/data:/app/data",
  $Image
)
& docker @dockerArgs
