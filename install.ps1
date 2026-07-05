# NeuroSploit installer for Windows (PowerShell) — by Joas A Santos & Red Team Leaders
#
#   irm https://raw.githubusercontent.com/JoasASantos/NeuroSploit/main/install.ps1 | iex
#
# Downloads the prebuilt neurosploit.exe + agent library, installs them, and sets
# your User PATH + NEUROSPLOIT_BASE so you can run `neurosploit` from ANY folder —
# no need to cd into the repo. Falls back to building from source if needed.
# Env: NEUROSPLOIT_DIR (install dir), NEUROSPLOIT_REF (release tag),
#      NEUROSPLOIT_BUILD=1 (force source build).
$ErrorActionPreference = "Stop"

function Say($m) { Write-Host "  > $m" -ForegroundColor Magenta }
function Ok ($m) { Write-Host "  + $m" -ForegroundColor Green }
function Warn($m){ Write-Host "  ! $m" -ForegroundColor Yellow }

Write-Host ""
Write-Host "  NeuroSploit installer (Windows) — v3.5.5" -ForegroundColor Cyan

# arch → asset arch (only x64 prebuilt today; arm64 falls back to source)
$rawArch = $env:PROCESSOR_ARCHITECTURE
$arch = if ($rawArch -match 'ARM64') { "arm64" } else { "x64" }
Say "Platform: Windows / $arch"

$slug = "JoasASantos/NeuroSploit"
$dir  = if ($env:NEUROSPLOIT_DIR) { $env:NEUROSPLOIT_DIR } else { Join-Path $env:LOCALAPPDATA "NeuroSploit" }
$ref  = $env:NEUROSPLOIT_REF

# resolve latest release tag unless pinned
if (-not $ref) {
  try { $ref = (Invoke-RestMethod "https://api.github.com/repos/$slug/releases/latest").tag_name } catch { }
}
if (-not $ref) { $ref = "v3.5.5" }
Say "Release: $ref"

New-Item -ItemType Directory -Force -Path $dir | Out-Null
$installed = $false

# ---- try the prebuilt asset (no Rust needed; x64 only) ----
if ($env:NEUROSPLOIT_BUILD -ne "1" -and $arch -eq "x64") {
  $asset = "neurosploit-$ref-windows-x64.zip"
  $url   = "https://github.com/$slug/releases/download/$ref/$asset"
  $tmp   = Join-Path $env:TEMP "ns-dl"
  Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
  New-Item -ItemType Directory -Force -Path $tmp | Out-Null
  try {
    Say "Downloading prebuilt binary: $asset"
    Invoke-WebRequest $url -OutFile (Join-Path $tmp "a.zip")
    Expand-Archive -Path (Join-Path $tmp "a.zip") -DestinationPath $tmp -Force
    $exe = Get-ChildItem -Path $tmp -Recurse -Filter neurosploit.exe | Select-Object -First 1
    if (-not $exe) { throw "no neurosploit.exe in archive" }
    $srcdir = $exe.DirectoryName
    Copy-Item (Join-Path $srcdir "neurosploit.exe") (Join-Path $dir "neurosploit.exe") -Force
    Remove-Item -Recurse -Force (Join-Path $dir "agents_md") -ErrorAction SilentlyContinue
    Copy-Item (Join-Path $srcdir "agents_md") (Join-Path $dir "agents_md") -Recurse -Force
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
    $installed = $true
    Ok "Downloaded & unpacked -> $dir"
  } catch {
    Warn "Prebuilt download failed ($($_.Exception.Message)) — building from source."
  }
}

# ---- build from source (needs git + Rust) ----
if (-not $installed) {
  if (-not (Get-Command git -ErrorAction SilentlyContinue)) { throw "git is required to build from source (install Git for Windows)." }
  if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
    Say "Rust not found — installing rustup..."
    if (Get-Command winget -ErrorAction SilentlyContinue) {
      winget install -e --id Rustlang.Rustup --accept-source-agreements --accept-package-agreements
    } else {
      $ri = Join-Path $env:TEMP "rustup-init.exe"
      Invoke-WebRequest "https://win.rustup.rs/$rawArch" -OutFile $ri
      & $ri -y --default-toolchain stable --profile minimal
    }
    $env:Path = "$HOME\.cargo\bin;$env:Path"
  }
  Ok ("Rust: " + (cargo --version))
  $src = Join-Path $dir "src"
  if (Test-Path (Join-Path $src ".git")) {
    Say "Updating $src..."; git -C $src fetch --depth 1 origin $ref; git -C $src checkout -q FETCH_HEAD
  } else {
    Say "Cloning to $src..."; git clone --depth 1 --branch $ref "https://github.com/$slug.git" $src
  }
  Say "Building release binary (first build downloads crates)..."
  Push-Location (Join-Path $src "neurosploit-rs"); cargo build --release; Pop-Location
  Copy-Item (Join-Path $src "neurosploit-rs\target\release\neurosploit.exe") (Join-Path $dir "neurosploit.exe") -Force
  Remove-Item -Recurse -Force (Join-Path $dir "agents_md") -ErrorAction SilentlyContinue
  Copy-Item (Join-Path $src "agents_md") (Join-Path $dir "agents_md") -Recurse -Force
  Ok "Built -> $dir"
}

$exePath = Join-Path $dir "neurosploit.exe"
if (-not (Test-Path $exePath)) { throw "install did not produce $exePath" }

# ---- set User PATH + NEUROSPLOIT_BASE (so it runs from any folder) ----
$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($userPath -notlike "*$dir*") {
  [Environment]::SetEnvironmentVariable("Path", "$userPath;$dir", "User")
  Ok "Added $dir to your User PATH."
}
[Environment]::SetEnvironmentVariable("NEUROSPLOIT_BASE", $dir, "User")
Ok "Set NEUROSPLOIT_BASE=$dir (User)."
# make it work in THIS session too
$env:Path = "$dir;$env:Path"; $env:NEUROSPLOIT_BASE = $dir

Ok ("Version: " + (& $exePath --version))
Write-Host ""
Ok "Installed. Open a NEW terminal, then from ANY folder:"
Write-Host "      neurosploit                 # interactive session"
Write-Host "      neurosploit run http://testphp.vulnweb.com/ --subscription --model anthropic:claude-opus-4-8 -v"
Write-Host "      neurosploit --help"
Warn "Update later: just re-run this script."
