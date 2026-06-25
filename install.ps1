# NeuroSploit installer for Windows (PowerShell) — by Joas A Santos & Red Team Leaders
#
#   irm https://raw.githubusercontent.com/JoasASantos/NeuroSploit/main/install.ps1 | iex
#
# Installs the Rust toolchain if needed, clones the repo, builds the release
# binary, and adds it to your PATH. Works on x64 and arm64.
$ErrorActionPreference = "Stop"

function Say($m) { Write-Host "  > $m" -ForegroundColor Magenta }
function Ok ($m) { Write-Host "  + $m" -ForegroundColor Green }
function Warn($m){ Write-Host "  ! $m" -ForegroundColor Yellow }

Write-Host ""
Write-Host "  NeuroSploit installer (Windows) — v3.5.1" -ForegroundColor Cyan
$arch = $env:PROCESSOR_ARCHITECTURE
Say "Platform: Windows / $arch"

$dir    = if ($env:NEUROSPLOIT_DIR) { $env:NEUROSPLOIT_DIR } else { Join-Path $HOME ".neurosploit-src" }
$ref    = if ($env:NEUROSPLOIT_REF) { $env:NEUROSPLOIT_REF } else { "main" }

# 1) git
if (-not (Get-Command git -ErrorAction SilentlyContinue)) { throw "git is required (install Git for Windows) and re-run." }

# 2) Rust (rustup) — winget if available, else the rustup-init bootstrap
if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
  Say "Rust not found — installing rustup..."
  if (Get-Command winget -ErrorAction SilentlyContinue) {
    winget install -e --id Rustlang.Rustup --accept-source-agreements --accept-package-agreements
  } else {
    $ri = Join-Path $env:TEMP "rustup-init.exe"
    Invoke-WebRequest "https://win.rustup.rs/$arch" -OutFile $ri
    & $ri -y --default-toolchain stable --profile minimal
  }
  $env:Path = "$HOME\.cargo\bin;$env:Path"
}
Ok ("Rust: " + (cargo --version))

# 3) clone or update
if (Test-Path (Join-Path $dir ".git")) {
  Say "Updating $dir..."; git -C $dir fetch --depth 1 origin $ref; git -C $dir reset --hard "origin/$ref"
} else {
  Say "Cloning to $dir..."; git clone --depth 1 --branch $ref "https://github.com/JoasASantos/NeuroSploit.git" $dir
}

# 4) build
Say "Building release binary (first build downloads crates)..."
Push-Location (Join-Path $dir "neurosploit-rs"); cargo build --release; Pop-Location
$bin = Join-Path $dir "neurosploit-rs\target\release\neurosploit.exe"
if (-not (Test-Path $bin)) { throw "build did not produce $bin" }
Ok ("Built: " + (& $bin --version))

# 5) add to PATH (user)
$binDir = Split-Path $bin
$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($userPath -notlike "*$binDir*") {
  [Environment]::SetEnvironmentVariable("Path", "$userPath;$binDir", "User")
  Ok "Added $binDir to your PATH (open a new terminal)."
}
Write-Host ""
Ok "Done. Launch:  neurosploit"
Write-Host "      neurosploit run http://testphp.vulnweb.com/ --subscription --model anthropic:claude-opus-4-8 -v"
