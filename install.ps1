# install.ps1
# CoReason Platform Swarm-in-a-Box bootstrap installer script for Windows

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

# 1. Check and install uv if not present
if (-not (Get-Command uv -ErrorAction SilentlyContinue)) {
    Write-Host "=== Installing uv package manager ===" -ForegroundColor Cyan
    powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
    # Ensure uv is in path for this terminal session
    $env:Path += ";$HOME\.local\bin"
}

# 2. Launch CLI or Web Installer using uv
$LaunchWeb = $false
foreach ($arg in $args) {
    if ($arg -eq "--web" -or $arg -eq "--gui") {
        $LaunchWeb = $true
        break
    }
}

Set-Location $ScriptDir
if ($LaunchWeb) {
    Write-Host "=== Bootstrapping CoReason Web Setup Dashboard ===" -ForegroundColor Cyan
    uv run src/web_gui.py
} else {
    Write-Host "=== Bootstrapping CoReason CLI Installer ===" -ForegroundColor Cyan
    uv run src/cli.py $args
}
