# DcPgp installer for Windows: builds Vencord with DcPgp from source and patches the Discord desktop app.
# Run it again at any time to update.
#
#   irm https://raw.githubusercontent.com/Algonilol/dc-pgp/main/install.ps1 | iex
#
# It installs into <your user folder>\Vencord. To use another folder, set $env:DCPGP_FOLDER first.
# Only ASCII in here: Windows PowerShell reads script files without a BOM as ANSI.

& {
    $pluginRepo = "https://github.com/Algonilol/dc-pgp.git"
    $vencordRepo = "https://github.com/Vendicated/Vencord.git"
    $folder = if ($env:DCPGP_FOLDER) { $env:DCPGP_FOLDER } else { Join-Path $HOME "Vencord" }
    $plugin = Join-Path $folder "src\userplugins\dcPgp.desktop"

    function Step([string]$text) {
        Write-Host ""
        Write-Host "== $text" -ForegroundColor Cyan
    }

    # Programs like git and npm don't stop a script when they fail, so every call checks the exit code.
    function Invoke-Checked([string]$what, [scriptblock]$command) {
        & $command
        if ($LASTEXITCODE -ne 0) { throw "$what failed (exit code $LASTEXITCODE). Discord was not changed." }
    }

    # A checkout that exists is updated, a missing (or empty) folder gets a fresh clone, anything else is left alone.
    function Get-Repo([string]$url, [string]$path, [string]$name) {
        if (Test-Path (Join-Path $path ".git")) {
            Invoke-Checked "Updating $name" { git -C $path pull --ff-only }
        } elseif ((Test-Path $path) -and (Get-ChildItem -Force $path | Select-Object -First 1)) {
            throw "$path exists, but it is not a git checkout of $name. Set `$env:DCPGP_FOLDER to another folder and run the installer again."
        } else {
            Invoke-Checked "Downloading $name" { git clone $url $path }
        }
    }

    $identity = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    if ($identity.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Please run the installer in a normal PowerShell window, not as administrator."
    }

    Step "Checking Git and Node.js"
    if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
        throw "Git is missing. Install it with: winget install Git.Git  - then open a new PowerShell window and run the installer again."
    }
    if (-not (Get-Command node -ErrorAction SilentlyContinue)) {
        throw "Node.js is missing. Install it with: winget install OpenJS.NodeJS.LTS  - then open a new PowerShell window and run the installer again."
    }
    $nodeVersion = [version]((node --version).Trim().TrimStart("v"))
    if ($nodeVersion -lt [version]"20.11.0") {
        throw "Node.js $nodeVersion is too old, 20.11 or newer is needed: winget upgrade OpenJS.NodeJS.LTS"
    }
    if (-not (Get-Command corepack -ErrorAction SilentlyContinue)) {
        throw "corepack is missing (newer Node.js versions leave it out). Install it with: npm install --global corepack"
    }
    Write-Host "Git and Node.js $nodeVersion found. Installing into $folder"

    Step "Vencord"
    Get-Repo $vencordRepo $folder "Vencord"

    Step "DcPgp"
    Get-Repo $pluginRepo $plugin "DcPgp"
    Push-Location $plugin
    try {
        # Only the libraries DcPgp runs with, not its test tools.
        Invoke-Checked "Installing DcPgp's libraries" { npm ci --omit=dev }
    } finally {
        Pop-Location
    }

    Push-Location $folder
    $previousPrompt = $env:COREPACK_ENABLE_DOWNLOAD_PROMPT
    $env:COREPACK_ENABLE_DOWNLOAD_PROMPT = "0"
    try {
        Step "Building"
        Invoke-Checked "Installing Vencord's libraries" { corepack pnpm install --frozen-lockfile }
        Invoke-Checked "Building Vencord" { corepack pnpm build }

        Step "Patching Discord - choose your Discord with the arrow keys and press Enter"
        Invoke-Checked "Patching Discord" { corepack pnpm inject }
    } finally {
        $env:COREPACK_ENABLE_DOWNLOAD_PROMPT = $previousPrompt
        Pop-Location
    }

    Write-Host ""
    Write-Host "Done. Quit Discord completely (also in the system tray), start it again and enable DcPgp under Settings -> Vencord -> Plugins." -ForegroundColor Green
    Write-Host "To update later, run the same command again."
}
