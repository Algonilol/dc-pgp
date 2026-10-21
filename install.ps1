# DcPgp installer for Windows: builds Vencord with DcPgp from source and patches the Discord desktop app.
# Run it again at any time to update.
#
#   irm https://raw.githubusercontent.com/Algonilol/dc-pgp/main/install.ps1 | iex
#
# It installs into <your user folder>\Vencord. To use another folder, set $env:DCPGP_FOLDER first.
# The file is plain ASCII on purpose (Windows PowerShell reads files without a BOM as ANSI): the logo,
# symbols and box lines are made from their code points while it runs.

& {
    $pluginRepo = "https://github.com/Algonilol/dc-pgp.git"
    $vencordRepo = "https://github.com/Vendicated/Vencord.git"
    $folder = if ($env:DCPGP_FOLDER) { $env:DCPGP_FOLDER } else { Join-Path $HOME "Vencord" }
    $plugin = Join-Path $folder "src\userplugins\dcPgp.desktop"
    $logDir = Join-Path $env:TEMP ("dcpgp-install-" + (Get-Date -Format "yyyyMMdd-HHmmss"))
    $inv = [Globalization.CultureInfo]::InvariantCulture
    $state = @{ step = 0; log = ""; seconds = 0.0 }

    # ---- look ----------------------------------------------------------------------------------------
    $esc = [char]27
    $vt = [bool]$Host.UI.SupportsVirtualTerminal
    # Windows Terminal draws every symbol; the old console window lacks a few, so it gets simpler ones.
    $fancy = $vt -and [bool]$env:WT_SESSION
    $sym = @{
        ok   = if ($fancy) { [string][char]0x2714 } else { [string][char]0x221A }
        fail = if ($fancy) { [string][char]0x2716 } else { [string][char]0x00D7 }
        dot  = [string][char]0x00B7
        h    = [string][char]0x2500
        v    = [string][char]0x2502
        tl   = [string][char]0x256D
        tr   = [string][char]0x256E
        bl   = [string][char]0x2570
        br   = [string][char]0x256F
    }
    $frames = if ($fancy) {
        @(0x280B, 0x2819, 0x2839, 0x2838, 0x283C, 0x2834, 0x2826, 0x2827, 0x2807, 0x280F) | ForEach-Object { [string][char]$_ }
    } else { @("|", "/", "-", "\") }
    $color = @{
        ok     = @(34, 197, 94)
        fail   = @(239, 68, 68)
        dim    = @(148, 163, 184)
        accent = @(34, 211, 238)
    }

    function Paint([string]$text, [int[]]$rgb) {
        if (-not $vt -or -not $text) { return $text }
        return "$esc[38;2;$($rgb[0]);$($rgb[1]);$($rgb[2])m$text$esc[0m"
    }

    function Clear-Line {
        if ($vt) { Write-Host -NoNewline "`r$esc[2K" } else { Write-Host -NoNewline ("`r" + (" " * 79) + "`r") }
    }

    function Write-Row([string]$mark, [int[]]$markColor, [string]$label, [string]$detail, [string]$time) {
        Clear-Line
        Write-Host ("   " + (Paint $mark $markColor) + "  " + $label.PadRight(22) + (Paint $detail.PadRight(36) $color.dim) + (Paint $time $color.dim))
    }

    function Seconds { [string]::Format($inv, "{0:0.0}s", $state.seconds) }

    function Show-Banner {
        $art = @(
            '######7  ######7######7  ######7 ######7',
            '##F==##7##F====J##F==##7##F====J ##F==##7',
            '##I  ##I##I     ######FJ##I  ###7######FJ',
            '##I  ##I##I     ##F===J ##I   ##I##F===J',
            '######FJL######7##I     L######FJ##I',
            'L=====J  L=====JL=J      L=====J L=J'
        )
        $glyph = @{ '#' = 0x2588; '7' = 0x2557; 'F' = 0x2554; '=' = 0x2550; 'J' = 0x255D; 'I' = 0x2551; 'L' = 0x255A }
        $from = @(168, 85, 247)
        $to = @(34, 211, 238)
        Write-Host ""
        for ($row = 0; $row -lt $art.Count; $row++) {
            $line = New-Object Text.StringBuilder
            [void]$line.Append("   ")
            $chars = $art[$row].ToCharArray()
            for ($col = 0; $col -lt $chars.Count; $col++) {
                $key = [string]$chars[$col]
                if ($key -eq " ") { [void]$line.Append(" "); continue }
                # A diagonal violet-to-cyan gradient.
                $t = [Math]::Min(1.0, ($col + 2 * $row) / 51.0)
                $rgb = @(0, 1, 2) | ForEach-Object { [int]($from[$_] + ($to[$_] - $from[$_]) * $t) }
                [void]$line.Append((Paint ([string][char]$glyph[$key]) $rgb))
            }
            Write-Host $line.ToString()
        }
        Write-Host ("   " + (Paint "end-to-end encrypted DMs for Discord" $color.dim))
        Write-Host ("   " + (Paint "installing into $folder" $color.dim))
        Write-Host ""
    }

    function Show-Box([string[]]$lines, [int[]]$frameColor) {
        $width = ($lines | Measure-Object -Property Length -Maximum).Maximum + 4
        Write-Host ("   " + (Paint ($sym.tl + ($sym.h * $width) + $sym.tr) $frameColor))
        foreach ($l in $lines) {
            Write-Host ("   " + (Paint $sym.v $frameColor) + "  " + $l.PadRight($width - 2) + (Paint $sym.v $frameColor))
        }
        Write-Host ("   " + (Paint ($sym.bl + ($sym.h * $width) + $sym.br) $frameColor))
    }

    # ---- work ----------------------------------------------------------------------------------------

    # Runs a command line with its output in a log file and a spinner meanwhile; returns the exit code.
    # No input: a command that unexpectedly asks something gets an answer of nothing and stops instead of hanging.
    function Invoke-Quiet([string]$label, [string]$dir, [string]$commandLine) {
        $state.step++
        $state.log = Join-Path $logDir ("{0:D2}.log" -f $state.step)
        $info = New-Object Diagnostics.ProcessStartInfo
        $info.FileName = $env:ComSpec
        $info.Arguments = "/d /s /c `"$commandLine < NUL > `"$($state.log)`" 2>&1`""
        $info.WorkingDirectory = $dir
        $info.UseShellExecute = $false
        $info.CreateNoWindow = $true
        $watch = [Diagnostics.Stopwatch]::StartNew()
        $process = [Diagnostics.Process]::Start($info)
        try { [Console]::CursorVisible = $false } catch { }
        try {
            $i = 0
            while (-not $process.WaitForExit(80)) {
                Write-Host -NoNewline ("`r   " + (Paint $frames[$i % $frames.Count] $color.accent) + "  " + $label + " ...")
                $i++
            }
            $process.WaitForExit()
        } finally {
            try { [Console]::CursorVisible = $true } catch { }
        }
        $state.seconds = $watch.Elapsed.TotalSeconds
        return $process.ExitCode
    }

    function Stop-WithLog([string]$what, [string]$consequence) {
        Write-Row $sym.fail $color.fail $what "failed" ""
        if (Test-Path $state.log) {
            Write-Host ""
            Write-Host ("   " + (Paint "Last lines of the log:" $color.dim))
            Get-Content $state.log -Tail 15 | ForEach-Object { Write-Host ("     " + $_) }
            Write-Host ("   " + (Paint "Full log: $($state.log)" $color.dim))
        }
        throw "$what failed. $consequence"
    }

    # An existing checkout is updated, a missing (or empty) folder gets a fresh clone, anything else is left alone.
    function Sync-Repo([string]$name, [string]$url, [string]$path) {
        if (Test-Path (Join-Path $path ".git")) {
            $before = git -C $path rev-parse HEAD
            if ((Invoke-Quiet "Updating $name" $path "git pull --ff-only") -ne 0) { Stop-WithLog "Updating $name" "Discord was not changed." }
            $after = git -C $path rev-parse HEAD
            if ($before -eq $after) { return "up to date" } else { return "updated" }
        }
        if ((Test-Path $path) -and (Get-ChildItem -Force $path | Select-Object -First 1)) {
            throw "$path exists, but it is not a git checkout of $name. Set `$env:DCPGP_FOLDER to another folder and run the installer again."
        }
        $parent = Split-Path $path
        New-Item -ItemType Directory -Force $parent | Out-Null
        if ((Invoke-Quiet "Downloading $name" $parent "git clone `"$url`" `"$path`"") -ne 0) { Stop-WithLog "Downloading $name" "Discord was not changed." }
        return "downloaded"
    }

    function Find-Discord {
        @(
            @{ Name = "Stable"; Branch = "stable"; Folder = "Discord"; Exe = "Discord.exe"; Process = "Discord" },
            @{ Name = "PTB"; Branch = "ptb"; Folder = "DiscordPTB"; Exe = "DiscordPTB.exe"; Process = "DiscordPTB" },
            @{ Name = "Canary"; Branch = "canary"; Folder = "DiscordCanary"; Exe = "DiscordCanary.exe"; Process = "DiscordCanary" }
        ) | Where-Object { Test-Path (Join-Path $env:LOCALAPPDATA "$($_.Folder)\Update.exe") }
    }

    function Restart-Discord($discord) {
        $exe = Join-Path $env:LOCALAPPDATA "$($discord.Folder)\Update.exe"
        Get-Process -Name $discord.Process -ErrorAction SilentlyContinue | Stop-Process -Force
        for ($i = 0; $i -lt 50 -and (Get-Process -Name $discord.Process -ErrorAction SilentlyContinue); $i++) { Start-Sleep -Milliseconds 100 }
        Start-Process -FilePath $exe -ArgumentList "--processStart", $discord.Exe
    }

    function Install-DcPgp {
        $overall = [Diagnostics.Stopwatch]::StartNew()
        Show-Banner

        $identity = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
        if ($identity.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            throw "Please run the installer in a normal PowerShell window, not as administrator."
        }
        if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
            throw "Git is missing. Install it with:  winget install Git.Git  - then open a new PowerShell window and run the installer again."
        }
        if (-not (Get-Command node -ErrorAction SilentlyContinue)) {
            throw "Node.js is missing. Install it with:  winget install OpenJS.NodeJS.LTS  - then open a new PowerShell window and run the installer again."
        }
        $nodeVersion = [version]((node --version).Trim().TrimStart("v"))
        if ($nodeVersion -lt [version]"20.11.0") {
            throw "Node.js $nodeVersion is too old, 20.11 or newer is needed:  winget upgrade OpenJS.NodeJS.LTS"
        }
        if (-not (Get-Command corepack -ErrorAction SilentlyContinue)) {
            throw "corepack is missing (newer Node.js versions leave it out). Install it with:  npm install --global corepack"
        }
        $gitVersion = if ((git --version) -match "(\d+\.\d+\.\d+)") { $Matches[1] } else { "?" }
        $discords = @(Find-Discord)
        if ($discords.Count -eq 0) {
            throw "No Discord desktop app found. Install it from discord.com/download, start it once, then run the installer again."
        }
        Write-Row $sym.ok $color.ok "Git & Node.js" "Git $gitVersion $($sym.dot) Node.js $nodeVersion" ""

        New-Item -ItemType Directory -Force $logDir | Out-Null
        $result = Sync-Repo "Vencord" $vencordRepo $folder
        Write-Row $sym.ok $color.ok "Vencord" $result (Seconds)

        $result = Sync-Repo "DcPgp" $pluginRepo $plugin
        $total = $state.seconds
        if ((Invoke-Quiet "Installing DcPgp's libraries" $plugin "npm ci --omit=dev") -ne 0) { Stop-WithLog "Installing DcPgp's libraries" "Discord was not changed." }
        $state.seconds += $total
        $version = (Get-Content -Raw (Join-Path $plugin "package.json") | ConvertFrom-Json).version
        Write-Row $sym.ok $color.ok "DcPgp $version" $result (Seconds)

        $previousPrompt = $env:COREPACK_ENABLE_DOWNLOAD_PROMPT
        $env:COREPACK_ENABLE_DOWNLOAD_PROMPT = "0"
        try {
            if ((Invoke-Quiet "Installing Vencord's libraries" $folder "corepack pnpm install --frozen-lockfile") -ne 0) { Stop-WithLog "Installing Vencord's libraries" "Discord was not changed." }
            $total = $state.seconds
            if ((Invoke-Quiet "Building" $folder "corepack pnpm build") -ne 0) { Stop-WithLog "Building" "Discord was not changed." }
            $state.seconds += $total
            Write-Row $sym.ok $color.ok "Build" "Vencord + DcPgp" (Seconds)

            if ($discords.Count -gt 1) {
                Write-Host ""
                Write-Host "   Several Discord versions are installed:"
                for ($i = 0; $i -lt $discords.Count; $i++) { Write-Host ("     " + (Paint ([string]($i + 1)) $color.accent) + "  " + $discords[$i].Name) }
                $answer = Read-Host "   Which one should get DcPgp? (number, or Enter for all)"
                if ($answer -match "^\d+$" -and [int]$answer -ge 1 -and [int]$answer -le $discords.Count) { $discords = @($discords[[int]$answer - 1]) }
                Write-Host ""
            }
            foreach ($discord in $discords) {
                # Vencord's runner prints "Success" when the patch worked; it does not report failures in its exit code.
                $code = Invoke-Quiet "Patching Discord $($discord.Name)" $folder "corepack pnpm inject --branch $($discord.Branch)"
                if ($code -ne 0 -or -not (Select-String -Path $state.log -Pattern "Success" -Quiet)) { Stop-WithLog "Patching Discord $($discord.Name)" "Run the installer again; if it keeps failing, report it with the log." }
                Write-Row $sym.ok $color.ok "Discord $($discord.Name)" "patched" (Seconds)
            }
        } finally {
            $env:COREPACK_ENABLE_DOWNLOAD_PROMPT = $previousPrompt
        }

        Remove-Item -Recurse -Force $logDir -ErrorAction SilentlyContinue
        Write-Host ""
        Show-Box @(
            ("DcPgp $version is ready " + [string]::Format($inv, "({0:0}s).", $overall.Elapsed.TotalSeconds)),
            "",
            "Restart Discord, then click the lock next",
            "to the chat box to get started."
        ) $color.ok
        Write-Host ""

        foreach ($discord in $discords) {
            $running = [bool](Get-Process -Name $discord.Process -ErrorAction SilentlyContinue)
            $question = if ($running) { "Restart Discord $($discord.Name) now?" } else { "Start Discord $($discord.Name) now?" }
            $answer = Read-Host ("   " + $question + " [Y/n]")
            if ($answer -notmatch "^\s*n") {
                Restart-Discord $discord
                Write-Host ("   " + (Paint $sym.ok $color.ok) + "  Discord $($discord.Name) is starting.")
            }
        }
        Write-Host ""
        Write-Host ("   " + (Paint "To update later, run the same command again." $color.dim))
        Write-Host ""
    }

    try {
        Install-DcPgp
    } catch {
        Write-Host ""
        Write-Host ("   " + (Paint ($sym.fail + "  " + $_.Exception.Message) $color.fail))
        Write-Host ""
    }
}
