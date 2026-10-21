# Changelog

## 0.1.2 – 2026-10-21

- **A new look for the installer:** a DCPGP logo in color, one line with a check mark per step instead of the raw output of Git, npm and the build, and a summary at the end. The raw output is only shown if something fails, together with the log file.
- **The installer finds your Discord by itself** – no more choosing with the arrow keys; it only asks when several Discord versions are installed. At the end it offers to restart Discord for you.
- **DcPgp switches itself on** after installing; there is no need to look for it in the plugin list anymore.

## 0.1.1 – 2026-10-21

- **One-command installer.** In a normal PowerShell window, `irm https://raw.githubusercontent.com/Algonilol/dc-pgp/main/install.ps1 | iex` checks Git and Node.js, downloads and builds Vencord with DcPgp and patches Discord. Running it again updates everything.
- **Key requests link to DcPgp,** so people without the plugin see where to get it. The link is in angle brackets, so Discord shows no preview card under the request.
- **README:** a table of contents, the quick install, a note that DcPgp makes no network connections of its own, that it has only been tested by its author so far, and how to remove it again. The manual install now uses `npm ci --omit=dev`, which leaves out the test tools.

Compatible with 0.1.0: vault, keys and contacts stay as they are.

## 0.1.0 – 2026-10-21

The first public version.
