# Changelog

## 0.1.3 – 2026-10-26

New:

- **Encrypted files in 1:1 DMs.** Pictures, videos, audio and any other file up to 100 MB. DcPgp encrypts a file the moment you attach it; your contact sees pictures, videos and audio in the chat and saves any file with one click. The message lists its files, signed, so none can be swapped.
- **Editing encrypted messages.** The edit box shows your text instead of the PGP block, and saving encrypts the new text again. An unchanged text saves nothing.
- **Unlock with Windows** (optional, in the setup or the settings): no password to type – DcPgp opens when Discord starts and when you unlock Windows, protected by your Windows account instead of your password.
- **`npm run simulate`**: the real plugin against a simulated Discord with two accounts, run on every change; it checks that Discord never receives plaintext.

Security fixes:

- **Attaching a file in an encrypted chat no longer uploads it unencrypted.** Discord uploads attachments the moment they are added – before DcPgp could block the message. Files are now encrypted first; any other file in an encrypted chat is stopped.
- A contact's **replaced key** no longer verifies messages Discord received after the switch (dated by Discord's time of the key message, not by the PC clock). Your own replaced keys follow the same rule.
- The lock is **green only without warnings**; forwarded, misdirected and old or replayed messages show grey. **Copies** of a message are recognized by their content, however their block is formatted.
- The **emergency brake** only lets out content exactly as DcPgp builds it, and the check of your own sent messages reports text written around an encrypted block.
- **Server channels** are encrypted only for contacts who can see the channel (threads: the channel they belong to); if Discord's permission check is missing, encryption there pauses instead of including everyone.
- Smaller fixes: the lock menu says who can't read a message and why; no false "copy" warning on your own messages; leftover German words translated.

Compatible with 0.1.0–0.1.2: vault, keys and contacts stay as they are. Older versions show a file as `dcpgp-1.pgp`.

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
