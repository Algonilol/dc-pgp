# Security

## Reporting a vulnerability

Please **do not open a public issue** for security problems. Use GitHub's private reporting instead: *Security* tab → *Report a vulnerability*.

Helpful in a report: what an attacker needs (position, access), what they gain, and the steps to reproduce it. Only the latest version on the default branch is supported.

## Threat model

**DcPgp aims to protect the content of text messages against:**

- Discord itself and anyone with access to Discord's servers, data or backups;
- network observers;
- other chat participants who re-post, forward or replay encrypted blocks, or forge a sender;
- a stolen vault file (without the password and this PC's device key);
- its own failures: if the hooks break after a Discord or Vencord update, encrypted chats refuse to send instead of leaking plaintext.

**It does not protect against:**

- malware, other Vencord plugins, or anyone controlling your Windows account while DcPgp is unlocked;
- a malicious Discord client update that bypasses the plugin;
- metadata: who writes to whom, when, how often and roughly how much;
- your contacts: they see the plaintext and can copy it;
- key substitution before safety numbers are compared (trust on first use).

## Design limits you should know

- **No forward secrecy.** OpenPGP encrypts to long-term keys. Whoever obtains a private key and old ciphertext can read those messages.
- **Device binding uses DPAPI.** Code running as your Windows user – including other plugins inside Discord – can unwrap the device key; the vault password is then the remaining barrier.
- **No revocation.** A contact's replaced key is not revoked: messages it signed earlier stay valid. A message signed with it that Discord received after you accepted the new key is rejected.
- **Replays within 10 minutes.** Each message carries its signed send time and chat, so a block delivered again later is flagged. Within the 10-minute clock tolerance, a replay is only noticed while the original message is still in the chat.
- **Not audited.** The cryptography comes from OpenPGP.js, hash-wasm (Argon2id), @noble/hashes and the Web Crypto API. The protocol around it ([PROTOCOL.md](PROTOCOL.md)) is this project's own and has not been reviewed independently.
