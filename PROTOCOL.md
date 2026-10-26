# dcpgp/1

This document describes what DcPgp sends through Discord and what it stores locally, so that it can be reviewed and reimplemented.

All dcpgp/1 content is ordinary Discord message text. A client recognises it by its **first line, which must contain `dcpgp/1`**. The human-readable wording around the marker is free and may change (earlier versions used German).

## Encrypted message

````
-# 🔒 Encrypted message · dcpgp/1
```
-----BEGIN PGP MESSAGE-----
…
-----END PGP MESSAGE-----
```
````

Nothing follows the closing fence, and receivers ignore anything that does. Mentions inside the encrypted text therefore do not ping: Discord cannot see them.

The PGP block is an OpenPGP message with:

- **SEIPD v1** (integrity-protected, no AEAD) and **AES-256**, so GnuPG and Kleopatra can decrypt it;
- **no compression**;
- a **signature** by the sender's key;
- one encrypted session key for **every reader and for the sender**, with **wildcard key ids** (recipients are not visible).

A receiver rejects armored messages over 64 KiB, more than 100 encrypted session keys and more than 1 MiB of plaintext. A sender encrypts to at most 50 readers and refuses messages that would exceed Discord's length limit (2,000 characters, 4,000 with Nitro).

An **edit** replaces the content with a new message of the same format: encrypted to the chat's readers as they are now, with `t` set to the time of the edit, which receivers compare with Discord's edit timestamp. If the text did not change, nothing is sent. In an encrypted chat, and for an encrypted message anywhere, an edit is never saved unencrypted.

### Inner plaintext

```
<text>\n-- dcpgp/1;s=<sender id>;c=<channel id>;r=<recipient ids, comma-separated>;t=<intended send time, ms>;a=<attachment ids>;p=<padding>
```

- The **last** occurrence of `\n-- dcpgp/1;` counts, so a line typed into the text cannot override the metadata.
- `a` (only with encrypted files) lists the message's files in order, at most 10; see [Encrypted files](#encrypted-files). Parsers that don't know it ignore it.
- `p` is random URL-safe padding that brings the UTF-8 length to a multiple of 64 bytes.

### Checks on receipt

| Check | Result if it fails |
|---|---|
| Signature valid and made by the stored key of the Discord author (own key for own messages) | error, or a warning if no key of the author is stored |
| If a replaced key of the author (or one of the user's own replaced keys) signed it: Discord's timestamp is at most 10 minutes after the new key was announced – Discord's time of the key message, or the acceptance if that message is older than the key it replaced | error: possibly forged with the old key (warning if the time is not recorded) |
| `s` equals the Discord author | error: the block was re-posted by another account |
| `c` equals the channel | warning: copied or forwarded |
| Own id in `r` (unless sender) | warning: probably forwarded |
| `t` within 10 minutes of Discord's timestamp | warning: old or replayed |
| No earlier message (by Discord's time, a later edit counting as new; then by snowflake id) decrypted since unlocking has the same decrypted content (SHA-256), whatever the armor looks like | warning: replayed or re-posted copy |

A signature made after the stored copy of the author's key expired cannot be checked. It is reported as such – an error, not "forged" – and checked again once an updated copy of the key arrives.

### Encrypted files

1:1 DMs only. Discord uploads an attachment as soon as it is added to the chat input, so a file is encrypted at that moment, not on sending:

- The file becomes an OpenPGP message like a text message (signed, every reader and the sender as recipients, wildcard key ids, SEIPD v1, AES-256, no compression), but **binary**, with the original file name in the literal data. GnuPG opens it: `gpg --decrypt --use-embedded-filename`.
- Discord gets it as `dcpgp-<n>.pgp`, with no alt text and no spoiler flag.
- Its **id** is the first 128 bits of SHA-256 over the encrypted file, base64url (22 characters). The message sent with the files lists their ids in `a`, so the signature over the message covers which files belong to it; a message with files and no text still carries this list.
- Files are encrypted for the chat's readers at the time of attaching. If they changed before sending (a new key), the message is refused and the files have to be attached again.

On receipt, a file is downloaded from Discord's CDN, its id must be in the message's `a` list, it must decrypt for the reader, and its signature must be by the key that signed the message – otherwise it is not shown. Pictures (PNG, JPEG, GIF, WebP, AVIF), videos (MP4, WebM) and audio (MP3, Ogg, Opus, WAV, M4A, FLAC) are shown inline, chosen by the file name's extension; everything else, SVG and HTML included, is only offered for saving. Displayed names lose paths, control characters and direction marks. An edit keeps the message's `a` list.

Trust levels: **verified** (signature fine, the contact's safety number was compared, and no warning), **unverified**, **failed** (any error).

## Key exchange

````
-# 🔑 Key request · dcpgp/1 keyreq
I'd like to chat with you end-to-end encrypted with DcPgp, a Vencord plugin. Get it here: <https://github.com/Algonilol/dc-pgp> – without it, you can ignore this message.
```
-----BEGIN PGP PUBLIC KEY BLOCK-----
…
-----END PGP PUBLIC KEY BLOCK-----
```
````

A key response looks the same with `keyresp`. The key is a **minimal transferable public key**: primary key, one user id with its two newest self-signatures, the current encryption and signing subkeys with their two newest binding signatures, no third-party certifications.

Key messages are only accepted in **1:1 DMs**, never from oneself, and not from blocked users. The receiver decides:

| Situation | `keyreq` | `keyresp` |
|---|---|---|
| No key stored, we did not ask | ask the user | ask the user |
| No key stored, our own request is pending | store it and answer with our key ("crossing requests") | store it |
| Same key as stored | take over newer signatures (see below); resend our key – without asking if their copy of ours predates its last extension, otherwise after asking | take over newer signatures |
| Different key than stored | key change: ask; encryption to this contact pauses until decided | same |
| Our own key, or the key of another contact | rejected | rejected |

Stored keys stay **unverified** until the safety numbers are compared. A user may send at most one request per contact per 24 hours (more after a confirmation).

## Key lifetime

Keys generated by DcPgp are Curve25519 keys (Ed25519 primary key for signatures, X25519 subkey for encryption), valid for **two years**.

**Extension.** When less than a year is left – or the key has already expired, but was not revoked – the client extends the own key after unlocking: a new self-signature for the user id and new binding signatures for the current encryption and signing subkeys, expiring two years from now. The key packets stay, so the **fingerprint and the safety numbers do not change**. The old signatures stay in the own copy, so messages signed before remain verifiable. Older or revoked subkeys are not signed again. An expired key imported at setup is extended the same way.

**Key update message.** The extended key travels as a `keyresp`, so clients that only know requests and responses treat it as a response with a known key:

````
-# 🔑 Key update · dcpgp/1 keyresp
My DcPgp key was extended. DcPgp takes the update over automatically.
```
-----BEGIN PGP PUBLIC KEY BLOCK-----
…
-----END PGP PUBLIC KEY BLOCK-----
```
````

**Distribution.** The vault records when the own key was last extended (`renewedAt`) and, per contact, when the own key was last sent to them (`sentKeyAt`; requests and responses count). A contact with an older copy receives one key update right after the user's next encrypted message in their 1:1 DM, and a key request from such a contact is answered without asking.

**Taking over an update.** A key message with the fingerprint of the stored key is merged into the stored copy. Only signatures that verify against the key itself are taken over; added user ids and third-party certifications are dropped, an added subkey is kept only with a valid binding signature. The verification status stays, because the key material is unchanged.

**Expired contact keys.** Nothing is encrypted to a contact whose stored key has expired; the user is asked to request the updated key. The lock menu offers that 30 days before expiry.

## Safety number

For each party:

1. `h = SHA-512(0x00 0x01 ‖ fingerprint ‖ UTF-8(Discord user id))`
2. 5200 times: `h = SHA-512(h ‖ fingerprint)`
3. Bytes 0–29 of `h` in 6 chunks of 5 bytes; each chunk as a big-endian integer modulo 100000 → 5 digits.

The two 30-digit strings are sorted and concatenated: 60 digits, identical on both sides, shown as 12 groups of 5.

## Local vault (never sent)

- The vault content (keys, contacts, chat settings; JSON) is encrypted with a random 256-bit **data key** using AES-256-GCM. The associated data binds version, mode, owner and own fingerprint.
- **Slot A** (mode *Stored*): the data key, encrypted with `HKDF-SHA256(Argon2id(password) ‖ device key, salt, "dcpgp vault slotA v1")`. Argon2id uses 256 MiB, p = 1, and 3–10 passes calibrated to about one second. The device key is 32 random bytes protected by Electron safeStorage (Windows DPAPI) in Vencord's data folder; it never leaves the main process. Where safeStorage is unavailable, the password alone is used (info `"dcpgp vault slotA v1 (no device)"`).
- **Slot B**: the data key, OpenPGP-encrypted to the own key, for recovery with the key file.
- **Slot W** ("Unlock with Windows", optional, *Stored* mode only, next to slot A): the data key, encrypted with `HKDF-SHA256(device key, salt, "dcpgp vault slotW v1")` – no password. The plugin then unlocks on startup, and again when Windows unlocks after DcPgp locked with the screen. Switching it on needs the vault password; switching it off too, and it creates a new data key and replaces the fallback copy, so no older copy opens without the password. Changing the password keeps it; *RAM only* drops it.
- **RAM only** mode has no slot A and keeps no private key in the vault; unlocking needs the key file. A key file older than the vault is refreshed on unlock with the newer signatures of the vault's copy of the public key.
- **Previous version**: every save keeps the version before as a fallback copy, used if the current one is damaged. Changing the password creates a new data key and replaces the fallback copy too, so neither the old password nor an old copy opens the vault; removing the stored private key also replaces it.
- **Vault backup** (`.dcpgp`, JSON): the content encrypted with AES-256-GCM under `HKDF-SHA256(Argon2id(backup password), salt, "dcpgp backup v1")`, header bound as associated data, no device key.
- To recognise encrypted chats while locked, the plugin stores `HMAC-SHA256(guard key, "dcpgp-guard|" ‖ channel id)` truncated to 128 bits, never the channel ids themselves.
