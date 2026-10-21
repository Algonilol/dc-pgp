# Third-party notices

Discord-PGP is licensed under GPL-3.0-or-later. It is built into [Vencord](https://github.com/Vendicated/Vencord) (GPL-3.0-or-later) and bundles the following components.

| Component | Version | License | Used for |
|---|---|---|---|
| [OpenPGP.js](https://github.com/openpgpjs/openpgpjs) (`openpgp`) | 6.3.2 | LGPL-3.0-or-later | keys, encryption, signatures |
| [hash-wasm](https://github.com/Daninet/hash-wasm) | 4.12.0 | MIT | Argon2id |
| [@noble/hashes](https://github.com/paulmillr/noble-hashes) | 2.4.0 | MIT | SHA-2, HMAC |
| [@zxcvbn-ts/core](https://github.com/zxcvbn-ts/zxcvbn), `language-common`, `language-en`, `language-de` | 4.2.0 / 4.1.3 / 4.1.1 / 4.1.1 | MIT | password strength check |
| [EFF Large Wordlist](https://www.eff.org/dice) | 2016 | CC BY 4.0, © Electronic Frontier Foundation | passphrase generator (`core/wordlist-en.txt`) |
| [Material Design Icons](https://github.com/google/material-design-icons) "lock", "lock_open" | – | Apache-2.0 | lock icon (`ui/icons.tsx`) |

**Changes to the EFF Large Wordlist:** the dice numbers were removed, and the four hyphenated words (`drop-down`, `felt-tip`, `t-shirt`, `yo-yo`) were left out, because generated passphrases use `-` as separator. 7772 of the 7776 words remain.

Development only (not bundled): [tsx](https://github.com/privatenumber/tsx) (MIT) and [@openpgp/web-stream-tools](https://github.com/openpgpjs/web-stream-tools) (MIT, type definitions).

The full license texts are included in each package under `node_modules/<package>/` after `npm ci`.
