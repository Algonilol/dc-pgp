# Test fixtures

Throwaway OpenPGP keys and a message, made with GnuPG only for the tests. They protect nothing: the private keys and their passphrase (`gpg-passphrase.txt`) are public on purpose, so the tests can check that DcPgp works with keys and messages from GnuPG and Kleopatra. **Never use them for real messages.**

The keys expire on 2028-10-19; the tests need new ones before then.
