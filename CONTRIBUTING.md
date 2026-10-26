# Contributing

Thanks for helping! Bug reports and ideas are welcome as [issues](../../issues/new/choose) – the forms ask for what is needed. Security problems: please report them privately, see [SECURITY.md](SECURITY.md).

## Pull requests

Small, focused pull requests are the easiest to review. For larger changes, please open an issue first, so we can agree on the approach.

DcPgp protects people's messages, so a few rules are strict:

- **Fail closed.** If something goes wrong, nothing is sent – never plaintext in an encrypted chat.
- **No secrets in logs or messages.** Never log or display plaintext, keys, passwords or vault content, not even in error messages.
- **Logic in `core/`, with tests.** Decisions and cryptography are pure functions in `core/`, covered by `tests/`; `discord/` and `ui/` only connect them to Discord.
- **No changes to Vencord itself** – only to this plugin.
- **New dependencies** need a good reason; versions are pinned.
- **English** for code, comments, interface and documentation.
- **Protocol changes** must keep working with existing clients and are described in [PROTOCOL.md](PROTOCOL.md).

## Checks

In the plugin folder:

```powershell
npm ci
npm test
npm run simulate
```

`npm run simulate` drives the real plugin through two accounts on a simulated Discord and fails if anything that should stay encrypted reaches it. Add a step there for every new flow.

In the Vencord folder:

```powershell
corepack pnpm exec tsc --noEmit
corepack pnpm exec eslint --no-ignore --rule "simple-header/header: off" --rule "prefer-destructuring: off" "src/userplugins/dcPgp.desktop/**/*.{ts,tsx}" --ignore-pattern "**/node_modules/**"
corepack pnpm build
```

If you changed anything outside `core/`, please also try it in Discord with two accounts (for example Discord Stable and PTB) before opening the pull request.
