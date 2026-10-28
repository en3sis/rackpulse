# Contributing to Rackpulse

Thanks for helping. Bug reports, ideas, and pull requests are all welcome.

## Before you start

- **Bugs:** open an issue with your macOS version, the Rackpulse version (Settings, About), and steps to reproduce. For agent issues, add the agent version (`rackpulse-agent version`) and the server's distribution.
- **Larger changes:** open an issue or ask on [Discord](https://discord.gg/s4AzG5sc36) first, so we can agree on the approach before you write code.
- **Security issues:** don't open a public issue. See [SECURITY.md](SECURITY.md).

## Set up

You need Xcode 16 or later for the app and Go 1.23 or later for the agent.

```bash
make dev          # build and run Rackpulse Dev; Ctrl-C stops it
make test         # HetznerKit unit tests
make test-agent   # agent vet and tests
```

`make dev` builds Rackpulse Dev, a separate app with its own settings and Keychain entries, so it runs next to an installed Rackpulse. It signs with your Apple Development certificate when you have one, so the Keychain doesn't ask for access after every build. Without one, it signs ad hoc.

To see every screen without clicking through, run a dev build with `RACKPULSE_SNAPSHOTS=<folder>`. It waits for data, saves each screen in light and dark mode to `~/Downloads/<folder>`, and quits.

The agent has its own guide: [agent/README.md](agent/README.md).

## Guidelines

- Keep changes focused. One pull request per fix or feature.
- Match the style around your change. The code has no comments: use clear names and small functions instead.
- UI text is plain and concrete. Say what something is or does, in sentence case.
- Add or update tests where logic is easy to get wrong: alert rules, cost math, uptime, parsing, and the agent protocol.
- The app must stay read-only with a Read token, and the agent must stay read-only. Pull requests that weaken either won't be merged.
- Run `make test` and `make test-agent` before you open a pull request.

## License

By contributing, you agree that your contributions are licensed under the [MIT License](LICENSE).
