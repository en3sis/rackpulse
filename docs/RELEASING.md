# Releasing Rackpulse

How the owner signs, notarizes, and publishes a release. Contributors do not need this document: `make dev`, `make build`, and `make test` work with no setup.

## The workflow

1. Add a `## <version>` section to `CHANGELOG.md` with the release notes, and commit it. The update window and the GitHub release both show it.
2. Run:

```bash
make release              # patch: 0.2.1 -> 0.2.2
make release BUMP=minor   # 0.2.1 -> 0.3.0
```

`make release` stops if there are uncommitted changes, if `CHANGELOG.md` has no section for the new version, or if the agent version in `agent/VERSION` is not published yet (see "Agent releases"). Then it:

1. Bumps `VERSION`, if the current version is already tagged. An untagged version is released as it is, which is also how a failed release is retried.
2. Runs `make notarize`: builds, signs, notarizes, staples, and writes `dist/appcast.xml` with the release notes.
3. Runs `make publish`: uploads the disk images, delta updates, and the feed to R2.
4. Commits `VERSION`, tags `v<version>`, pushes, and creates the GitHub release with the disk image and the notes.

`make notarize` and `make publish` also work on their own, for example to rebuild a release without tagging it.

## Setup, one time

| Item | Where it is | How to set it |
|---|---|---|
| Developer ID Application certificate | Login keychain | Xcode, Settings, Accounts, Manage Certificates |
| Signing identity | `.env`, `SIGN_ID` (git-ignored) | Copy `.env.example` to `.env`. No quotes around values |
| Notary credentials | Login keychain, profile named in `.env` as `NOTARY_PROFILE` | `xcrun notarytool store-credentials <profile>` with the Apple ID, the team ID, and an app-specific password |
| Sparkle update key | Login keychain, account named in `.env` as `SPARKLE_ACCOUNT`, with a copy in 1Password | See "Update key" |
| Public download address | `.env`: `SITE_URL`, the public URL of the release files, without a trailing slash. Today `https://rackpulse.app` | The feed and download links are built from it, for example `$SITE_URL/download/Rackpulse.dmg`. The app's feed URL (`SUFeedURL` in `macos/Info.plist`) and the agent install URL (`AgentStore.installURL`, `agent/install.sh`) must match it |
| R2 upload credentials | `.env`: `R2_ACCOUNT_ID`, `R2_BUCKET` (today `rackpulse-prod`, the same bucket as the website), `R2_PREFIX` (a folder in the bucket, empty for the bucket root), `R2_TOKEN`, `R2_SECRET` | Cloudflare dashboard, R2, Manage API tokens, with Object Read & Write on the bucket. Copy the token value and the Secret Access Key |
| Tools | Homebrew | `create-dmg`, `rsvg-convert` |

The upload signs requests with the R2 access key pair. The Access Key ID is the token's ID, so `make publish` asks Cloudflare for it with `R2_TOKEN`. To skip that call, set `R2_ACCESS_KEY_ID` as well.

## Update key

Sparkle signs every update with a private key. Installed copies accept only updates signed with the key whose public half is `SUPublicEDKey` in `macos/Info.plist`. Without the private key, installed apps can never update again, so keep the copy in 1Password.

To create it (done once):

```bash
macos/.build/artifacts/sparkle/Sparkle/bin/generate_keys --account "$SPARKLE_ACCOUNT"
```

To restore it on a new Mac from the 1Password copy:

```bash
op read "op://<vault>/<item>/<field>" > /tmp/rackpulse-key
macos/.build/artifacts/sparkle/Sparkle/bin/generate_keys --account "$SPARKLE_ACCOUNT" -f /tmp/rackpulse-key
rm /tmp/rackpulse-key
```

Exported key files are git-ignored by the pattern `*sparkle-key*`. Delete them after you store them.

## What `make notarize` does

1. Stops if `SIGN_ID` is not set.
2. Builds the app with the version from `VERSION`, signed with the Developer ID and the hardened runtime, and the release entitlements (App Sandbox, outgoing network, Sparkle installer).
3. Sends the app to the Apple notary service, waits, and staples the ticket.
4. Builds the disk image, signs it, notarizes it, staples it, and checks it with Gatekeeper.
5. Moves it to `dist/Rackpulse-<version>/Rackpulse-<version>.dmg`.
6. Writes `dist/appcast.xml` from the disk images of all versions, signed with the update key. Sparkle makes delta files from older versions into each version's folder.

The two notary steps take most of the time, usually 2 to 10 minutes each. If a step fails, fix the cause and run `make notarize` again. The version stays the same.

## What goes to R2

Bucket `R2_BUCKET`, folder `R2_PREFIX` (empty means the bucket root), served at `SITE_URL`. The website is in the same bucket. Publishing the website never deletes `appcast.xml`, `download/` or `agent/`, and publishing a release never touches the website.

| Path | Source | Cache |
|---|---|---|
| `appcast.xml` | `dist/appcast.xml` | 5 minutes |
| `download/Rackpulse-<version>.dmg` and `*.delta` | `dist/Rackpulse-<version>/` | 1 year, never changes |
| `download/Rackpulse.dmg` | The newest disk image | 5 minutes |

The app reads `appcast.xml` (`SUFeedURL` in `macos/Info.plist`) one time each day and when the user selects Check for Updates.

Keep the `dist/Rackpulse-<version>/` folders. The feed is built from all of them. `dist/` is git-ignored, and `make clean` does not remove them.

## Agent releases

The Linux agent has its own version in `agent/VERSION` and ships separately from the app.

```bash
echo 0.2.2 > agent/VERSION
make test-agent       # Go tests
make agent            # build both binaries, SHA256SUMS and install.sh into dist/agent/<version>
make publish-agent    # upload to R2 under agent/ (inside R2_PREFIX when it is set)
```

| Path | Cache |
|---|---|
| `agent/install.sh`, `agent/rackpulse-agent-linux-amd64`, `agent/rackpulse-agent-linux-arm64`, `agent/SHA256SUMS` | 5 minutes |
| `agent/<version>/` with the same files | 1 year, never changes |

The app offers the agent in `agent/VERSION` as the latest one. `make build` writes it into the app's `Info.plist` as `RackpulseAgentVersion`, and servers with an older agent show an update notice with the command. So publish a new agent before the app release that should offer it. `make release` checks this: it stops if `$SITE_URL/agent/<agent version>/SHA256SUMS` does not exist yet.

The app and the agent keep separate versions. A new app works with older agents and skips what they don't support, so an app release does not need a new agent.

## Checks after a release

```bash
curl -s "$SITE_URL/appcast.xml" | grep -E "<title>|sparkle:version"
curl -sI "$SITE_URL/download/Rackpulse.dmg" | head -5
```

Then open an installed older version and select Check for Updates.
