# rackpulse-agent

The optional Linux agent for Rackpulse. It is one static Go binary that runs as a systemd service and serves memory, disks, Docker containers and uptime history over HTTPS. The protocol, install options and security model are in [../docs/AGENT.md](../docs/AGENT.md).

## Layout

| Path | Contents |
|---|---|
| `cmd/rackpulse-agent` | `main`: subcommands, and the version set at build time |
| `internal/config` | Config file, file paths, pairing key validation |
| `internal/pairing` | TLS certificate, fingerprint, `/v1/hello` proof |
| `internal/collect` | Host, memory, disks, systemd, Hetzner metadata, Docker, and the snapshot taken every 60 seconds |
| `internal/security` | Packages, pending updates, hardening checks, listening ports, Compose lockfiles and container images for `/v1/security` |
| `internal/history` | Uptime minutes, host samples, container samples, and their files |
| `internal/boots` | Past boots from the system journal, read at install |
| `internal/server` | HTTPS handlers, key check, and the `run` daemon |
| `internal/install` | `install`, `set-key`, `uninstall`, `status`, the systemd unit, and the upgrade from `rackbar-agent` |
| `internal/atomicfile` | Writes a file through a temporary file and a rename |
| `install.sh` | The script behind `curl ... \| sudo sh`, with the release public key |
| `VERSION` | The release version |

Imports go one way. `history` stores what `collect` produces, `security` reads Docker through `collect`, `boots` writes into `history`, and `server` and `install` use the rest. Only `main` imports `server` and `install`.

## Build and test

Go 1.23 or newer. Standard library only.

```bash
cd agent
go vet ./...
go test ./...
```

From the repository root, `make agent` builds `dist/agent/<version>/` with `rackpulse-agent-linux-amd64`, `rackpulse-agent-linux-arm64`, `SHA256SUMS` and `install.sh`, plus `SHA256SUMS.sig` when `AGENT_SIGNING_KEY` is set (see "Agent signing key" in [../docs/RELEASING.md](../docs/RELEASING.md)). `install.sh` refuses a build without `SHA256SUMS.sig`. `make test-agent` runs the tests.

To build one binary by hand:

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath \
  -ldflags "-s -w -X main.version=dev" -o rackpulse-agent ./cmd/rackpulse-agent
```

## Try it on Linux

Any Linux machine with systemd works. Copy the binary over and run `sudo ./rackpulse-agent install --pair <key>`. A key is `rb1_` followed by 43 characters:

```bash
key="rb1_$(openssl rand 32 | base64 | tr '+/' '-_' | tr -d '=')"
```

With OrbStack on a Mac, a machine sees your files under `/Users`, so `install.sh` can read the build output through a `file://` URL. Set `AGENT_SIGNING_KEY` before `make agent`, because `install.sh` refuses an unsigned build:

```bash
make agent
orbctl create ubuntu agent-dev
orb -m agent-dev -u root sh -c "RACKPULSE_AGENT_URL=file://$PWD/dist/agent/$(cat agent/VERSION) sh $PWD/dist/agent/$(cat agent/VERSION)/install.sh --pair $key"
curl -sk "https://agent-dev.orb.local:7311/v1/hello?nonce=$(openssl rand -hex 32)"
curl -sk -H "Authorization: Bearer $key" https://agent-dev.orb.local:7311/v1/snapshot
orbctl delete -f agent-dev
```

OrbStack machines turn off most systemd sandboxing with `/run/systemd/system/service.d/zzz-lxc-service.conf`. To test the agent under the same sandbox as a real server, add `/etc/systemd/system/rackpulse-agent.service.d/sandbox.conf` that sets `ProtectSystem=strict`, `ProtectHome=read-only`, `PrivateTmp=yes`, `PrivateDevices=yes`, `ProtectKernelTunables=yes`, `ProtectKernelModules=yes`, `ProtectKernelLogs=yes`, `ProtectControlGroups=yes` and `NoNewPrivileges=yes`, then restart the service.

For a quick check without systemd, for example in a container, `rackpulse-agent run` reads `/etc/rackpulse-agent/config.json` and writes to `/var/lib/rackpulse-agent`, which must exist:

```json
{ "token": "rb1_...", "port": 7311, "listen": "" }
```

## Code style

- Standard library only.
- No comments. Names and small functions carry the meaning.
- Everything lives under `internal/`. Nothing here is a public library.
- `gofmt` and `go vet ./...` must be clean, also with `GOOS=linux`.
