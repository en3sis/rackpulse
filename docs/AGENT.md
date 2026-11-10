# Rackpulse agent

The agent is optional. Rackpulse works without it, using only the Hetzner API. Install the agent on a server to also see memory, disk space, Docker containers, and 30 days of uptime recorded on the server itself.

## How it works

- `rackpulse-agent` is one static binary for Linux (x86_64 and ARM64). It runs as a systemd service under its own `rackpulse` user.
- It listens on TCP port 7311 over HTTPS. Rackpulse on your Mac connects to it. The server never connects to your Mac or to any other host, except Hetzner's metadata service at `169.254.169.254` to read its own server ID.
- It is read-only. It has no endpoint that runs a command or changes anything on the server.
- It keeps 30 days of history in `/var/lib/rackpulse-agent`, so charts and uptime fill in when your Mac wakes up.
- For the Security tab it reads the installed packages (`/var/lib/dpkg/status` or `/lib/apk/db/installed`), runs `apt-get -s dist-upgrade` and `apt-config dump` to see waiting updates (both only simulate, without root), reads the SSH, apt and ufw settings, `/etc/passwd`, and the listening ports in `/proc/net`. It also reads lockfiles such as `package-lock.json` in the folders of your Docker Compose projects, when the `rackpulse` user can read them. For the images of running containers, it copies a few files out of each container through the Docker API (see "Container images"). It sends this only to Rackpulse. Your Mac does the vulnerability lookups, only if you turn them on.

## Install

Open a server in Rackpulse, choose **Set up agent**, and run the command it shows as root on the server:

```bash
curl -fsSL https://rackpulse.app/agent/install.sh | sudo sh -s -- --pair rb1_...
```

`--pair` is a key Rackpulse generated for this server. Options:

| Option | Default | Meaning |
|---|---|---|
| `--pair <key>` | | The pairing key. Required on the first install. Pass it again to pair with another Mac; the old key stops working |
| `--port <port>` | `7311` | TCP port |
| `--listen <ip>` | all addresses | Listen only on this address, for example a private network IP. `--listen tailscale` uses the server's Tailscale IPv4 address |
| `--no-docker` | | Keep the `rackpulse` user out of the `docker` group. Later installs and updates keep this choice. See "Docker access" |
| `--docker` | | Add the `rackpulse` user to the `docker` group again after `--no-docker` |
| `--allow-downgrade` | | Install even if the download is an older agent version than the installed one. Read by `install.sh` only |

Running the script again without `--pair` updates the agent and keeps its key and settings, including the Docker access choice. `--docker` and `--no-docker` cannot be used together.

The script downloads the binary for the server's architecture from `rackpulse.app`, together with `SHA256SUMS` and its signature `SHA256SUMS.sig`. It checks the signature with `openssl` against the release public key written in `install.sh`, then checks the binary against its SHA-256 checksum, and stops without installing anything if either check fails. It also stops if the download is an older version than the installed agent, or if either version cannot be read, unless you pass `--allow-downgrade`. This keeps an old signed release from being installed over a newer one. Then it runs `rackpulse-agent install`, which:

1. Copies itself to `/usr/local/bin/rackpulse-agent`.
2. Creates the system user `rackpulse` and adds it to the `docker` group if Docker is installed, unless Docker access is off. With Docker access off it removes the user from the group.
3. Writes `/etc/rackpulse-agent/config.json` (mode 0640, `root:rackpulse`) with the key, port, address, the Docker access choice (`"noDocker": true` when off), and the server's MagicDNS name if Tailscale runs on it (`tailscale status --json`).
4. Creates a self-signed TLS certificate in `/var/lib/rackpulse-agent`.
5. Reads past boots from the system journal, so the uptime history starts with the last 30 days.
6. Installs and starts `rackpulse-agent.service`.
7. If ufw is active, allows the port: on `tailscale0` for a Tailscale address, to the listen address for another address, or on all addresses. `rackpulse-agent uninstall` removes the rule again.
8. Prints the firewall rule to add outside the server.

## Firewall

Rackpulse must reach the port from your Mac.

| Address Rackpulse uses | What to open |
|---|---|
| Public IPv4 or IPv6 | Hetzner Cloud Firewall attached to the server: inbound rule, TCP, port 7311. If you have a fixed IP, set it as the source. The installer adds the ufw rule |
| Tailscale (`--listen tailscale`) | No public rule. The installer allows the port on `tailscale0` in ufw |
| Other VPN address | No public rule. The installer allows the port to that address in ufw |
| Hetzner private network | No public rule. Your Mac must reach the private network, for example through a VPN server in it |

A server without a Cloud Firewall and without ufw accepts the connection on all addresses.

## Security

- **Pairing.** Rackpulse generates a random 256-bit key for each server. On the first connection, the agent proves that it knows the key for the TLS certificate it presents. Rackpulse then saves the certificate's SHA-256 fingerprint and only accepts that certificate from then on. The key and the fingerprint are stored in the macOS Keychain.
- **Requests.** Every data request carries the key. The agent compares it in constant time and waits before answering a wrong key.
- **Docker.** To list containers, the `rackpulse` user joins the `docker` group. See "Docker access".
- **Downloads.** Each agent release is signed. `install.sh` checks the signature of `SHA256SUMS` with the release public key it contains, and the binary against `SHA256SUMS`. `install.sh` itself is trusted through HTTPS from `rackpulse.app`: the key inside it cannot check the script it is part of.
- **What is exposed.** The port answers only `/v1/hello` without the key, which returns the agent's version and the proof. Everything else needs the key.

## Docker access

By default the `rackpulse` user is in the `docker` group, so the agent can read the Docker API. Members of that group can start a container with the host's file system mounted, which is close to root access. The agent only sends read requests to the Docker API, never runs anything in a container, and never writes container files to disk. It runs with systemd sandboxing: read-only file system, no new privileges, no capabilities.

Install with `--no-docker` if you do not want the agent to have that access. Rackpulse then does not show:

- Containers, their CPU, memory, health and history, volumes, and Docker disk usage.
- Container image scanning: packages and lockfiles inside images.
- Docker checks: privileged containers, socket mounts, host network, host PID namespace, added capabilities, root user, image tags and image age.
- Lockfiles of Docker Compose projects, because the agent finds the project folders through Docker.

The choice is saved in `/etc/rackpulse-agent/config.json`, so updates keep it, including the update command Rackpulse shows. To turn access back on, run the install command with `--docker`. An agent installed before 0.4.0 has no saved choice and keeps Docker access on. `sudo rackpulse-agent status` prints whether Docker access is on.

## Change the key

To pair the server with another key without reinstalling, run as root:

```bash
echo rb1_... | sudo rackpulse-agent set-key
```

The key can also be an argument: `sudo rackpulse-agent set-key rb1_...`. The agent restarts with the new key and keeps its certificate, port, and address. The old key stops working.

## Upgrading from rackbar-agent

Before Rackpulse was renamed, the agent was called `rackbar-agent`. Running the install command on a server that has it replaces it with `rackpulse-agent`:

- Without `--pair`, the old key, port, and address stay in use. With `--pair`, the new key replaces the old one.
- The TLS certificate, the uptime history, and the container history move to `/var/lib/rackpulse-agent`, so Rackpulse keeps trusting the server.
- `rackbar-agent.service`, `/usr/local/bin/rackbar-agent`, `/etc/rackbar-agent`, `/var/lib/rackbar-agent`, and the `rackbar` user are removed.

The firewall rule for the port stays as it is.

## Remove

```bash
sudo rackpulse-agent uninstall
```

This stops the service and removes the binary, the user, `/etc/rackpulse-agent`, and `/var/lib/rackpulse-agent`, and anything left from `rackbar-agent`. Remove the firewall rule yourself. In Rackpulse, choose **Remove agent** on the server page.

## Protocol

HTTPS, TLS 1.3, self-signed ECDSA P-256 certificate. JSON responses. Times are Unix seconds.

### `GET /v1/hello?nonce=<64 hex characters>`

No key needed.

```json
{ "agent": "rackpulse-agent", "version": "0.2.0", "proof": "<hex>" }
```

`proof` is HMAC-SHA256 with the pairing key (UTF-8) as the key, over `rackpulse-agent-v1|<nonce>|<certificate fingerprint>`. The fingerprint is the lowercase hex SHA-256 of the leaf certificate's DER bytes. Rackpulse checks the proof against the certificate it received before it sends the key.

### `GET /v1/snapshot`

Header `Authorization: Bearer <key>`. The current state, collected every 60 seconds.

```json
{
  "version": "0.2.0",
  "time": 1761480000,
  "host": {
    "hostname": "web-1", "os": "Ubuntu 24.04.3 LTS", "kernel": "6.8.0-85-generic", "arch": "arm64",
    "serverID": 12345678, "bootTime": 1758000000, "cores": 4, "load": [0.12, 0.2, 0.18]
  },
  "memory": { "total": 8221065216, "available": 5123440640, "swapTotal": 0, "swapFree": 0 },
  "disks": [
    { "mount": "/", "device": "/dev/sda1", "fs": "ext4", "total": 80000000000, "used": 41000000000,
      "available": 35000000000, "inodesTotal": 5000000, "inodesUsed": 400000, "readOnly": false }
  ],
  "system": { "rebootRequired": false, "failedUnits": [] },
  "docker": {
    "error": null,
    "containers": [
      { "id": "4f1c…", "name": "app-web-1", "image": "ghcr.io/acme/web:1.4", "project": "app",
        "state": "running", "health": "healthy", "exitCode": 0, "startedAt": 1761400000, "finishedAt": null,
        "restartCount": 0, "restartsLastHour": 0, "cpu": 1.8, "memory": 412000000, "memoryLimit": null,
        "createdAt": 1761390000,
        "ports": [ { "private": 80, "public": 8080, "type": "tcp", "ip": "0.0.0.0" } ],
        "mounts": [
          { "type": "volume", "name": "app_pgdata", "source": "/var/lib/docker/volumes/app_pgdata/_data",
            "destination": "/data", "readOnly": false },
          { "type": "bind", "name": null, "source": "/srv/app/site", "destination": "/usr/share/nginx/html",
            "readOnly": true }
        ],
        "networks": [ "app_default" ],
        "healthLog": { "exitCode": 0, "output": "ok", "time": 1761479990 } }
    ],
    "volumes": [ { "name": "app_pgdata", "size": 18000000000, "containers": 1 } ],
    "volumesTime": 1761479100,
    "disk": {
      "images": 2400000000, "imagesReclaimable": 900000000, "buildCache": 1200000000,
      "buildCacheReclaimable": 1200000000, "volumes": 18500000000, "volumesReclaimable": 500000000,
      "containers": 52000000
    }
  }
}
```

- `serverID` is the Hetzner server ID from the metadata service, or `null`.
- `tailscale` is left out when Tailscale does not run on the server. Otherwise `name` is the MagicDNS name saved at install and `ip` the current address of `tailscale0`. Rackpulse uses them to keep reaching the server over Tailscale.
- `disks` lists block-device file systems, one entry per device. `readOnly` is the file system's own state, so it is `true` only when the file system is mounted read-only on the server. `inodesTotal` and `inodesUsed` are 0 on file systems without fixed inodes, such as btrfs. `kind` is the device type: `sd`, `emmc`, `nvme`, `usb`, `ssd`, `hdd`, `virtual`, `ram`, `image`, `raid` or `mapped`. `model` is the device's model name when the kernel reports one. Older agents leave both out.
- `docker` is `null` when Docker is not installed. `error` is set when the socket exists but cannot be read.
- `project` is the Docker Compose project label, or `null`.
- `state` is Docker's state: `running`, `restarting`, `paused`, `exited`, `created`, `dead`.
- `health` is `healthy`, `unhealthy`, `starting`, or `null` when the container has no health check.
- `cpu` is percent of the whole server (100 means all cores busy). `memory` is bytes in use without the page cache.
- `ports` lists each published or exposed port once. `public` is the host port, or `null` when the port is not published. `ip` is the host address the port is bound to, or `null`.
- `mounts`: `type` is Docker's mount type, usually `volume`, `bind`, or `tmpfs`. `name` is set for volumes only. `source` is the host path, or `null` for `tmpfs`.
- `networks` are the Docker network names the container is attached to.
- `healthLog` is the latest health check result, or `null`. `output` is at most 300 characters, trimmed.
- Volume sizes and `disk` are measured every 15 minutes, from Docker's disk usage. `volumesTime` is the time of that measurement. `disk` and `volumesTime` are `null` until the first measurement and while Docker cannot be read. `size` is `-1` when unknown.
- `disk` values are bytes. `images` is the size of all image layers, and `imagesReclaimable` the size of images no container uses, without layers they share with other images. `buildCacheReclaimable` is the build cache not in use. `volumesReclaimable` is the size of volumes no container uses. `containers` is the size of the containers' writable layers.

### `GET /v1/history?since=<time>`

Header `Authorization: Bearer <key>`.

```json
{
  "time": 1761480720,
  "coverageStart": 1758900000,
  "hours": { "1761476400": 60, "1761480000": 12 },
  "step": 300,
  "samples": [ { "t": 1761479700, "memory": 0.62, "swap": 0, "disk": 0.51, "load": 0.2, "cpu": 4.5,
                 "diskReadIOPS": 0.2, "diskWriteIOPS": 3.1, "diskReadBytes": 820, "diskWriteBytes": 41000, "netInBytes": 1900, "netOutBytes": 1300 } ]
}
```

- `time`: the agent's current time. Use it to judge the current hour, which is not over yet.
- `coverageStart`: from this time on, the agent knows when the server was running. Before it, nothing is known.
- `hours`: for each hour that starts at or after `since`, the number of minutes the server was running. An hour after `coverageStart` that is missing had 0 running minutes.
- `samples`: `memory`, `swap`, and `disk` are used fractions; `disk` is the fullest file system. `cpu` is the percent of the whole server from `/proc/stat`. The disk fields are per second over whole disks from `/proc/diskstats`, and the network fields bytes per second over network cards from `/proc/net/dev` (no loopback, bridges, Docker or VPN interfaces). Older agents leave them out. With `since` in the last 24 hours, `step` is 60 and samples are one minute apart; otherwise `step` is 300.
- Without `since`, the response covers the full 31 days.

### `GET /v1/containers/history?name=<container name>&since=<time>`

Header `Authorization: Bearer <key>`. CPU and memory of one container. Samples are kept per container name, so they continue when Docker Compose recreates the container.

```json
{
  "time": 1761480720,
  "step": 60,
  "samples": [ { "t": 1761480600, "cpu": 1.8, "memory": 412000000 } ]
}
```

- `cpu` is percent of the whole server, `memory` is bytes in use without the page cache. Either is `null` when it could not be measured.
- Samples exist only while the container is running. One sample per minute is kept for 24 hours and one 5-minute average for 7 days. With `since` in the last 24 hours, `step` is 60; otherwise `step` is 300.
- A container that has not been seen for 7 days is dropped. An unknown name returns 404.

### `GET /v1/security`

Header `Authorization: Bearer <key>`. Installed packages, pending updates, hardening checks, listening ports, and the lockfiles of Docker Compose projects. The agent reads local files and runs `apt-get -s dist-upgrade` and `apt-config dump APT::Periodic`. It never connects to the internet. Returns 503 until the first check is done.

```json
{
  "version": "0.3.0",
  "time": 1761480000,
  "os": { "id": "ubuntu", "versionID": "24.04", "codename": "noble", "name": "Ubuntu 24.04.3 LTS", "like": ["debian"] },
  "packages": { "manager": "dpkg", "time": 1761470000, "error": null,
    "items": [ { "name": "libssl3t64", "version": "3.0.13-0ubuntu3.4", "source": "openssl", "sourceVersion": "3.0.13-0ubuntu3.4", "arch": "arm64" } ] },
  "updates": { "time": 1761479000, "listsTime": 1761400000, "error": null,
    "items": [ { "name": "libssl3t64", "current": "3.0.13-0ubuntu3.4", "available": "3.0.13-0ubuntu3.5", "security": true,
      "origins": ["Ubuntu:24.04/noble-updates", "Ubuntu:24.04/noble-security"] } ] },
  "kernel": { "running": "6.8.0-85-generic", "latestInstalled": "6.8.0-88-generic" },
  "checks": [ { "id": "ssh.passwordLogin", "status": "fail", "title": "SSH accepts passwords",
    "detail": "PasswordAuthentication yes", "source": "/etc/ssh/sshd_config.d/50-cloud-init.conf" } ],
  "listening": [ { "protocol": "tcp", "address": "0.0.0.0", "port": 5432 } ],
  "projects": [ { "name": "app", "path": "/srv/app", "error": null,
    "lockfiles": [ { "path": "web/package-lock.json", "ecosystem": "npm", "packages": [ { "name": "lodash", "version": "4.17.20" } ], "truncated": false } ] } ],
  "images": [ { "id": "sha256:4f2c...", "names": ["ghcr.io/acme/web:1.4"], "containers": ["app-web-1", "app-web-2"], "created": 1790000000,
    "os": { "id": "debian", "versionID": "12", "codename": "bookworm", "name": "Debian GNU/Linux 12 (bookworm)", "like": [] },
    "packages": { "manager": "dpkg", "time": 1761480000, "error": null,
      "items": [ { "name": "libssl3", "version": "3.0.11-1~deb12u2", "source": "openssl", "sourceVersion": "3.0.11-1~deb12u2", "arch": "amd64" } ] },
    "lockfiles": [ { "path": "/app/package-lock.json", "ecosystem": "npm", "packages": [ { "name": "express", "version": "4.18.2" } ], "truncated": false } ],
    "error": null } ]
}
```

- Packages are re-read when the dpkg or apk database changes (checked every 5 minutes). `manager` is `dpkg`, `apk`, or `null`. Versions are as dpkg stores them, with epochs. At most 20000 packages.
- Updates run at start, when the package lists or the dpkg database change (at most every 30 minutes), and at least every 6 hours. `current` is `null` for a new package. `security` is `true` when an origin's archive ends in `-security` or its label is `Debian-Security`. `listsTime` is when the package lists were last updated, or `null`. On failure, `error` is set and the last items stay. On Alpine, `items` is empty and `error` says so.
- `kernel` values are `null` when unknown.
- Checks run every 15 minutes. `status` is `pass`, `fail`, or `unknown`. `source` is a file path or `null`. Ids: `ssh.passwordLogin`, `ssh.rootLogin`, `updates.automatic`, `firewall.ufw`, `users.extraRoot`, `kernel.reboot`, `docker.privileged`, `docker.socketMount`, `docker.hostNetwork`, `docker.hostPID`, `docker.capAdd`, `docker.root`, `docker.latestTag`, `docker.oldImage`. A check is left out when it does not apply, for example without sshd, ufw, or a readable Docker socket.
- Docker checks count running containers only, and `detail` names them. `docker.socketMount` fails when a container mounts `/var/run/docker.sock`, `/run/docker.sock`, `/var/run`, `/run`, or `/`. `docker.hostPID` fails for `pid: host`, `docker.capAdd` for any `cap_add`. `docker.root` fails when the user is empty, `0`, `root`, or starts with `0:` or `root:`. `docker.latestTag` fails when the container was created from a reference without a tag or with `:latest`; a reference pinned by digest passes. `docker.oldImage` fails when the image was built more than 90 days ago; images with no build time, or a build time of 1970 as reproducible builds set it, are skipped.
- `listening` lists TCP ports in the listen state on addresses other than loopback, including the agent's own port. At most 200.
- `projects` come from the Compose labels of all containers and are scanned every 6 hours and when they change. Lockfiles are searched up to 3 folders deep, without following symbolic links. Supported: `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`, `requirements.txt`, `poetry.lock`, `uv.lock`, `Pipfile.lock`, `go.mod`, `Cargo.lock`, `composer.lock`, `Gemfile.lock`. `ecosystem` uses OSV names. Limits: 20 projects, 50 lockfiles per project, 10 MB per file, 50000 packages in total; `truncated` is `true` on a lockfile whose packages were cut. `error` is set when the folder or a lockfile cannot be read.
- `images` lists the images of running containers, one entry per image ID with all its containers. `names` are the image's tags, or its digests, or the references the containers were created with. `created` is the build time, or `null`. The agent copies single files out of one container of each image with `GET /containers/{id}/archive`, which returns a tar: `/etc/os-release` (following a symbolic link once, else `/usr/lib/os-release`), `/var/lib/dpkg/status`, the files directly in `/var/lib/dpkg/status.d/` (distroless images), `/lib/apk/db/installed`, and the lockfile names above directly in the container's working directory, which are read only when the image sets one. Lockfile paths are paths in the container. It does not walk folders, read `node_modules`, or read Go build info. Only regular files are read; symbolic links, other entries, and files under other names are skipped. Nothing runs in the container and nothing is written to disk.
- Images are scanned in the background, at most 4 per pass (every minute), and the report does not wait for them. An image appears after its first scan. Results are kept per image ID and dropped when no running container uses the image. A failed scan is tried again after an hour. Limits: 50 images, 60 seconds per image, 64 kB for `os-release`, 32 MB for a package database, 10 MB per lockfile, 64 MB per image, 4000 entries in `status.d`, 20000 lockfile packages per image, 30000 packages across all images. A package database over its limit sets `packages.error`; a lockfile over its limit is skipped. `packages.manager` is `null` with no `error` when the image has no package database, for example a `scratch` image. `error` is set when the scan of the image fails, for example on a timeout; an image left out by the 30000 package limit has empty `packages` and `lockfiles` and an `error` that says so. `images` is empty when Docker cannot be read.
