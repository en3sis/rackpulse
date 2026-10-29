# Rackpulse agent

The agent is optional. Rackpulse works without it, using only the Hetzner API. Install the agent on a server to also see memory, disk space, Docker containers, and 30 days of uptime recorded on the server itself.

## How it works

- `rackpulse-agent` is one static binary for Linux (x86_64 and ARM64). It runs as a systemd service under its own `rackpulse` user.
- It listens on TCP port 7311 over HTTPS. Rackpulse on your Mac connects to it. The server never connects to your Mac or to any other host, except Hetzner's metadata service at `169.254.169.254` to read its own server ID.
- It is read-only. It has no endpoint that runs a command or changes anything on the server.
- It keeps 30 days of history in `/var/lib/rackpulse-agent`, so charts and uptime fill in when your Mac wakes up.

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

Running the script again without `--pair` updates the agent and keeps its key and settings.

The script downloads the binary for the server's architecture from `rackpulse.app`, checks its SHA-256 checksum, and runs `rackpulse-agent install`, which:

1. Copies itself to `/usr/local/bin/rackpulse-agent`.
2. Creates the system user `rackpulse` and adds it to the `docker` group if Docker is installed.
3. Writes `/etc/rackpulse-agent/config.json` (mode 0640, `root:rackpulse`) with the key, port, address, and the server's MagicDNS name if Tailscale runs on it (`tailscale status --json`).
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
- **Docker.** To list containers, the `rackpulse` user joins the `docker` group. Members of that group can control Docker, which is close to root access. The agent only sends read requests to the Docker API, and it runs with systemd sandboxing: read-only file system, no new privileges, no capabilities.
- **What is exposed.** The port answers only `/v1/hello` without the key, which returns the agent's version and the proof. Everything else needs the key.

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
