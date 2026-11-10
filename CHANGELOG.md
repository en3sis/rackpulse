# Changelog

## 0.4.0

### App

- Security checks for each server with the agent: security updates waiting, a hardening checklist, and known vulnerabilities in the server's packages, in Docker Compose project dependencies, and inside the images of running containers. Vulnerability lookups are off until you turn them on in Settings, Security.
- Vulnerabilities come from OSV.dev. Known exploited ones are marked from the CISA list, and the chance of exploit comes from FIRST's daily EPSS file. Both lists are downloaded whole, so CVE ids stay on your Mac.
- Optional malware and typosquatting checks for app dependencies from Socket, with your own API token. Settings shows how many checks are left this hour, and each server can use only part of the quota.
- The Security tab starts with what to fix now: packages known to be exploited, malware, and critical vulnerabilities that have a fix. Findings are grouped by package, with the command to upgrade host packages and where each one was found: the host, a lockfile, or an image.
- Ignore a vulnerability with a reason (Not affected, Accept risk, Fix later), a note, and an end: 30 days, 90 days, or until a fix is available. It comes back when the ignore ends, or when it becomes known exploited or malware. Ignored findings are listed under Show ignored. Critical and known exploited vulnerabilities can only be ignored as Not affected, with a note, for up to 30 days. Malware can't be ignored.
- A Security tab in the popover lists each server with its vulnerabilities and failing checks, most urgent first. ⌘3 opens it.
- Export a server's findings as a Markdown report, its packages as a CycloneDX SBOM, and its ignores as OpenVEX.
- Copy a fix prompt for an AI agent: the packages to upgrade, fixed versions, advisory ids and failing checks of a server, in Markdown.
- Each vulnerable package shows whether a fix is available, waiting to be installed, or not published yet.
- In a server, ⌘1 to ⌘4 switch its tabs.
- Failed login session units (`session-*.scope`) no longer count as failed services.
- Servers without the Hetzner API, such as agent-only hosts, now raise vulnerability and hardening alerts.
- Security alerts notify once per finding: one summary after the first scan, then only new findings, worse ones, and ones that come back.
- Version comparison follows each ecosystem's rules (Alpine, Python, npm, Go, Cargo, RubyGems, Composer), so fix versions and pre-releases are right. CVSS v4 scores are read when an advisory has no v3 score.

### Agent

- Reports the packages, security updates, SSH, firewall, update and Docker settings, open ports and lockfiles of Compose projects that the app needs for the Security tab.
- Reads OS packages and lockfiles inside the images of running containers through the Docker API, without running anything in them. Each image is read once.
- New Docker checks: `pid: host`, added capabilities, containers running as root, images on `:latest` or with no tag, and images older than 90 days. The Docker socket check also finds mounts of `/run` and `/var/run`. All Docker checks look only at running containers.
- `--no-docker` installs the agent without access to Docker, since the docker group is close to root. Updates keep this choice. `--docker` turns access back on.
- Releases are signed. `install.sh` checks the signature before it installs anything and needs `openssl` on the server. It refuses to replace an agent with an older version unless you pass `--allow-downgrade`.

## 0.3.0

### App

- Each alert notifies once, also after Rackpulse restarts. Alert state and a log of sent notifications are kept in a local database.
- Many alerts at once arrive as one notification. Alerts during quiet hours arrive as one summary when they end.
- Choose per rule between a notification, a daily summary, or the popover only. Set the summary time in Settings, Alerts.
- Stopped Docker containers no longer count as unhealthy.
- A new agent setup: choose how your Mac reaches the server (Tailscale, private network, public IP, or another address) and get the matching command and firewall steps. The pairing key is hidden in the command. Change a paired agent's address without pairing again.
- Agent data shows right after Rackpulse starts, instead of after the first check interval.
- While a server's page is open, its agent is read every 5 seconds.
- Add servers that run only the agent, with no provider account: home lab, bare metal or any cloud. They live in their own projects. Power controls, traffic and the Console are not available for them, and they count in Costs only with a price you enter.
- Adding servers starts with a choice of provider. Hetzner Cloud is available, and AWS, DigitalOcean and Railway are listed as coming soon.
- On a Mac with Tailscale, the agent setup finds the server by its name in your tailnet, so you no longer type an address. A server that is not paired yet can be removed from its setup page.
- Servers with only the agent get the same CPU, disk I/O and network charts as cloud servers, and the CPU and disk I/O alerts. Rows for these servers show the same columns as the others, with the OS and address in tooltips.
- An agent server's Disk tile shows its system disk, named by type (SD card, eMMC, NVMe, USB drive and others). Other drives and volumes are listed below it with their usage.
- The server list opens in the detailed view each time. The refresh icon finishes its turn, and the label reads "Updated 12s ago".

### Agent

- `--listen tailscale` listens on the server's Tailscale address.
- If ufw is active, the installer allows the agent's port, and uninstall removes the rule.
- The installer saves the server's Tailscale MagicDNS name, and the agent reports it with its Tailscale address.
- The agent records CPU use, disk reads and writes, and network traffic every minute, kept for 31 days like memory and disk space.
- Each disk reports its device type (SD card, eMMC, NVMe, USB, SSD, hard disk, virtual) and model. `/dev/root` is reported as the real device.

## 0.2.2

### App

- Enter the monthly price you pay for a server that is still on an older Hetzner price. Rackpulse then uses it for the month's cost, the forecast, and the budget alert. Set it in Settings, on the project's page, under Costs. A server page shows whether its cost comes from the list price or from your price.
- A Show cost estimates switch in Settings, General. When it is off, Rackpulse hides the Costs tab and all cost amounts, and stops budget alerts.
- Updates and downloads now come from rackpulse.app. Older versions keep updating through a redirect.

### Agent

- The install and update command downloads from rackpulse.app. The old command still works through a redirect. The agent itself is unchanged.

## 0.2.1

### App

- The Docker tab is easier to scan on servers with many containers. Each container is one compact row with its memory and CPU, Compose projects can be opened and closed and show how many containers run, and stopped containers have their own group.
- Docker icons for containers, images, volumes, and build cache, and larger text in the Docker views.
- Charts no longer draw outside their area, and they only show the selected time range.
- In the uptime bar, hours where the server ran with an alert are green with an orange mark. Notes like "needs a reboot" no longer count as alerts.

### Agent

- The install command stops with a clear message when you run it on a Mac or another system that isn't Linux.
- The code is reorganized into Go packages. Nothing changes in how the agent works.

## 0.2.0

The first release as Rackpulse, renamed from Rackbar.

### App

- The optional agent: memory, disk space, failed services, Docker containers, and 30 days of uptime recorded on the server.
- A page for each Docker container, with 7 days of history, ports, volumes, and the last health check.
- Server pages with Overview, Docker, and Details tabs.
- Uptime from Hetzner's start and stop history, so the 30-day bar is filled from the start.
- Production, staging, and development tags per server, also read from a Hetzner `env` label.
- New alerts for disk space, memory, Docker containers, failed services, pending reboots, and an agent that stops answering.
- A Change key option for each agent, and an About page with update settings.

### Agent

- First release. It replaces an older `rackbar-agent` and keeps its key and history.
