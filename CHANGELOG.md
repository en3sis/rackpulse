# Changelog

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
