<img src="assets/icon.png" width="128" alt="Rackpulse app icon">

# Rackpulse

A menu bar app for Hetzner Cloud. Rackpulse shows your servers from all your projects, whether they are running, how busy they are, and what they cost this month. It tells you when something goes wrong.

It is free and open source, with no account and no telemetry. It needs macOS 14 or later.

**[Download Rackpulse](https://rackpulse.app/download/Rackpulse.dmg)** · [Website](https://rackpulse.app) · [Discord](https://discord.gg/s4AzG5sc36)

<img src="assets/screenshot.png" alt="Rackpulse: the server list, a server page, the Docker tab, and a container page">

## Why it exists

I run side projects in several Hetzner projects. To check on them I had to open the Hetzner Console and go through each project one by one. A stopped server or a full disk often went unnoticed until something broke, and I only saw the cost on the invoice.

Rackpulse puts all of this in the menu bar, one click away.

## What it does

### Servers from all projects

One line tells you if everything is fine, for example "All 5 servers running" or "1 not running · 2 alerts". Servers are grouped by project, and servers with a problem are listed first. Press ⌃⌥R from any app to open the panel, then type to find a server.

### Server pages

Each server has charts for CPU, disk, and network, from the last hour to the last 30 days, and its uptime for the last 30 days. From the server page you can open SSH, copy its IP address, or open it in the Hetzner Console. With a Read & Write token you can also start, stop, and reboot it. Rackpulse asks before it does.

### Costs

What each project costs so far this month, and what it will cost by the end of the month. Set a monthly budget per project to get an alert when the forecast goes over it. Servers that are stopped but still billed, and volumes or IPs that nothing uses, are listed separately.

The numbers are estimates from Hetzner's list prices. Hetzner has no billing API, so VAT, credits, and extra traffic are not included. If a server is on an older price, enter the monthly price you pay on the project's page in Settings, or turn cost estimates off in General.

### Alerts

Rackpulse sends a notification when a server goes down, when CPU stays high, when a server uses most of its included traffic, when a project goes over its budget, or when a server or volume is added or deleted, or a firewall changes. Each alert notifies once, also across restarts. You can snooze an alert, give each server its own limits, and choose per rule between a notification, a daily summary, or the popover only. Notifications that arrive during quiet hours are sent as one summary afterwards. [docs/ALERTS.md](docs/ALERTS.md) has the details.

## The agent (optional)

Hetzner's API can't see inside a server. To see memory, disk space, and Docker, install the Rackpulse agent on the server. Without it, everything above still works.

With the agent, a server page also shows:

- Memory, how full each disk is, failed services, and when a reboot is needed.
- Your Docker containers, grouped by Compose project, with their health, restarts, CPU, and memory. Each container has its own page with ports, volumes, and 7 days of history.
- 30 days of uptime recorded on the server itself, so it also catches crashes that Hetzner can't see.

To install it, open a server in Rackpulse, choose **Set up agent**, and run the command it shows on the server. Your Mac connects to the agent on port 7311, so that port must be open to your Mac. Over Tailscale or a private network you don't need to open anything. The setup page tells you what to do for your server.

The agent only reads. It can't run commands or change anything on the server. To remove it, run `sudo rackpulse-agent uninstall`. [docs/AGENT.md](docs/AGENT.md) has the details.

## Install

1. [Download Rackpulse](https://rackpulse.app/download/Rackpulse.dmg), open it, and drag Rackpulse to Applications.
2. In the [Hetzner Console](https://console.hetzner.com/projects), open a project, go to **Security**, then **API tokens**, and create a token. Choose **Read**, or **Read & Write** if you want to start and stop servers from Rackpulse.
3. Click the Rackpulse icon in the menu bar, paste the token, and click **Verify and Save**. Add one token for each project.

Rackpulse checks for updates once a day and asks before it installs one.

## Privacy

- Rackpulse only talks to the Hetzner API, its own update feed, and the agents you set up.
- Your tokens and agent keys are stored in the macOS Keychain. They are never written to a file.
- With a Read token, Rackpulse can't change anything in your projects.
- Each agent has its own key. Without that key, nobody can read the agent's data.

To report a security problem, see [SECURITY.md](SECURITY.md).

## Build from source

You need Xcode 16 or later. For the agent you also need Go 1.23 or later.

```bash
make dev          # build and run the app
make test         # run the app tests
make test-agent   # run the agent tests
make help         # list all commands
```

| Folder | What's in it |
|---|---|
| `macos` | The menu bar app |
| `packages/HetznerKit` | The Hetzner API client, the cost estimates, and the alert rules |
| `agent` | The Linux agent and its install script |
| `scripts` | Scripts to build, sign, and publish a release |
| `docs` | [How the agent works](docs/AGENT.md), [how alerts and notifications work](docs/ALERTS.md), and [how a release is made](docs/RELEASING.md) |

## Contributing

Questions, bugs, and ideas are welcome, on [Discord](https://discord.gg/s4AzG5sc36) or in an issue. Read [CONTRIBUTING.md](CONTRIBUTING.md) before you open a pull request.

## License

[MIT](LICENSE). Rackpulse is not affiliated with Hetzner Online GmbH.
