# Alerts and notifications

How Rackpulse decides when to raise an alert, when to send a notification, and what it stores. The rules are in `packages/HetznerKit/Sources/HetznerKit/Engine`, delivery in `packages/HetznerKit/Sources/HetznerKit/Notifications`, and storage in `packages/HetznerKit/Sources/HetznerKit/Storage`. The app connects them in `macos/Sources/Rackpulse/AlertCenter.swift`.

## Alerts

An alert is a state that starts and stops: a server is down, CPU stays high, a disk is full, a service failed. Each one has an id such as `serverDown:<server>`. It fires once when the rule's threshold is crossed and clears after the value stays below it for 2 polls (`clearAfter`). A notification is sent when it fires. When it clears, Rackpulse removes the notification from Notification Center instead of sending a new one.

Nothing is sent again while an alert stays active, including after Rackpulse restarts or updates.

## Delivery

Each rule has a delivery setting:

| Setting | What happens |
|---|---|
| Notification | Sent right away, grouped as below |
| Daily summary | Collected and sent as one notification a day, at the time set in Settings, Alerts |
| Popover only | Shown in the popover and the menu bar, never as a notification |

Grouping and limits:

- **More than 3 notifications at once become one**, for example "5 new alerts", listing the first 5.
- **Quiet hours delay notifications instead of dropping them.** What arrives during quiet hours is sent as one summary when they end. An alert that clears before its summary is sent, during quiet hours or before the daily summary, is taken out of it.
- **Snooze** on a notification or in the popover silences that alert for 24 hours, and removes it from anything still waiting to be sent.

Notifications for the same server share a thread, so Notification Center stacks them. A new notification for the same alert replaces the old one.

## What is stored

Alerts use one SQLite file: `~/Library/Containers/dev.rackpulse.mac/Data/Library/Application Support/Rackpulse/rackpulse.sqlite`. It is opened in WAL mode, and the schema version is in `PRAGMA user_version`.

| Table | Contents |
|---|---|
| `alert_state` | The state of each project's alerts: which are active, counters, hold times, snoozes, and the last known servers, volumes and firewalls. Restored at launch, so alerts do not fire again after a restart, and changes made while Rackpulse was closed (a new or deleted server, a changed firewall) are reported once. Saved when an alert changes, and at least every 5 minutes. Counters that were still building up are dropped when the app was closed for more than about 15 minutes |
| `meta` | Notifications waiting for quiet hours or the daily summary, and the last time each was sent |
| `notification_log` | Every decision: time, server, rule, title, and the outcome (`sent`, `summarized`, `quietHours`, `dailySummary`, `snoozed`, `popoverOnly`, `resolved`) |

Each server is stored as a target id in the form `<provider>/<account>/<kind>/<id>`, for example `hetzner/<project UUID>/server/12345678`, so other providers and agent-only hosts can use the same tables.

Retention:

- The log keeps 90 days. Older rows are deleted when Rackpulse starts.
- Everything stored for a removed project is deleted when the project is removed.

The decision and the log entry are written in one transaction, so a crash can't send the same notification twice. If a write fails, it is retried with the next one. If the file can't be opened, Rackpulse keeps working with the state in memory.

You can read the log with:

```bash
sqlite3 ~/Library/Containers/dev.rackpulse.mac/Data/Library/Application\ Support/Rackpulse/rackpulse.sqlite \
  "SELECT datetime(time, 'unixepoch', 'localtime'), outcome, title FROM notification_log ORDER BY time DESC LIMIT 20"
```
