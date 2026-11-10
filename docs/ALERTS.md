# Alerts and notifications

How Rackpulse decides when to raise an alert, when to send a notification, and what it stores. The rules are in `packages/HetznerKit/Sources/HetznerKit/Engine`, findings and delivery in `packages/HetznerKit/Sources/HetznerKit/Notifications`, and storage in `packages/HetznerKit/Sources/HetznerKit/Storage`. The app connects them in `macos/Sources/Rackpulse/AlertCenter.swift`.

## Two kinds of alerts

**Conditions** are states that start and stop: a server is down, CPU stays high, a disk is full, a service failed. Each one is an alert with an id such as `serverDown:<server>`. It fires once when the rule's threshold is crossed and clears after the value stays below it for 2 polls (`clearAfter`). A notification is sent when it fires. When it clears, Rackpulse removes the notification from Notification Center instead of sending a new one.

**Findings** are things found by a security scan: a vulnerable package or a failing hardening check. A server can have many, and they come and go one at a time. Each finding is tracked on its own, so a new one is noticed even when the server already has an open security alert. The Security tab and the popover still show one alert per server and rule.

## When a notification is sent

Conditions send one notification when the alert fires. Nothing is sent again while it stays active, including after Rackpulse restarts or updates.

Findings send a notification when:

- a finding is new and meets the rule (for vulnerabilities: the severity threshold with a fix, or any package that is known to be exploited or malicious)
- a known finding gets worse: its severity goes up, or it becomes known to be exploited
- a finding comes back more than 7 days after it was fixed

Nothing is sent when a finding is unchanged, when its exploit-chance score (EPSS) or its text changes, or when it is fixed. Lowering the severity threshold, or turning a rule on, makes the findings that now meet it count as new on the next poll, without waiting for a new scan. Raising it sends nothing.

The first scan of a server sends one notification with what it found, for example "web-1: 29 vulnerabilities found". So does the first scan after you turn on vulnerability checks. Later scans only report what changed.

A finding counts as fixed after 2 complete scans without it. A scan is not complete for vulnerabilities when vulnerability checks are off, or when OSV.dev or Socket failed or only partly answered. Such a scan fixes nothing.

### Finding keys

A finding is identified by its server and a key, never by the installed version, so an upgrade that is still vulnerable is not a new finding. Each finding also stores the advisory's aliases (CVE, GHSA and distro ids). If OSV.dev later gives the same vulnerability a different main id, the finding keeps its history under the new key instead of counting as new.

| Finding | Key |
|---|---|
| Vulnerability | `vulnerability|<advisory id>`, where the advisory id is the CVE when there is one. A CVE that affects several packages on the server is one finding |
| Malicious package | `vulnerability|<location>|<ecosystem>|<package>|<advisory id>` |
| Hardening check | `hardening|<check id>`, for example `hardening|ssh.passwordLogin` |

Of the Docker checks, only `docker.privileged`, `docker.socketMount` and `docker.hostPID` alert. `docker.hostNetwork`, `docker.capAdd`, `docker.root`, `docker.latestTag` and `docker.oldImage` show in the Security tab without alerting. All Docker checks look at running containers only.

### Ignored findings

A vulnerability can be ignored from the Security tab with **Ignore…**. Each ignore has:

- a reason: Not affected, Accept risk, or Fix later
- an end: 30 days, 90 days, or until a fix is available
- a scope: this server, or all servers
- an optional note

Critical and known exploited vulnerabilities can only be ignored as Not affected, for 30 days, and the note is required. Malicious packages can't be ignored.

While an ignore is active, the finding is left out of the Security tab counts, Fix now, the popover alert and notifications. **Show ignored** lists it with its reason, note and end date, and **Unignore** ends it right away.

An ignore ends by itself, and the finding comes back, when:

- its end date passes
- it was set to last until a fix is available, and a fix is published
- the vulnerability becomes known to be exploited, and it was not when it was ignored
- the package becomes known to be malicious, and it was not when it was ignored

How ignores interact with notifications:

- An ignored finding stays open in the ledger while the scan still reports it, so it is not counted as fixed and does not come back later as new. It is still marked fixed after 2 complete scans without it, like any other finding, and then it is no longer ignored in the ledger. If it returns after its ignore has ended, it notifies like any new or returning finding.
- Ignoring a finding clears its notified state, and removes the server's notification from Notification Center when no other notified finding of that rule is open.
- When an ignore ends by itself, the finding notifies like a finding that came back, for example "web-1: CVE-2025-32463 in sudo is back", if it meets the rule. It does not wait 7 days.
- **Unignore** sends nothing. The finding counts as already notified, so it only notifies again if it gets worse.
- Ignoring or unignoring takes effect on the next poll, without waiting for a new scan.

Ignores are stored separately from findings, by server and advisory key, with `*` as the server for all servers. The advisory key is the finding key without the `vulnerability|` prefix.

The server is a target id in the form `<provider>/<account>/<kind>/<id>`, for example `hetzner/<project UUID>/server/12345678`. It does not depend on Hetzner, so other providers and agent-only hosts can use the same store.

## Delivery

Each rule has a delivery setting:

| Setting | What happens |
|---|---|
| Notification | Sent right away, grouped and rate limited as below |
| Daily summary | Collected and sent as one notification a day, at the time set in Settings, Alerts |
| Popover only | Shown in the popover and the menu bar, never as a notification |

Grouping and limits:

- **One notification per server and rule per scan.** New findings from one scan arrive together, for example "web-1: 3 new vulnerabilities" with the first 3 listed.
- **Security notifications are limited to one per server and rule per hour.** Anything that arrives within the hour is sent together when the hour is over.
- **More than 3 notifications at once become one**, for example "5 new alerts", listing the first 5.
- **Quiet hours delay notifications instead of dropping them.** What arrives during quiet hours is sent as one summary when they end. An alert that clears before its summary is sent, during quiet hours or before the daily summary, is taken out of it.
- **Snooze** on a notification or in the popover silences that alert for 24 hours, and removes it from anything still waiting to be sent. For security notifications it covers all findings of that rule on that server. Findings that appear during a snooze are not sent later.

Notifications for the same server share a thread, so Notification Center stacks them. A new notification for the same alert replaces the old one.

## What is stored

Alerts and security share one SQLite file: `~/Library/Containers/dev.rackpulse.mac/Data/Library/Application Support/Rackpulse/rackpulse.sqlite`. It is opened in WAL mode, and the schema version is in `PRAGMA user_version`. The code is in `packages/HetznerKit/Sources/HetznerKit/Storage`.

| Table | Contents |
|---|---|
| `alert_state` | The state of each project's alerts: which are active, counters, hold times, snoozes, and the last known servers, volumes and firewalls. Restored at launch, so alerts do not fire again after a restart, and changes made while Rackpulse was closed (a new or deleted server, a changed firewall) are reported once. Saved when an alert changes, and at least every 5 minutes. Counters that were still building up are dropped when the app was closed for more than about 15 minutes, except the hold for security updates |
| `ledger_target` | Each server's last scan time, which kinds it has scanned (used for the first-scan summary), and the rule settings the findings were last checked against |
| `finding` | One row per finding: key, aliases, title, severity, exploited, malware, first seen, last seen, fixed, whether it is ignored, and when and at what severity it was last notified |
| `finding_decision` | One row per ignore: server (or `*`), finding key, title, reason, note, end date or until a fix is available, when it was made, and whether the finding was exploited or malicious at that time |
| `meta` | Notifications waiting for quiet hours, the daily summary or the hourly limit, and the last time each was sent |
| `notification_log` | Every decision: time, server, rule, title, and the outcome (`sent`, `summarized`, `quietHours`, `dailySummary`, `rateLimited`, `snoozed`, `popoverOnly`, `resolved`) |
| `security_result` | The last security scan of each server, with the agent report digest and settings it was made with. Replaces `security-results.json`, which is imported once and then deleted |
| `security_cache` | Lookups from OSV.dev, CISA, FIRST and Socket, so a rescan only fetches what changed. Up to 30,000 OSV records are kept. **Clear Cached Data** in Settings, Security empties it and the scan results. Replaces the `security` folder, which is deleted |

Retention:

- The log keeps 90 days. Older rows are deleted when Rackpulse starts.
- Fixed findings are deleted 30 days after they were fixed.
- Ignores are deleted 30 days after their end date, or when no scan has reported their finding for 30 days. Scans with vulnerability checks off or failed lookups do not count. This is checked at most once an hour. Ignores for a deleted server or a removed project are deleted with its findings.
- Findings of deleted servers are deleted the first time Rackpulse polls their project after it starts.
- Everything stored for a removed project is deleted when the project is removed.

The decision, the finding update and the log entry are written in one transaction, so a crash can't send the same notification twice. If a write fails, it is retried with the next one. If the file can't be opened, Rackpulse keeps working with the state in memory.

You can read the log with:

```bash
sqlite3 ~/Library/Containers/dev.rackpulse.mac/Data/Library/Application\ Support/Rackpulse/rackpulse.sqlite \
  "SELECT datetime(time, 'unixepoch', 'localtime'), outcome, title FROM notification_log ORDER BY time DESC LIMIT 20"
```
