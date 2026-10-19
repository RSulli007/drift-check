# drift-check

A small Python tool that scans a Linux host's TCP ports, compares the result to an approved baseline, and records timestamped evidence of every check. It flags **configuration drift**: ports that are open but shouldn't be, and ports that should be open but aren't.

Built and tested against a CentOS Stream 9 lab VM.

## Why

Hardening a system once isn't enough; systems drift. Someone starts a service, opens a firewall port for a quick test, or a required service stops. This tool answers a simple question on demand: *does this host still match the baseline configuration?* It also leaves a record that an assessor could follow later.

## How it works

1. **Scan.** Attempts a TCP connection to each port in a range, 100 ports at a time in parallel (`ThreadPoolExecutor`). Scanning 10,000 ports takes about 50 seconds; scanning one at a time would take over an hour.
2. **Compare.** Loads the expected open ports for the host from `baseline.json` and uses set comparison:
   - `actual - expected` gives **unexpected open ports**
   - `expected - actual` gives **missing expected ports**
3. **Record.** Writes a JSON evidence file to `scans/` with the target, port range, open ports, drift result, scan duration, and a UTC timestamp.
4. **Signal.** Exits with code `0` on PASS and `1` on DRIFT, so a scheduler or pipeline can alert on drift without parsing text.

## Usage

```
python drift_check.py
Target host or IP: 192.168.12.240
Starting port: 1
Ending port: 10000
```

Example baseline (`baseline.json`):

```json
{
  "192.168.12.240": {
    "description": "CentOS Stream 9 lab VM",
    "expected_open_ports": [22]
  }
}
```

Example evidence file (`scans/scan_192.168.12.240_20261019T011635Z.json`):

```json
{
  "target": "192.168.12.240",
  "ip": "192.168.12.240",
  "port_range": [1, 10000],
  "open_ports": [22, 8080],
  "scanned_at": "2026-10-19T01:16:35+00:00",
  "duration_seconds": 50.1,
  "drift": {
    "status": "DRIFT",
    "unexpected_open": [8080],
    "missing_expected": []
  }
}
```

## Testing

I verified the scanner against the host's own view before trusting it. On the VM, `ss -tlnp` showed `sshd` on port 22 (all interfaces) and `cupsd` on port 631 (localhost only), and `firewall-cmd --list-all` allowed only `ssh`, `cockpit`, and `dhcpv6-client`. The expected network-visible result was therefore port 22 only, and the scanner matched it.

Then I introduced drift on purpose in both directions:

| Time (UTC) | Change made on the VM | Result | Exit code |
|---|---|---|---|
| 2026-10-19 01:14 | None (baseline state) | PASS: `[22]` | 0 |
| 2026-10-19 01:16 | Started `python3 -m http.server 8080` and ran `firewall-cmd --add-port=8080/tcp` | DRIFT: unexpected open `[8080]` | 1 |
| 2026-10-19 01:20 | Removed the 8080 rule, stopped the web server, ran `systemctl stop sshd` | DRIFT: expected port missing `[22]` | 1 |
| 2026-10-19 01:22 | Ran `systemctl start sshd` | PASS: `[22]` | 0 |

## Design notes

- **Listening is not the same as reachable.** A service bound to `127.0.0.1` (like CUPS on 631), or one blocked by firewalld, won't appear in a network scan. This tool measures what the network can actually reach, which is the security-relevant view.
- **UTC timestamps** keep evidence comparable across hosts and time zones and easy to line up with logs.
- **Consistent JSON fields** in every record make scans comparable and easy to collect or report on.
- **Scan results are excluded from Git** (`.gitignore`). Evidence can reveal internal addresses and services; the baseline (the approved state) is tracked so changes to it are reviewed.
- **Finding from testing:** the VM's firewall allows Cockpit (9090), but Cockpit isn't running. That's an unneeded allow rule; if Cockpit were enabled later, it would be exposed without a deliberate decision. Removing unused rules is part of a hardening baseline.

## Limitations and next steps

- TCP and IPv4 only (UDP services like `dhcpv6-client` aren't checked).
- Takes input interactively; command-line arguments would allow scheduled runs (cron or Windows Task Scheduler).
- One host per run; the baseline format already supports multiple hosts.
- Could route drift alerts to email or a chat channel, or forward evidence to a log platform.

## Responsible use

Only scan systems you own or are authorized to test. Fast parallel scans can look like an attack and trigger security alerts on networks you don't control.
