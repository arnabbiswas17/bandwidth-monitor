# Router Bandwidth Monitor

A small, dependency-free monitor for a Juniper MX204 that answers three questions without
double counting:

1. **How much internet bandwidth are we buying?** Traffic on the upstream transit links.
2. **How much are we providing to customers?** Traffic on customer and distribution links.
3. **How much passes through the router in total?** All physical ports.

It polls the router's 64-bit SNMP interface counters every 60 seconds, stores the rates in
SQLite and serves a web dashboard with live values, history (1h to 30d), average,
95th percentile and peak, and a per-interface breakdown.

> It measures **actual traffic (usage)**. It does not know package or contract sizes
> (e.g. "customer bought 100 Mbps"). Those are not stored on the router; see
> [Contracts](#contracts).

## Requirements

- Linux with Python 3.8+ (standard library only, no `pip install`)
- net-snmp command-line tools: `snmpget`, `snmpbulkwalk`
  (`sudo apt install snmp` on Debian/Ubuntu)
- SNMP v2c read access to the router from this machine

## Setup

```bash
git clone <this repo> bandwidth-monitor
cd bandwidth-monitor

# 1. SNMP credentials (never committed)
mkdir -p .secrets && chmod 700 .secrets
cp snmp.conf.example .secrets/snmp.conf
chmod 600 .secrets/snmp.conf
nano .secrets/snmp.conf          # put the real community string in defCommunity

# 2. Router address, polling interval, interface roles
nano config.json

# 3. Test one measurement (takes ~60 s)
python3 bwmon.py --once

# 4. Run collector + dashboard
python3 bwmon.py                 # http://127.0.0.1:8080
```

The SNMP community is read by net-snmp from `.secrets/snmp.conf` via `SNMPCONFPATH`,
so it never appears in the code, in logs, or in the process list (`ps`).
No SSH password is needed or stored.

### Run as a service

```bash
mkdir -p ~/.config/systemd/user
cp bandwidth-monitor.service ~/.config/systemd/user/   # edit the paths inside first
systemctl --user daemon-reload
systemctl --user enable --now bandwidth-monitor
loginctl enable-linger $USER     # keep running after logout
journalctl --user -u bandwidth-monitor -f              # logs
```

To open the dashboard from other machines, set `listen_host` to `0.0.0.0` in
`config.json` and restrict access with a firewall. The dashboard has no login.

## How it counts

### Router total
Sum of `ifHCInOctets` / `ifHCOutOctets` over every **physical port** (`et-*`, `xe-*`,
`ge-*`). Every packet enters through exactly one physical port and leaves through exactly
one, so each bit is counted once. Aggregates (`ae*`), VLAN units (`*.N`), `lo0`, `fxp0`,
internal `em*` and tunnel interfaces are never added. New ports are picked up automatically.

Incoming and outgoing are almost equal here by nature: a router forwards what it receives.

### Buying vs providing
Logical units (VLANs such as `ae3.1741`) are grouped by **role** in `config.json` → `roles`.
Each unit is in exactly one role (the app refuses to start otherwise). An aggregate's
counter is the exact sum of its units, so the roles add up to the router total.

| Role | Meaning | Main direction |
|---|---|---|
| `buy` | Upstream internet transit you pay for | **In**: taken from the internet |
| `provide` | Customers and your own distribution routers | **Out**: delivered to customers |
| `peer` | Private interconnects (PNI), not internet transit | both |
| `cache` | GGC / CDN content sources | in |
| `transport` | VLAN pairs that only pass traffic through this router | excluded |
| `mgmt` | Management VLANs | excluded |
| *unclassified* | Any `aeN.U` unit not listed in a role | shown so nothing is missed |

Example: a customer downloads 1 GB. It is counted once as **Buying → from upstreams** (as it
enters from the internet) and once as **Providing → to customers** (as it leaves to the
customer). They are two different measurement points, not double counting within a view.

Providing is usually larger than buying, because PNIs and caches supply traffic that does
not come through paid transit.

### How roles were decided
Each unit has a confidence level and a reason in `config.json` → `notes`, shown on the
dashboard:

- **Upstream**: the BGP peer sends this router the full internet table.
- **Customer**: this router sends the peer routes (`full-route-for-Client`, `default-only`).
- **Own router**: iBGP session (same AS) that receives the full table.
- **Low confidence**: no BGP on this router, so classified from the interface description
  and traffic direction. These should be confirmed by the network team.

To change a classification, move the unit between lists in `roles`, update its `notes`
entry, and restart.

### Accuracy
- Rates are 60-second averages; short bursts are smoothed.
- Byte counters include Ethernet framing, so values can be a few percent above IP-level or
  billing figures.
- Junos refreshes its counter cache about every 5 s. The collector waits for a refresh and
  reads every counter immediately after it, so all values in a sample are from the same
  instant.
- Physical-port and VLAN counters are gathered by the hardware at slightly different
  moments, so a single minute's router total and sum of roles can differ by a few percent.
  Over longer periods they agree within about 0.5%.
- A sample is **discarded** (and listed on the dashboard), not stored as a spike or dip,
  when a counter goes backwards, a counter discontinuity is reported, the SNMP agent
  restarts, an interface index changes, or a rate exceeds the port's line rate.

## Contracts

Contracted capacity is not on the router. Fill it in per upstream unit (Gbps) to show the
share used on the dashboard:

```json
"contracts_gbps": { "ae3.751": 20, "ae3.1741": 20 }
```

## Configuration reference (`config.json`)

| Key | Purpose |
|---|---|
| `router_host` | Router management IP |
| `snmp_conf_dir` | Directory holding `snmp.conf` (default `.secrets`) |
| `poll_interval_seconds` | Polling interval (default 60) |
| `retention_days` | How long history is kept (default 90) |
| `port_name_regex` | Which interfaces count as physical ports |
| `unit_name_regex` | Which units are checked for being unclassified |
| `exclude_ports` | Physical ports to leave out of the total |
| `roles` | Interface → role assignment |
| `notes` | Interface → `[confidence, reason]` shown on the dashboard |
| `contracts_gbps` | Contracted capacity per upstream unit |
| `db_path`, `listen_host`, `listen_port` | Storage and web server |

## Files

| File | |
|---|---|
| `bwmon.py` | Collector and web server (`--once` for a single measurement) |
| `static/index.html` | Dashboard |
| `config.json` | Settings and interface classification |
| `snmp.conf.example` | Template for `.secrets/snmp.conf` |
| `bandwidth-monitor.service` | systemd user unit |

Not committed (see `.gitignore`): `.secrets/`, `bandwidth.db*`, `__pycache__/`.

## API

| Endpoint | Returns |
|---|---|
| `GET /api/current` | Latest totals, role totals, per-interface rates, status, discarded samples |
| `GET /api/history?range=<seconds>&view=buy\|provide\|total` | Time series and avg / 95th / peak |
