#!/usr/bin/env python3
"""Router bandwidth monitor for a Juniper MX204.

Two independent views, each free of double counting:

* Router total: sum of ifHCIn/OutOctets over all physical ports. Every packet
  enters through exactly one physical port and leaves through exactly one.
* Buying / providing: logical units (aeX.N VLANs) grouped by role in
  config.json. Each unit belongs to exactly one role; units are disjoint, so the
  roles add up to the router total. Unlisted aeX.N units are tracked as
  "unclassified" so no traffic silently disappears.

The SNMP community is read by net-snmp from <snmp_conf_dir>/snmp.conf
(defCommunity), so it never appears on a command line, in logs, or in code.
"""
import argparse
import json
import logging
import os
import re
import sqlite3
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

BASE = Path(__file__).resolve().parent
OID_SYSUPTIME = ".1.3.6.1.2.1.1.3.0"
OID_IFNAME = ".1.3.6.1.2.1.31.1.1.1.1"
OID_HC_IN = ".1.3.6.1.2.1.31.1.1.1.6"
OID_HC_OUT = ".1.3.6.1.2.1.31.1.1.1.10"
OID_HIGHSPEED = ".1.3.6.1.2.1.31.1.1.1.15"
OID_DISCONT = ".1.3.6.1.2.1.31.1.1.1.19"
OID_ALIAS = ".1.3.6.1.2.1.31.1.1.1.18"
VARBINDS_PER_REQUEST = 40
RESOLVE_EVERY_SECONDS = 600
SPEED_MARGIN = 1.05  # a rate above line rate + 5% is a counter glitch, not traffic
CACHE_WAIT_SECONDS = 12      # Junos counter cache refreshes every ~5 s
REFRESH_PROBE_SECONDS = 0.2  # timing resolution: 0.2 s over a 60 s interval = 0.3%
PORT = "port"        # role of physical ports (router total)
UNCLASSIFIED = "unclassified"
ROLE_ORDER = ["buy", "provide", "peer", "cache", "transport", "mgmt", UNCLASSIFIED]

log = logging.getLogger("bwmon")


def load_config():
    cfg = json.loads((BASE / "config.json").read_text())
    for key in ("snmp_conf_dir", "db_path"):
        cfg[key] = str((BASE / cfg[key]).resolve())
    seen = {}
    for role, units in cfg.get("roles", {}).items():
        for u in units:
            if u in seen:
                raise SystemExit(f"config.json: {u} is in both '{seen[u]}' and '{role}' (would double count)")
            seen[u] = role
    return cfg


class SnmpError(Exception):
    pass


class Snmp:
    def __init__(self, host, conf_dir):
        self.host = host
        self.env = dict(os.environ, SNMPCONFPATH=conf_dir, MIBS="")
        if not (Path(conf_dir) / "snmp.conf").exists():
            raise SystemExit(f"missing {conf_dir}/snmp.conf (see README)")

    def _run(self, cmd, oids):
        res = subprocess.run(
            [cmd, "-On", "-Oq", "-Ot", "-t", "5", "-r", "1", self.host, *oids],
            capture_output=True, text=True, env=self.env, timeout=120,
        )
        if res.returncode != 0:
            raise SnmpError(res.stderr.strip().splitlines()[-1] if res.stderr.strip() else f"{cmd} failed")
        out = {}
        for line in res.stdout.splitlines():
            oid, _, val = line.partition(" ")
            out[oid] = val.strip().strip('"')
        return out

    def walk(self, oid):
        return {int(k.rsplit(".", 1)[1]): v for k, v in self._run("snmpbulkwalk", [oid]).items()}

    def get(self, oids):
        out = {}
        for i in range(0, len(oids), VARBINDS_PER_REQUEST):
            out.update(self._run("snmpget", oids[i:i + VARBINDS_PER_REQUEST]))
        for oid in oids:
            if oid not in out or out[oid].startswith(("No Such", "No more")):
                raise SnmpError(f"missing value for {oid}")
        return out


class Collector:
    def __init__(self, cfg, db):
        self.cfg = cfg
        self.db = db
        self.snmp = Snmp(cfg["router_host"], cfg["snmp_conf_dir"])
        self.port_re = re.compile(cfg["port_name_regex"])
        self.unit_re = re.compile(cfg["unit_name_regex"])
        self.role_of = {u: r for r, units in cfg.get("roles", {}).items() for u in units}
        self.ifs = {}     # ifIndex -> {"name", "role", "speed_bps", "alias"}
        self.resolved_at = 0
        self.prev = None  # previous raw reading
        self.status = {"last_poll": None, "last_error": None, "ports": [], "unclassified": [], "missing": []}

    def resolve(self):
        names = self.snmp.walk(OID_IFNAME)
        speeds = self.snmp.walk(OID_HIGHSPEED)
        aliases = self.snmp.walk(OID_ALIAS)
        excluded = set(self.cfg["exclude_ports"])
        ports = {i: n for i, n in names.items() if self.port_re.match(n) and n not in excluded}
        # A channelized port (et-0/0/0:1) replaces its parent; never count both.
        channel_parents = {n.split(":")[0] for n in ports.values() if ":" in n}
        ports = {i: n for i, n in ports.items() if n not in channel_parents}
        picked = {i: (n, PORT) for i, n in ports.items()}
        unclassified = []
        for i, n in names.items():
            if n in self.role_of:
                picked[i] = (n, self.role_of[n])
            elif self.unit_re.match(n) and not n.endswith(".32767"):
                picked[i] = (n, UNCLASSIFIED)
                unclassified.append(n)
        present = set(names.values())
        missing = sorted(u for u in self.role_of if u not in present)
        new = {i: {"name": n, "role": r, "speed_bps": int(speeds.get(i, 0) or 0) * 1_000_000,
                   "alias": aliases.get(i, "").strip("* ")} for i, (n, r) in picked.items()}
        hc_in = self.snmp.walk(OID_HC_IN)
        self.sentinel = max(ports, key=lambda i: int(hc_in.get(i, 0)))
        if {i: (v["name"], v["role"]) for i, v in new.items()} != {i: (v["name"], v["role"]) for i, v in self.ifs.items()}:
            if self.ifs:
                self.event("interface set changed; baseline reset")
            log.info("counting %d physical ports and %d logical units", len(ports), len(new) - len(ports))
            if unclassified:
                log.warning("unclassified units (add them to a role in config.json): %s", ", ".join(sorted(unclassified)))
            if missing:
                log.warning("configured units not found on router: %s", ", ".join(missing))
            self.prev = None
        self.ifs = new
        self.resolved_at = time.monotonic()
        self.status.update(ports=sorted(ports.values()), unclassified=sorted(unclassified), missing=missing)

    def wait_for_refresh(self, sentinel):
        """Junos serves interface counters from a cache refreshed every ~5 s, all interfaces at
        once. Return (time, value) just after the next refresh, so a full read that follows
        sees every counter from the same instant."""
        last = self.snmp.get([sentinel])[sentinel]
        t_last = time.monotonic()
        deadline = t_last + CACHE_WAIT_SECONDS
        while time.monotonic() < deadline:
            time.sleep(REFRESH_PROBE_SECONDS)
            val = self.snmp.get([sentinel])[sentinel]
            now = time.monotonic()
            if val != last:
                return (t_last + now) / 2, val
            t_last = now
        return None, None

    def read(self):
        # Busiest physical port changes on every cache refresh, so it marks refresh instants.
        sentinel = f"{OID_HC_IN}.{self.sentinel}"
        oids = [OID_SYSUPTIME]
        for i in self.ifs:
            oids += [f"{OID_IFNAME}.{i}", f"{OID_HC_IN}.{i}", f"{OID_HC_OUT}.{i}", f"{OID_DISCONT}.{i}"]
        for _ in range(3):
            t_refresh, marker = self.wait_for_refresh(sentinel)
            if t_refresh is None:
                raise SnmpError("router counters did not refresh")
            vals = self.snmp.get(oids)
            if vals[sentinel] == marker:  # no refresh happened mid-read
                break
        else:
            raise SnmpError("could not read all counters within one cache period")
        reading = {"mono": t_refresh, "wall": time.time(), "uptime": int(vals[OID_SYSUPTIME]), "ifs": {}}
        for i, p in self.ifs.items():
            if vals[f"{OID_IFNAME}.{i}"] != p["name"]:
                raise SnmpError(f"ifIndex {i} is no longer {p['name']}")
            reading["ifs"][i] = (int(vals[f"{OID_HC_IN}.{i}"]), int(vals[f"{OID_HC_OUT}.{i}"]),
                                 vals[f"{OID_DISCONT}.{i}"])
        return reading

    def rates(self, prev, cur):
        """Per-interface bps, or None with a reason if the interval is not trustworthy."""
        dt = cur["mono"] - prev["mono"]
        if dt <= 0:
            return None, "non-positive interval"
        if cur["uptime"] < prev["uptime"]:
            return None, "router SNMP agent restarted"
        out = {}
        for i, p in self.ifs.items():
            in0, out0, d0 = prev["ifs"][i]
            in1, out1, d1 = cur["ifs"][i]
            if d1 != d0:
                return None, f"{p['name']} counter discontinuity"
            if in1 < in0 or out1 < out0:
                return None, f"{p['name']} counter went backwards"
            rin, rout = (in1 - in0) * 8 / dt, (out1 - out0) * 8 / dt
            limit = p["speed_bps"] * SPEED_MARGIN
            if p["speed_bps"] and (rin > limit or rout > limit):
                return None, f"{p['name']} rate above line rate"
            out[i] = (rin, rout)
        return out, None

    def poll_once(self):
        if not self.ifs or time.monotonic() - self.resolved_at > RESOLVE_EVERY_SECONDS:
            self.resolve()
        try:
            cur = self.read()
        except SnmpError:
            # Index moved or a value is missing: re-map next time and start a fresh baseline.
            self.resolved_at = 0
            self.prev = None
            raise
        prev, self.prev = self.prev, cur
        self.status["last_poll"] = cur["wall"]
        if prev is None:
            return None
        per_if, reason = self.rates(prev, cur)
        if per_if is None:
            self.event(f"sample discarded: {reason}")
            return None
        ts = int(round(cur["wall"]))
        roles = {}
        for i, (rin, rout) in per_if.items():
            acc = roles.setdefault(self.ifs[i]["role"], [0.0, 0.0])
            acc[0] += rin
            acc[1] += rout
        total = roles.get(PORT, [0.0, 0.0])
        with self.db:
            self.db.execute("INSERT OR REPLACE INTO samples VALUES (?,?,?,?)",
                            (ts, total[0], total[1], len(self.status["ports"])))
            self.db.executemany("INSERT OR REPLACE INTO role_samples VALUES (?,?,?,?)",
                                [(ts, r, v[0], v[1]) for r, v in roles.items() if r != PORT])
            self.db.executemany("INSERT OR REPLACE INTO port_samples VALUES (?,?,?,?)",
                                [(ts, self.ifs[i]["name"], v[0], v[1]) for i, v in per_if.items()])
        return ts, roles, {self.ifs[i]["name"]: v for i, v in per_if.items()}

    def event(self, msg):
        log.warning(msg)
        with self.db:
            self.db.execute("INSERT INTO events VALUES (?,?)", (int(time.time()), msg))

    def prune(self):
        cutoff = int(time.time()) - self.cfg["retention_days"] * 86400
        with self.db:
            for table in ("samples", "role_samples", "port_samples", "events"):
                self.db.execute(f"DELETE FROM {table} WHERE ts < ?", (cutoff,))

    def run_forever(self):
        interval = self.cfg["poll_interval_seconds"]
        next_at = time.monotonic()
        last_prune = 0
        while True:
            try:
                self.poll_once()
                self.status["last_error"] = None
            except Exception as e:  # keep polling through router/network hiccups
                self.status["last_error"] = str(e)
                log.error("poll failed: %s", e)
            if time.time() - last_prune > 86400:
                self.prune()
                last_prune = time.time()
            next_at += interval
            time.sleep(max(0, next_at - time.monotonic()))


def open_db(path):
    db = sqlite3.connect(path, check_same_thread=False)
    db.execute("PRAGMA journal_mode=WAL")
    db.executescript("""
        CREATE TABLE IF NOT EXISTS samples (ts INTEGER PRIMARY KEY, in_bps REAL, out_bps REAL, ports INTEGER);
        CREATE TABLE IF NOT EXISTS role_samples (ts INTEGER, role TEXT, in_bps REAL, out_bps REAL,
                                                 PRIMARY KEY (role, ts)) WITHOUT ROWID;
        CREATE TABLE IF NOT EXISTS port_samples (ts INTEGER, port TEXT, in_bps REAL, out_bps REAL,
                                                 PRIMARY KEY (ts, port)) WITHOUT ROWID;
        CREATE TABLE IF NOT EXISTS events (ts INTEGER, message TEXT);
        CREATE INDEX IF NOT EXISTS events_ts ON events (ts);
    """)
    return db


def percentile(values, pct):
    if not values:
        return None
    values = sorted(values)
    return values[min(len(values) - 1, int(len(values) * pct / 100))]


def stats(values):
    return {"avg": sum(values) / len(values) if values else None, "peak": max(values, default=None),
            "p95": percentile(values, 95)}


def make_handler(cfg, collector):
    index_html = (BASE / "static" / "index.html").read_bytes()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def send(self, code, body, ctype="application/json"):
            if not isinstance(body, bytes):
                body = json.dumps(body).encode()
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            url = urlparse(self.path)
            if url.path == "/":
                return self.send(200, index_html, "text/html; charset=utf-8")
            db = sqlite3.connect(cfg["db_path"])
            try:
                if url.path == "/api/current":
                    return self.send(200, self.current(db))
                if url.path == "/api/history":
                    q = parse_qs(url.query)
                    seconds = int(q.get("range", ["3600"])[0])
                    seconds = max(300, min(seconds, cfg["retention_days"] * 86400))
                    return self.send(200, self.history(db, seconds, q.get("view", ["total"])[0]))
                return self.send(404, {"error": "not found"})
            finally:
                db.close()

        def current(self, db):
            row = db.execute("SELECT ts, in_bps, out_bps FROM samples ORDER BY ts DESC LIMIT 1").fetchone()
            links, roles = [], {}
            if row:
                aliases = {v["name"]: v["alias"] for v in collector.ifs.values()}
                speeds = {v["name"]: v["speed_bps"] for v in collector.ifs.values()}
                role_of = {v["name"]: v["role"] for v in collector.ifs.values()}
                notes = cfg.get("notes", {})
                for name, i, o in db.execute("SELECT port, in_bps, out_bps FROM port_samples WHERE ts = ?", (row[0],)):
                    confidence, note = notes.get(name, ["", "Not assigned in config.json"])
                    links.append({"name": name, "role": role_of.get(name, "?"), "alias": aliases.get(name, ""),
                                  "confidence": confidence, "note": note,
                                  "in_bps": i, "out_bps": o, "speed_bps": speeds.get(name, 0),
                                  "contract_bps": (cfg["contracts_gbps"].get(name) or 0) * 1e9 or None})
                roles = {r: {"in_bps": i, "out_bps": o} for r, i, o in db.execute(
                    "SELECT role, in_bps, out_bps FROM role_samples WHERE ts = ?", (row[0],))}
            events = db.execute("SELECT ts, message FROM events ORDER BY ts DESC LIMIT 10").fetchall()
            return {
                "router": cfg["router_host"],
                "interval": cfg["poll_interval_seconds"],
                "latest": {"ts": row[0], "in_bps": row[1], "out_bps": row[2]} if row else None,
                "roles": roles,
                "role_order": ROLE_ORDER,
                "links": links,
                "status": collector.status,
                "events": [{"ts": t, "message": m} for t, m in events],
            }

        def history(self, db, seconds, view):
            since = int(time.time()) - seconds
            bucket = max(cfg["poll_interval_seconds"], seconds // 600)
            if view == "total":
                src, where, args = "samples", "ts >= ?", (since,)
            else:
                src, where, args = "role_samples", "role = ? AND ts >= ?", (view, since)
            rows = db.execute(
                f"SELECT (ts / ?) * ? AS b, AVG(in_bps), AVG(out_bps), MAX(in_bps), MAX(out_bps) "
                f"FROM {src} WHERE {where} GROUP BY b ORDER BY b", (bucket, bucket, *args)).fetchall()
            raw = db.execute(f"SELECT in_bps, out_bps FROM {src} WHERE {where}", args).fetchall()
            return {
                "bucket": bucket,
                "points": [{"ts": b, "in": ai, "out": ao, "in_max": mi, "out_max": mo} for b, ai, ao, mi, mo in rows],
                "summary": {"samples": len(raw), "in": stats([r[0] for r in raw]), "out": stats([r[1] for r in raw])},
            }

    return Handler


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--once", action="store_true", help="take one measurement over one poll interval and print it")
    args = ap.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    cfg = load_config()
    db = open_db(cfg["db_path"])
    collector = Collector(cfg, db)

    if args.once:
        collector.poll_once()
        time.sleep(cfg["poll_interval_seconds"])
        result = collector.poll_once()
        if result is None:
            raise SystemExit("sample discarded; see log above")
        ts, roles, _ = result
        total = roles.pop(PORT)
        for role in ROLE_ORDER:
            if role in roles:
                i, o = roles[role]
                print(f"{role:13} in {i / 1e9:8.3f} Gbps   out {o / 1e9:8.3f} Gbps")
        si, so = sum(v[0] for v in roles.values()), sum(v[1] for v in roles.values())
        print(f"{'sum of roles':13} in {si / 1e9:8.3f} Gbps   out {so / 1e9:8.3f} Gbps")
        print(f"{'ROUTER TOTAL':13} in {total[0] / 1e9:8.3f} Gbps   out {total[1] / 1e9:8.3f} Gbps")
        return

    threading.Thread(target=collector.run_forever, daemon=True).start()
    server = ThreadingHTTPServer((cfg["listen_host"], cfg["listen_port"]), make_handler(cfg, collector))
    log.info("dashboard on http://%s:%d", cfg["listen_host"], cfg["listen_port"])
    server.serve_forever()


if __name__ == "__main__":
    main()
