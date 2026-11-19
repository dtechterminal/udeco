#!/usr/bin/env python3
"""Wi-Fi client internet monitor for the home UCG (runs on the gateway).

Every run (systemd timer, 2 min) it checks each wireless client the
controller lists:
  no_ip        associated for 5+ min without an IP
  no_internet  opened new internet connections since the last run and none
               of them got a reply (conntrack [UNREPLIED])
  ok           at least one new internet connection got a reply
  idle         no new internet connections; answers ping
  unreachable  no new internet connections and no ping reply (phones asleep
               often look like this, so it is reported, never acted on)

Fixes (never when the gateway itself has no internet, or when most clients
fail at once, which means the WAN, not Wi-Fi):
  - a client in no_internet or no_ip for 3 runs in a row, that had working
    internet in the last 24 h, gets a UniFi reconnect (kick-sta), at most
    once per hour per client and 5 per run
  - a Deco AP (UniFi model UAL6 with a b0:a7:b9 MAC) that has been
    disconnected for 10+ min gets a UniFi restart, at most once per hour

State, log and a JSON summary live in /data/wifi-inet-monitor. The summary
is also published to MQTT (Home Assistant discovery) when the broker is up.
Read-only except the two fixes above. --dry-run reports without fixing.
"""
import ipaddress, json, os, socket, struct, subprocess, sys, time, urllib.request

BASE = "/data/wifi-inet-monitor"
STATE = BASE + "/state.json"
LOG = BASE + "/monitor.log"
API = "http://127.0.0.1:8081/api/s/default/"
MQTT = ("192.168.0.4", 1883)
TOPIC = "wifi_inet_monitor"
DECO_OUI = "b0:a7:b9"
FAIL_RUNS = 3
KICK_EVERY = 3600
KICK_MAX = 5
OK_WITHIN = 24 * 3600
AP_DOWN = 600
AP_RESTART_EVERY = 3600
DRY = "--dry-run" in sys.argv


def log(msg):
    line = time.strftime("%Y-%m-%d %H:%M:%S ") + msg
    print(line)
    try:
        if os.path.exists(LOG) and os.path.getsize(LOG) > 1_000_000:
            os.replace(LOG, LOG + ".1")
        with open(LOG, "a") as f:
            f.write(line + "\n")
    except OSError:
        pass


def uid():
    return open("/root/.netapp-owner-uid").read().strip()


def api(path, body=None):
    req = urllib.request.Request(API + path, headers={"X-UserId": uid(), "Content-Type": "application/json"})
    if body is not None:
        req.data = json.dumps(body).encode()
        req.method = "POST"
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.load(r)["data"]


_LOCAL = None


def local_nets():
    """The gateway's directly connected networks (LAN prefixes, incl. its public IPv6 /64s)."""
    nets = []
    for fam in ("-4", "-6"):
        out = subprocess.run(["ip", fam, "route", "show", "table", "all"], capture_output=True, text=True).stdout
        for l in out.splitlines():
            f = l.split()
            if f and "proto" in f and f[f.index("proto") + 1] == "kernel" and "/" in f[0]:
                try:
                    nets.append(ipaddress.ip_network(f[0], strict=False))
                except ValueError:
                    pass
    return nets


def private(ip):
    global _LOCAL
    if _LOCAL is None:
        _LOCAL = local_nets()
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return True
    if a.is_private or a.is_link_local or a.is_multicast or a.is_loopback or a in ipaddress.ip_network("100.64.0.0/10"):
        return True
    return any(a.version == n.version and a in n for n in _LOCAL)


def policy_blocked():
    """Clients your firewall keeps off the internet on purpose: sources of
    enabled BLOCK policies with "internet" in their name (IP groups, IPs or
    ranges, client MACs). Returns (networks, macs)."""
    nets, macs = [], set()
    try:
        groups = {g["_id"]: g.get("group_members", []) for g in api("rest/firewallgroup")}
        req = urllib.request.Request("http://127.0.0.1:8081/v2/api/site/default/firewall-policies", headers={"X-UserId": uid()})
        with urllib.request.urlopen(req, timeout=15) as r:
            pols = json.load(r)
    except Exception as e:
        log("firewall policies unreadable: %s" % e)
        return nets, macs
    for p in pols:
        if p.get("action") != "BLOCK" or not p.get("enabled") or "internet" not in p.get("name", "").lower():
            continue
        src = p.get("source", {})
        for ip in groups.get(src.get("ip_group_id"), []) + (src.get("ips") or []):
            try:
                nets.append(ipaddress.ip_network(ip, strict=False))
            except ValueError:
                pass
        macs.update(m.lower() for m in src.get("client_macs") or [])
    return nets, macs


def neighbours():
    """ip -> mac from the gateway's neighbour tables (v4 and v6)."""
    out = subprocess.run(["ip", "neigh"], capture_output=True, text=True).stdout
    m = {}
    for l in out.splitlines():
        f = l.split()
        if "lladdr" in f:
            m[f[0]] = f[f.index("lladdr") + 1].lower()
    return m


def flows():
    """Internet flows started by LAN hosts: (key, src ip, replied)."""
    res = []
    for fam in ("ipv4", "ipv6"):
        out = subprocess.run(["conntrack", "-L", "-f", fam], capture_output=True, text=True).stdout
        for l in out.splitlines():
            f = l.split()
            kv = [x.split("=", 1) for x in f if "=" in x]
            srcs = [v for k, v in kv if k == "src"]
            dsts = [v for k, v in kv if k == "dst"]
            ports = [v for k, v in kv if k in ("sport", "dport")]
            if len(srcs) < 2 or len(dsts) < 1:
                continue
            src, dst = srcs[0], dsts[0]
            if private(dst):
                continue
            key = " ".join([f[0], src, dst] + ports[:2])
            res.append((key, src, "[UNREPLIED]" not in l))
    return res


def ping_all(ips):
    procs = {ip: subprocess.Popen(["ping", "-c", "1", "-W", "2", ip], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) for ip in ips}
    return {ip: p.wait() == 0 for ip, p in procs.items()}


def gateway_online():
    for ip in ("1.1.1.1", "8.8.8.8", "9.9.9.9"):
        if subprocess.run(["ping", "-c", "1", "-W", "3", ip], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
            return True
    return False


def mqtt_publish(msgs):
    """Minimal MQTT 3.1.1: connect (anonymous), publish retained QoS 0, disconnect."""
    def enc_len(n):
        b = b""
        while True:
            d, n = n % 128, n // 128
            b += bytes([d | (0x80 if n else 0)])
            if not n:
                return b

    def s(x):
        x = x.encode()
        return struct.pack("!H", len(x)) + x

    with socket.create_connection(MQTT, timeout=5) as c:
        var = s("MQTT") + bytes([4, 0x02]) + struct.pack("!H", 30) + s("wifi-inet-monitor")
        c.sendall(bytes([0x10]) + enc_len(len(var)) + var)
        if c.recv(4)[:2] != b"\x20\x02":
            raise OSError("mqtt connack")
        for topic, payload in msgs:
            body = s(topic) + payload.encode()
            c.sendall(bytes([0x31]) + enc_len(len(body)) + body)
        c.sendall(b"\xe0\x00")


def discovery():
    dev = {"identifiers": ["wifi_inet_monitor"], "name": "Wi-Fi internet monitor", "manufacturer": "udeco"}
    mk = lambda key, name, tmpl, icon: ("homeassistant/sensor/wifi_inet_monitor/%s/config" % key, json.dumps({
        "name": name, "unique_id": "wifi_inet_monitor_" + key, "state_topic": TOPIC + "/state",
        "value_template": tmpl, "json_attributes_topic": TOPIC + "/state", "json_attributes_template": "{{ value_json.problems | tojson }}" if key == "problems" else "{{ value_json.counts | tojson }}",
        "icon": icon, "device": dev}))
    return [mk("problems", "Wi-Fi clients without internet", "{{ value_json.problems | length }}", "mdi:wifi-alert"),
            mk("ok", "Wi-Fi clients with internet", "{{ value_json.counts.ok }}", "mdi:wifi-check")]


def main():
    os.makedirs(BASE, exist_ok=True)
    now = int(time.time())
    try:
        st = json.load(open(STATE))
    except (OSError, ValueError):
        st = {}
    st.setdefault("clients", {})
    st.setdefault("aps", {})
    st.setdefault("flows", [])

    sta = api("stat/sta")
    devs = api("stat/device-basic")
    neigh = neighbours()
    fl = flows()
    seen = set(st["flows"])
    new = [x for x in fl if x[0] not in seen]
    st["flows"] = sorted({x[0] for x in fl})

    wifi = [c for c in sta if not c.get("is_wired")]
    # the controller sometimes has no IP for a client that has one (an Apple
    # Watch with a lease and a REACHABLE neighbour entry, 2026-11-19): take
    # its IPv4 from the gateway's neighbour table
    v4 = {}
    for ip, mac in neigh.items():
        if ":" not in ip and not ip.startswith("169.254."):
            v4.setdefault(mac, ip)
    for c in wifi:
        if not c.get("ip") and v4.get(c["mac"]):
            c["ip"] = v4[c["mac"]]
    ipmac = {ip: mac for ip, mac in neigh.items()}
    for c in wifi:
        if c.get("ip"):
            ipmac[c["ip"]] = c["mac"]
    per = {}
    for key, src, replied in new:
        mac = ipmac.get(src)
        if mac:
            r, u = per.get(mac, (0, 0))
            per[mac] = (r + replied, u + (not replied))

    pings = ping_all([c["ip"] for c in wifi if c.get("ip")])
    online = gateway_online()
    bnets, bmacs = policy_blocked()

    def blocked(c):
        if c["mac"] in bmacs:
            return True
        try:
            a = ipaddress.ip_address(c.get("ip") or "")
        except ValueError:
            return False
        return any(a.version == n.version and a in n for n in bnets)

    results, counts = {}, {"ok": 0, "idle": 0, "unreachable": 0, "no_internet": 0, "no_ip": 0, "blocked": 0}
    for c in wifi:
        mac = c["mac"]
        r, u = per.get(mac, (0, 0))
        if blocked(c):
            s = "blocked"
        elif not c.get("ip"):
            s = "no_ip" if c.get("uptime", 0) >= 300 else "idle"
        elif r:
            s = "ok"
        elif u >= 2:
            s = "no_internet"
        elif pings.get(c["ip"]):
            s = "idle"
        else:
            s = "unreachable"
        results[mac] = s
        counts[s] += 1

    active = counts["ok"] + counts["no_internet"]
    wan_issue = (not online) or (active >= 4 and counts["no_internet"] * 2 >= active)
    if wan_issue:
        log("WAN problem (gateway online=%s, %d of %d active clients without internet): no client fixes" % (online, counts["no_internet"], active))

    names = {c["mac"]: (c.get("name") or c.get("hostname") or c["mac"]) for c in wifi}
    aps = {d["mac"]: d for d in devs}
    problems, kicks = [], 0
    for c in wifi:
        mac, s = c["mac"], results[c["mac"]]
        cs = st["clients"].setdefault(mac, {"fails": 0, "last_ok": 0, "last_kick": 0, "status": ""})
        if s == "ok":
            cs["last_ok"] = now
        cs["fails"] = cs["fails"] + 1 if s in ("no_internet", "no_ip") else 0
        if s != cs["status"] and (s in ("no_internet", "no_ip") or cs["status"] in ("no_internet", "no_ip")):
            log("%s (%s) %s -> %s on %s %s" % (names[mac], mac, cs["status"] or "new", s, aps.get(c.get("ap_mac"), {}).get("name", "?"), c.get("essid")))
        cs["status"] = s
        if s in ("no_internet", "no_ip"):
            problems.append({"name": names[mac], "mac": mac, "status": s, "ap": aps.get(c.get("ap_mac"), {}).get("name"), "ssid": c.get("essid"), "runs": cs["fails"]})
        if (not wan_issue and cs["fails"] >= FAIL_RUNS and now - cs["last_ok"] < OK_WITHIN
                and now - cs["last_kick"] >= KICK_EVERY and kicks < KICK_MAX):
            log("FIX: reconnect %s (%s): %s for %d runs, last working %d min ago%s" % (names[mac], mac, s, cs["fails"], (now - cs["last_ok"]) // 60, " [dry run]" if DRY else ""))
            if not DRY:
                try:
                    api("cmd/stamgr", {"cmd": "kick-sta", "mac": mac})
                except Exception as e:
                    log("FIX failed for %s: %s" % (mac, e))
            cs["last_kick"] = now
            kicks += 1

    # Decos the controller lost
    for d in devs:
        if not d["mac"].startswith(DECO_OUI):
            continue
        a = st["aps"].setdefault(d["mac"], {"down_since": 0, "last_restart": 0})
        if d.get("state") == 1:
            if a["down_since"]:
                log("AP %s back (was down %d min)" % (d.get("name"), (now - a["down_since"]) // 60))
            a["down_since"] = 0
            continue
        if not a["down_since"]:
            a["down_since"] = now
            log("AP %s (%s) not connected (state %s)" % (d.get("name"), d["mac"], d.get("state")))
        if now - a["down_since"] >= AP_DOWN and now - a["last_restart"] >= AP_RESTART_EVERY:
            log("FIX: restart AP %s: disconnected %d min%s" % (d.get("name"), (now - a["down_since"]) // 60, " [dry run]" if DRY else ""))
            if not DRY:
                try:
                    api("cmd/devmgr", {"cmd": "restart", "mac": d["mac"], "reboot_type": "soft"})
                except Exception as e:
                    log("FIX failed for AP %s: %s" % (d["mac"], e))
            a["last_restart"] = now

    # forget clients not seen for a week
    st["clients"] = {m: v for m, v in st["clients"].items() if m in results or now - max(v["last_ok"], v["last_kick"]) < 7 * 86400}
    tmp = STATE + ".tmp"
    json.dump(st, open(tmp, "w"))
    os.replace(tmp, STATE)

    summary = {"time": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "gateway_online": online, "wan_issue": wan_issue,
               "counts": counts, "problems": problems,
               "aps": {d.get("name"): d.get("state") == 1 for d in devs if d["mac"].startswith(DECO_OUI)}}
    json.dump(summary, open(BASE + "/last.json", "w"), indent=1)
    print(json.dumps(summary))
    try:
        mqtt_publish([*discovery(), (TOPIC + "/state", json.dumps(summary))])
    except OSError as e:
        log("mqtt: %s" % e)


if __name__ == "__main__":
    main()
