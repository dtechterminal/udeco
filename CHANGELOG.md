# Changelog

Each release has a section `## vX.Y.Z (YYYY-MM-DD)`. The release workflow
publishes that section as the GitHub release's notes, next to the builds
(`.github/release-notes.sh` prints it). A release without its section here
fails.

How sure each feature is:

- **Verified:** seen working on the real units with the UniFi controller.
- **Built:** written and tested in code, device commands checked on a unit,
  but not yet proven end to end.
- **Partial:** works, with a named gap.
- **Not possible:** this hardware or its software can't do it.

## v0.2.0 (2026-11-21)

The first udeco release. udeco makes TP-Link Deco X20 mesh units, and a
JioFiber JCOW414 router, show up in a UniFi Network controller as UniFi
access points. You then manage their Wi-Fi from UniFi like any UniFi AP.
Everything the agent does today is listed below.

### Downloads

| File | For | Install with |
|---|---|---|
| `udeco-ap-deco-x20-linux-armv7` and `.gz` | TP-Link Deco X20 V2 (Broadcom, armv7) | `deploy/deco-ap.sh` |
| `udeco-ap-jio-jcow414-linux-mipsle` and `.gz` | JioFiber JCOW414 (MediaTek, mipsle) | `deploy/jio-ap.sh` |
| `SHA256SUMS` | checksums of all four files | |

The deploy scripts build these same files from the same commit (the build
is reproducible), so a deploy's md5 matches the download's. You need root
SSH (Deco) or telnet (JioFiber) on the unit; getting it is not covered.

### What to expect

- The unit appears in UniFi as a **U6-Lite** (Deco) or a **UAP-AC-Lite /
  UAP-IW-HD** (JioFiber). Adopt it like any UniFi AP.
- After a reboot the Deco runs TP-Link's own Wi-Fi for about 2 minutes,
  then the agent takes over. Clients see one short drop at takeover.
- TP-Link's mesh, app and cloud stop working on taken-over units: every
  unit must be wired to your network, and you manage it only from UniFi.
- Firmware upgrades from UniFi are ignored; no Ubiquiti firmware is ever
  flashed.
- Remove the launcher and reboot, and the unit is stock TP-Link again.
- Tested on: three Deco X20 V2 (TP-Link firmware 1.3.0 Build 20250912)
  wired, UniFi Network 11.1.50 on a UniFi Cloud Gateway; one JCOW414. Other
  models and firmware are untested.

### Deco X20: management

- **Verified:** adoption, provisioning, Forget and re-adoption (no Wi-Fi
  restart on re-adoption).
- **Verified:** live stats following the controller's 1 s / 10 s inform
  interval.
- **Built:** `inform_every_s` (5-60 s, off by default) reports more often
  than the controller's ~30 s pacing for unwatched APs (Verified on the
  JioFiber at 10 s; not yet run on a Deco).
- **Verified:** restart from UniFi (back in UniFi about 3 minutes later).
- **Verified:** Locate and LED on/off (green; UniFi's LED colour is not
  carried).
- **Verified:** topology: UniFi shows the switch port the unit is on (LLDP).
- **Verified:** site SSH keys and site logins pushed from UniFi.
- **Verified:** login lock: while UniFi's Device SSH Authentication is off
  and the controller answers, new root logins to the unit are refused; they
  open after 10 minutes without the controller, or when Device SSH is
  turned on.
- **Verified:** encrypted remote syslog to the controller.
- **Built:** SNMP and an mDNS bridge (both off by default).

### Deco X20: Wi-Fi networks and security

- **Verified:** open and WPA2-Personal networks, with PMF optional or
  required.
- **Verified:** WPA2/WPA3 transition and WPA3 (SAE) with `"wpa3": true`.
- **Verified:** hidden networks, enabling and disabling networks, a VLAN per
  network, networks per AP group, MAC allow/deny lists, and Wi-Fi schedules.
- **Built:** WPA2/WPA3 Enterprise, RADIUS MAC authentication, private PSK
  and Hotspot 2.0. A network whose RADIUS server is unusable is refused,
  never brought up open.
- **Not possible:** Enhanced Open (OWE) and RADIUS-assigned VLANs (this
  hostapd has neither); such networks are refused.

### Deco X20: roaming and client tuning

- **Verified:** 802.11k neighbour reports listing the other units, and
  802.11v.
- **Built:** 802.11r fast roaming for WPA2 (FT-PSK) and WPA3 (FT-SAE). The
  units share roaming keys with signed announcements on the LAN. Phones join
  with it on; a fast roam between units has not been observed yet.
- **Verified:** client isolation, proxy ARP, multicast-to-unicast, DTIM and
  U-APSD settings, and Intelligent DHCP (DHCP replies sent unicast).
- **Built:** BSS Load element, BPDU filter, IGMP/MLD snooping on the
  agent's VLAN bridges, Target Wake Time (on by default, as on a U6 Pro).
- **Built:** band steering and max clients per radio.
- **Built:** Restrict to 5 GHz: dual-band clients seen on 5 GHz in the last
  hour are asked to leave 2.4 GHz; clients never seen on 5 GHz are never
  refused.
- **Built:** Minimum RSSI: a client below the controller's minimum for 3
  readings is asked to roam, then disconnected with a 30 s ban on that AP.
- **Built:** minimum data rates (off by default; it restarts the radio).

### Deco X20: radios

- **Verified:** channel, width (80 MHz on 5 GHz), transmit power, custom
  power without a radio restart, and U6 Pro radio defaults (implicit
  beamforming off, receiver desense off).
- **Built:** low/medium/high power presets, matching a U6 Pro.
- **Built:** auto channel: picked once when the radio restarts anyway; 2.4
  GHz uses 1, 6 or 11; 5 GHz never picks DFS; blocked channels are never
  used.
- **Verified:** country tables, including per-radio tables
  (`driver_country_bands`). The tested units run Broadcom's `#a` table on
  5 GHz for Wi-Fi 6 rates on 36-144 and 149-161; under it the agent
  refuses 120-128 (weather radar).
- **Verified:** DFS channels with the driver's channel availability check
  under a country table that has DFS; radar moves are followed and reported
  to UniFi (a real radar move has not been seen).
- **Verified:** neighbour and rogue-AP list, refreshed every minute.
- **Partial:** spectrum scan: 2.4 GHz complete; 5 GHz covers 36-48 only.

### Deco X20: clients

- **Verified:** client list with signal, rates, traffic and Wi-Fi
  generation; no clients flapping between APs.
- **Verified:** connect and leave events; a client that leaves disappears
  from UniFi at once.
- **Verified:** per-client TX retries; reconnect, block and unblock; lock a
  client to an AP (live, no hostapd restart).
- **Verified:** per-client speed limits (user groups). While any limit is
  set, the unit turns off its hardware flow cache, which costs some
  throughput.
- **Built:** network and user-group speed limits.
- **Built:** connection-timing events (association, authentication, DHCP,
  DNS timings, as UniFi APs report them), and a gratuitous ARP when a
  client joins so switches learn it at once.

### Deco X20: guests

- **Verified:** guests reach the gateway and internet but never LAN hosts.
- **Verified:** the gateway-hosted guest portal: before login a guest gets
  DHCP, DNS and the portal only; authorise opens the internet.
- **Built:** guest isolation across APs.
- **Not possible:** automatic captive-portal redirect (this ebtables has no
  redirect target); guests open the portal page themselves.

### Deco X20: stats, uplink and safety

- **Verified:** channel utilisation, CPU, memory, uptime, load, Wi-Fi
  Experience, wired uplink and its traffic.
- **Built:** networks go down when the uplink cable has no link for 5 s
  (and back after 10 s of link), so clients move to another AP; the LED
  blinks red meanwhile.
- **Built-in safety:** a failed apply retries the last good config, then
  hands Wi-Fi back to TP-Link with every network restored and stops
  changing anything (observe mode). TP-Link's app and web ports are closed;
  the unit's own internet access is blocked except to the controller. An
  unexplained reboot is recorded in `events.log`.

### JioFiber JCOW414

Run with `"platform": "jio-mtk"`; adopted as a UAP-AC-Lite (`U7LT`) or, with
`"model": "UHDIW"`, a UAP-IW-HD with LAN ports.

- **Verified:** adoption and provisioning; networks per AP group with WPA2
  and VLANs; channel, width and power; client list and stats; login lock
  (telnet and SSH). Jio's own services are stopped; telnet is kept.
- **Verified:** downlink watchdog: a 2.4 GHz client that stops answering
  while dozing (seen with a Tuya pump) is disconnected so it reconnects
  (seen live). In this release it checks every 5 s between informs, which
  has not yet caught a real stall.
- **Verified:** DTIM period per radio over the controller's
  (`driver_dtim_bands`, 2 on 2.4 GHz on the tested unit).
- **Partial:** WPA3 on 5 GHz only (the 2.4 GHz driver has no SAE); no SAE
  client seen yet.
- **Built:** U6 parity on this hardware: Minimum RSSI, WPS off, group rekey
  and PMK cache, 2.4 GHz auto channel on 1/6/11, multicast enhancement, tx
  power reported in dBm, implicit beamforming and 20/40 coexistence off,
  networks down on uplink loss (except one management network), immediate
  leave events, stable BSSIDs per network (`bss_pinning`), guest networks
  with the portal, proxy ARP, DFS on 52-64 (`dfs`), gratuitous ARP on join.
- **Built:** RF scans from UniFi (`site_survey`): neighbour list on both
  bands and per-channel utilisation charts on 2.4 GHz.
- **Built:** LAN port VLANs as a UAP-IW-HD, with a port monitor that undoes
  any port change that cuts the unit off from the controller.
- **Built:** gateway guard: a new build that loses the gateway rolls back
  to the previous build after 180 s, and the unit reboots after 480 s.
- **Not on this platform:** speed limits.

### Tooling

- `deploy/deco-ap.sh` and `deploy/jio-ap.sh`: build, read-only preflight
  checks, md5-checked install, launcher, and a one-line rollback.
- GitHub Actions: tests every push and builds one agent per device; tagged
  releases publish the builds with these notes.
- The Go module is `github.com/dtechterminal/udeco`. The OpenWrt code,
  tools and packaging inherited from unifi-openwrt (the project udeco was
  forked from) are removed; its UniFi protocol notes stay in
  `docs/internals.md`.
