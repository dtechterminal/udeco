# udeco

Run TP-Link Deco X20 units as UniFi access points.

`udeco-ap` is a small Go agent that runs **on** each Deco. It takes the unit's
Wi-Fi over from TP-Link's firmware and speaks the UniFi inform protocol, so a
UniFi Network controller adopts the unit as a **U6-Lite** (`UAL6`). From then
on UniFi configures it and shows its clients, radios and stats like those of
its own APs. TP-Link's firmware stays on the unit and takes back over if the
agent is removed or an apply fails.

The same agent also runs a JioFiber JCOW414 router as a plain UniFi AP
([second platform](#second-platform-jiofiber-jcow414)).

> **Tested setup.** Three Deco X20 V2 units on wired backhaul (TP-Link firmware
> 1.3.0 Build 20250912, kernel 4.1, Broadcom `wl`, hostapd 2.9), one mesh
> master and two satellites. They are adopted into UniFi Network 11.1.50 on a
> UniFi Cloud Gateway. All three run release `d9dd8fe` (19 Nov 2026), and the
> tables below were checked against that build. Other Deco models and firmware
> versions are untested.

## What works

Status key:

- **Verified:** working on the units with the controller.
- **Built:** written and unit-tested, with the device commands confirmed on a
  unit, but not proven end to end.
- **Partial:** works, with the gap named.
- **Not yet:** possible, not built.
- **Not possible:** this hardware, driver or hostapd build can't do it.

### Management

| Feature | Status | Notes |
|---|---|---|
| Adopt, provision, Forget, re-adopt | Verified | Adopted over SSH. Config sync uses the cfgversion handshake. A forgotten unit re-adopts without a Wi-Fi restart. |
| Live stats | Verified | Follows the controller's 1 s / 10 s inform interval. |
| Restart from UniFi | Verified | Back on UniFi about 3 minutes after the reboot. The unit runs stock TP-Link Wi-Fi until the agent's boot gate opens (at least 120 s). |
| Locate, LED on/off | Verified | LED on is steady green, also right after a reboot. Off goes dark. Locate blinks green until Unlocate. UniFi's LED colour can't be carried. |
| Topology (LLDP) | Verified | UniFi shows the parent switch port. |
| Device SSH keys and site logins | Verified | Site SSH keys pushed from UniFi let the site user log in; root login stays key-only. |
| Encrypted remote syslog | Verified | The controller's AES-GCM syslog format. |
| Firmware upgrade | Not possible | By design: upgrade offers are answered and ignored. Ubiquiti firmware is never flashed. |
| SNMP, mDNS bridge | Built | Off by default (`mdns_bridge` config key for the bridge). |

### SSIDs and security

| Feature | Status | Notes |
|---|---|---|
| Open, WPA2-Personal | Verified | PMF optional or required. |
| WPA2/WPA3 transition, WPA3 (SAE) | Verified | With `"wpa3": true`, 16 phones and laptops across the three units joined with SAE (AKM 00-0f-ac-8), and WPA2-only clients with PSK. A WPA3-only SSID has not been tried. |
| Hidden SSID, enable/disable | Verified | |
| VLAN per SSID | Verified | One bridge per VLAN on the uplink. |
| SSID per AP group | Verified | An SSID is broadcast only by the APs of its group. |
| MAC allow/deny lists | Verified | The driver's macmode together with hostapd's ACL. |
| WLAN schedules | Verified | An SSID goes off within seconds of its off-window starting. |
| WPA2/WPA3 Enterprise, RADIUS MAC auth, private PSK, Hotspot 2.0 | Built | Not tested against a RADIUS server. An SSID whose server is unusable is refused, never brought up open. |
| Enhanced Open (OWE) | Not possible | This hostapd build has no OWE; such an SSID is refused. |
| RADIUS-assigned VLANs | Not possible | No dynamic VLAN support in this hostapd. |

### Roaming and client tuning

| Feature | Status | Notes |
|---|---|---|
| 802.11k, 802.11v | Verified | Neighbour reports list the other units. |
| 802.11r (FT-PSK) | Built | On for every SSID. The units exchange FT key holders over signed announcements on the LAN. A client doing a fast transition has not been observed yet. |
| 802.11r for WPA3 (FT-SAE) | Off | Advertising FT-SAE stopped WPA3 phones (iPhone, Apple Watch, Pixel, Samsung) from joining at all. Keep `"ft_sae": false`. |
| Client isolation, proxy ARP, multicast-to-unicast, DTIM, U-APSD | Verified | |
| Band steering, minimum RSSI, max clients | Built | Band steering uses 802.11v nudges. |
| Minimum data rates | Built | Off by default (`"min_rates": true`). `wl rateset` runs inside a radio down/up, which drops that radio's clients. |

### Radios and RF

| Feature | Status | Notes |
|---|---|---|
| Channel, width, transmit power | Verified | Includes 80 MHz on 5 GHz. |
| Country | Verified | The driver's India table (IN/0) has no 80 MHz channel. Stock TP-Link runs these units as US/0, and so does the agent with `"driver_country": "US"`: all three units run 80 MHz on 5 GHz. |
| Power presets (low/medium/high) | Verified | Low, Medium and High set the driver's power reduction to 6 dB, 3 dB and none, without a radio restart. |
| Neighbour and rogue-AP list | Verified | Refreshed every minute by a passive listen on the AP's own channel. A full scan from UniFi adds the other channels. |
| Spectrum scan | Partial | 2.4 GHz is complete; 5 GHz covers 36–48. Channels 149–165 are reported as unmeasured, not as clean. |
| DFS channels | Not yet | No radar or CAC handling, so the units stay on 36–48 and 149–165. |

### Clients

| Feature | Status | Notes |
|---|---|---|
| Client list with signal, rates, traffic, Wi-Fi generation | Verified | Only stations the driver reports as associated are listed, so clients don't flap between APs. |
| Connect and leave events | Verified | A departed client leaves UniFi at once, not after about 5 minutes. |
| Connection-timing events | Not yet | |
| Per-client TX retries | Verified | Attempts, retries and retry % on each client's page. |
| Reconnect, block, unblock | Verified | |
| Lock client to AP | Verified | Every other unit denies a locked client. Its deny lists are updated live, without a hostapd restart. |
| Per-client speed limits | Verified | A client's own user group. A 512/768 kbit/s limit held at 460/652 kbit/s, and full speed returned when the client went back to the default group. The limit survives restarts and follows the client to any SSID of the unit. |
| SSID and user-group speed limits | Built | Same shaping path as per-client limits. |

Speed limits have one cost. Flows that the Deco's Broadcom flow cache
accelerates bypass Linux traffic shaping, so a unit turns its flow cache off
while it has any limit, and back on when none are left. Details are in
[client-rate-limit](docs/deco/features/client-rate-limit.md).

### Guest networks

| Feature | Status | Notes |
|---|---|---|
| Guest-to-LAN blocking | Verified | A guest reaches the gateway and the internet, never LAN hosts. |
| Gateway-hosted guest portal | Verified | Before login a guest gets DHCP, DNS and the portal only. Authorise opens the internet within one inform; unauthorise closes it again. |
| Guest isolation across APs | Built | |
| Captive-portal redirect | Not possible | This ebtables has no redirect target (checked on a unit). A guest opens the portal page themselves. |

### Stats and uplink

| Feature | Status | Notes |
|---|---|---|
| Channel utilisation, CPU, memory, uptime, load | Verified | |
| Wi-Fi Experience (AP and client) | Verified | |
| Wired uplink and uplink traffic | Verified | With a UniFi gateway, the controller credits the AP with its clients' traffic. |
| Wireless mesh uplink | Not planned | TP-Link's mesh is switched off at takeover; every unit is wired. |

## Hardware

| | Real U6-Lite | Deco X20 V2 |
|---|---|---|
| Wi-Fi | Wi-Fi 6, dual band | Wi-Fi 6, dual band |
| Streams | 2×2 on each band | 2×2 on each band |
| Widest channel | 80 MHz on 5 GHz | 80 MHz on 5 GHz, 40 MHz on 2.4 GHz |
| Transmit power | 20 dBm (2.4 GHz), 25 dBm (5 GHz) | 24 dBm (2.4 GHz), 23.5 dBm (5 GHz) target |
| 5 GHz channels | All for the country, DFS included | 36–48 and 149–165 |
| SSIDs per band | 8 | 5 (one driver slot is hostapd's hidden anchor) |
| Ethernet | 1 × GbE | 2 × GbE |
| Power | PoE | DC adapter |
| LED | White/blue ring | Green, red and a blink |

## How it behaves on the unit

- **Boot gate.** After a reboot the unit runs stock TP-Link Wi-Fi until
  TP-Link's boot has finished (at least 120 s); then the agent takes over.
- **TP-Link services stopped.** The mesh controller, auto channel, cloud, app
  server and Wi-Fi triggers would undo the agent's config, so they are stopped.
  Kept: procd, netifd, crond, dropbear, the LED daemon, `eapd`, `apsd`.
- **Fences.** TP-Link's app and web ports (20001–20003, 80, 443) are dropped
  inbound. An egress firewall blocks the unit's own traffic to the internet;
  the controller stays reachable.
- **One copy.** A second agent exits at once.
- **Rollback.** A failed apply first retries the last good config. If that
  fails too, Wi-Fi goes back to TP-Link with every SSID restored, and the
  agent drops to observe mode.
- **Reboot cause.** `/tp_data/udeco/alive` records whether the last boot ended
  with a clean stop, so an unexplained reboot shows up in `events.log`.
- **Persistence.** The agent and its config live on flash in `/tp_data/udeco`.
  They are started from the unit's existing cron hook.

## Install

You need root SSH on each unit; how to get it is out of scope here.

1. **Configure.** `/tp_data/udeco/udeco-ap.json` on the unit, for example:

   ```json
   {
     "inform_url": "http://192.168.0.1:8080/inform",
     "console_ip": "192.168.0.1",
     "model": "UAL6",
     "sshd_port": 2222,
     "takeover": true,
     "apply": true,
     "egress": true,
     "driver_country": "US",
     "ft_sae": false
   }
   ```

   Unknown keys are an error, so a typo can't silently flip a safety switch.
   With `"takeover": false` the agent only reports to UniFi and changes
   nothing. With `"apply": false` it logs its plans without applying them.
   Optional keys, all off by default: `wpa3`, `min_rates`, `mdns_bridge`,
   `hotspot2`, `mgmt_sources`.

2. **Deploy.** From a machine with Go and SSH access to the unit:

   ```sh
   deploy/deco-ap.sh <unit-ip>               # the canary unit
   deploy/deco-ap.sh --force-host <unit-ip>  # any other unit
   ```

   The script builds the armv7 binary, checks the unit (read-only), installs
   the gzipped agent to `/tp_data/udeco` with an md5 check and starts it. It
   prints a one-line rollback command at the end. Do satellites first, then
   the master.

3. **Supervise.** One line at the end of the unit's `/data/persist_shell.sh`,
   which cron runs every minute:

   ```sh
   [ -f /tp_data/udeco/start.sh ] && sh /tp_data/udeco/start.sh
   ```

4. **Adopt** the unit in UniFi. It appears as a U6-Lite.

The agent logs to `/tmp/udeco-bin/agent.log` (RAM, capped at 2 MB);
`/tp_data/udeco/events.log` keeps the important events across reboots.

**Undo:** `rm /tp_data/udeco/start.sh` and reboot. The unit comes back as stock
TP-Link. More in [packaging/deco](packaging/deco/README.md).

To build by hand:

```sh
GOOS=linux GOARCH=arm GOARM=7 CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o udeco-ap ./cmd/udeco-ap
```

Run `go test ./... && go vet ./...` before deploying a change.

## Second platform: JioFiber JCOW414

With `"platform": "jio-mtk"`, the agent runs a JioFiber JCOW414 (MediaTek
EN7528, MT7603 + MT7663) as a plain AP, adopted as a UAP-AC-Lite (`U7LT`).

- **Verified:** adopt and provision; SSIDs per AP group with WPA2 and VLANs;
  radio channel, width and power; client list and stats. Jio's services are
  stopped, and telnet is kept.
- **Partial:** WPA3 on 5 GHz only (the 2.4 GHz driver has no SAE). The driver
  accepts the profile, but no SAE client has been seen yet.
- **Not on this platform:** speed limits.
- **Neighbour scans (`"site_survey": true`, off by default; needs
  `takeover`):** UniFi's scan commands run the driver's site survey (`iwpriv
  <radio> set SiteSurvey=1`), which takes the radio off its channel for a
  few seconds, and the unit then claims RF scan. A scan from UniFi surveys
  both bands; the Environment page's spectrum scan (both bands) and the
  nightly quick scan (one band) have no spectrum measurement on this driver,
  so they run the same survey and fill only the neighbour list: no
  channel-utilisation table is reported. A quick scan reports itself running
  until its survey ends, as a real AP does: UniFi then asks for the next
  band (inferred from the real AP's logs). Surveys run only on a command
  from UniFi, one at a time, never during a Wi-Fi apply, a radio restart or
  the 20 s after it, and never on a radio that is down. Off, the neighbour
  list comes only from the driver's cached survey. Not yet measured on the
  unit: how long clients stall during a survey, and whether the survey's end
  is detected correctly (the agent takes a table that changed and then
  stayed the same for 2 s as finished; a driver that refills its table
  channel by channel could look finished early on the quiet 5 GHz DFS
  channels). Check both before turning it on.
- **LAN ports (`"model": "UHDIW"`):** the unit can instead report as a
  UAP-IW-HD: LAN ports 1-3, port 4 absent, the uplink as rear port 5. With
  Enable Port VLAN on, the controller's port VLANs apply to ports 2 and 3
  (port 1 only with `ports_unlocked`; the uplink never). Untested on the
  unit: tagged VLANs on ports 2-3. Give ports 2 and 3 explicit port
  profiles before turning Port VLAN on: the default "All" trunks every site
  network onto them.
- **Port monitor:** a port change that cuts the unit off from the
  controller undoes itself, since telnet over the LAN is the only way in.
  - *Confirm or revert:* every change to a port waits for an inform the
    controller answers that started after the change. That includes a move
    back to the plain LAN (a loop through a downstream switch can cut the
    unit off too) and a failed change whose rollback took the port off a
    VLAN. The change triggers an inform at once, and while it waits, failed
    informs are retried at least every 15 s. With none answered within
    `ports_confirm_s` (default 90 s, 60-900), the ports of that change go
    back to their previous settings, and the agent logs
    `EVENT: PORTS REVERTED (no inform reached the controller ...)`. A port
    that was in no bridge goes back on the plain LAN, never into no bridge
    again. The reverted setting is not applied again until the controller
    sends a different one for that port. A running Wi-Fi apply holds the
    bridges, so a revert can wait for it (at most one Wi-Fi apply).
  - *Controller loss:* when no inform is answered for `ports_loss_s`
    (default 300 s, 60-3600), every port the agent may change goes back on
    the plain LAN, and the agent logs
    `EVENT: PORTS REVERTED (controller unreachable ...)`. Port settings
    stay off until informs are answered again, then come back through the
    confirm window. A setting taken off this way twice in a row is not
    applied again until the controller sends a different one. Once informs
    have been answered for twice `ports_loss_s` after the controller came
    back, the count starts over, so two unrelated outages do not count.
  - *Startup:* no port setting is applied before the first answered inform.
  - A port that cannot be put back is retried every 5 s until it is on the
    LAN. Port 1 (when locked) and the uplink are never touched. Events also
    go to `events.log` next to the config. To re-apply a reverted setting,
    change the port's profile in UniFi (or restart the agent).
- **Changing the model** (U7LT to UHDIW or back) of an adopted unit needs a
  Forget and a new adoption: the controller keeps the model it adopted. The
  agent records that model in its state and, while the config differs,
  logs `MODEL NOT CHANGED IN UNIFI` and claims no port VLANs. Forget drops
  the AP's name, AP groups and radio settings, so note them first.
- **Gateway guard** (`deploy/jio-start.sh`): if the unit loses the gateway, it
  rolls back to the previous build after 180 s and reboots after 480 s. A new
  build is confirmed after 30 minutes healthy. A deploy that changes the
  config keeps the old one as `udeco-ap.json.prev` next to
  `udeco-ap.gz.prev`; the rollback restores both.

## Layout

| Path | What |
|---|---|
| `cmd/udeco-ap` | the agent: inform loop, adoption, config, actions |
| `internal/bcmwifi`, `internal/wl` | Deco Wi-Fi: hostapd configs, `wl` driver control, shaping, guest rules |
| `internal/decosys` | TP-Link service control, fences, boot gate |
| `internal/mtkwifi`, `internal/jiosys` | the JioFiber platform |
| `internal/inform`, `internal/device`, `internal/translate` | UniFi inform protocol and the controller's settings |
| `internal/ftpeer`, `internal/pathmon`, `internal/lldp`, `internal/snmpagent`, `internal/mdnsbr`, `internal/hs20`, `internal/radsec` | fast-roaming key exchange, uplink monitor, LLDP, SNMP, mDNS bridge, Hotspot 2.0, RadSec |
| `deploy/` | `deco-ap.sh` (Deco deploy), `jio-start.sh` (JioFiber supervisor with the gateway guard) |
| `packaging/deco` | persistent install on a Deco |
| `tools/wifi-inet-monitor` | per-client internet monitor that runs on the gateway |
| `docs/deco/` | [design](docs/deco/agent-design.md), [device capabilities](docs/deco/device-capabilities.md), [interference audit](docs/deco/interference-audit.md), [feature notes](docs/deco/features/) |

## Legal

Not affiliated with, endorsed by or supported by Ubiquiti, TP-Link or Reliance
Jio. It relies on unofficial UniFi controller behaviour that Ubiquiti can
change in any update. No Ubiquiti software, firmware or code is included.
UniFi and Ubiquiti are trademarks of Ubiquiti Inc.; Deco and TP-Link of
TP-Link; JioFiber of Reliance Jio. The names are used only to say what this
software works with.

## License

GPL-2.0-or-later; see [LICENSE](LICENSE). Third-party attributions are in
[NOTICE](NOTICE).
