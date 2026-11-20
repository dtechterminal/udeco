# udeco: making the three Deco X20s appear as UniFi APs

**What it is.** udeco is a fork of unifi-openwrt (Go, GPL-2.0) with an off-device Deco backend. It runs as one Docker container on the Unraid host (192.168.0.4). It shows the three Decos to UniFi Network 11.1.47 on the UCG-Ultra (inform `http://192.168.0.1:8080/inform`) as three UniFi APs, and pushes Wi-Fi configuration from UniFi to the Decos over TMP.

**How to read the references.**

| Prefix | Meaning |
|---|---|
| `R/` | the reference repo `scratchpad/unifi-openwrt` |
| `J/` | the jadx output `deco-jadx/out/sources` |
| `P§n` | section n of `deco-tmp-protocol.md` |
| **INFERRED** | reasoned out, not read from code |
| **OPEN** | needs a live test; see `open-questions.md` |

## 0. Decisions

1. **One process.** It holds one `deco.Mesh` and three per-unit `runner`s.
   - The Mesh keeps the **only** TMP session, to the master 192.168.0.241. The app never talks to satellites (P§1). The Mesh polls and caches a `MeshState`.
   - Each runner owns its own `device.Session`, state directory and SSH-adoption listener. A runner only reads the cache; there is no TMP I/O on the inform path.
2. **Apply work runs off the inform path.** Apply, verify and rollback run on a Mesh goroutine. Upstream `syncAP` blocks its inform loop (R/cmd/uow/main.go:301-302, 566-571); we must not.
3. **Wi-Fi config is apply-gated.** `apply:false` is the default. Only the Mesh writes Wi-Fi config, as partial 0x4008 Sets shaped like the app's (P§8.4).
4. **Network.**
   - `--network host` on 192.168.0.4.
   - One shared daemon IP, with a different `sshd_port` per emulated AP: 22201, 22202 and 22203.
   - Never put a Deco MAC on a macvlan, which would cause an ARP conflict with the real Deco.
5. **Upstream code is reused unchanged:** `internal/inform`, `internal/device`, `internal/models`, `internal/unifiapi`, plus `openwrt.Snapshot`, `Fields`, `InfoFromCfg` and satisfaction. There is one additive file, `internal/translate/wlans.go`. `cmd/uow` is untouched.

## 1. Facts this design rests on

| Fact | Source |
|---|---|
| Master is .241 (b0:a7:b9:3e:16:94). Satellites are .205 (…:28:00) and .232 (…:26:fc). | TDP LIVE; P§0 R8/R9 |
| SSH 20001; user `sha1hex(TP-Link ID)`; plaintext password; owner account required | P§3.1 |
| Business V2 with token; JSON envelope | P§5, P§6 |
| Enum wire values are lowercase (`master`, `online`, `band5`, `band2+band5`, `guest`) | P§0 R2, R12 |
| WirelessInfo bands `band2_4`, `band5_1` (no `band5`) | P§0 R10 |
| `operation_mode` (`AP` or `Router`) comes from NEGOTIATE | P§8.1 |
| Client speeds are kbps. Runtime and rates are INFERRED as s and Mbps. | P§8.3 |
| Fields that drive the UniFi payload: `Snapshot.IP` (`ip`, `if_table.ip`), `Uptime`, `Radios`, `Stations`, `Ports`, `ARP` | R/internal/openwrt/unifi.go:39-70, 157-245 |
| `Session.Dev.MAC` is `net.HardwareAddr`; a length other than 6 is an error | R/internal/inform/u7pg2.go:45,72-74 |
| `Extra` overrides the U7PG2 defaults, so Uptime and IP must come from the snapshot | R/internal/device/session.go:116-177 |
| The SSH adopt request carries no MAC, so there must be one listener per session | R/internal/device/sshadopt.go:36-38 |

## 2. Package layout

```
cmd/udeco/main.go          config, Mesh, runners, signal handling
cmd/udeco/runner.go        per-AP port of uow's loop (main.go:290-477)
cmd/udeco/print.go         -print: one read-only poll dumped as JSON (no UniFi traffic)
internal/deco/             spec/go/{tmp,business,schemas,discovery}.go
internal/deco/mesh.go      session owner, poller, MeshState cache, apply queue, block reconcile
internal/deco/collect.go   Unit + clients -> openwrt.Snapshot (normMAC, connKey, Skeleton)
internal/deco/wlan.go      UniFi WLANs -> partial 0x4008 bodies, backup/verify/rollback
internal/translate/wlans.go  exported WLANs() + Mask() (additive)
```

**Config** is JSON at `/data/udeco.json`. JSON needs no new dependency: `go.mod` today has only `x/crypto` (R/go.mod).

## 3. Mesh

### 3.1 Session lifecycle

1. **Startup.** Run TDP discovery against the three configured IPs (P§2). Then require all of the following, and refuse to start otherwise:
   - exactly one unit with `role=master`;
   - that unit is `mesh.master` in the config;
   - `OwnerMatches(tplink_id)`;
   - `!UsesTLS()`;
   - `!TPSBanner()`.
2. **Connect.** Call `deco.Connect` with these settings:
   - `SSHUser = info.SSHUsername(id)`;
   - `HostKey = PinnedHostKey(<.241 fp>)`;
   - `Owner = true`;
   - `RequestTimeout = 45s` (the app's 30 s + 15 s); 0x4012 gets 75 s, as in the app (`postRequestForGet(..., 60L)` at `tpm5/component/network/client/repository/l0.java:930`, plus 15 s at `apps/network/tmp/i0.java:581`). See `AppRequestTimeout`.

   Then record `Negotiation.OperationMode`. If it is not `AP`, log a warning: in Router mode, Deco clients are NATed and will not appear in UniFi's client table.
3. **Reconnect.**
   - On transport loss, `Client.ensureTransport` redials lazily on the next call.
   - The Mesh rate-limits redials: at least 60 s apart, with exponential backoff up to 15 min. Each redial costs one SSH password attempt, and the lockout thresholds are OPEN.
   - On SSH auth failure, **latch off** and stop all logins until the process restarts. This protects against the TP-Link lockout.
4. **BYE handling.**
   - On reason 3 (CLIENT_LIMIT) or 7 (USER_COUNT_EXCEED), back off for 10 min. The phone app may be competing for the session (INFERRED).
   - On reason 4 (reboot) or 6 (upgrade), back off for 3 min.
   - On reason 8 (auth changed), latch off.

### 3.2 Polling and the cache

Polls run one at a time, in this order (the slow 0x4012 last):

| What | Opcode | Interval | Gated on component |
|---|---|---|---|
| Device list | 0x400f | 15 s | |
| Client speeds (presence) | 0x4014 | 15 s | `client_speed` |
| IoT clients | 0x4040 | 15 s | `iot_client` |
| Wireless info | 0x4009 | 60 s, and after every apply | |
| Port status | 0x4327 for all device_ids | 5 min | |
| Block list | 0x4018 | 60 s | |
| Client list (enrichment) | 0x4012 | `clients_every`, default and minimum 10 min; `no_client_list` turns it off | `client` |
| Resource info | 0x4317, once per id if `resource_support` | 5 min (optional) | |

- A gated Get is sent only when NEGOTIATE lists the component, as the app does (`mesh/context/c.java:1142,1232,1630`); a NEGOTIATE without a component list gates nothing.
- **Who is connected (`deco.LiveClients`).** Live, on fw 1.3.0 in AP mode, 0x4012 took 62 s and returned only the stored per-client settings: 192 entries, all `online:false`, no `ip`, and `linked_device_info` on 10 of them. The app has no other client-list opcode (p.java name map :1313-1481; `client_mesh`/`client_link`/`client_device` are per-client settings on the same ClientBean). So presence comes from the fast lists: a client is connected when a fresh 0x4014 lists its MAC, a fresh 0x4040 entry is `inet_status:online`, or a fresh 0x4012 entry is `online:true`. The units' own MACs (and their +2 locally administered variants, `l0.java:622-633,872-884`) are left out.
- **Where (placement).** The access Deco and band are `linked_device_info.device_id` and `connection_type[0]`: of the 0x4040 entry, else of the session's last 0x4012 entry (`clients` when it said online, `clients_last` when it said offline: the last known attachment, INFERRED possibly stale after a roam). A present client with no placement is reported in `-print` (`live.unplaced`) but not put on any radio: nothing says which.
- While the slow 0x4012 blocks the session (up to its 75 s budget), `Fresh` does not age the other lists (`MeshState.Busy`), nor after it returns until they are read again (`MeshState.LastSlow`), so the lists read before it do not all turn stale the moment it returns.
- The `MeshState` cache holds the results plus a timestamp and an `ok` flag.
- `AppError.NoData()` (1010) means empty.
- An opcode that returns any other `error_code` repeatedly (unsupported) is disabled for the session.

### 3.3 Master and ownership

- `ConfigOwner` requires exactly one device_list entry with:
  - `device_id == master_device_id` (or no `master_device_id`);
  - `role == master`;
  - `normMAC(mac) == mesh.master`;
  - TDP cross-check: `md5hex(device_id)` equals the TDP `master_device_id`. TDP carries MD5 digests of the TMP ids (`TmpGenericDevice.a()` = `dj.a.r(device_id)`), so the raw ids are never compared directly.
- If two disagree, apply is refused and the problem is logged.

## 4. Runner (one per unit, a port of R/cmd/uow/main.go)

**Startup.** These steps mirror `main.go:129-165, 270, 275-279`:

1. `MkdirAll(dir, 0700)`.
2. `device.Load`. On a miss, `NewState(inform_url)` with `Version = profile.Version`.
3. Create `HashID` and save it.
4. `RestoreFromMgmtCfg()`.
5. Build the Session with `Dev.MAC = net.ParseMAC(unit.mac)` and `Dev.IP = daemon IP`.
6. Start the `SSHAdopt` listener on `:<sshd_port>` with `AllowFrom = [192.168.0.1]` and a per-unit RSA host key.
7. If `system_cfg.txt` exists, plan and log once.
8. Do **not** exit when the Deco is unreachable: `Collect` falls back to a skeleton.
9. Once the mesh has been read, refuse a unit whose MAC is missing from device_list.

**Loop.** This is `main.go:290-410`:

1. `informOnce`. It is skipped while the unit is offline (see Offline policy).
2. Action dispatch, per §7.
3. On a cfgversion change, plan and log through `translate.Mask`. If `apply` is on and this runner's unit is the config owner, submit the plan to `Mesh.SubmitWLAN`, which is debounced by 10 s.
4. The runner does **no** block re-assert; the Mesh does it.
5. Reset handling. With `on_remove: stop`, stop this runner and drop its block list. With `pending`, keep informing on the factory key.
6. Interval, backoff and `select`, as upstream.

**Extra, run on every inform.**

```go
s, err := ap.Collect()                       // from the Mesh cache
if err != nil || s == nil { s = prev; if s == nil { s = deco.Skeleton(view, sinceStart, now) } }
c := *s
c.IP = r.reportIP()                          // daemon IP until adopted (unifi.go:40,70 overwrite Dev.IP)
cfg, _ := os.ReadFile(dir+"/system_cfg.txt") // re-read each time (main.go:211-212)
info := openwrt.InfoFromCfg(string(cfg))
info.Authorized = guestStations(&c, info)    // Deco guest has no portal (unifi.go:234-237); INFERRED rendering
f := c.Fields(prev, info, nil); prev = &c; return f
```

**Offline policy.**

- A unit is offline when it is absent from device_list, or when `inet_status == "offline"`. An absent `inet_status` means online (TMPDeviceBaseBean.java:71-72).
- After a 60 s grace period, the runner stops informing, and UniFi shows the AP as disconnected.
- If the master session has been down for more than 120 s, all runners stop informing until it recovers.

## 5. Adoption

**Default: Option A.** The controller SSHes to `<reported ip>:<sshd_port>` as `ubnt` and runs `set-adopt`. `sshadopt.go` accepts any password from allow-listed sources only (R/internal/device/sshadopt.go:66-71,92-97). The `setparam mgmt_cfg authkey` path and the `cmd set-adopt` reply are also handled (session.go:321-332,433-443).

| Setting | Behaviour |
|---|---|
| `report_ip: daemon` (default) | Always report 192.168.0.4, so the controller can reach the SSH listener for re-provisioning. |
| `report_ip: deco` | After adoption, report the Deco's IP. This is cosmetic, and **OPEN** (does the controller re-SSH?). |

**Profile.** The default is `U7PG2` (AC-Pro), the only model tested upstream on Network 10.x (R/README.md:36-43; R/docs/internals.md:537-539). The X20 is AX, so `UAL6` is a closer match but untested on 11.1.47 (OPEN). `wifi_caps=131072` claims WPA3 (main.go:59).

## 6. Mapping Deco data to a Snapshot (`internal/deco/collect.go`)

### 6.1 Unit-level fields

| Snapshot | From | Notes |
|---|---|---|
| `MAC` | config unit MAC (`normMAC`: dashes to colons, lowercase) | The device_list MAC format is OPEN, so normalise everywhere. |
| `IP` | the runner's `reportIP()` | The real Deco IP is kept separately. |
| `Hostname` | `custom_nickname` (LocB64), else `nickname`, else config name | |
| `Uptime` | `runtime` (INFERRED seconds), else seconds since first seen online | Always set (unifi.go:39,64). |
| `Ports` | eth0 `Up:true`, 1000/full; `port_speed` from 0x4327 when known | `UplinkName="eth0"` (unifi.go:329-333). |
| `Radios` | always `wifi0` ng and `wifi1` na (the controller never forgets radio rows) | `channel` from TDP `channel_2g`/`channel_5g` or `band.radio.channel`; `Width` from `htmode` (HE40/HE80, INFERRED); NSS and power from the profile |
| `MemTotal`/`MemFree`, CPU | 0x4317 if supported, else placeholders | |
| `ARP` | client `mac → ip` for this unit's clients, plus the parent unit MAC (for mesh rendering) | Exact-key lookup (unifi.go:238). |

### 6.2 VAPs and stations

- **VAPs.** For each radio:
  - the **main** VAP, from `band.host` (`enable`, `ssid`);
  - optionally a **guest** VAP, from `band.guest.enable`.
- **BSSIDs** are synthetic: the unit MAC with the LA bit set and the last byte varied. No real BSSIDs are exposed (P§8.7).
- **Assigning a station to a unit:**
  - `online == true`;
  - `linked_device_info.device_id == unit.device_id`;
  - link key = `connKey(linked_device_info.connection_type[0])`.
- **Radio for a link key:** `band2_4` or `band2` → ng; `band5`, `band5_1` or `band5_2` → na. A combo key (`band2+band5`) uses its first part. `wired` and `plc` are not wireless.
- **Guest VAP or main VAP:** `interface == "guest"` puts a station on the guest VAP; anything else goes on main.
- **Station fields:**
  - `Signal` = `signal_strength[key]` when it is negative (dBm, INFERRED); else bars from `signal_level[key]`; else -60. It is never 0, because `rssi = Signal - Noise` (unifi.go:222).
  - `TxRate`/`RxRate` = `tx_rate_list[key]` / `rx_rate_list[key]` × 1000 (Mbps to kbit/s, INFERRED).
  - `Connected` = `online_time`, else `now - access_time`.
  - Byte counters come from 0x4014 `up_speed`/`down_speed` (kbps), integrated over the poll interval. They are approximate.
- **`is_guest` in the payload** follows the UniFi config: a VAP is guest only if its SSID matches a UniFi guest WLAN on that radio (unifi.go:203-216).

### 6.3 Mesh uplink (phase 2, optional)

For a satellite whose `connection_type` is wireless, emit a `Mode=="Client"` VAP:

- Its station MAC is the **parent's synthetic BSSID**: LA bit set, same bytes 1-4. It must not be the parent unit MAC, because `parentDevice` excludes equal MACs (unifi.go:566-582).
- Add the parent unit MAC to `ARP`.

## 7. Actions from UniFi

| UniFi | Deco | Gate |
|---|---|---|
| `block-sta` / `unblock-sta`, `blocked_sta` | Desired set = the **most recently received** `blocked_sta` across adopted, informing runners. The Mesh reconciles every 60 s: read 0x4018, add with 0x4017 (`{mac, name b64, client_type}` copied from the client list), remove with 0x4019 only MACs listed in `blocks.json` (ones udeco added). With apply on, `blocks.json` also keeps the last received list; after a restart it is the desired set until a new list arrives (without it, the union of the runners' saved lists), so stale per-runner state never makes blocks flap. | `apply` |
| `restart` | 0x4016 `{device_list:[{device_id}]}` for that unit, then wait until it is back in device_list | `apply` |
| `led` on/off | If `led_individual_control`, set `schedule[device_id].enable`; else only the owner sets global `enable` (0x401b) | `apply` |
| `kick-sta` | Unsupported (no opcode). Optionally emulate with block, wait 5 s, unblock. | `apply` + `kick_emulation` |
| locate, scan, upgrade, guest portal | Logged as unsupported | |
| forget | Stop the runner; the Deco is untouched | |

## 8. UniFi Wi-Fi config to Deco (`internal/deco/wlan.go`)

### 8.1 Extraction

Call `translate.WLANs(cfg)`, which factors out `Plan`'s walk (R/internal/translate/translate.go:168-302).

- Skip mesh and uplink WLANs.
- Group by SSID and radio.

### 8.2 Mapping

These rules apply only to the WLAN chosen as **main** (non-guest, enabled, on both radios) and the one chosen as **guest**.

| UniFi | Deco host or guest key |
|---|---|
| `ssid` | `ssid` (b64) |
| `wpa.psk` | `password` (b64, secret: always masked in logs) |
| `hide_ssid` | `enable_hide_ssid` |
| `status=disabled` on a radio | that band's `enable=false` |
| `sae` / `sae-mixed` | `enable_wpa3=true` (OPEN: transition mode or WPA3-only); `encryption_mode` is left unchanged |
| `psk2+ccmp` | `enable_wpa3=false` |
| open | not applied (logged) |

- **More than one non-guest WLAN, or different SSIDs per radio:** apply the first and log the rest. The app never sends per-band SSIDs (P§8.4), so this is OPEN.

### 8.3 Body

Use `BuildHostSet(get, patchedHost)` and, separately, `BuildGuestSet`. Each body is partial, contains only the bands present, and mirrors `band60` (P§8.4).

### 8.4 Apply safety (on the Mesh goroutine)

1. **Debounce** for 10 s, then **diff** the patched keys against the fresh 0x4009. If nothing changed, do nothing.
2. **Back up** the raw 0x4009 JSON to `/data/backups/wireless-<ts>.json`, mode 0600 because it contains PSKs.
3. **Send** host Set (0x4008), then guest Set if needed. `error_code == 0` means accepted.
4. **Verify.** Within 3 min, all of these must hold:
   - a re-read of 0x4009 shows the patched keys;
   - all three units are back in device_list and online;
   - the TMP session works.

   Satellites may drop briefly when the backhaul re-keys (OPEN).
5. **On failure, roll back.** Send partial Sets built from the backup objects, every 30 s for up to 30 min. Then **latch apply off** and log loudly.
6. **Rate-limit:** at most one apply per 5 min.

## 9. Deployment on Unraid (192.168.0.4)

**Image.** The [`Dockerfile`](../../Dockerfile) is multi-stage: a static binary is built in the Go image and copied into a distroless one (the Dockerfile names both images). The binary is `/udeco` and the volume is `/data`.

**Run command.** [`deploy/unraid.sh`](../../deploy/unraid.sh) `run` builds the image on the host and starts the container. The script holds the command, the user the container runs as and the host directory mounted at `/data`; [README.md](README.md), Setup step 4, shows the equivalent `docker run`.

**Config `/data/udeco.json`.** [`deploy/udeco.example.json`](../../deploy/udeco.example.json) is the example, and a test loads it. README.md, Setup step 1, lists every key and its default.

**Secrets.**

- The TP-Link password is never in the JSON. README.md, Setup step 2, lists where it is read from; `deploy/unraid.sh` gives the files in the appdata directory to the container's user and makes the credential files mode 0600.
- The password is never logged, and is passed only to `ssh.Password`.
- State directories are `/data/units/<mac>/`, mode 0700, and hold `state.json`, `system_cfg.txt`, the host keys and `unhandled.json`.

**Firewall.**

- The daemon must reach the UCG at 192.168.0.1:8080. Informs go **out** from the daemon; nothing listens on 8080 locally.
- The UCG must reach 192.168.0.4:22201-22203 for SSH adoption.
- The daemon must reach the master on TCP 20001 and all three units on UDP 20002 (TDP).

## 10. Rollout

1. **`udeco -print` (read-only).** Run TDP, one login, NEGOTIATE, and 0x400f, 0x4012, 0x4014, 0x4009, 0x4327. Dump the JSON, with PSKs masked. This settles the OPEN items: MAC format, units, `operation_mode`, the reply style, and whether the heartbeat is echoed. One SSH login only (`MaxLogins = 1`), whatever `-print-timeout` (default 90 s) is. `-only devices,speeds,iot,clients` polls just those Gets in that order (names: `devices,speeds,iot,wireless,ports,blocks,clients`), each until it succeeds once (`MeshConfig.Once`: an answered Get is never re-sent in the run, and a cancelled retry never clears an earlier success); every unit's snapshot is printed (the skeleton when device_list was not read); `-trace` logs every TMP frame, V2 packet header and request time (never payloads, the token or credentials). A request the caller's deadline ends is not counted as a link error, and nothing is sent on an expired context.
2. **Inform with `apply:false`, one unit (.241).** Adopt it in UniFi. Check that clients, uptime and radios render, and that the phone app still works alongside it.
3. **All three units, `apply:false`.** Watch for 24 h for session drops, BYE reasons and redial counts.
4. **`apply:true`, block and LED only.**
5. **`apply:true`, Wi-Fi.** Change the guest SSID first and verify; then the main network.

## 11. Known limitations

- **Per-AP channel, tx power and BSSID.** These are placeholders or network-wide values.
- **Satisfaction.** Retries are never penalised. 5 GHz satisfaction follows the PHY rate when known.
- **Statistics.** Byte counters are integrated speeds, not true counters.
- **Session contention.** One TMP session may compete with the phone app (OPEN).
- **Internet dependence.** Behaviour when the internet is down depends on whether dropbear checks the password locally (OPEN).
