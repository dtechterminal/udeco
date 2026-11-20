# Path monitoring, encrypted syslog, SNMPv3, RADIUS filter

Status 2026-11-19. Covers fw3_caps 0x40 (path monitoring), fw_caps 0x1000000
(syslog encryption), fw_caps 0x4000 (SNMPv3) and fw_caps 0x20000000 (RADIUS
filter). Source of truth: the decompiled Network 11.1.50 controller
(internal-dependencies.jar) and the U6 Pro captures in docs/reference/u6pro/.
Syslog (syslogfwd.go) and RADIUS filter (radiusfilter.go) point here too.

## Path monitoring (fw3_caps 0x40): implemented, observe and takeover

### What the controller does with the bit

- `XCfthFC.supportsPathMonitoring()` = `hasFirmware3Capability(64)`.
- system_cfg (`ubntconf.PCBG`, only when the bit is set):

  ```
  # pathmon
  pathmon.status=enabled
  pathmon.interval=5
  pathmon.timeout=1000
  pathmon.ema_samples=60
  pathmon.size=56
  pathmon.target.1.type=gateway
  pathmon.target.2.type=uplink
  ```

  The U6 Pro's ubntbox also knows `target.N.type=host` with `target.N.addr`
  (`U6 Pro ubntbox strings`).
- The inform reply's `include_blocks` lists `"pathmon"`
  (`devmgr.l.PfwtrEhZ`). The agent sends the object whenever monitoring is
  on, so the request needs no answer of its own.
- The inform's `pathmon` object is stored on the device as is
  (`service.ax.QdjEeOBh`). It is removed when the bit is missing.
- Site feature `INFRASTRUCTURE_PATHMON` (`described-features`) exists once
  any device of the site has the bit. It is absent today.
- The infrastructure snapshot keeps each target's family, type, resolved
  address, state, latency, jitter, loss, samples and last update
  (`infrastructure.snapshot.history.SbNDDvSF`).
- Field names (`data.bccfhZmSuPJVNcK$YUuUodNhxQgik`): `interval`,
  `ema_samples`, `targets[]` with `type`, `addr`, `resolved`, `state`,
  `latency_us`, `latency_us_ema`, `jitter_us`, `jitter_us_ema`, `loss_pcm`,
  `loss_pcm_ema`, `samples`, `last_update_ts` and `family`.
- Enums: state `pending|reachable|unreachable|unknown`; type
  `gateway|host|uplink|unknown`.

### What the agent does

`internal/pathmon` handles the protocol. `cmd/udeco-ap/pathmon.go` wires it in.

- **Config.** It is read from the saved system_cfg when the cfgversion or
  system_cfg changes, and only while adopted.
- **Limits.** The interval is held to 1 s-60 s and the timeout to at most the
  interval. The size is held to 1472, at most 8 targets are kept, and a
  host target must be an IPv4 literal. Each clamp or skip is logged and
  noted in the intent notes.
- **Probes.** ICMP echo over a raw `ip4:icmp` socket, opened per probe, so
  targets run in parallel. A reply must match the identifier, the sequence,
  an 8-byte random token and the source.
  - The agent runs as root. The unit's `ping_group_range` is `1 0`, so an
    unprivileged ICMP socket is not available.
  - Verified as root in a Linux container (`TestICMPLoopback`). The test is
    skipped on macOS without root.
- **Targets.**
  - `gateway` is the reading's default gateway.
  - `uplink` is the first IPv4 management address of the LLDP neighbour
    heard on the uplink port. On the U6 Pro the uplink target resolved to
    the address in its `lldp_table` `mgmt_ips[0]`.
  - With no such neighbour, `uplink` stays `pending` and is not probed. This
    is the case behind an unmanaged switch or a Deco master, which send no
    LLDP.
  - `host` is `target.N.addr`.
  - A target whose address changes starts again from zero.
- **Inform.** The shape is the U6 Pro's: `{interval, ema_samples, targets[]}`
  with one `family:"ipv4"` row per target. Each row carries `type`, `state`,
  `resolved`, `latency_us`, `latency_us_ema`, `jitter_us`, `jitter_us_ema`,
  `loss_pcm_ema`, `samples` and `last_update_ts`, plus `addr` for a host.
  The test compares the row keys with `mca-dump.json`.
- **Averages.** These are our choice, not measured from upathmond:
  - Each average is exponential with weight `1/ema_samples`, and is the
    plain mean until `ema_samples` samples exist.
  - Jitter is `|rtt - previous rtt|`.
  - Loss is per-cent-mille (0-100000) over all probes. A lost probe keeps
    the last latency.
  - `samples` counts probes sent, and `last_update_ts` is the unix time of
    the last finished probe.
- **State.**
  - `pending` until the first probe and while there is no address.
  - `reachable` after a reply.
  - `unreachable` after 3 unanswered probes in a row, so one lost echo does
    not flap the state.
- **Not done.** No IPv6 rows: the U6 Pro also sends a `pending` ipv6
  gateway row, and we do not fake one. `loss_pcm` (no EMA) is not sent
  either; the U6 Pro does not send it.
- **Egress.** With `egress` on (takeover), `UDECO-OUT` allows the LAN
  subnet only. Gateway and LAN hosts work; a host target outside the LAN
  shows `unreachable`.

Claim: fw3_caps 0x40 in both modes. The bit is not takeover-only, because
the probes do not touch Wi-Fi. The inform needs an `fw3_caps` word; see
"Integration" below.

## Encrypted remote syslog (fw_caps 0x1000000): implemented, observe and takeover

Controller (`service.config.RngEFIxepjqE`):

- With "log to this controller" (`this_controller`) it sends:

  ```
  syslog.status=enabled
  syslog.level=<8 debug|7 info|5 warn>
  syslog.remote.encrypt=enabled
  syslog.remote.key=<device syslog key>
  syslog.remote.ip=<controller>
  syslog.remote.port=5514
  syslog.remote.status=enabled
  netconsole.*
  ```

  It sends `encrypt` and `key` whether or not the bit is set.
- The bit only matters for "encrypted only"
  (`this_controller_encrypted_only`). Without the bit, that setting makes
  the controller send no `# syslog` section at all.
- The receiver (`service.aM.CqACYAR`, UDP 5514) is unchanged from 10.6.109:
  - magic `ABCDDCBA`, then `01`, then `00000001`
  - then hash_id (8 bytes), then the nonce (12 bytes)
  - AES-256-GCM, with bytes 0-28 as AAD

  This is `device.SealSyslog`.

The U6 Pro runs `logread -f -u -r <ip> 5514 -h <host> -E <key>`. The Deco's
logread has `-f -r -u -h` but no `-E`. So `cmd/udeco-ap/syslogfwd.go` does
it this way:

- It follows `logread -f -l 1`. The `-l 1` means a restart does not resend
  the ring buffer.
- It rewrites each line as a UAP line,
  `<pri>Mmm dd hh:mm:ss host UAL6,mac12,version: msg`. It keeps only
  severities below `syslog.level`, the busybox `-l` meaning, and is rate
  limited to 50 lines/s with bursts of 100.
- It sends each line as one UDP datagram: sealed when `encrypt=enabled`,
  plain RFC 3164 text otherwise (a syslog server of the user's own).
- It restarts on a change of system_cfg, hash_id, version or hostname, and
  retries every 10 s when logread exits.
- The key is never logged.
- logd's own remote target is not touched, so this is safe in observe mode.

Wi-Fi notes no longer say "remote syslog: not implemented".

Limits:

- netconsole (kernel console over UDP) is not sent. The note
  "netconsole: kernel log streaming is not supported" stays.
- With `egress` on, a syslog server outside the LAN is dropped by
  `UDECO-OUT`. The controller is on the LAN.

Claim: fw_caps 0x1000000 in both modes.

## RADIUS filter (fw_caps 0x20000000): implemented, takeover only

Controller (`service.config.XHjguBsIf`, about line 1084): for a WPA-EAP
WLAN, when the site uses the console's RADIUS server
(`SERVICES_RADIUS_SERVER`), it sends `aaa.N.filter_id=wpa-eap`, or
`uid-wifi` for a UniFi Identity WLAN. The enum `com.ubnt.i.b.W.vFiJoQiuQjMZUx`
also has `mac-acl`, `uid-vpn` and `vpn`.

U6 Pro ubntbox: `aaa.%d.filter_id` -> `radius_auth_req_attr=11:s:%s`. This
puts RADIUS Filter-Id in every Access-Request, so the console's RADIUS
server can tell which policy applies.

The agent:

- `translate.Radius.FilterID` takes a plain token of at most 64
  characters. Anything else is noted and dropped.
- `wifi.go` passes it on to `bcmwifi.Radius.FilterID`.
- `bcmwifi.writeRadiusFilter` writes `radius_auth_req_attr=11:s:<id>` in that
  BSS.
- The X20's hostapd 2.9 has the option: `strings /sbin/hostapd` on .205
  lists `radius_auth_req_attr`.

It is takeover only, because hostapd is the agent's only in takeover.

Claim: fw_caps 0x20000000, takeover only. Not yet tested live with an
enterprise WLAN; see the live test plan.

## SNMPv3 (fw_caps 0x4000): implemented, observe and takeover

Superseded: the agent serves SNMP v1/v2c and v3 (USM authPriv) itself, read
only, from `internal/snmpagent`. See docs/deco/features/snmp.md.

## Integration (for the agent that owns models/agent.go)

Done since this list was written (2026-11-19): `internal/models/agent.go`
claims all three bits below as listed, and the capability table in
agent-design.md has them. The list is kept as the record of what was asked.

- **fw3_caps 0x40** (path monitoring), both modes.
  - When this was written nothing sent `fw3_caps`. It needed `inform.Profile.FW3Caps`,
    `device.Session.FW3Caps` emitted as `m["fw3_caps"] = uint32(...)` like
    fw2_caps, and `agent.go setup` passing `FW3Caps: int(p.FW3Caps)`.
  - Multicast inspect (fw3 0x80) needed the same word.
- **fw_caps 0x1000000** (syslog encryption), both modes.
- **fw_caps 0x20000000** (RADIUS filter), takeover only, like RF_SCAN:
  `DecoAgentFeatures`.
- The capability table in agent-design.md: move 0x1000000 and 0x20000000
  from "not implemented", and add fw3_caps 0x40.
