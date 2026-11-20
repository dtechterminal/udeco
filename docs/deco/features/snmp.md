# SNMP: v1/v2c community and SNMPv3 (fw_caps 0x4000)

Status: built 2026-11-19 (`internal/snmpagent`, `cmd/udeco-ap/snmp.go`). It is tested in Go and
against net-snmp 5.6.2.1's command-line tools on loopback. It has not been run on a unit yet.

## What the controller sends

Network 11.1.50 (decompiled 10.6.109): `com.ubnt.service.config.RngEFIxepjqE` writes the section. The AP
generator `XHjguBsIf.AbtwUDHGrXug` calls it with prefix `""`, the key `community` and a 256-character
limit. Its input is the site setting `snmp`. That setting's schema in `api/fields/Setting.json` is:
`enabled`, `enabledV3`, `community .{1,256}`, `username [a-zA-Z0-9_-]{1,30}` and `x_password [^'"]{8,32}`.

```
snmp.status=enabled              enabled, or (enabledV3 and supportsSNMPv3)
snmp.version=1_2c | 3 | all
snmp.location=<device snmp_location>   only when set on the device
snmp.contact=<device snmp_contact>     only when set on the device
snmp.community=<community>             enabled ("public" if unset)
snmp.user.1.name=<username>            enabledV3 and supportsSNMPv3
snmp.user.1.password=<x_password>
```

- `supportsSNMPv3()` (`XCfthFC`) is `hasFirmwareCapability(16384)`, which is **fw_caps 0x4000**.
  For a UGW it is the USG word instead.
- Without the bit, v3 is never sent. v1/v2c does not depend on any bit.
- When v3 is on and v1/v2c is off, the site upgrade path (`JLudBrawuIVqu`) re-provisions UniFi OS
  devices with the bit. It never applies to an AP.
- No protocol keys are sent. `snmp.user.N.proto` / `.encrypt` exist on the device side, but the
  controller never writes them.

## What a real UAP does with it

ubntbox `ubntconf` (U6 Pro 8.8.14 strings, `docs/reference/u6pro/actions-scans/strings-ubntbox.txt`
around line 5800):

- It writes `/etc/snmp.conf` and an inittab line
  `null::respawn:/usr/sbin/snmpd -C -c /etc/snmp.conf -f -LS 0-4 d -Lf /dev/null -p /var/run/snmpd.pid`.
- The config contains:
  - `sysName`, `sysLocation`, `sysContact` and `sysDescr` (`%s %s.%s`, model and version);
  - `sysservices 79`;
  - `load 8.0 8.0 8.0`;
  - `rocommunity <community>`;
  - `createUser "<name>" <proto> "<password>" <encrypt> "<password>"` and `rouser <name> authpriv`.
- The strings right after `snmp.user.%i.proto` and `snmp.user.%i.encrypt` are `md5` and `des`
  (`strings -n 3` of the scratchpad ubntbox). Those are the defaults, so a UAP serves **MD5 + DES,
  authPriv only**.
- The UAP's snmpd is net-snmp. NMSes poll UniFi APs with net-snmp's standard MIBs plus
  UBNT-UniFi-MIB (1.3.6.1.4.1.41112.1.6).
- LibreNMS detects a UniFi AP by sysObjectID `.1.3.6.1.4.1.8072.3.2.10` or `.41112` together with
  sysDescr `^UAP|^U6|^U7`.

## What the agent does

The agent runs a read-only SNMP agent written in Go, on UDP `0.0.0.0:161` (IPv4). It starts when
system_cfg turns SNMP on and stops when SNMP is turned off. It runs in observe and takeover mode
alike, because it only reads the unit. Nothing is executed and nothing on the unit changes, except
the engine-boots file described below.

- **v1/v2c.** The site community, compared in constant time. A wrong community is dropped silently
  and counted in `snmpInBadCommunityNames`.
- **v3 (USM, RFC 3414).**
  - One user, **authPriv only**. A lower security level gets `usmStatsUnsupportedSecLevels`.
  - Authentication: HMAC-MD5-96 (the UAP's protocol), HMAC-SHA-96, and HMAC-SHA-224/256/384/512
    (RFC 7860).
  - Privacy: DES-CBC (the UAP's protocol) and AES-128-CFB (RFC 3826).
  - Every protocol uses the controller's one password. A request is answered under whichever auth
    protocol its digest verifies with, and its ciphertext decrypts as DES or AES. The reply uses
    the same pair.
  - Keys are localised to the engine. Each one is derived the first time a request needs it, in
    the server goroutine.
  - Discovery and reports work as RFC 3414 describes: unknownEngineIDs, unknownUserNames,
    wrongDigests, notInTimeWindows (authenticated) and decryptionErrors. A report is sent only
    for a reportable message.
- **Engine.**
  - `snmpEngineID` is `80 00 a0 98 03` followed by the br-lan MAC (RFC 3411, enterprise 41112,
    MAC format).
  - `snmpEngineBoots` is read, incremented and saved (0600) in
    `/tp_data/udeco/session/snmp-engine-boots`. That happens once per agent run, and only when v3
    is first wanted.
  - If the file cannot be read or written, v3 stays off. v1/v2c still runs (fail closed).
  - `snmpEngineTime` counts from the server's start.
- **Read-only.**
  - A Set gets noAccess (v2c/v3) or noSuchName (v1), and nothing is written.
  - No traps are sent: `snmpEnableAuthenTraps` and `ifLinkUpDownTrapEnable` are both disabled.
- **Who is answered.**
  - Only loopback and the LAN prefix of the unit's own address (the reading's IP/netmask). No
    known address means loopback only.
  - Everyone else is dropped before the packet is parsed.
  - TP-Link's `zone_lan` already accepts br-lan input, and `UDECO-IN` does not block 161, so no
    firewall change is needed.
  - Replies go to the LAN, which `UDECO-OUT` allows.
- **Bounds.**
  - The agent serves 100 requests/s with bursts of 200 across all sources.
  - Messages are at most 8192 bytes. GetBulk is cut to fit, and max-repetitions is capped at 64.
  - A request may carry at most 128 varbinds and OIDs may have at most 128 arcs.
  - One reading of /proc and /sys serves requests for 2 s (a walk is thousands of GetNexts).

### Objects served

| MIB | objects | source |
|---|---|---|
| SNMPv2-MIB system | sysDescr (`U6-Lite <version>`), sysObjectID (net-snmp Linux `.1.3.6.1.4.1.8072.3.2.10`), sysUpTime (since the SNMP agent started), sysContact, sysName (hostname), sysLocation, sysServices 79 | system_cfg, inform |
| SNMPv2-MIB snmp | snmpInPkts, OutPkts, BadVersions, BadCommunityNames, BadCommunityUses, ASNParseErrs, EnableAuthenTraps, SilentDrops, ProxyDrops | agent counters |
| IF-MIB | ifNumber, ifTable (columns 1-22) and ifXTable (1-19), for every `/proc/net/dev` interface, indexed by kernel ifindex | /proc/net/dev, /sys/class/net |
| SNMP-FRAMEWORK-MIB | snmpEngineID, Boots, Time, MaxMessageSize | engine |
| SNMP-USER-BASED-SM-MIB | usmStats 1-6 | agent counters |
| UCD-SNMP-MIB | laTable (1-5, 100, 101; limit 8.0 as the UAP's `load 8.0 8.0 8.0`) and memory (memTotalReal, memAvailReal, ...) | /proc/loadavg, /proc/meminfo |
| UBNT-UniFi-MIB | unifiRadioTable, unifiVapTable, unifiIfTable and unifiApSystem | the inform's radio_table_stats, vap_table, if_table, ip, uplink, uptime, model, version |

Details of the objects:

- **IF-MIB interface types.** loopback 24, tunnel 131, bridge 209 (a `bridge/` dir), IEEE 802.11
  71 (`wl*`), l2vlan 135 (a name with a dot), Ethernet 6 otherwise.
- **IF-MIB oper status.** `operstate`, or the IFF_UP/IFF_RUNNING flags when the state is
  `unknown` (as net-snmp does).
- **IF-MIB counters.** They are widened to 64 bits. The counters are sampled every 10 s while
  the agent runs, so a 32-bit kernel counter that wraps is extended; at 1 Gb/s, 2^32 bytes takes
  34 s. ifHC* are those widened values, and the 32-bit columns are the same values mod 2^32.
- **UBNT-UniFi-MIB rows.** Names (`ra0`, `rai1`, `eth0`) and channel utilisation are exactly what
  the controller sees. Radio rx/tx packets are summed over the radio's VAPs. unifiVapUsage is
  `guest` for a guest VAP and `user` otherwise.

Not served: sysORTable, HOST-RESOURCES-MIB, IP-MIB/TCP-MIB/UDP-MIB, IEEE802dot11-MIB, VACM views,
SNMP over TCP, IPv6, AES-192/256, traps and informs.

## Capability bit

- **fw_caps 0x4000** (`supportsSNMPv3`). Claimed in **both modes** since 2026-11-19
  (`models.FWCapSNMPv3`, in `DecoAgentFWCaps`): observe `fw_caps 0x1405403`, takeover
  `0x21405403`. translate no longer notes "snmp: not supported".
- The agent answers v3 whenever system_cfg carries a v3 user and an engine boots count could be
  saved. That only reads the unit, which is what the other observe-mode claims (path monitoring,
  encrypted syslog) rest on.
- Without the bit, the controller strips v3 from the section. A v3-only site then sends
  `snmp.status` only when v1/v2c is also on.

## Integration (for the owner of models/agent.go and agent_test.go)

Done since this list was written (2026-11-19), as "Capability bit" above
says. The list is kept as the record of what was asked.

- `cmd/udeco-ap/agent.go` already has the hooks; they are additive:
  - `options.snmpListen`;
  - the `agent.snmp` field;
  - `a.snmpFollow(ctx, f, &c)` in `fields`, after `mcastMerge` and before `a.prev = &c`.
- `internal/models/agent.go`: add 0x4000 to the observe fw_caps word (`DecoAgent...FWCaps`, not
  the takeover-only one). Observe then becomes `0x1405403` and takeover `0x21405403`, so the
  expected words in agent_test.go / agent_e2e_test.go change.
- `internal/translate/intent.go` (around line 1230, `case "switch", "snmp", ...`): stop noting
  "snmp: not supported" for `snmp.*` (the agent handles it). `intent_test.go:772` expects that note.
- agent-design.md capability table: replace the 0x4000 row ("no SNMP agent on the unit") with
  "**yes** (both modes)" and point to this document. Also replace the "SNMPv3 (fw_caps 0x4000):
  not feasible" section in `docs/deco/features/pathmon.md`.

## Live test plan (.205, takeover or observe)

1. Deploy the build, then turn on in the UniFi site settings: SNMP v1/v2c with a community and
   SNMPv3 with a user. Optionally set location/contact on the device.
2. The agent's log should say `snmp: v1/v2c (read-only community) + v3 user "<name>" (authPriv)`.
   Check that the unit has `/tp_data/udeco/session/snmp-engine-boots` (mode 600) and that
   `netstat -lnu` shows `0.0.0.0:161`.
3. From a LAN host:
   - `snmpwalk -v2c -c <community> 192.168.0.205 system`
   - `snmpbulkwalk -v2c -c <community> 192.168.0.205 ifXTable`
   - `snmpwalk -v3 -l authPriv -u <user> -a MD5 -A <pw> -x DES -X <pw> 192.168.0.205 .1.3.6.1.4.1.41112.1.6`
   - the same with `-a SHA -x AES`
   - `snmpget ... -v3 -l authNoPriv ...`, which must fail (unsupportedSecLevels).

   Compare the VAP rows with the controller's device panel.
4. Run a wrong community and a wrong password: both must get no data. An `snmpset` must get
   noAccess.
5. From a host outside 192.168.0.0/24, or across the WAN, there must be no answer.
6. Restart the agent: the boots file must go up by one, and the v3 walk must still work.
7. Turn SNMP off in the site: the log should say `snmp: off` and :161 should be closed.
8. Over 10 minutes of `snmpbulkwalk` every 5 s, RSS and CPU in `top` must stay flat. Compare
   ifHCInOctets on eth1 with `/proc/net/dev` across a counter wrap if one happens.
