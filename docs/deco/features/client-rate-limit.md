# Per-client speed limits (cmd rate-update)

Status 2026-11-19: built, unit- and e2e-tested; tc trees seen live on .205,
but **the limits only hold with the Broadcom flow cache off** (measured, see
[Flow cache off while limits are set](#flow-cache-off-while-limits-are-set)),
which bcmwifi now does; that change is not yet proven live.
Covers the per-client limit UniFi Network sets by putting a client in a user
group (client settings, "Speed Limit"), and the hotspot guest override. The
SSID-wide limit (the WLAN's own user group, in system_cfg) is a separate,
older feature (`internal/bcmwifi/shape.go`); this one reuses its tc trees.
Source of truth: the decompiled Network 11.1.x controller in the session
scratchpad (`ctrl/src/`) and the U6 Pro reference in `docs/reference/u6pro/`.

## What the controller sends

Not system_cfg. A devmgr command, queued for the AP the client is on
(`devmgr_QNAsAi/.../devmgr/QNAsAi.java:1040-1045`):

```json
{"_type":"cmd","cmd":"rate-update","mac":"<client>",
 "ul_max":<qos_rate_max_up>,"ul_min":64,"dl_max":<qos_rate_max_down>,"dl_min":64}
```

- `dl_max`/`ul_max` are the user group's `qos_rate_max_down`/`_up` in kbit/s,
  `-1` when the group has no limit that way (`group.getInt(.., -1)`).
- `dl_min`/`ul_min` are always 64. A U6 Pro's mcad reads all four
  (`U6 Pro mcad strings`: `rate-update: %s ul: (%d, %d), dl: (%d, %d)`).

When it is sent:

1. **A client shows up on an AP** (`sjeMc.java:135-185`, the per-station
   processing of a UAP inform, built at `dm_xbPjw/.../xbPjw.java:1614` for any
   non-mesh device): once per client record (`qos_policy_applied`), when the
   client's `usergroup_id` is not the site default group, or when it is a
   hotspot guest with `qos_overwrite` (then the guest's own
   `qos_rate_max_up/down`). Clients in the default group get nothing.
2. **The client's user group changes** (`QNAsAi.java:1069-1074`): the new
   group's limits (blank `usergroup_id` = the default group's, normally -1/-1),
   to the AP the client is on, only while it is online.
3. **A user group's limits change** (`QNAsAi.java:1082-1094`): to the AP of
   every cached client in that group.

`QNAsAi.bpxBUxW` (`:1047`) clears `qos_policy_applied`, which makes (1) send
again; its callers are not in the decompiled subset, so **when the controller
re-sends after a roam or reconnect is not known** (see open questions).

No capability bit gates it: the sender (`sSmg.java:2611-2619`, the generic
`scheduleTask`) only skips devices marked unsupported, and the live test saw
the controller send it to the Decos (model UAL6) with the current
capability words. Nothing new is advertised.

## What the Deco does

- `internal/device/session.go` `rateUpdate`: parses the cmd (`dl_max`,
  `ul_max`, `dl_min`, `ul_min` as numbers or numeric strings), keeps
  `State.ClientRates` (state.json `client_rates`, MAC -> `{down, up, set}`;
  a direction `<= 0` is "no own limit"), and emits action
  `rate-update:<mac>`. Both directions -1 removes the client's entry. A
  bad MAC or a cmd with neither `dl_max` nor `ul_max` is ignored (and noted in
  the unhandled ledger). The list is capped at 512 entries; the entry set
  longest ago makes room (the controller never says a forgotten client's limit
  is gone). The four fields are read, so they are no longer reported as
  unhandled.
- `cmd/udeco-ap/ratelimit.go`: the agent hands the **whole** list to
  bcmwifi (`SetClientRates`) on every rate-update, at startup (also clearing a
  stale list left in RunDir), and when a client with an entry appears on a VAP
  of this unit (new association, re-association, or another SSID) since the
  previous reading, so the limit is in place within one inform interval
  instead of at the next 60 s Tick. In observe mode the list is kept and
  nothing is applied (logged).
- `internal/bcmwifi/clientrate.go` + `shape.go` `wantShaping`: the list is
  folded into the SSID-wide per-station trees. For each station in the
  association list of every SSID vif: download/upload = the entry's value in
  each direction it limits, else the SSID's (if any). So:
  - entry + unlimited SSID: the station alone is shaped;
  - entry + limited SSID: the entry replaces the SSID's limit only in the
    directions the entry sets; other stations keep the SSID's limit;
  - entry cleared: the station goes back to the SSID's limit (class changed in
    place) or is unshaped (its filter, class, redirect removed; a tree with no
    station left is removed).
  The trees are unchanged from the SSID-wide feature: htb root `1:` on the vif
  keyed on `ether dst`, ingress `u32 match ether src` mirred to `ifb0`
  (2.4 GHz) / `ifb1` (5 GHz) with an htb keyed on `ether src`, sfq leaves,
  explicit filter handles, every tc command checked, a failing device rebuilt
  at the next sync (audit R24).
- **Flow cache**: turned off on the unit while any limit is built, back on
  when none is (next section). Every station whose limit was added, changed or
  removed also gets `fc flush --mac <sta>` (`syncShaping`, audit R21).
- **Never the uplink**: only SSID vifs of the layout are read and shaped
  (`layout.Radios[].Used`); TP-Link's backhaul vif `wlN1` is skipped explicitly;
  the wired uplink, VLAN devices and `br-lan` (TP-Link's own `htb 2:`, owned by
  decosys) are never touched.
- **Restarts**: the session keeps the list in state.json (survives agent
  restarts and unit reboots; startup hands it over). bcmwifi also keeps it in
  `RunDir/client-rates.json` (ramfs), so an agent restart's first Tick, which
  runs before the startup jobs, does not tear down the per-client classes.
  A failed write there is only logged: the new list is still the one shaped,
  now and by every later Tick.
- When the agent does not own Wi-Fi (before the first apply, after a
  hand-back), the list is only stored, as with the SSID-wide limits.
- Cost: no hardware acceleration on the unit while any station is limited
  (next section). Only vifs with a limited station carry a tree. While the list is
  non-empty each sync reads `wl -i <vif> assoclist` for every SSID vif (one
  `wl` call per vif per Tick); an error reading a vif that has no SSID-wide
  limit is logged, that vif's per-client classes are kept as built (no
  teardown, no flush), and the other vifs are still synced. (A read error on a
  vif with a SSID-wide limit fails the sync as before: nothing changes.)

## Flow cache off while limits are set

Measured on .205 (2026-11-19). A rate-update arrived and the agent built htb
512 kbit/s on the SSID vif `wl03` (download) and 768 kbit/s on `ifb0`
(upload, ingress redirect). With the Broadcom flow cache on (`fc status`:
"Flow Learning Enabled", Acceleration Mode L3, HW Acceleration Enabled) iperf
got **4.9 Mbit/s down / 8.2 Mbit/s up**, and the htb classes counted only
~150 packets: accelerated flows bypass tc completely. `fc flush --mac <mac>`
during the transfer let ~14 packets through before the flow was accelerated
again. With `fc disable` the same limits held, **473 kbit/s down / 698 kbit/s
up**, and the classes counted the traffic; `fc enable` restored acceleration.
`fc enable`/`fc disable` print "Broadcom Packet Flow Cache learning via BLOG
enabled." (or "... disabled."). `fc status` prints a tab-indented table on
stdout whose last line carries the state: `Flow Learning Enabled : Max<16383>,
Active<93>, ...` or `Flow Learning Disabled : ...` ("OVS Flow Learning" and
"MCast Learning" are other switches). The first draft parsed the BLOG line out
of `fc status` and would have done nothing on a unit; caught before deploy.

There is no narrower way: `wl` has no per-station limit, ebtables has no
`skiplog` target, there is no bridge netfilter (`/proc/sys/net/bridge` is
absent), so `xt_SKIPLOG` (a module, not loaded) cannot see bridged traffic,
and Archer's `sysport_tm` is a per-port queue, not per client. The SSID-wide
limits (`shape.go`, system_cfg user groups) are bypassed the same way.

So `internal/bcmwifi/fcache.go` `syncFlowCache`, the one place that decides,
runs at the end of every shaping sync (Apply, Tick, `SetClientRates`,
`SyncRateLimits`) with what that sync wants shaped:

- **A limit is built** (a per-client entry or a SSID-wide limit, for a
  station associated now): the flow cache must be off. It reads the
  `Flow Learning Enabled/Disabled` line of `fc status`; if it is learning, `fc disable` then `fc flush` (whole cache,
  so flows learnt before take the slow path too), and logs once
  `flow cache off: N per-client / M SSID limits need the slow path`. N counts
  stations limited by their own entry, M the limited SSIDs with a station on
  the SSID's limit. From then on the agent owns the off state
  (`/tmp/udeco/fc-off` and in memory), also when it found the cache already off.
  The record is written before `fc disable` runs (and removed again if the
  disable fails), so an agent killed between the two, for example in a crash
  loop that ends in observe mode, still leaves a record that the observe-mode
  start restores.
- **Drift**: Tick runs the sync every 60 s, so a cache turned back on (by
  TP-Link or by hand) is turned off again, logged with "(it had been turned
  back on)". An idle sync runs only `fc status`.
- **No limit left**: `fc enable` and `flow cache on: no limits`, only when the
  agent owns the off state; a cache someone else turned off while no limit was
  set is left alone (and no `fc` command runs at all).
- **Hand-back to TP-Link** (rollback without a usable last-good, drop to
  observe): after the trees are removed, the cache is turned **on** whoever
  turned it off (stock TP-Link learns flows): `flow cache on: no limits
  (hand-back to TP-Link)`.
- **Observe-mode start / drop to observe** (`cmd/udeco-ap/flowcache.go`): when
  `/tmp/udeco/fc-off` is there (an earlier takeover run left the cache off),
  a bcmwifi handle built for that alone turns it back on. Without the record
  nothing is built and nothing runs.
- **Plain stop (SIGTERM, agent restart or upgrade)**: the cache is left as it
  is, like the rest of Wi-Fi. The agent's hostapd and tc trees stay, and the
  trees only hold while the cache is off; turning it on at stop would silently
  void the limits until the agent is back. The next start's first sync
  decides again (and turns it on if no limit remains). Safe either way: a
  reboot turns the cache back on (`fc disable` is not saved) and clears the
  record with `/tmp`.
- **No fc** (`fc status` fails or has no `Flow Learning` line):
  nothing is done, logged once; the trees are still built. jio-mtk never runs
  bcmwifi.
- Dry-run: `fc status` is read, the flip only logged; the agent takes no
  ownership, so a later dry-run sync is not reported as drift.

**Trade-off**: while any station on the unit is limited, **no flow on that
unit is accelerated** (fc and Archer HW forwarding off, every packet on the
3 usable CPUs, audit X14). Limits are meant to be few and temporary; a unit
with none keeps full acceleration. Limits for clients that are not associated
on this unit, and SSID limits with no station, keep the cache on.

**jio-mtk (Garage AP)**: unchanged. The MediaTek backend has no
`SetClientRates`; the agent logs once "per-client speed limits (...): not
supported on platform jio-mtk; not applied" and keeps the list in the
session. No tc or other command runs there.

The other users of `internal/device` apply nothing either: `cmd/udeco` (the
app-API Deco runner) logs the action as ignored, upstream's `uow` (OpenWrt) drops it
silently; both now log the parsed `cmd rate-update` event and keep the list
in their state.json instead of noting the cmd as unhandled.

## Tests

- `internal/device/ratelimit_test.go`: parsing, string numbers, one
  direction, repeat (applied again, no state change), -1/-1 clear, bad MAC,
  missing fields, no unhandled-field entries, the 512 bound.
- `internal/bcmwifi/clientrate_test.go` (fake device): only the limited
  station shaped on unlimited SSIDs, both directions, only its flows flushed,
  no `br-lan`/backhaul/match-all; idle sync runs no tc; re-joining another
  SSID on the other radio moves the limit (Tick) and removes the old trees;
  clear removes every tree; with a SSID-wide limit the entry replaces it per
  direction in place and clearing restores it; the list survives a new
  Applier (agent restart) through RunDir; dry-run writes nothing; a vif whose
  association list cannot be read keeps its classes while the others sync.
- `internal/bcmwifi/fcache_test.go` (fake device with `fc status/enable/
  disable`): off (status, disable, whole flush) when a per-client limit
  appears and logged with its counts; idle syncs only read the status; on when
  the station leaves or its entry goes; SSID-wide limits count; drift repaired
  by Tick; hand-back turns it on (ours or someone else's); a cache someone
  else turned off is left alone with no limit, and an earlier run's record is
  restored by `RestoreFlowCache`; no `fc`: limits still built, nothing flipped,
  logged once; dry run flips nothing.
- `cmd/udeco-ap/flowcache_test.go`: an observe-mode start with
  `/tmp/udeco/fc-off` restores the cache (one handle built, nothing else);
  jio-mtk builds and restores nothing.
- `cmd/udeco-ap/ratelimit_test.go`: rate-update reaches the Wi-Fi backend as
  the whole list; a limited client that leaves and re-joins triggers a
  hand-over; -1/-1 clears; restart hands the saved list over; a backend
  without it logs "not supported" once; observe mode applies nothing.
- `cmd/udeco-ap/ratelimit_e2e_test.go`: the captured .205 unit with the real
  bcmwifi and decosys (DryRun): rate-update for a captured wl12 client is kept
  in state.json and handed to bcmwifi, a -1/-1 for an unknown client is
  harmless, nothing is reported unhandled, no mutating command, no secret
  leaked.

## Live test (to do)

1. Put a phone in a user group with e.g. 5 Mbit/s down / 2 Mbit/s up
   (client -> Settings -> Speed Limit). Agent log: `cmd rate-update <mac>
   down=5000kbit up=2000kbit`, then `per-client speed limits (rate-update
   <mac>): 1 client(s) changed`.
2. On the unit: `tc -s class show dev wl12` / `dev ifb1` show the class for
   that MAC and count the traffic; agent log `flow cache off: 1 per-client /
   0 SSID limits need the slow path`; `fc status | head -1` says
   "disabled."; a speed test from the phone sits at the limits (a running
   stream, started before the limit, too: whole flush after `fc disable`).
3. Other clients on the same SSID keep their own speed, unaccelerated
   (expect a higher load average while limits are set).
4. Toggle the phone's Wi-Fi, then move it to the other band/SSID: limit
   re-applied (log `joined <mac>`).
5. Restart the agent, then reboot the unit: limit still applied.
6. Roam the phone to another Deco: does the controller send rate-update to
   the new unit? (open question 1).
7. Put the phone back in the default group: `cmd rate-update <mac>
   down=none up=none`, classes gone, full speed, `flow cache on: no limits`,
   `fc status` "enabled.".
8. With an SSID-wide limit on the same SSID: the client's own limit wins in
   the directions it sets.
9. Flow cache drift: with a limit set, `fc enable` by hand; within 60 s the
   log says `... need the slow path (it had been turned back on)`.
10. Hand-back (force a rollback with no last-good, or drop to observe) with a
    limit set: `fc status` "enabled." afterwards.

## Open questions

1. Re-send on roam: `qos_policy_applied` is per client record; if the
   controller does not clear it on a roam, the new unit never hears of the
   limit and the client is unlimited there until it reconnects after its
   record expired. A real UAP would have the same gap. If live shows this, the
   units could share their lists (the FT peer channel already links them).
2. Precedence when the default group itself has limits: the controller then
   sends the default group's values on a move back to it, and the agent keeps
   them as the client's own entry (it cannot tell them from a real group).
3. Whether a U6's mcad treats -1 as "unlimited" (overriding the WLAN's group)
   or as "no override": the agent does the latter, so a -1 never loosens a
   SSID-wide limit.
4. `dl_min`/`ul_min` (64) are ignored: htb gets `rate = ceil = max`.
