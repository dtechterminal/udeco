# Per-client speed limits (cmd rate-update)

Status 2026-11-19: built, unit- and e2e-tested, **not yet proven live**.
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
  (`strings-mcad.txt:1756-1763`: `rate-update: %s ul: (%d, %d), dl: (%d, %d)`).

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
- **Flow cache**: every station whose limit was added, changed or removed gets
  `fc flush --mac <sta>` (`syncShaping`), so established flows that the
  Broadcom flow cache would carry past the qdiscs are re-learnt through the new
  path (audit R21). Unchanged stations are not flushed.
- **Never the uplink**: only SSID vifs of the layout are read and shaped
  (`layout.Radios[].Used`); TP-Link's backhaul vif `wlN1` is skipped explicitly;
  the wired uplink, VLAN devices and `br-lan` (TP-Link's own `htb 2:`, owned by
  decosys) are never touched.
- **Restarts**: the session keeps the list in state.json (survives agent
  restarts and unit reboots; startup hands it over). bcmwifi also keeps it in
  `RunDir/client-rates.json` (ramfs), so an agent restart's first Tick, which
  runs before the startup jobs, does not tear down the per-client classes.
- When the agent does not own Wi-Fi (before the first apply, after a
  hand-back), the list is only stored, as with the SSID-wide limits.
- Cost: only vifs with a limited station carry a tree. While the list is
  non-empty each sync reads `wl -i <vif> assoclist` for every SSID vif (one
  `wl` call per vif per Tick); an error reading a vif that has no SSID-wide
  limit is logged, that vif's per-client classes are kept as built (no
  teardown, no flush), and the other vifs are still synced. (A read error on a
  vif with a SSID-wide limit fails the sync as before: nothing changes.)

**jio-mtk (Garage AP)**: unchanged. The MediaTek backend has no
`SetClientRates`; the agent logs once "per-client speed limits (...): not
supported on platform jio-mtk; not applied" and keeps the list in the
session. No tc or other command runs there.

The other users of `internal/device` apply nothing either: `cmd/udeco` (the
app-API Deco runner) logs the action as ignored, `cmd/uow` (OpenWrt) drops it
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
   that MAC; a speed test from the phone sits at the limits (a running stream,
   started before the limit, too: flow-cache flush).
3. Other clients on the same SSID are unaffected (speed test, and
   `/proc/fcache/brlist` still shows their flows accelerated).
4. Toggle the phone's Wi-Fi, then move it to the other band/SSID: limit
   re-applied (log `joined <mac>`).
5. Restart the agent, then reboot the unit: limit still applied.
6. Roam the phone to another Deco: does the controller send rate-update to
   the new unit? (open question 1).
7. Put the phone back in the default group: `cmd rate-update <mac>
   down=none up=none`, classes gone, full speed.
8. With an SSID-wide limit on the same SSID: the client's own limit wins in
   the directions it sets.

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
