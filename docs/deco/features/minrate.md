# Minimum data rate control and QoS mark bits

Status 2026-11-19. Covers wifi_caps bit 9 (MINRATE_CTRL, 0x200) and bit 19
(QOS_MARK_BITS, 0x80000). Source of truth: the decompiled Network 11.1.50
controller (internal-dependencies.jar) and the U6 Pro reference captures in
docs/reference/u6pro/.

## What the controller sends

`ubntconf` minrate factory (`KCqNcrDhlq`), called from the UAP system.cfg
generator for every WLAN that is not a WDS link (`XHjguBsIf`, around line 927).
Per `wireless.N`:

| key | when | value |
|---|---|---|
| `minrate_data` | 2.4 GHz always; 5 GHz when `minrate_na_enabled` | minimum, kbps (2.4 default 1000) |
| `beacon_rate`, `mgmt_rate` | with `minrate_data` | 5 GHz: the minimum. 2.4 GHz: by rate group, below |
| `minrate_cck_rates.status` | 2.4 GHz | rate group's CCK flag |
| `minrate_below_disable` | when the WLAN's `minrate_*_advertising_rates` is true | `true` |

2.4 GHz rate groups (`com.ubnt.ace.api.a` enum):

| minimum (Mb/s) | CCK | beacon/mgmt |
|---|---|---|
| 1, 2, 5.5, 11 | on | the minimum |
| 6, 9 | on | 11 Mb/s |
| 12, 24 | off | the minimum |
| 18, 36, 48, 54 | off | 24 Mb/s |

**MINRATE_CTRL is not consulted.** `XCfthFC.supportMinRateCtrl()`
(`hasWifiCapability(512)`) has no caller in the controller jar, the React UI
does not test it, and `described-features` has no minimum-rate entry. The keys
above go to every UAP whatever the bit says. Claiming the bit changes nothing
the controller sends; it only states that the agent applies them.

A UAP (U6 Pro, `sysinit/wireless.conf`) applies them per VAP with
`cfg80211tool <vap> minrate_data / bcast_rate / mcast_rate / mgmt_rate /
set_bcn_rate / minrate_nobelow / minrate_nocck`.

## What the Deco does

- `internal/translate/minrate.go`: `wlanMinRate` reads the minimum (through
  the existing `wlanRates`), the beacon rate (`beacon_rate`, else
  `mgmt_rate`) and `minrate_cck_rates.status` into
  `WLANIntent.MinRateKbps` / `MinRateOpts` per band. `minrate_below_disable`
  is a known key (no "unrecognised" note).
- `internal/bcmwifi/rates.go`: `minRateset` builds the BSS's legacy
  `wl -i <vif> rateset`: rates below the minimum removed; on 2.4 GHz CCK rates
  at or above the minimum kept unless CCK is off; the beacon rate is the lowest
  basic rate (the driver beacons at it), TP-Link's basic rates above it stay
  basic. Examples: 2.4 GHz 6 Mb/s -> `6 9 11b 12 18 24 36 48 54`; 5 GHz
  12 Mb/s -> `12b 18 24b 36 48 54`.
- With `Options.MinRates` every placed vif gets an explicit rateset (TP-Link's
  default when its SSID has no minimum on that band), so no BSS inherits
  another's minimum if `wl rateset` turns out to be per radio. The hand-back
  restores the baseline rateset per vif (baseline.go).
- `cmd/udeco-ap`: config `min_rates` (takeover only, default off) sets
  `bcmwifi.Options.MinRates`; `desiredFrom` carries `MinRateOpts`.

Differences from a UAP, all forced by the driver:

- One rateset per BSS serves as both the advertised and the usable set, so
  lower rates are never advertised (as if `minrate_below_disable` were always
  true).
- A beacon rate below the minimum (2.4 GHz 36/48/54 Mb/s: 24 Mb/s beacons)
  would let clients use that rate for data too: the minimum wins, beacons go
  at the minimum, and the plan notes it.
- No separate multicast/broadcast rate: `wl mrate`/`bg_mrate`/`a_mrate` are
  per radio. Broadcom sends broadcast/multicast at the lowest basic rate.

Not used:

- hostapd `supported_rates`/`basic_rates`/`beacon_rate` (all in the X20's
  hostapd 2.9, driver=nl80211): the Broadcom driver builds the rate elements
  from its rateset, and `beacon_rate` needs nl80211 legacy beacon-rate support.
  Without it the binary fails the beacon ("nl80211: Driver does not support
  setting Beacon frame rate (legacy)", in /sbin/hostapd's strings). No `iw` on
  the unit to check the flag.
- `wl 2g_rate`/`5g_rate`/`bg_rate`/`a_rate` force one fixed rate, not a floor.

## Not verified on hardware (why `min_rates` is off by default)

Read on .205 (2026-11-19, getters only): `wl -i wl02 rateset` =
`[ 1(b) 2(b) 5.5(b) 6 9 11(b) 12 18 24 36 48 54 ]`, `wl -i wl12/wl13 rateset` =
`[ 6(b) 9 12(b) 18 24(b) 36 48 54 ]`, `bg_mrate`/`a_mrate` `auto`. TP-Link only
sets the radio's rateset (nvram `wlN_rateset=default`). Open questions for the
live test:

1. Does `wl -i wlXY rateset ...` on a BSS-down vif stick per BSS, or set the
   radio's default (last write wins)?
2. Does a legacy-only list keep the MCS/VHT/HE sets (`wl -i wlXY rateset`
   still lists `MCS SET`/`VHT SET` afterwards)?
3. Do beacons go out at the lowest basic rate (sniff, or a client's beacon
   rate)?

Verify logs (not fails) a vif whose rateset does not read back as planned.

## QoS mark bits (QOS_MARK_BITS, 0x80000): not claimed

Controller (`XHjguBsIf`, `wOqBLRIMPnQPsW` mark manager). With the bit, the
system.cfg gets a `mark.N.name/bits/shift/location` layout for UAPs (GUEST 2
bits at 30 in `skb`, VAP_ID 5 bits at 11 and ASSOC_ID 11 bits at 0 in `ubnt`)
and no `qos.ebt.N.cmd` lines. Without it (the deprecated layout: VAP_ID at
12, ASSOC_ID at 0, all in `skb`), each rate-limited VAP gets
`qos.ebt.N.cmd = PREROUTING/POSTROUTING --in/out-interface <vap> -j mark
--mark-or <vapid << 12>`. A UAP's ubntbox writes the layout to
`/proc/ubnt_frame_id/{mark_bits,mark_shift,mark_location,netdevs}`, a Ubiquiti
kernel module that tags frames with VAP and association IDs for
`qos_control.sh`.

The X20 has no `/proc/ubnt_frame_id` (checked on .205). The agent's per-client
limits are tc htb classes on each vif (bcmwifi shape.go), keyed by station and
not by mark. It reads neither `mark.*` nor `qos.ebt.*`, and the guest mark
(2 bits at 30) is the same in both layouts. Nothing on the Deco implements the
mark layout, and claiming the bit would change only which lines the agent
ignores.
