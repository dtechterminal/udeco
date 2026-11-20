# Radio and VAP driver parity with a U6 Pro

The driver defaults a U6 Pro applies on every boot are listed below, next to
what the agent sets on the X20's Broadcom `wl.ko`. Code:
`internal/bcmwifi/parity.go`, `hostapd.go` (driverFor, driverSteps) and
`plan.go`.

## What the U6 Pro does

The U6 Pro's per-radio and per-VAP settings
(`docs/reference/u6pro/config-apply/sysinit/radio.conf` and `wireless.conf`):

| U6 Pro | Meaning |
|---|---|
| `qbssload 1` (per VAP, unless the controller sends `wireless.N.qbssload=disabled`) | BSS Load element in beacons |
| `idhcp 1` | Intelligent DHCP: DHCP replies to stations are sent unicast |
| `implicitbf 0` | No implicit beamforming |
| `vht_11ng 0` | No vendor VHT rates on 2.4 GHz |
| `ant_ps_on 0` | No antenna/RX-chain power save |
| `ani_enable 0` | No adaptive noise immunity, the glitch-based receiver desense |
| `rrm 1` on every VAP | 802.11k |
| `wnm` follows the controller's `bss_transition` | 802.11v |

## What the agent does

| Setting | X20 knob | When it is written | Hand-back |
|---|---|---|---|
| BSS Load | `wl bssload 1` (radio-wide in this driver); 0 on a radio where any SSID has `qbssload=disabled` | Live. Tick puts it back if it drifts. | Baseline value, else TP-Link's 0 |
| Intelligent DHCP | `wl -i <vif> dhcp_unicast 1` on every served vif | Live | 0 |
| Implicit beamforming off | `wl txbf_imp 0` | Live (iovar flags 0). Tick puts it back if it drifts. | Baseline value, else 1 |
| No VHT on 2.4 GHz | `wl vht_features 0x6` (TP-Link's 0x7 without bit 0x1), wl0 only | Radio-down window | Baseline value, else 0x7 |
| Power save off | `wl rxchain_pwrsave_enable 0`, `wl radio_pwrsave_enable 0` | Radio-down window | Baseline value, else 0 |
| Receiver desense off | interference mode without bit 0x1 (TP-Link runs 361), `interference_override -1` | Live | Baseline value, else TP-Link's 361 and -1 |
| 802.11k | `wl rrm 0x33` on every served vif; hostapd's neighbour scan only where the controller turns RRM on | Radio-down window (dwds/rrm cycle). A stored value that differs only because the agent changed (an upgrade) waits for the next radio down/up. | Baseline value |
| 802.11v off | `wl -i <vif> wnm 0` where `bss_transition` is off | Radio-down window, as rrm | Baseline value |
| 802.11h | `wl spect 1` on 5 GHz ([dfs](dfs.md)) | Radio-down window | Baseline value, else left alone |

Notes:

- **BSS Load is per radio.** The controller sends `qbssload` per VAP, but
  the driver has one switch per radio. As deco-crosscheck specifies, a radio
  advertises the element only when no SSID on it has `qbssload=disabled`;
  when such an SSID shares the radio with others, the plan notes that they
  go without it too. The old `bssload 0` in radioProfile is gone.
- **Radio-down settings never cost a restart of their own.** They follow the
  TWT pattern (`twt.go`): the plan reads the live value and notes a
  mismatch. It writes the value inside the next radio down/up made for
  something else: a PHY change's radioProfile, a full reconcile's dwds/rrm
  cycle, or Tick's dwds repair. Live settings are re-asserted by Tick.
- **rrm/wnm after an upgrade.** The stored driver state (`drv-wlN.json`)
  keeps what the driver was given. When only rrm or wnm differ from the
  wanted value (the previous build stored rrm 0x0 for an SSID with 11k off
  and no wnm), the radio is not reconciled: the plan notes the vif, and the
  values ride the next radio down/up made for something else.
- **Opt-out.** `rx_desense: true` (Deco only, takeover only) keeps TP-Link's
  interference mitigation, and puts the desense bit back (the baseline's
  mode, else the live mode with bit 0x1) on a radio an earlier run cleared,
  live. Desense trades sensitivity for robustness. In a
  room with a strong nearby interferer, TP-Link's mode may hold clients
  better than the U6 Pro's default, so this is the one setting with a
  switch.
- **Baseline.** The takeover baseline (`tplink-baseline.json`) records each
  radio's values (`iovars`). An older agent's baseline lacks them: the
  first Apply or Tick of a new agent, before it changes anything, records
  the values the radio reads then (the older agent never changed them, so
  they are TP-Link's). Without any reading, the hand-back uses TP-Link's
  known values, interference 361 and override -1 included; spect is left
  alone.

## Unverified on hardware

- None of these writes has been run on an X20 yet. The settings come from
  the Bedroom Deco's read-back (2026-11-20): bssload 0, txbf_imp 1,
  vht_features 0x7 on wl0, interference 361, both power-save iovars 0.
- Whether `vht_features` and the power-save iovars really need the radio
  down. They are treated as down-only to be safe. Writing a live-capable
  iovar while the radio is down is harmless. `txbf_imp` is live (iovar
  flags 0 in the decompile), not yet written on an X20.
- The exact text `wl interference` prints. The parser accepts "Mode 361",
  "mode: 361" and a bare number, and leaves anything else alone.
- Whether `dhcp_unicast` and `wnm` exist as per-vif iovars in this `wl.ko`.
  The steps are optional, so a driver without them is logged and skipped.
