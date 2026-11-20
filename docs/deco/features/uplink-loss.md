# Uplink loss: SSIDs down while the uplink is gone (2026-11-20)

## What a U6 does

- A UniFi AP whose wired uplink goes away (and that has no wireless uplink to fall back to) takes
  its user and guest SSIDs down, so clients roam to an AP that still reaches the network instead of
  staying associated to one that does not. The SSIDs come back once the uplink is back. The exact
  timers of the U6 are not known (no capture of an uplink loss on the U6 Pro).

## What the agent does (takeover, Deco)

- `internal/bcmwifi/ssidhold.go`: `SSIDsDown(ctx, down)` runs `wl -i <vif> bss down` (or `up`) on
  every BSS the agent serves. No radio restart; hostapd keeps running; the vifs stay in their
  bridges. While the hold lasts, Plan leaves those BSSes down instead of raising them (and takes
  one that came up down again, not reported as foreign), a full apply ends with them down, and
  Verify wants them down, so neither Tick, an apply nor the health check undoes the hold. The hold
  lives in the Applier only: a new agent process starts without it, and a hand-back to TP-Link
  forgets it.
- `cmd/udeco-ap/uplink.go`: a watcher reads `/sys/class/net/<uplink>/carrier` every second for the
  tracked uplink port (topology.go).
  - No carrier for 5 s: SSIDs down. Carrier again for 10 s (a shorter return changes nothing):
    SSIDs up.
  - Never during a Wi-Fi apply or rollback, nor while a takeover hold stands (a TP-Link Wi-Fi
    rebuild or upgrade in flight): the change waits, logged once, and runs when that ends.
  - Each change is logged and kept as an event (`EVENT: uplink eth1 lost (...): SSIDs down`,
    `... back (...): SSIDs up`) in the event ring on flash. A failed change is retried after 10 s.
  - Takeover with the Wi-Fi live only; a drop to observe mode forgets the hold.
- `uplink_gateway_down` (default off; needs `uplink_ssid_down`): the agent's own ICMP echo to the
  gateway every 5 s (1 s timeout); unanswered for 60 s counts as a lost uplink with the carrier up,
  and an answer (plus 10 s of carrier) brings the SSIDs back. Off by default because a gateway that
  drops ICMP, or a busy one, would take the Wi-Fi away.
- `uplink_ssid_down` false turns the whole behaviour off. It is the one behaviour that takes the
  unit's own Wi-Fi away, which is why it has a key. Both keys need takeover and are refused on
  platform jio-mtk (the Garage's Wi-Fi backend has no hold).
- The Deco's SSH and inform path is wired: with no carrier there is no management to cut off, and
  the SSIDs come back by themselves.

## Unverified on hardware

- That `/sys/class/net/eth0|eth1/carrier` follows the cable on each X20 (the ports are real netdevs
  in the readings, but the carrier file itself was not read under a cable pull).
- That hostapd 2.9 leaves a BSS down that `wl bss down` lowered (no re-raise of its own) and that
  `wl bss up` afterwards serves clients without a hostapd reload.
- Client roaming behaviour when the SSIDs disappear.
