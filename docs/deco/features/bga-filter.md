# Bridge group address (BPDU) filter

## What the U6 Pro does

The controller sends `wireless.N.bga_filter=enabled` on every WLAN, which a
U6 Pro has too (`tmp_system.cfg`). It also sends ebtables lines that drop
frames to the 802.1D bridge group address on the UAP's own radio
interfaces, for example
`-t nat -A PREROUTING --in-interface ra0 -d BGA -j DROP` (`ebtables.N.cmd`).

## What the agent does

The controller's ebtables lines name the UAP's interfaces, so they are not
run. The agent builds the same filter for the vifs it serves
(`internal/bcmwifi/bga.go`):

```
FORWARD -j UDECO-BGA              (inserted first; UDECO-BGA policy RETURN)
UDECO-BGA -i <vif> -d BGA -j DROP
UDECO-BGA -o <vif> -d BGA -j DROP
```

- `BGA` is ebtables' name for exactly 01:80:c2:00:00:00 (STP BPDUs). EAPOL
  (01:80:c2:00:00:03) and LLDP (:0e) are not affected.
- Without the filter, `br-lan` (STP off) forwards the switch's BPDUs onto
  the air, and a bridging client could inject BPDUs into the LAN.
- With policy RETURN, a frame the filter keeps carries on through FORWARD,
  including the guest chains.
- A WLAN whose `bga_filter` is `disabled` on every VAP is left out
  (translate `WLANIntent.NoBGAFilter`).
- The served vifs are kept in `RunDir/bga-ebtables.txt`. A change rebuilds
  the chain, Tick rebuilds a chain or jump something removed, and the
  hand-back deletes both.
- The steps are optional, so a filter that cannot be built never holds
  Wi-Fi back.

## Unverified on hardware

- The `BGA` keyword in this ebtables v2.0.10-4 build. It is documented in
  ebtables 2.0.10's man page but has not been run on the X20.
- That `-o <vif>` matches frames the bridge floods to a wireless port on
  this kernel.

## Garage (platform jio-mtk)

`internal/mtkwifi/bga.go` builds the same `UDECO-BGA` chain on the served
`ra*`/`rai*` BSSes, with the address written out (`-d 01:80:c2:00:00:00`)
rather than the `BGA` keyword. It is live ebtables only (never a radio
restart), rebuilt by Tick after the settle time if the chain is gone, and
removed at the hand-back. Unverified on the unit.
