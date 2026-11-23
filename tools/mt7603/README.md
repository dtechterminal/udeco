# mt7603roam: the JioFiber JCOW414's optional 2.4 GHz driver

The JCOW414's own 2.4 GHz driver (Jio's `mt7603eap.ko`) has no WPA3 and no
802.11r. `mt7603roam` is MediaTek's MT7603 AP driver 4.1.2.0 (module
`mt76x3_ap`) as published in padavan-ng, with `mt7603roam.patch` on top,
built for the unit's EcoNet 3.18.21 kernel. It adds to 2.4 GHz:

- WPA3 (SAE) and the WPA2/WPA3 transition mode, with PMF;
- 802.11r: FT-PSK (keys derived locally, as hostapd's
  `ft_psk_generate_local`) and FT-SAE (the agent moves the keys with the
  Decos), in the Decos' mobility domains;
- 802.11k neighbour lists and 802.11v BSS transition requests set by the
  agent; U-APSD; the off-channel scan the agent's RF scans use;
- fixes for this board: the EcoNet PCIe init and IRQ unmask, Jio's profile
  path and calibration file, a module reference leak on a failed open.

The agent runs without it: the unit then keeps Jio's driver and 2.4 GHz
stays WPA2 without 802.11r (the agent notes what it can't serve).

## Install

From a release: `mt7603roam-jio-jcow414.ko.gz`, then

    deploy/jio-ap.sh --driver mt7603roam-jio-jcow414.ko.gz

It is installed as `/flash2/udeco/mt7603wpa3.ko.gz` and replaces Jio's
driver from the next reboot. `deploy/jio-start.sh` (drv2g) swaps it in
once per boot, and after 3 failed tries it puts Jio's driver back and stops
trying until the file `/flash2/udeco/mt7603wpa3.failed` is removed (a new
`--driver` install removes it). To go back to Jio's driver for good, remove
`/flash2/udeco/mt7603wpa3.ko.gz` and reboot.

## Build

    tools/econet-kernel/build-modules.sh     # Docker; output in dist/modules

`tools/econet-kernel/build-in-container.sh` has the pinned sources:
linux-3.18.21 from kernel.org (by sha256), with the unit's config and its
`sk_buff` layout (`econet_skb.py`), and padavan-ng
(`gitlab.com/hadzhioglu/padavan-ng`, branch `mt7603_4.1.2.0`, commit
`6c0edcbd`, the source checked by its git tree hash). The build is
reproducible: the same commit gives the release's bytes.

## Licence

The driver source is MediaTek's. Its files carry MediaTek's and Ralink's
proprietary notices, while the module declares `MODULE_LICENSE("GPL")`
and has been published openly in padavan for years. This repository's GPL
does not cover it: `mt7603roam.patch` and the module built from it are
offered as they are, for people who already run this hardware, and are
removed on request of the rights holder.
