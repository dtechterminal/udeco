# Proxy ARP

## What the U6 Pro does

When the controller turns proxy ARP on for a WLAN, the U6 Pro sets
`cfg80211tool <vap> proxyarp 1` (`aaa.conf`). It does this whether or not
the WLAN has client isolation (`l2_isolation`).

## What the agent does

hostapd's own `proxy_arp` kills hostapd on a vif it creates (live fact F5).
So the agent sets the bridge port's `proxyarp_wifi`
(`/sys/class/net/<vif>/brport/proxyarp_wifi`) on every vif of an SSID with
proxy ARP. The bridge answers ARP for the stations from its neighbour table,
and an ARP request it answers is not flooded onto the air. The setting is
applied live, with no hostapd restart, and goes back to 0 when the
controller turns proxy ARP off.

Until now the agent did this only on SSIDs with client isolation, and
dropped proxy ARP with a note on the others. That precondition was removed
(`internal/bcmwifi/plan.go` proxyARPWanted, `desired.go` normalizeSSID). The
bridge attribute does not depend on isolation. Hotspot 2.0's DGAF note now
asks only for proxy ARP.

There is no hostapd DHCP/ND snooping table behind it. Only addresses the
bridge has already learnt are answered; other requests are flooded as
usual.

## Unverified on hardware

- `proxyarp_wifi` on an SSID without isolation, on the X20's 4.1 kernel.
  The isolated case is verified.
