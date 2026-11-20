# Restrict high-performance clients to 5 GHz (2026-11-20)

## What a U6 does

- WLAN setting "Restrict high-performance clients to 5 GHz" (`no2ghz_oui`). The controller writes
  `wireless.N.no2ghz_oui=enabled` on the WLAN's 2.4 GHz VAP (the Bedroom unit's system_cfg on
  2026-11-20 carries `wireless.1.no2ghz_oui=enabled`). A UAP's driver then keeps clients it
  recognises as dual-band (by OUI list and by having seen them on 5 GHz) off the 2.4 GHz twin of
  the SSID. Its client list and the six numeric parameters of the older seven-integer form are not
  documented; the UniFi defaults for the 5 GHz / 2.4 GHz signal floors are 30 and 16 (SNR-style
  units, about -65 dBm and -79 dBm).
- Independent of the band steering mode.

## What the agent does (takeover, Deco)

- `internal/translate`: `wireless.N.no2ghz_oui=enabled` on a 2.4 GHz VAP ->
  `WLANIntent.No2GHz` (any other value, or the key on a 5 GHz VAP, is off). It no longer counts as
  "not carried". `cmd/udeco-ap/wifi.go` -> `bcmwifi.SSID.No2GHz` (nothing is configured in the
  driver) -> `wifiPolicy.no2ghz` for an enabled SSID broadcast on both bands.
- `cmd/udeco-ap/no2ghz.go` (inform loop, every fresh reading, before band steering):
  - a client on the SSID's 2.4 GHz BSS qualifies only when this unit saw it on the same SSID's
    5 GHz BSS within the last hour at -65 dBm or better (the 5 GHz minimum RSSI plus 5 dB when one
    is set), and its 2.4 GHz signal is -70 dBm or better (the gaps.json spec's usable signal; the
    UniFi default of -79 dBm would ask, and then ban, a client at the 2.4 GHz cell edge, which is
    about -86 dBm on 5 GHz). A client never seen on 5 GHz, seen there
    weak, or seen too long ago is never asked and never refused;
  - it gets an 802.11v BSS transition request naming the 5 GHz BSS (`bcmwifi.SteerToBand`), at
    most once per 10 minutes, whatever the band steering mode (band steering then leaves that
    client alone, and a client band steering or the Roaming Assistant asked lately is left to
    them);
  - still on the 2.4 GHz BSS a minute later without having been seen on 5 GHz in between: it ignored
    the request and, when it was seen on 5 GHz within the last 5 minutes (an older sighting asks
    but never bans), is kept off the 2.4 GHz BSS for one minute (`bcmwifi.TempDeny`, the same short
    ban as the minimum RSSI kick: driver MAC filter in deny mode on that vif, which also hides it
    from the client's probes, plus a deauth from that vif), at most once per hour; after that it
    is let back. An allow-list SSID cannot take the ban: the request only (logged once).
- No config key: the controller's switch is the opt-out, and a client is only refused with
  evidence it can use 5 GHz.

## Unverified on hardware

- That the X20 driver's per-vif deny filter keeps a station off the 2.4 GHz BSS while it may join
  the 5 GHz BSS of the same unit.
- How clients that ignore BTM behave with a one-minute ban (some may give up on the SSID for a
  while rather than try 5 GHz).
- The U6's exact selection (OUI list); the agent uses observed 5 GHz use only.
