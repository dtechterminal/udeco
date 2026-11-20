# RADIUS MAC authentication, Hotspot 2.0 and RadSec on the Deco agent

Status (2026-11-19): none of the three was claimed when this page was
written. Two have been built since, as their sections below say: RadSec is
claimed in takeover (`models.FW2CapRadSec`, [radsec](radsec.md)) and
Hotspot 2.0 in takeover with the `hotspot2` key (`models.FWCapHotspot2`,
[hotspot2](hotspot2.md)). RADIUS MAC authentication is still not claimed
(`models.WifiCapRadiusMACAuth`). This page records what
the controller sends and why the TP-Link hostapd on the X20 cannot do each
one as asked. Evidence comes from the read-only `strings` of `/sbin/hostapd`
v2.9 on .205, `wl` getters, `wl.ko` strings and the hostapd syslog.

## RADIUS MAC authentication (wifi_caps 0x1000, `supportRadiusMacAuth`)

**Controller.** In 11.1.50 the generator writes the following whatever the
bit says. The bit is only defined in the device class; no caller in
internal-dependencies.jar was found.

```
aaa.N.radius.macacl.status=enabled|disabled
aaa.N.radius.macacl.emptypassword=enabled|disabled
aaa.N.radius.macacl.format=<printf format>
aaa.N.radius.auth.M.{ip,port,secret}
```

For a non-EAP WLAN, the RADIUS auth/acct servers are added as well. The format
value is the format string itself, not a name (`wCwrhOHigpg$aoUDgXMlCqEvTSIrOtq`):

| Name | Format string |
|---|---|
| NONE_LOWER (the default) | `%.2x%.2x%.2x%.2x%.2x%.2x` |
| HYPHEN_LOWER | `%.2x-...` |
| COLON_LOWER | `%.2x:...` |
| NONE_UPPER | `%.2X%.2X...` |
| HYPHEN_UPPER | `%.2X-...` |
| COLON_UPPER | `%.2X:...` |

A UAP's patched hostapd takes `macaddr_format=` and `mac_acl_empty_passwd=`.

**This hostapd.**

- `macaddr_format` and `mac_acl_empty_passwd` occur 0 times in the binary.
  Stock 2.9 sends User-Name = User-Password = `%02x%02x%02x%02x%02x%02x`.
  That matches the controller's default (NONE_LOWER, empty password off).
- The blocker is the association path. The Broadcom driver does the 802.11
  authentication and association itself (driver SME):
  - The syslog shows only "IEEE 802.11: associated" from
    `hostapd_notif_assoc`, never "authenticated".
  - `wl.ko` has no `set_mac_acl`, so `max_acl_mac_addrs=0`.

  In that mode hostapd 2.9 checks the station in `hostapd_notif_assoc` with
  `hostapd_check_acl`. The string "STA ... not allowed to connect" sits among
  that function's strings. With `macaddr_acl=2` this check returns PENDING,
  never ACCEPT, so the station is disassociated before any RADIUS query. The
  RADIUS ACL query (`hostapd_acl_recv_radius`) is only started from
  `handle_auth`, the host-SME path that this driver does not use.
- Expected result of today's `macaddr_acl=2` output (bcmwifi/hostapd.go): the
  check fails closed. Every station on such an SSID is refused, and none is let
  in unchecked. This is inferred from hostapd 2.9's code and this binary's
  strings, not yet observed on a unit.

**Not claimed.** A working version has to be agent-side:

1. Gate new stations with an ebtables drop on the vif. The gate has to be
   built like the guest chains (guest.go), since `among` is missing.
2. On AP-STA-CONNECTED (hostapd ctrl socket ATTACH), send a PAP Access-Request
   from Go. Use the controller's format and empty-password flag, add
   Message-Authenticator, and verify the response.
3. Open the gate on Accept. On Reject, add the station to the deny file and
   deauthenticate it.

Live test needed first: an SSID with `macaddr_acl=2`. Expect "not allowed to
connect" in `hostapd -d`, or an immediate disassociation with no
Access-Request on the RADIUS server.

## Hotspot 2.0 (fw_caps 0x800000, `supportHotspot2`)

Superseded: built in `internal/hs20` and claimed with takeover and the
`hotspot2` config key (off by default until the live checks pass). See
docs/deco/features/hotspot2.md.

## RadSec (fw2_caps 0x80000, `supportsRadSec`)

Superseded: the agent runs a local UDP-to-RadSec proxy (`internal/radsec`)
and claims the bit in takeover mode. See docs/deco/features/radsec.md.
