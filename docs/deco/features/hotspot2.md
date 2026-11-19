# Hotspot 2.0 / Passpoint on the Deco agent

Status (2026-11-19): the config path is built and tested off-device. The
capability bit (fw_caps 0x800000) is claimed only in takeover mode with the
config key `hotspot2`, which is off by default: what the Broadcom driver does
with the Interworking elements and GAS frames needs the live checks below.
Set `"hotspot2": true` on one unit for those checks.

Code: `internal/hs20` (parse and render, no I/O), `internal/translate/hs20.go`
(the `WLANIntent.Hotspot2` hook), `internal/bcmwifi/hs20.go` (normalize and
write into the SSID's `bss=` section), one line in `cmd/udeco-ap/wifi.go`.

## What the controller sends

Capability: **fw_caps 0x800000** (`supportHotspot2` =
`hasFirmwareCapability(8388608)` in the device class). Passpoint
(`supportsHotspot2Passpoint`) is `supportHotspot2 && supportsRadSec`.

- Without the bit, a WLAN with `hotspot2conf_enabled`, or with OSEN
  security, is not sent at all ("Hotspot 2 cannot provision OSEN on ...",
  `ubntconf.qemBJTmR`).
- With the bit, the generator (`service.config.XHjguBsIf`) writes the
  hotspot2conf from inside the WPA-EAP/OSEN branch. Every other EAP WLAN gets
  `aaa.N.hs20.status=disabled`. Null values are left out (the key writer
  skips them).

```
aaa.N.hs20.status=enabled
aaa.N.hs20.{access_network_type,internet,asra,esr,uesa,venue_group,venue_type}
aaa.N.hs20.{disable_dgaf,deauth_req_timeout,t_c_filename,t_c_timestamp,osu_ssid}
aaa.N.hs20.{gas_comeback_delay,gas_frag_limit}          (gas_advanced only, > 0)
aaa.N.hs20.network_availability=<(v4<<2)+v6>
aaa.N.hs20.network_auth_type=<0..3>  .network_auth_url=<url>
aaa.N.hs20.anqp_domain_id   aaa.N.hs20.hessid          (hessid_used only)
aaa.N.hs20.venue_name.I.{lang,name,url}
aaa.N.hs20.hs20_domain_name_list=<a,b,...>
aaa.N.hs20.nai_realm.I.{status,encoding,name,eap_method}
aaa.N.hs20.nai_realm.I.eap_method.auth.J.{id,val}
aaa.N.hs20.I.roaming_consortium=<oid>                  (index before the key)
aaa.N.hs20.3gpp.I.{mcc,mnc}
aaa.N.hs20.friendly_name.I.{language,text}             (operator friendly name)
aaa.N.hs20.capab.I.{protocol,port,status}              (tcp_udp is split in two)
aaa.N.hs20.icon.I.{name,width,height,media,language,filename,data}
aaa.N.osu.I.{server_uri,nai,nai2,operating_class,method_soap_xml_spp,method_oma_dm}
aaa.N.osu.I.{friendly_name,description}.J.{language,text}   aaa.N.osu.I.icon.J.name
aaa.N.hs20.qos.status  .qos.exception.I.{dcsp,up}  .qos.map.I.{low,high}
aaa.N.hs20.metrics.{status,info,downlink_speed,uplink_speed,downlink_load,uplink_load,measurement}
wireless.N.dgaf_disable=enabled|disabled               (default: on for a guest WLAN)
```

Booleans are `enabled`/`disabled`. The field schema is
`api/fields/Hotspot2Conf.json`. A UAP's ubntbox turns these into hostapd
lines (`docs/reference/u6pro/actions-scans/strings-ubntbox.txt`).

## What the agent writes

Each key below was found as a config keyword in `strings /sbin/hostapd` on
.205 (TP-Link 2.9 build, CONFIG_INTERWORKING and CONFIG_HS20). Each value is
checked the way hostapd 2.9's `config_file.c` checks it (`hs20.CheckLine`).
One refused line would make hostapd refuse the whole file, which would take
down every SSID on the radio.

| Controller | hostapd line |
|---|---|
| status | `interworking=1`, `hs20=1` |
| access_network_type, internet, asra, esr, uesa | same names, 0/1 |
| venue_group/type | `venue_group`, `venue_type` |
| hessid | `hessid` (default: the BSSID) |
| venue_name.I | `venue_name=<lang>:<name>`, `venue_url=<I>:<url>` |
| network_auth_type + url | `network_auth_type=<2 hex digits><url>` (URL only for 0 and 2) |
| network_availability | `ipaddr_type_availability=<hex octet>` |
| hs20_domain_name_list | `domain_name=<a,b>` |
| I.roaming_consortium | `roaming_consortium=<hex>` (3..15 octets) |
| 3gpp.I | `anqp_3gpp_cell_net=<mcc,mnc;...>` |
| nai_realm.I | `nai_realm=<enc>,<realm>,<eap>[id:val]...` (status disabled: skipped) |
| gas_* | `gas_frag_limit`, `gas_comeback_delay` |
| disable_dgaf (or wireless dgaf_disable) | `disable_dgaf=1` |
| anqp_domain_id, deauth_req_timeout | `anqp_domain_id`, `hs20_deauth_req_timeout` |
| friendly_name.I | `hs20_oper_friendly_name=<lang>:<text>` |
| metrics.* | `hs20_wan_metrics=<info hex>:<dl>:<ul>:<dl load>:<ul load>:<lmd>` |
| capab.I | `hs20_conn_capab=<proto>:<port>:<0 closed/1 open/2 unknown>` |
| osu.I.operating_class (first) | `hs20_operating_class=<hex>` |
| osu_ssid, osu.I.* | `osu_ssid=<hex>`, then per provider `osu_server_uri` (first), `osu_friendly_name`, `osu_nai`, `osu_nai2`, `osu_method_list` (1 SPP, 0 OMA-DM), `osu_service_desc` |

Not carried, noted by index (never by value):

- **Icons** (`hs20_icon` needs a file on disk; the agent writes none) and OSU
  icon references.
- **QoS map**: hostapd sets it with `NL80211_CMD_SET_QOS_MAP` at BSS setup and
  fails the BSS when the driver refuses. wl.ko has no `set_qos_map`
  cfg80211 op (its strings show only `wlc_11u_*qos_map*`).
- Entries hostapd would refuse: bad hex OI, realm with `,` `[` `]`, more than
  10 realms, 5 EAP methods or 4 auth parameters, language not 2-3 lower-case
  letters, text over 252 octets, control characters, and similar.
- OSU providers when no OSU SSID is set.

## Fail-closed rules

- **OSEN** (`wpa.key.1.mgmt=OSEN`, the OSU sign-up network): the WLAN stays
  off. Before this, translate would have built it as WPA2-Enterprise.
- **Terms and Conditions** (`t_c_filename` set): the WLAN stays off. The
  RADIUS server then expects the AP to filter the station's traffic
  (HS20-T-C-FILTERING-ADD). hostapd only reports that, so nothing would
  filter.
- **Hotspot 2.0 on a WLAN that is not WPA-Enterprise**: the WLAN stays off.
  hostapd refuses `hs20=1` without WPA2-Enterprise/CCMP, and would take the
  radio's hostapd down with it.
- **PMF** is raised to optional (never lowered). hostapd refuses a Release 2+
  station that does not use PMF.
- **DGAF disabled**: hostapd gives each station its own random GTK, so
  stations get no group-addressed frames. hostapd's `proxy_arp` cannot run
  on these vifs (live fact F5). A note asks for client isolation plus proxy
  ARP (the bridge's `proxyarp_wifi`), or ARP and ND to the stations depend
  on unicast.

## Driver: what is known and what is not

- wl.ko has an 802.11u module (`wlc_11u_*`, `wlc_11u_calc_iw_ie_len`,
  `_iwap_`, `_iwrc_`, `wlc_11u_check_probe_req_iw`). It also has
  `wl_cfg80211_add_iw_ie` and `wl_cfg80211_clear_iw_ie` ("set interworking
  IE", "skip to set interworking IE", "Failed to add interworking IE"). So
  the cfg80211 layer takes element 107 from hostapd's beacon data.
- Elements 108 (Advertisement Protocol) and 111 (Roaming Consortium) are not
  vendor IEs. Whether the driver forwards them, or the firmware builds them,
  is unknown. The HS 2.0 indication (vendor 50:6f:9a type 0x10) uses the
  vendor-IE path. wl.ko drops only the OSEN vendor IE ("Found WFA OSEN OUI.
  Do not add it").
- `wl -i wl0|wl1 interworking` reads `0`, `wl hs20` is "Unsupported", and
  `wl osen` reads `0`.
- GAS: wl.ko forwards action frames to `cfg80211_rx_mgmt` and implements
  `wl_cfg80211_mgmt_tx`. But it also has its own GAS engine (`wl_gas_*`,
  `bcm_gas_*`, `WLC_E_GAS_RQST_ANQP_QUERY`), which may take GAS Initial
  Requests before hostapd sees them.

## Live checks (before claiming 0x800000)

Use one test WLAN (WPA2-Enterprise, Hotspot 2.0 on, a realm and an OI) on
one unit. Apply's verify-and-rollback covers a hostapd that will not start.

1. **hostapd accepts the config**: `hostapd_cli -p /var/run/udeco-hostapd -i
   <vif> status` shows `state=ENABLED`, and syslog has no "Line N:" errors.
   Expected to pass: every line is checked and every key is in the binary.
2. **Beacon/probe**: capture from a monitor-mode laptop on the channel.
   Pass if the beacon or probe response has element 107 (Interworking),
   element 108 with ANQP, the 50:6f:9a:10 HS 2.0 indication, and the
   Extended Capabilities Interworking bit (31). Element 111 is wanted when
   OIs are set. If 107 is missing, try `wl -i <vif> interworking 1` while
   the BSS is down (a later bcmwifi driver step). If 108 or 111 is missing,
   the driver drops them.
3. **ANQP**: from a Linux client run `wpa_cli interworking_select` or
   `wpa_cli anqp_get <bssid> 257,258,263,268`, with `hostapd -dd` on the
   unit (a debug copy, not the service instance). Pass if hostapd logs
   "GAS: GAS Initial Request from ..." and the client gets the venue and
   realm. Fail if the frame never reaches hostapd (wl's GAS engine took it,
   or the frame was not registered).
4. **Association**: a Passpoint profile (Android or iOS) for the realm
   connects automatically. Check that PMF was negotiated and that unicast
   ARP and DHCP work with DGAF disabled.

## Wiring

- `internal/models/agent.go`: `FWCapHotspot2 = 0x800000`, set by
  `DecoAgentFeatures.Hotspot2` and in `DecoAgentTakeoverFWCaps`, so a drop to
  observe clears it at once. `cmd/udeco-ap/agent.go` passes
  `Hotspot2: own && cfg.Hotspot2`; leave the key off until checks 2 and 3
  pass.
- Passpoint (`supportsHotspot2Passpoint`) also needs RadSec (fw2_caps
  0x80000), which takeover now claims, so a unit with `hotspot2` on is
  Passpoint-capable for the controller.
