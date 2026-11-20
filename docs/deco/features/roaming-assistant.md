# Roaming Assistant and Radio AI neighbour isolation (2026-11-19)

## Roaming Assistant (wifi_caps2 0x20): implemented, takeover only

### What the controller does (Network 11.1.50, decompiled)

- Gate: `com.ubnt.data` device `supportsAssistedRoaming()` = `hasWifiCapability2(32)`, i.e.
  **wifi_caps2 0x20**. The site feature `ROAMING_ASSISTANT` (described-features) lists every adopted
  AP without the bit under `NOT_ALL_DEVICES_SUPPORT_FEATURE` / `NO_SUPPORTED_DEVICES_IN_SETUP`
  (`com.ubnt.service.wifi.j.aoUDgXMlCqEvTSIrOtq`). On 2026-11-19 it shows the Deco
  (b0:a7:b9:3e:17:00) as `NO_SUPPORTED_DEVICES_IN_SETUP`.
- WLAN fields (`api/fields/WlanConf.json`): `roaming_assistant_na_enabled`,
  `roaming_assistant_na_rssi` (`^-([6-7][0-9]|80)$`, default -75), `roaming_assistant_6e_enabled`,
  `roaming_assistant_6e_rssi` (`^-([7-8][0-9]|90)$`, default -88). Not coupled to `bss_transition`.
- system_cfg (`com.ubnt.service.config.ubntconf.QdjEeOBh`, appended per VAP by the AP generator
  `XHjguBsIf`): only when the device has the bit, the VAP's radio is na or 6e, the VAP is not WDS or
  element-adopt, and the WLAN has the band's `roaming_assistant_*_enabled`:

  ```
  wireless.N.btm_disassoc.status=enabled
  wireless.N.btm_disassoc.threshold=<rssi>
  ```

  Nothing is written otherwise (the `wireless.2.btm_disassoc.status=disabled` in the U6 Pro capture
  comes from that AP's own template, not from this factory). `status` uses the enabled/disabled
  boolean helper (`OhAbgZpGPkrXsqI`).
- A UAP applies it in its QCA driver: `btm_disassoc 1` and `btm_dis_thld <rssi>` (ubntbox strings,
  docs/reference/u6pro/actions-scans/strings-ubntbox.txt). The real U6 Pro claims wifi_caps2
  0x4030F0, which includes 0x20.

### What the agent does

- `internal/translate/roaming.go`: `wireless.N.btm_disassoc.{status,threshold}` ->
  `WLANIntent.RoamAssist` (band -> dBm). A threshold outside -95..-40 or missing falls back to the
  controller's default for the band (-75 na, -88 6e) with a note. A WLAN without 802.11v
  (`aaa.N.bss_transition` off) gets no assistant, with a note: stations need not act on a BSS
  transition request from a BSS that does not advertise it, and the timer would only disconnect them.
- `cmd/udeco-ap/wifi.go` `desiredFrom` -> `bcmwifi.SSID.RoamAssist`; `steer.go` `policyFrom` ->
  `wifiPolicy.roam` ("SSID|band" -> dBm), stored when the Wi-Fi is live, cleared on a drop to observe.
- `cmd/udeco-ap/roaming.go` (inform loop, every reading, takeover only, not while memory is short):
  - **Sustained weakness.** A client on such a BSS qualifies only when its `wl sta_info` signal has
    stayed below the threshold in at least 3 readings in a row and for at least 60 s
    (`roamBelow`, `timing.roamSustain`). One reading at or above the threshold, or a reading
    without the client, starts the count again.
  - **Candidates are other APs only.** A candidate is a BSS with the same SSID that this unit's scans
    heard within the last 15 min (`roamCandAge`) at the threshold + 10 dB or better
    (`roamCandMargin`, e.g. -65 dBm for -75). Up to 4 are named, strongest first. This unit's
    own BSSes are never candidates, on any band. That covers every radio and VAP address in the
    reading, and each of those with another first octet, because the X20 derives its BSSIDs as
    locally administered variants of one address (`aa:a7:b9:3e:15:f8` / `ba:a7:b9:3e:15:f8`).
  - **No candidate means no request.** The client is never disassociated. This is logged once per
    client per hour (`roamNoCandLog`).
  - **Hysteresis and backoff.** After a request the same client is not asked again for 10 min
    (`roamHold`). A client that is still, or again, on the same BSS 1 min after the request
    (`roamJudge`) either ignored it or the move did not hold. A client that comes back within 30 min
    (`roamReturn`) counts the same way. Each such outcome doubles the wait: 20, 40, 80 min, capped at
    2 h (`roamHoldMax`). A client that stays away for 30 min ends the backoff.
  - **Limits.** At most 2 requests are sent per reading, weakest client first. A client that is asked
    also gets band steering's rate limit, so band steering does not move it back at once.
  - **Refusals are not requests.** The Wi-Fi worker hands each request's outcome back to the next
    reading. If `RoamAssist` refuses a client that does not advertise BSS transition (`ErrNoBTM`), the
    client is held for 24 h (`roamNoBTMHold`) and this is logged once. If no usable candidate is left
    (`ErrNoCandidate`), it is handled like the no-candidate case above. Neither refusal counts as an
    ignored request for the backoff, and neither gives the client band steering's rate limit.
- `internal/bcmwifi/roaming.go` `RoamAssist`: drops every candidate that is one of the BSSes the
  agent serves (any band, any first octet), as a second guard. If the BSSID of any served BSS cannot
  be read, it sends nothing, because that BSS could be one of the candidates.
  It then checks the station's `wl sta_info` "wnm" capability word (bit 0x1 BSS-Transition, as the
  X20 driver prints it; fixtures in internal/wl/testdata) and refuses (`ErrNoBTM`) a station without
  it. The request it sends is
  `hostapd_cli -i <vif> bss_tm_req <sta> disassoc_imminent=1 disassoc_timer=100 pref=1 abridged=1 neighbor=<bssid>,<info>,<opclass>,<chan>,<phy> ...`.
  hostapd 2.9 disassociates the station when the timer (100 beacon intervals, about 10 s) runs out
  and the station is still associated. A request with no usable candidate is refused
  (`ErrNoCandidate`): never a bare kick. The option names were checked in the hostapd 2.9 binary on
  .205 (`disassoc_timer=`, `disassoc_imminent=1`, `abridged=1`, `set_disassoc_timer`).

### The bug this replaced (Bedroom unit, 2026-11-19)

The live log showed this every ~6 minutes, with threshold -75 on na:

```
roaming assistant: asked d2:f7:e5:58:6f:89 (-76 dBm < -75 dBm on na) to move to aa:a7:b9:3e:15:f8 (ng ch 6)
```

`aa:a7:b9:3e:15:f8` is the **same unit's** 2.4 GHz BSS. The earlier version named the SSID's other
BSSes on this unit first. hostapd's disassociation timer then dropped the iPhone, which went straight
back to the 5 GHz BSS. In hostapd's syslog that shows as `wl12: STA d2:f7:... disassociated` followed
by `associated`. Before the station events came from hostapd's control socket (staevents.go), the
controller never saw those drops.

A UAP does none of this. Its driver's `btm_disassoc` / `btm_dis_thld` sends a BTM request with
Disassociation Imminent to a client below the threshold so that the client roams to *another* AP.
Moving the client to the same AP's other band is band steering's job, not this one's.

### Deviations from a UAP

- Signal is sampled once per inform reading (about 10 s, or 1 s while the device panel is open). A
  UAP's driver measures it per frame. Here 3 readings and 60 s below the threshold are needed.
- Stations that do not advertise BSS transition are never disconnected. How a UAP's driver treats
  them is unknown.
- "Better" is judged from this unit's own scans: another AP of the SSID that this unit heard well and
  recently. A client at the edge of this unit is then plausibly near it. The client's own view (an
  802.11k beacon report) is not asked for. A UAP's driver may send no candidate list at all.
- The hold and backoff are agent policy. A UAP's driver is not known to keep any per-client record.

### Capability bit

Claim **wifi_caps2 0x20 in takeover mode only**, when the Wi-Fi backend implements `roamer`
(`bcmwifi.Applier` does), like BANDSTEER. Observe mode sends nothing (no hostapd of ours), so a drop to
observe should clear the bit from the next inform, like RF_SCAN. Today the profile sends no
wifi_caps2 at all (`models.DecoAgentProfileWith` leaves `WifiCaps2` 0, and `device.Session` omits a
zero word), so the controller never writes `btm_disassoc` for the Deco until the bit is claimed.

### Live test

Needs takeover with `apply=true`, the bit claimed, a dual-band WLAN with BSS transition on and the
Roaming Assistant on (threshold e.g. -60 to trigger easily), and a second unit with the same SSID
that this unit's scans hear at the threshold + 10 dB or better. Check that
`/tp_data/udeco/session/system_cfg.txt` carries `wireless.N.btm_disassoc.status=enabled` on the 5 GHz
VAP. Walk a BTM-capable phone away and keep it below the threshold for a minute, until
`roaming assistant: asked ...` appears in the agent log. Then
`hostapd_cli -p /var/run/udeco-hostapd -i wl1X all_sta` no longer lists it, and the controller's
client list shows it on the other unit. With no such unit heard, the log shows
`no other AP ... left alone` once and the phone stays connected.

## Radio AI neighbour isolation (wifi_caps2 0x200): not implemented, do not claim

- Gate: described-features `RADIO_AI_NEIGHBOR_ISOLATION_NG/NA/6E` come from
  `com.ubnt.service.bF.oViVvFSgD` (wifiAiService): the feature exists for a band only when **every**
  AP with that band has `supportNeighbourInScan()` = `hasWifiCapability2(512)`, i.e. **wifi_caps2
  0x200**. The U6 Pro (8.8.14) does not have it either (0x4030F0).
- What it means (`com.ubnt.service.system.aCKvxuyc`, `com.ubnt.service.devmgr.ecPpL`): Radio AI's
  method `ISOLATE_NEIGHBOURS` plans channels from an AP-to-AP "isolation matrix" built from the
  neighbour store, with no rogue APs and **no scan command**. Before a `FULL_SCAN` run the
  controller sends `cmd scan_band band=<radio>` only to APs **without** 0x200; an AP with the bit is
  trusted to keep reporting its UniFi neighbours in every inform's `radio_table[].scan_table` on its
  own. The store is fed by rows with `is_unifi=true` and `serialno` = the peer device's MAC
  (`TocwLJhQU` -> `aS.UQKIrjV`), and a matrix entry is kept only when the scanned channel equals the
  peer's current `vap_table` channel. Nothing new is sent to the AP: the result is ordinary radio
  channel/width changes in system_cfg.
- Why not: the agent scans only on the controller's commands (`wl scan` takes the radio off
  channel; the spectrum runner has a client guard and a 2-minute budget per band), so its
  `scan_table` is empty until a scan command and stale 10 minutes after one. Claiming 0x200 would make
  the controller skip `scan_band` for it and plan from no data. Doing it properly needs a periodic
  background neighbour scan with the spectrum runner's client guard, which is new scan policy, not
  part of this change. The rows themselves already carry `is_unifi`/`serialno` for neighbours whose
  BSSID shares the middle four octets with a LAN device's MAC (`apstate.ParentDevice`; Deco BSSIDs
  are `ba:a7:b9:3e:17:0X` for br-lan `b0:a7:b9:3e:17:00` on .205).
- Related gap: `cmd scan_band` (what the controller sends to an AP without 0x200 before a
  `FULL_SCAN` Radio AI run) has no case in `internal/device/session.go`.
