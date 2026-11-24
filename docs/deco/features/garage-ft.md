# Garage: 802.11r, 802.11k and 802.11v with the Decos

**Status (2026-11-23): wired behind `ft` (off by default),
unit-tested; on the unit only the 5 GHz profile keys and an FT-PSK initial
association were run (see "On-unit checks").** The Garage's radios are
closed MediaTek drivers built into the EcoNet kernel, and its iappd cannot
do 802.11r. This note says what the kernel can do without being changed,
how the agent takes the place of the IAPP daemon so that clients roam
between the Garage and the Decos with FT-PSK and FT-SAE, and how it answers
802.11k and sends 802.11v. The codecs are in `internal/mtkft`; the plan is
`internal/mtkwifi/ftplan.go`, the runtime `internal/mtkwifi/roam.go`.

Every finding is marked **verified** (with the function and address in the
Garage kernel, or the source file) or **inferred**. Addresses are of the
running kernel, `vmlinux5.bin` (Linux 3.18.21 `#6 SMP Mon Jul 22 12:37:30
IST 2024`, confirmed with `/proc/version` on the unit; the extracted
`kallsyms.txt` matches it and the unit's `/proc/kallsyms`). `vmlinux2.bin`
(`#4`, October 2023) is the other flash bank, not used here. Jio's iappd is
not running either: the agent stops Jio's services, and `/var/run` has no
iappd pid.

## 5 GHz (MT7663)

### What the driver has

- **802.11r is compiled in (verified).** `FT_*`, `FT_KDP_*` and the
  iwpriv `ftenable`, `ftmdid`, `ftr0khid`, `ftric`, `ftotd` (set) and
  `ftinfo` (show) are in the kernel. The KDP is built with
  `FT_KDP_FUNC_SOCK_COMM` (see below).
- **No daemon (verified).** `/usr/bin/iappd` is a link to `tf1Main`, whose
  applets are openssl, sslClient/sslServer, eapAuthConfig, pnacd and the
  like. Any other name prints "functionality is unavailable".
- **SHA-256 only (verified).** `KDF` (0x804115c8), `FT_DerivePMKR0`
  (0x8053a4d8), `FT_DerivePMKR1` (0x8053a88c) and `FT_DerivePMKR1Name`
  (0x8053a764) are the IEEE 802.11 derivations with the labels "FT-R0",
  "FT-R0N", "FT-R1" and "FT-R1N", as hostapd's `wpa_common.c` does them. An
  R1KH entry holds a 32-byte PMK-R1. hostapd 2.9 also uses SHA-256 for
  FT-PSK and FT-SAE (AKM 4 and 9), so the two sides agree. FT-SAE-EXT-KEY
  and FT-802.1X-SHA384 cannot be served.

### Profile keys

`FT_rtmp_read_parameters_from_file` (0x8053d3e4), all verified:

| key | form | notes |
|---|---|---|
| `FtSupport` | `1;0;0;0` per BSS | bit 2 of wdev+0x86d. `APSecInit` (0x802ea18c) adds the FT AKMs when the radio starts: WPA2PSK gets FT-PSK, SAE gets FT-SAE, WPA2 gets FT-802.1X. `WPA2PSKWPA3PSK` therefore advertises AKMs 2, 4, 8 and 9. Changing it is a radio restart. |
| `FtMdId<n>` | two ASCII characters, or `<hex>:H` | n counts from 1. `simple_strtol` reads the hex, and the integer's two low octets are stored little-endian. The on-air MDIE octets m0 m1 are therefore written `m1m0:H`: hostapd's `mobility_domain=d530` is `FtMdId1=30d5:H` (`mtkft.MDIDValue`). This is the same swap the Decos' `wl fbt_mdid` needs. The default is "RT" (0x80943a44). |
| `FtR0khId<n>` | up to 48 characters | **Bug:** the string is copied but `FtR0khIdLen` is not set. It keeps the 24 of `FT_CfgInitial`'s random "Ralink:xx:xx:xx:xx:xx:xx" (0x8053834c). The agent uses an R0KH-ID of exactly 24 characters, the BSSID as 12 hex digits plus `-mt7663-r0kh` (`mtkft.R0KHID`). That ID is valid in the Decos' announcements. `iwpriv <if> set ftr0khid=` (`Set_FT_R0khid`, 0x8053dd9c) does set the length. |
| `FtOtd`, `FtRic` | per BSS | `FT_CfgInitial` clears both. They stay 0 (see Over the DS). |

`PMKCachePeriod=129600` (minutes, 90 days), which the agent writes, is also
the lifetime of the PMK-R0 in the driver's PMKID cache and of the R1KH entry
the driver makes for each FT initial association (see Key holder entries
that age).

The line `FT_rtmp_read_parameters_from_file: Invalid interface number
(24ff)(24ff).` in dmesg is the **success** print of the `<hex>:H` branch
(verified: format string 0x80937abc, printed after `simple_strtol` with the
parsed value; the two-character branch prints `::FtMdid(%d)=%c%c`, a bad
value `Invalid MdId=%s`). It comes once per profile read. The beacons'
MDIE confirms the value (on the unit: `ff 24` for `FtMdId1=24ff:H`).

### What the driver does

- **Initial mobility-domain association (verified).**
  `PeerPairMsg2Action` (0x8041b528) derives PMK-R0 from the 32-byte PMK, the
  SSID, MDID, R0KH-ID and the station, then PMK-R1 for its own BSSID.
  `PeerPairMsg4Action` (0x804192ac) stores the PMK-R0 in the PMKID cache and
  the PMK-R1 in the R1KH table, then calls `FT_KDP_EventInform` with
  FT_ASSOCIATION (0x50, the call at 0x80419988, unconditional on that
  branch). The PMK-R0 is never exported. A reassociation also gets 0x51
  (FT_REASSOCIATION, 14 octets) from `ap_cmm_peer_assoc_req_action`
  (call at 0x8032d114, verified).
  - **On the unit (2026-11-23):** an initial FT-PSK association created the
    R1KH entry, yet `tcpdump -i rai0 ether proto 0xeeee` saw **no** frame,
    while the KDP channel itself works (V3a, V3b). Why the 0x50 signal did
    not come is not known. The agent does not rely on it (below).
- **Where a KDP frame can be lost (verified code paths; none confirmed as
  the cause of the missing 0x50).**
  `FT_KDP_EventInform` returns at once while `FlgIsFtKdpInit`
  (pAd+0x17d534) is 0. It hands the frame, skb->dev =
  `get_netdev_from_bssid`, to `announce_802_3_packet_cmm` (0x80452778),
  which drops it silently when the wdev ops hook at +0xa8 or +0xac returns
  0 (its prints need debug category 0x800), or when the hw_nat rx hook
  takes it. **Inferred:** the +0xa8 hook is `ap_rx_pkt_foward`
  (0x802f12ac), which passes a frame to a non-station unicast address up.
- **FT authentication from another AP (verified).**
  `FT_AuthReqRsnValidation` (0x8053af98) computes PMKR1Name from the
  request's PMKR0Name, its own BSSID and the station, then looks it up in
  the R1KH table. On a hit it checks the AKM suite, the pairwise cipher and
  the R0KH-ID from the FTIE. **There is no local FT-PSK derivation.** On a
  miss (at most 7 per station) it sends KEY_REQ_AUTO (0xA0) with the station
  and its own BSSID, then **answers status 53 at once**. There is no wait
  for a key. **So a station arrives seamlessly only if its PMK-R1 SA was
  installed before its FT authentication.**
- **R1KH table (verified).** `FT_R1KH_ENTRY_TABLE_SIZE` is 64 entries for
  the whole radio. Inserts beyond that fail silently. Only entries whose
  AKM map has FT-802.1X age out (`FT_R1KHInfoMaintenance`, 0x80538fa8). An
  entry is freed only by an insert of the same PMKR1Name
  (`PeerPairMsg4Action` and `FT_KDP_KeyResponseToUs` are the only callers of
  `FT_R1khEntryDelete`) or by the radio stopping (`FT_Release` from
  `APStopByBss`). FT-PSK SAs are deterministic, so a station that rejoins
  reuses its name. Every FT-SAE join adds a new entry.

### The KDP: driver and daemon (`internal/mtkft/kdp.go`)

- **Driver to daemon (verified, `FT_KDP_EventInform` 0x80541d14).** A
  fake Ethernet frame is put up the stack on the BSS's interface
  (`announce_802_3_packet`). Its destination is the BSSID, its source
  00:00:00:00:00:01 and its EtherType 0xEEEE. It carries the 0x1c-byte
  signal header (Sig at 0x12), `{u32 EventLen, u32 PeerIp}` and the body,
  all little-endian. `FT_Init` (0x805384e4) runs unconditionally at AP
  start, so signals flow whether or not a daemon exists.
  - **Verified on the unit (2026-11-23):** an `ETH_P_ALL` socket bound to
    `raiN` sees the frame (packet type host); one bound to no interface
    sees it on `raiN` and again on the bridge (`bdg2`) about 6 ms later. The
    agent's KDP tap is bound to each `raiN`, and its bridge tap takes only
    0x88b7, so it sees each signal once.
- **Daemon to driver (verified, `RTMPAPSetInformation` 0x803143e0).** The
  request is SIOCIWFIRSTPRIV+1 (0x8BE1) with flags `OID | 0x8000`
  (`mtkwifi` privIO.OID). The buffer is `PeerIP (4) || nonce (8, unused) ||
  element`.
  - `KEY_REQ` (0x0409, `FT_KDP_KeyRequestToUs` 0x80542330) needs a
    non-zero PeerIP and the station still in the MAC table. It returns the
    PMK-R1 for another R1KH as `KEY_RSP_AUTO` (0xA1), with the PeerIP
    echoed. **Verified on the unit (2026-11-23)** for an FT-PSK station:
    PMKR0Name, PMKR1Name and the PMK-R1 matched hostapd's derivation from
    the PSK (MDID octets ff 24, the 24-character R0KH-ID); R0KH_MAC is the
    BSSID, AKM 00-0F-AC-04. The element's S1KH-ID is **zero** (the agent
    uses the station's MAC) and the signal header's station field is not
    filled (the element's station at +7 is the one). KeyLifeTime is what
    is left of the PMK-R0's life: 596 s under the vendor's
    `PMKCachePeriod=10`; the agent's profile writes 129600 (90 days), and
    its PUSH and RESP cap it at hostapd's 12 h. An unknown station gets no
    answer.
  - `KEY_RSP` (0x040a, `FT_KDP_KeyResponseToUs` 0x805431d4) installs an
    R1KH entry. It does not need the station to be associated.
  - Both use `FT_KDP_EVT_KEY_ELM`, which is `KeyElementLen` = 167 octets
    (`mtkft.KeyElement`; the offsets are in the type's comment and in
    `TestKeyResponseLayout`). The pairwise cipher and the AKM are 4-octet
    suite selectors (00-0F-AC-04 CCMP; 00-0F-AC-04 FT-PSK, 00-0F-AC-09
    FT-SAE). hostapd's PAIRWISE is a `WPA_CIPHER_*` bit (CCMP 0x10), which
    `mtkft.CipherFromHostapd` converts.

### hostapd 2.9 RRB-OUI (`internal/mtkft/rrb.go`, `siv.go`)

These are the Decos' frames with explicit peers and `pmk_r1_push=1`, from
`src/ap/wpa_auth_ft.c`, all verified from the source.

- **Frame.** EtherType 0x88b7, OUI 00:13:74, protocol octets 00 01
  (`eth_p_oui.c`'s `global_oui`) and a subtype octet, then
  `u16 authlen || auth TLVs || AES-SIV(enc TLVs)`. The SIV associated data
  are the source MAC, the auth TLVs and the subtype. A payload under 64
  bytes gets an empty TLV appended to the auth TLVs. The key is the r0kh/r1kh
  line's key: a 32-hex `iapp_key` is stretched with
  `hmac_sha256_kdf(key, "FT OLDKEY")` (`mtkft.RRBKey`).
- **PUSH.**
  - Auth TLVs: SEQ, R0KH_ID, R1KH_ID.
  - Encrypted TLVs: S1KH_ID, PMK_R0_NAME, PMK_R1, PMK_R1_NAME, PAIRWISE,
    EXPIRES_IN, IDENTITY, RADIUS_CUI, SESSION_TIMEOUT.
- **Sequence numbers.** A Deco takes the first PUSH from an R0KH as
  deferred. It sends a SEQ_REQ (auth NONCE, R0KH_ID, R1KH_ID) to the frame's
  source, which must be the `r0kh` line's address. It processes the PUSH
  only after a SEQ_RESP arrives within 10 s. The SEQ_RESP carries auth
  NONCE, SEQ, R0KH_ID and R1KH_ID, and no encrypted TLVs.
- **What gets pushed.** Only FT-SAE SAs, plus FT-802.1X with RADIUS. With
  `ft_psk_generate_local=1` hostapd stores no PMK-R0 for FT-PSK
  (`wpa_auth_derive_ptk_ft`), so it pushes nothing for FT-PSK.
- **Tests.** The vectors in `kdf_test.go`, `siv_test.go` and `rrb_test.go`
  come from two sources:
  - verbatim copies of hostapd's derivation functions, compiled locally;
  - pyca/cryptography's AES-SIV and CMAC, with the RFC 4493 and RFC 5297
    A.1 vectors and IEEE 802.11-2016 J.4.2 for the PSK.

  The pushes and sequence-number frames are byte-exact against frames built
  independently from the hostapd layouts. Those layouts left out the
  protocol octets 00 01 after the OUI until 2026-11-23, so neither side
  caught it, and every frame failed hostapd's `eth_p_rx` OUI check. It was
  found against a Deco's hostapd. The vectors now carry the octets, and a
  pull, SEQ_REQ, SEQ_RESP and RESP exchange with the Deco's own hostapd
  is verified (docs/deco/features/ft-sae.md, "Receiving key holder
  frames").

### Roaming with the Decos

The Garage announces its 5 GHz holders over `internal/ftpeer`. These are
its BSSID, R0KH-ID `mtkft.R0KHID(bssid)`, R1KH-ID = BSSID and MDID =
bcmwifi's `ssidMDID(s, "na")`. The Decos then list it in their
`r0kh`/`r1kh` lines without any Deco change. The MDID is per band for an
SSID with FT-SAE.

| roam | FT-PSK | FT-SAE |
|---|---|---|
| Garage to Deco | **Nothing to do.** `ft_psk_generate_local` derives the SA from the PSK, the R0KH-ID in the station's FTIE (the Garage's), the SSID and its own MDID (`wpa_ft_psk_pmk_r1`, verified). The MDID octets must match. | On FT_ASSOCIATION, send `KEY_REQ` per same-MDID Deco R1KH. Seal the `KEY_RSP_AUTO` as a PUSH to that Deco, and answer its SEQ_REQ. |
| Deco to Garage | The agent derives the SA itself: PSK, SSID, MDID, the Deco's R0KH-ID (its BSSID as 12 hex) and the station's MAC. It installs it with `KEY_RSP`, AKM 00-0F-AC-04 (`mtkft.FTPSKR1`). **The station must be known in advance:** see "Which stations". | Open the Deco's PUSH and `KEY_RSP` it, with AKM 00-0F-AC-09 (00-0F-AC-03 on an enterprise SSID). The push comes right after the station's SAE at the Deco, before any roam, so it is in place in time. |

**Which stations (FT-PSK, Deco to Garage).**
- The R1KH table has 64 entries, and each station needs one entry per Deco
  R0KH-ID in the mobility domain. Pre-installing for every possible
  station is impossible.
- Install for stations that were on this Garage BSS in the last 24 h. With
  three 5 GHz Decos that is 3 entries each, about 18 stations within a
  budget of 56.
- On a KEY_REQ_AUTO for any other station, install as well. Its first FT
  attempt is refused with 53 and the station does a full association
  (clients fall back; some retry FT, which then succeeds).

**Inferred:** a Deco agent that announced its stations would remove the
guesswork. That is not designed here.

**Table budget.** The agent counts FT_ASSOCIATION signals (FT-SAE) and its
own installs since the last radio start. Above 56 it stops pre-installing
and notes it once. A radio restart for any other reason empties the table.
No restart is ever forced for it (one restart per change).

### Key holder entries that age (2026-11-25)

[A: Ghidra of the kernel's `mt_wifi`; M: the agent's counters on the unit]

- `FT_R1KHInfoMaintenance` (0x80538fa8) runs once a second
  (`APMlmePeriodicExec`, beside the DFS countdowns). For each R1KH entry
  whose word at 0xc has bit 0x100, it counts down the word at 4 (the
  `KeyLifeTime` of a `KEY_RSP`, or `PMKCachePeriod` × 60 s for the
  driver's own entry from `PeerPairMsg4Action`). At zero it frees the
  entry, sends KDP 0x52, and if the station is in the MAC table calls
  `cntl_disconnect_request(wdev, disassoc, sta, 8)` on that station's AP
  wdev.
- `FT_R1khEntryInsert` never writes the word at 0xc, and `os_alloc_mem` is
  `kmalloc(GFP_ATOMIC)` with no zeroing. So whether an entry ages at all
  is whatever that memory held. [M 2026-11-24: `kdp-0x52=5` with only
  FT-PSK and FT-SAE entries; the earlier note that only FT-802.1X entries
  age was wrong.]
- `ap_cntl_disconnect_proc` moves the AP's CNTL machine to
  `CNTL_WAIT_DISASSOC` and queues the disassoc; `ap_cntl_init` has no
  disassoc-confirm handler, so it never goes back to idle. Every scan of
  that wdev (`SiteSurvey=1`, the off-channel visit) is then refused in
  `cntl_mlme_error_handle`, until the radio restarts [M 2026-11-24: from
  about 06:47 the 5 GHz survey found only the home channel's neighbours].
  The other callers of `cntl_disconnect_request` are repeater and ApCli
  paths the Garage does not use; the agent's kicks (`DisConnectSta`) do
  not go through it.
- The fix keeps every entry from reaching zero while the radio runs: the
  agent installs with `KeyLifeTime` `mtkft.DriverKeyLife` (2^31 s), and
  its own record keeps the SA's real lifetime (nothing is installed past
  it). The driver's own entries get `PMKCachePeriod=129600`
  (90 days; minutes × 6000 jiffies must fit an s32). The cost: the 5 GHz
  PMKSA cache lasts 90 days instead of 12 h, and a PMK-R1 the agent
  installed stays usable in the driver until the radio restarts. A client
  connected for 90 days with no 5 GHz restart would still trip it; the
  spectrum band's error then names this.

### Over the DS, PMKSA caching

- **Over the DS: stays off (verified).** The driver sends its RRB to the
  daemon as signal 0x54 and takes it back with `RT_FT_ACTION_FORWARD`
  (0x0411, `FT_RRB_ActionHandle` 0x80543754). The cross-AP part uses
  MediaTek's own format, encrypted with `RT_FT_DATA_ENCRYPT`, not hostapd's
  0x890d frames. The Decos run `ft_over_ds=0`.
- **PMKSA caching.** It works within the Garage (`PMKCachePeriod`). It
  cannot work between the Garage and a Deco: their SAE PMKs differ by
  design.
- **Opportunistic key caching.** Not looked at. It matters only for
  802.1X.

### 802.11k (`internal/mtkft/rrm.go`)

All verified.

- **The driver answers by default.** `RRMEnable` (already in the profile)
  turns it on. A neighbour report request is answered by
  `RRM_EnqueueNeighborRep` (0x80504710) from the driver's scan table, with
  the same-SSID BSSs only. **Inferred:** the agent's neighbour survey
  refreshes that table, so the Decos are listed when they were heard. The
  existing plan note "the driver has no command to add entries" is wrong
  and should be reworded at wiring time.
- **The agent can answer instead.** `OID_802_11_RRM_COMMAND` (0x094C)
  command 8 (`mtkft.NRByDaemon`) makes the driver hand each request to the
  agent as IWEVCUSTOM flags 0x094D (`wext_send_nr_req_event`, 0x80508ed0).
  The agent answers with command 6 (`mtkft.NRResponse`, Neighbor Report
  elements built with `mtkft.NeighborReport`, at most 1000 octets).
  - The flag is per radio.
  - A request the agent does not answer gets no response.
  - Hand-back sends command 8 off.

  Use this to list the Decos with the mobility-domain bit and their
  channels from the announcements, plus the neighbour scan.

### 802.11v (`internal/mtkft/rrm.go`)

All verified.

- **Sending a BTM request.** `OID_802_11_WNM_BTM_REQ` (0x0928,
  `mtkft.BTMReq`) goes to `Send_BTM_Req` (0x80313c30).
  - The driver writes category 10, action 7 and its own dialog token
    (`SendBTMReq`, 0x8050f954).
  - The body starts at the request mode.
  - The request is sent once the station's 4-way handshake is done.
  - With mode bits 2-4 the driver also arms a per-station countdown of the
    disassociation timer. **Inferred:** this is the disconnect.
- **Responses.** They come back as IWEVCUSTOM 0x093a:
  `{u32 ifindex, STA, u32 len, status, termination delay, target BSSID...}`
  (`SendBTMConfirmEvent` 0x8050cc3c, from `PeerWNMAction` 0x80512df8).
  - A one-octet event is the 15 s timeout (`ReceiveBTMRspTimeout`).
  - Station BTM queries are 0x0929.
  - These arrive on the rtnetlink listener `mtkwifi` already runs
    (`WirelessEvent=1`).
- **Inferred:** the kernel's `wireless_send_event` drops an IWEVCUSTOM over
  `IW_CUSTOM_MAX` = 256 octets, so a response with a long candidate list is
  lost.
- **Not present.** The `CONFIG_DOT11V_WNM` iwpriv commands (`WNMCertEnable`,
  `SendBTMReq`) are not in the set table, and OID 0x094A has no case.

### Agent side (`ft`)

1. **Config.** `ft` (`jio-mtk` only, default false): off until the
   roaming test below passes. Off, the controller's FT is noted as not
   served and nothing below runs. On, it is a profile change (one restart
   per radio).
2. **Plan (`ftplan.go`).** Each BSS takes the Decos' view of its SSID
   (`bcmwifi.NormalizeFT` with this unit's `wpa3`/`ft_sae`, MDID
   `bcmwifi.SSIDMDID(s, band)`), so the agent assumes the Decos run the
   same `wpa3` and `ft_sae` values. 5 GHz: `mtkft.ProfileKeys` with the
   R0KH-ID from the slot's netdev address (no address: FT off, noted).
   2.4 GHz (only with `mt7603roam`, detected by `FT_UDFT_GetEvents
   [mt76x3_ap]` in `/proc/kallsyms`): `FtSupport`, `FtSae`, `FtMdId<n>`,
   `PMKCachePeriod=720` (on 5 GHz `u6Defaults` writes 129600). No FT
   BSS: no FT key is written. The hand-back
   restores the vendor profile.
3. **Announcements.** `FTLocals` gives `internal/ftpeer` one holder per
   FT-SAE BSS (R0KH-ID: 5 GHz `mtkft.R0KHID`, 2.4 GHz the BSSID's 12 hex)
   on its bridge with the WLAN's key; `SetFTPeers` takes the Decos'.
4. **Runtime (`roam.go`, `RunRoaming`).** A KDP tap per FT `raiN` and an
   RRB tap (0x88b7) per FT-SAE bridge, reconciled each second. Every
   driver ioctl goes through the restart gate (never inside a restart or
   its settle time).
   - Garage to Deco, FT-SAE, 5 GHz: `KEY_REQ` per same-key, same-MDID Deco
     R1KH on the driver's FT_ASSOCIATION **or**, one second after a 4-way
     completion event (`DrvAuthorized`, `DrvKeyDone`), whichever comes
     first. The `KEY_RSP_AUTO` (AKM FT-SAE) is sealed as a PUSH from the
     BSSID; SEQ_REQs are answered. A Deco's PULL is answered through
     `KEY_REQ` (not found after 2 s).
   - Deco to Garage, FT-SAE: a PUSH (or a RESP) is checked (key, peer
     address, sequence) and installed with `KEY_RSP` (5 GHz) or `R1_SET`
     (2.4 GHz). Kept SAs are reinstalled after a radio restart.
   - 2.4 GHz: `R0_CREATED` becomes a PUSH per Deco (`R1_GET`), `R1_MISS` a
     PULL to the station's R0KH; Deco PULLs are answered with `R1_GET`.
   - Budget: 56 installs on 5 GHz (64 entries; the agent's never age,
     see below); a station
     never seen here gets a pushed SA only while 24 are free. A full table
     is a problem in the FT peers' sync.
   - Deco to Garage, FT-PSK, 5 GHz: the driver has no FT-PSK derivation
     and the Decos push nothing for FT-PSK, so the agent installs what
     hostapd's `wpa_ft_psk_pmk_r1` computes (`mtkft.FTPSKR1`: PSK, SSID,
     MDID, the Deco's R0KH-ID, the station) for each same-domain Deco
     holder of the WLAN: when the driver's answer to a join's `KEY_REQ`
     shows AKM FT-PSK (so a station that was here can roam back; an SAE or
     non-FT station gets none), and on a KEY_REQ_AUTO that is not FT-SAE
     (that attempt was refused with 53; the retry or the next roam finds
     it). The Decos' holders come
     from the FT peers, which are announced only for FT-SAE WLANs, so a
     WPA2-only WLAN gets none: such roams stay full associations.
   - 802.11v (`roamrrm.go`): `SteerToBand` and `RoamAssist`, so the agent's
     band steering and Roaming Assistant run on the Garage. 2.4 GHz:
     `BtmReq` (one candidate; EINVAL is "no BTM support"). 5 GHz: OID
     0x0928 with the ranked candidates (the mobility-domain bit for a
     same-domain Deco) and **never** "disassociation imminent": the driver
     does not check the station's BTM support on that path and its
     countdown would drop a station that cannot act on it. BTM responses
     are counted in the roaming stats.
   - 802.11k: both drivers already answer from their scan tables; the
     agent writes no lists and leaves `NRByDaemon` off (a request handed to
     it and not answered would get no response at all).

### On-unit checks (coordinator, serially)

- **V0 (read-only, optional).** The kernel image is confirmed.
  `grep -E ' (FT_KDP_EventInform|FT_KDP_KeyResponseToUs)$'
  /proc/kallsyms` should give 80541d14 and 805431d4.
- **V1 (read-only).** `iwpriv rai0 show ftinfo; dmesg | tail -n 20` prints
  `MDID=`, `R0KHID=..., Len=24`, `FT Enable=0` only when the driver's debug
  level allows. Nothing printed is not a failure.
- **V2 (one 5 GHz restart).** With the agent in observe mode, add
  `FtSupport=1;0;0;0`, `FtMdId1=<MDIDValue>` and `FtR0khId1=<R0KHID>` to
  the 5 GHz profile and restart the radio; a client's scan shows the FT
  AKMs and a Deco's mobility-domain octets. Rollback: restore the profile
  and restart.
  - **Result (2026-11-23, verified on the unit):** MDIE `ff 24` (the
    Decos' 5 GHz MDID for the SSID), AKMs `PSK FT/PSK SAE FT/SAE`, `ftinfo`
    FT Enable=1, R0KHID Len=24, "Initialize FT KDP Module".
- **V3.** `tcpdump -e -xx -i rai0 ether proto 0xeeee` during an FT join.
  - **Result:** an initial FT-PSK association (AKMMap 0x280, R1KH entry
    created, KeyTime 600, ReAssocDeaLine 20) gave **no** frame.
- **V3a (no client needed, harmless).** `iwpriv rai0 set ft=0` makes
  `FT_Ioctl` (0x8053f894; the `ft` set command, table entry at 0x809a8610)
  send one KDP signal 3 with no body on MBSS 0 (verified, call at
  0x8053f9e4). Tap `rai0`, then every netdev (a packet socket bound to no
  interface; `tcpdump -i any` shows the netdev but not the EtherType
  filter), while sending it. One 50-octet frame `dst <rai0 BSSID> src
  00:00:00:00:00:01` proves the channel; nothing on `any` means the frame
  dies in the driver (above).
  - **Result (2026-11-23, verified):** the frame on `rai0` (host), and on
    `bdg2` 6 ms later.
- **V3b (a client on an FT BSS).** Send `KEY_REQ` on `rai0` (SIOCIWFIRSTPRIV+1,
  flags 0x8409, buffer PeerIP (non-zero) || 8 zero octets || the 167-octet
  element with `ffff a300 000e2e`, the station at +7 and a Deco 5 GHz BSSID
  at +0x51) and tap for the `KEY_RSP_AUTO` (0xA1, the PeerIP echoed). The station must be associated with an R1KH
  entry; an FT-PSK one serves (`FT_QueryKeyInfoForKDP`, 0x8053aa70, finds
  its PMK-R0 in the PMKID cache by station and derives the PMK-R1 for the
  given R1KH; verified). Its element carries the R0KH-ID, PMKR1Name, AKM
  and the PMK-R1 (never log it whole).
  - **Result (2026-11-23, verified):** see `KEY_REQ` above; no frame for an
    unknown station.
- **V4.** The roaming test of the final report (both directions, WPA2 and
  WPA3 clients), with the integration build and `ft: true`.

## 2.4 GHz (MT7603, driver `mt7603roam`)

**Status: driver built (module `mt76x3_ap`, file `mt7603roam.ko`, md5 72ec9fa9...) and live-swapped
on the unit 2026-11-23: beacons, RX and two stations came back, `show ftinfo` and `show nrlist`
answer, `ApOffChanScan` works (below). FT, 802.11k and 802.11v have not run on air yet, and the
module is not persistent (the flash still holds `mt7603wpa3.ko.gz`).** Since 2026-11-23 it is the boot module
(`/flash2/udeco/mt7603wpa3.ko.gz`), built reproducibly by `tools/econet-kernel/build-modules.sh` from
`tools/mt7603/mt7603roam.patch` (same code as md5 72ec9fa9, only the build time differs), released as
`mt7603roam-jio-jcow414.ko.gz` and installed with `deploy/jio-ap.sh --driver`. This page is the contract between the rebuilt MT7603 driver
(padavan MediaTek 4.1.2.0 + drv2g patch) and the udeco agent on the Garage (`platform` jio-mtk).
It covers what the driver does by itself, what it needs the agent for, and every key and command.
"Verified" below means read in the driver source (function named) unless it says live.

The driver keeps what the SAE build has (SAE/PMF transition, the EcoNet ABI fixes, beacons) and the
`iwpriv` the agent uses today (`get_site_survey`, `show stainfo`, `show mibinfo`, OID 0x2014).

### 802.11r (FT)

Over the air only (`FtOtd=0`; the Decos run `ft_over_ds=0`). No RIC (`FtRic=0`). Reassociation
deadline 1000 TU in the msg 3 timeout element and `ftinfo` (hostapd `reassociation_deadline=1000`).
The MTK IAPP/KDP daemon path is compiled out (`FT_KDP_EMPTY`): no 0xEEEE frames.

#### Profile keys (`RT2860AP.dat`, ';' lists per BSS unless numbered)

| key | value | notes |
|---|---|---|
| `FtSupport` | `1;1;0;0` | FT on per BSS. Off by default (`FT_CfgInitial`). |
| `FtSae` | `1;0;...` | also offer FT-SAE (AKM 00-0f-ac-9) on a WPA3PSK or WPA2PSKWPA3PSK BSS with `FtSupport`. |
| `FtMdId<N>` (N = BSS 1..) | 4 hex digits, e.g. `d530` | **on-air order, the same string as hostapd `mobility_domain`** (MDIE bytes `d5 30`), not byte-swapped like the Deco's `wl fbt_mdid`. Two other characters are taken raw (vendor form). |
| `FtR0khId<N>` | 1-48 characters | empty: the BSSID as 12 lowercase hex digits (`FT_DefaultR0khId`), as the Decos' `nas_identifier`. |
| `FtOtd`, `FtRic` | `0` | leave 0. |
| `PMKCachePeriod` | minutes | R0/R1 lifetime. |

The AKM list (`RTMPMakeRsnIeAKM`): WPA2PSK `PSK FT-PSK`; WPA2PSKWPA3PSK `PSK FT-PSK SAE FT-SAE`
(FT-SAE only with `FtSae`); WPA3PSK `SAE FT-SAE`. Same order as the Decos' `wpa_key_mgmt`.

`iwpriv raN set ftenable=0|1`, `ftmdid=<4 hex>`, `ftr0khid=<id>`, `ftsae=0|1`, `ftotd`, `ftric`
change the running values only; a radio restart reads the profile again. `iwpriv raN show ftinfo`
prints MDID (as hex), R0KH-ID, FT SAE and the R1KH entry count to the kernel log.

#### FT-PSK: no agent needed

A Deco-to-Garage roam: the station's FT auth carries the Deco's R0KH-ID and PMKR0Name. With no
R1 for it, the driver derives R0 = KDF(PMK of the BSS's PSK, SSID, MDID, that R0KH-ID, STA), checks
its name against the station's PMKR0Name (status 53 if they differ: another PSK, SSID or MDID),
derives R1 for its own BSSID and goes on (`FT_UDFT_R1Miss`), as hostapd `ft_psk_generate_local=1`.
A Garage-to-Deco roam is the Deco's own `ft_psk_generate_local`. Needs: same SSID, PSK and MDID
on both sides (the agent writes the band's MDID the Decos use, `ssidMDID`).

#### FT-SAE: three OIDs

PMK-R0/R1 for an SAE PMK cannot be made locally, so the agent carries them over RRB to and from
the Decos' hostapd (2.9: `r0kh`/`r1kh` lists per peer, `pmk_r1_push=1`; see ft-sae.md). The
driver only derives, installs and reports keys.

All go through `ioctl(sock, 0x8BE1 /* RT_PRIV_IOCTL */, &iwreq)` on the BSS interface (`ra0`..):
`iwreq.u.data = {pointer, length, flags}`, flags = OID (query) or OID | 0x8000 (set). Integers
little-endian. Every call needs CAP_NET_ADMIN (EPERM otherwise). Layouts: `include/ft_udft.h`.

| OID | dir | buffer | result |
|---|---|---|---|
| 0x8960 `OID_UDFT_R1_SET` | set | `UDFT_R1`, 140 bytes | installs one PMK-R1. ENODEV: `r1kh_id` is not an FT BSS of this radio; EINVAL: version, R0KH length, or a given `pmk_r1_name` that is not KDF(R0Name, R1KH, STA) |
| 0x0961 `OID_UDFT_EVENT_GET` | query | n × 104 | dequeues whole `UDFT_EVENT` records (length returned = n × 104; 0 = none) |
| 0x0962 `OID_UDFT_R1_GET` | query in/out | `UDFT_R1_REQ` in (32 bytes) in a ≥140-byte buffer | returns a `UDFT_R1` derived for the requested peer R1KH from the R0 this radio holds; ENOENT: no R0 with that name |

`UDFT_R1` (140): version 1, r0kh_id_len, flags (bit 0: name given), 0, sta[6], r1kh_id[6],
r0kh_id[48], pmk_r0_name[16], pmk_r1_name[16], pmk_r1[32], akm[4] (0 = 00-0f-ac-09),
pairwise[4] (0 = CCMP), u32 lifetime_s (set: 0 = `PMKCachePeriod`; get: remaining).
`UDFT_R1_REQ` (32): version 1, 0, 0, 0, sta[6], r1kh_id[6], pmk_r0_name[16].
`UDFT_EVENT` (104): version 1, type, r0kh_id_len, apidx, sta[6], bssid[6] (ours), r0kh_id[48],
pmk_r0_name[16], pmk_r1_name[16], akm[4], u32 seq (+1 per event; a gap means the 32-record ring
dropped its oldest).

Events (queued, and each also announced as a wireless-extensions IWEVCUSTOM on the BSS netdev,
RTM_NEWLINK, flags 0x0961, the record as data, so the agent can sleep on an rtnetlink socket and
then dequeue):

- `1` R0_CREATED: an initial FT-SAE association finished its 4-way handshake here; the R0 is in
  this BSS's PMKID cache (32 per BSS) and our own R1 in the R1 table. Agent: `R1_GET` for every
  peer R1KH of the WLAN and send each as an RRB PUSH (what hostapd does with `pmk_r1_push=1`).
- `2` R1_MISS: an FT-SAE authentication named a PMKR1Name we lack (`pmk_r1_name` = the wanted one,
  `r0kh_id` = the station's R0KH, `bssid` = our R1KH). Agent: RRB PULL to the R0KH whose
  R0KH-ID matches (a Deco BSSID), and `R1_SET` the answer. The driver drops the first 2 tries of
  that station without a reply (`UDFT_MISS_SILENT`) and answers the next with status 28 (R0KH
  unreachable), after which the station does a full SAE. mac80211 sends 3 tries 200 ms apart, so
  the key must be installed within about 400 ms of the event (other client stacks: not known).
  The same miss is queued once (later tries only re-announce it).

Agent's other duties: answer a Deco's PULL for a key whose R0 is here (`R1_GET` with the Deco's
R1KH, RRB RESP); `R1_SET` a Deco's PUSH addressed to one of our BSSIDs. The RRB encryption
(AES-SIV under the `iapp_key`-derived key) and peer lists are the agent's; the Decos list the
Garage's BSSIDs as `r0kh`/`r1kh` peers like any unit (its R0KH-ID = R1KH-ID = BSSID hex).

Tables: R1 table 256 entries (when full, the entry expiring first goes), PMKID cache 32 per BSS
(shared with the SAE PMKSA cache). **Both are emptied by
every radio restart** (`APStop` → `FT_Release`): after a restart the agent re-pushes nothing it
cannot rebuild; stations simply do a full SAE once.

The reassociation response's FTIE carries the GTK and, for a PMF station, the IGTK subelement
(the vendor code had no caller for `FT_FTIE_InsertIGTKSubIE`; drv2g adds it in
`FT_ConstructGTKSubIe`, counted in the FTIE length and MIC).

Not supported: FT-1X (FT over 802.1X; R0 needs the MSK's second half, which the driver never has);
FT over the DS; RIC.

### 802.11k: neighbour list

`RRMEnable=1;...` (profile) or `iwpriv raN set RrmEnable=1` sets the RRM capability element.
A station's Neighbor Report Request is answered from the BSS's static list when it has entries,
else from the driver's scan table (`RRM_EnqueueNeighborRep`).

```
iwpriv raN set NrAdd=<bssid>,<bssid-info hex>,<op class>,<channel>,<phy type>   (replaces the same BSSID; 16 max)
iwpriv raN set NrDel=<bssid>
iwpriv raN set NrClear=1
iwpriv raN show nrlist     -> kernel log "nrlist raN rrm=<0|1> n=<n>", "nr <mac> info=<hex> opclass=<n> ch=<n> phy=<n>"
```

BSSID information as 802.11-2016 9.4.2.37 (e.g. `0x8f` reachable + security + key scope +
RRM; add 0x400 for the same mobility domain, which a client wants before trying FT, and 0x800
for HT). Op class 81 for 2.4 GHz, 115/128 etc. on 5 GHz; PHY 7 HT, 9 VHT.
The list is live only: the agent sends it after every restart's settle time (`live.go`).

### 802.11v: BSS transition request

`WNMEnable=1;...` (profile) sets the BSS Transition capability (extended capabilities bit 19).

```
iwpriv raN set BtmReq=<sta>,<bssid>,<channel>[,<disassoc timer TBTT>[,<validity TBTT, default 200>[,<request mode hex>]]]
```

One request, one candidate (preference 255, preferred-candidate bit set). Timer > 0 sets
"disassociation imminent". Op class, PHY and BSSID information come from the neighbour list when
it has the BSSID, else 81/115, HT, `0xf`. EINVAL: `WNMEnable` off, station not on this BSS, or it
did not claim BSS transition support. The response is logged by the driver only.

### U-APSD

Compiled in (`UAPSD_SUPPORT`); `APSDCapable=1;...` per BSS advertises it in the WMM element.

### Off-channel measurement (`ApOffChanScan`)

`iwpriv ra0 set ApOffChanScan=<passive|active>:<channel>:<ms 1..255>`, as the vendor
mt7603eap (`Set_ApOffChanScan_Proc` 0xb83bc, `ApSiteSurveyNew_by_wdev` 0x1fe14): one dwell on
the channel, then back, no AP restart. Kernel log: `ApSiteSurveyNew_by_wdev channel_index:<i>
channel:<ch> time:<ms>` at the request and `time_diff:<ms since the dwell timer + 1, u8>
Busytime:<µs> AvgNF:-95` at the dwell's end, the score in OID 0x2014 slot i. Differences from the
vendor: the end line prints at debug level 1 (this module's default) and up, the vendor at 2 and up;
`Debug=0` silences it (live 2026-11-23: `passive:11:50` printed `ApSiteSurveyNew_by_wdev
channel_index:10 channel:11 time:50`, then `time_diff:50 Busytime:52177 AvgNF:-95` more than 1 s
later, at the default level and at `Debug=1`; the radio stayed on its channel). A channel off the
list: EINVAL (live: channel 13). Interface down: success, no visit. Each
visit empties the scan table (`BssTableInit`), as the vendor's. Set-OID 0x8999 returns the
channel list as 28-byte records (channel, index, DFS at 0x18). `internal/mtkwifi/offchan.go`
works unchanged.

### 802.1X and Hotspot 2.0

802.1X is compiled in (`DOT1X_SUPPORT`) for `rtdot1xd`: `IEEE8021X`, `own_ip_addr`,
`RADIUS_Server`, `RADIUS_Port`, `RADIUS_Key<N>`, `EAPifname`, `PreAuthifname`, `PreAuth`,
`AuthMode=WPA2` (the daemon is the vendor's; not checked that the unit ships it).
Hotspot 2.0: **not possible in this source tree.** `MT7603E_HOTSPOT` adds `-DWAPP_SUPPORT` and
`wapp/wapp.o`, and `wapp/` (with `wapp_cmm_type.h`) is not in the padavan tree: the build stops at
`rt_config.h:323`. Without WAPP, Release 1 compiles after two fixes but cannot be switched on: the
only setters of the Interworking/HS IEs (`OID_802_11_HS_IE` → `Set_AP_IE`) are commented out and
`OID_802_11_HS_ONOFF` is Release 2 only; Release 2 needs `wapp_set_ap_ie`/`set_wapp_param` (in the
missing `wapp.c`). There is also no ANQP server on the unit (the driver hands ANQP queries to a
user-space daemon, `wext_send_anqp_req_event`). So the module is built without it; the vendor
mt7603eap has GAS only (`GasEnable`, `Send_ANQP_Rsp`), no Hotspot 2.0 either.
