# Connection-timing events: success, failure, soft failure, fixup (2026-11-20)

## What a U6 does

- For each connection attempt a UniFi AP sends a STA_ASSOC_TRACKER notification (an extra inform
  with `inform_as_notif`, `notif_reason` "event") with `event_type` success, failure,
  "soft failure" or fixup, besides association and sta_leave. Network 11.1.50 reads (decompiled
  `devmgr.w.a.qeIWtmwxgQ`, `mMObEXELV`, field names in `CjTLEUfgfDYCfBSnbyC`):
  - `event_id`, `mac`, `vap`, `auth_ts` (the per-AP metrics are keyed on it), `auth_rssi`
    (else `avg_rssi`; below -75 dBm the counters are dropped);
  - `assoc_delta`, `auth_delta`, `wpa_auth_delta`, `ip_delta` (counted only with
    `ip_assign_type` "dhcp"), `traffic_delta`: microseconds, counted only when 0 < d <= 60 s;
  - `assoc_failures`, `auth_failures`, `wpa_auth_failures`, `ip_failures`, `traffic_failures`,
    `radius_auth_status` ("success"/"failure"), `arp_reply_gw_seen` and `dns_resp_seen`
    ("yes"/"no"; "no" counts as a failure), `dns_timeouts`, `dns_responses`;
  - success = not a failure, and either a soft failure with `ip_assign_type` "roam", or
    `traffic_delta` > 0 and `dns_responses` > 0 (firmware 6.2.1 and later).
- `sta_roam` is read only from an AP claiming wifi_caps2 0x2000 (`supportsRoamTopologyStats`);
  without it, the success events go to the roaming detector instead.
- The U6's own state machine (its exact reference points and timers, and when it sends a fixup)
  was not captured.

## What the agent does (takeover, Deco; `sta_snoop`, default on)

- Sources:
  - hostapd's syslog (`logread -f`, a follower of its own; a line's time is when it arrived):
    "IEEE 802.11: authenticated", "associated"/"reassociated", "WPA: pairwise key handshake
    completed", "WPA: FT authentication already completed" (a fast transition), "EAPOL-Key
    timeout", "disassociated"/"deauthenticated";
  - the hostapd control sockets (internal/hapdmon): AP-STA-CONNECTED (authorized),
    AP-STA-DISCONNECTED, AP-STA-POSSIBLE-PSK-MISMATCH, CTRL-EVENT-EAP-STARTED / -SUCCESS[2] /
    -FAILURE[2] / -TIMEOUT-FAILURE[2], AP-REJECTED-MAX-STA (only the first two move a station in
    the association/sta_leave events);
  - a read-only AF_PACKET tap per served BSS (internal/stasnoop): a kernel BPF filter passes only
    ARP and IPv4 UDP to or from ports 53/67/68, frames go to a ring of 1024 that drops the oldest,
    nothing blocks the inform loop.
- `cmd/udeco-ap/staconn.go`: one attempt per station, started at its first anchor. Deltas:
  `assoc_delta` authenticated -> associated, `wpa_auth_delta` associated -> authorized,
  `ip_delta` authorized -> DHCP ACK, `traffic_delta` authorized -> its first frame,
  `radius_auth_delta` EAP start -> result; `auth_delta` is 0 (the driver authenticates and only
  the end is logged). `ip_assign_type` "dhcp" (an ACK seen), "roam" (an address used without
  DHCP after a fast transition), "static" (used without DHCP otherwise). Judged at each reading:
  - success: authorized, an address, a frame from the station and a DNS answer;
  - soft failure: authorized 30 s ago without that (unanswered queries older than 5 s are
    `dns_timeouts`, no address an `ip_failure`, no frame a `traffic_failure`), or the station left
    before; a success within 2 minutes after a soft failure sends a fixup with the completed
    values (the agent's reading of "fixup");
  - failure: never authorized 30 s after it started and not associated in the reading; PSK
    mismatches and EAPOL timeouts count as `wpa_auth_failures`, a full BSS as `assoc_failures`, an
    EAP rejection sets `radius_auth_status` "failure".
  - `auth_ts` is the attempt's start, made unique per unit; `event_id` is unique; `auth_rssi` is
    the first reading's signal, `avg_rssi` the latest.
- One event per extra inform, through the same bounded queue (128) as association/sta_leave.
- No attempt is judged on a BSS without a running tap (without DNS every attempt would read as a
  soft failure).
- No `sta_roam`, no wifi_caps2 0x2000: the controller needs the AP a client came from, which the
  agent cannot know reliably; roams stay association/sta_leave pairs plus the success events.
- `sta_snoop` false: no follower, no taps, no timing events. Takeover only; refused on jio-mtk.

## Unverified on hardware

- That hostapd 2.9 with the Broadcom driver (driver SME) logs "authenticated", "pairwise key
  handshake completed" and "EAPOL-Key timeout" to syslog (only "associated"/"disassociated" were
  seen live), and sends the PSK-mismatch, EAP and max-station control events.
- That ETH_P_ALL taps on the wl vifs see the clients' unicast DHCP/DNS frames in both directions
  with the flow cache on (fcache may bypass the netdev for accelerated flows; DNS/DHCP are short
  and usually not accelerated), and the CPU cost on a busy BSS.
- How the controller's WiFi Connectivity view shows these events from this agent.
