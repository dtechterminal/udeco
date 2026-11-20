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
  - hostapd's syslog (`logread -f`, a follower of its own; a line's time is when it arrived; the
    first line, which logread replays from its buffer on every (re)start, is skipped when its own
    timestamp is older than the follower; an "authenticated"/"associated" line that arrives within
    1 s after the same station's authorization on the same BSS (an FT roam, whose syslog line can
    trail the socket event) belongs to that attempt and starts no new one):
    "IEEE 802.11: authenticated", "associated"/"reassociated", "WPA: pairwise key handshake
    completed", "WPA: FT authentication already completed" (a fast transition), "EAPOL-Key
    timeout", "disassociated"/"deauthenticated";
  - the hostapd control sockets (internal/hapdmon): AP-STA-CONNECTED (authorized),
    AP-STA-DISCONNECTED, AP-STA-POSSIBLE-PSK-MISMATCH, CTRL-EVENT-EAP-STARTED / -SUCCESS[2] /
    -FAILURE[2] / -TIMEOUT-FAILURE[2], AP-REJECTED-MAX-STA (only the first two move a station in
    the association/sta_leave events);
  - a read-only AF_PACKET tap per served BSS (internal/stasnoop): a kernel BPF filter (48
    instructions) passes only ARP, IPv4 UDP to or from ports 53/67/68 (decided as before IPv6 was
    added; a test runs the old program beside the new one), IPv6 UDP to or from port 53, IPv6
    whose first header is hop-by-hop, routing or destination options (rare on a LAN: mostly MLD
    reports; the parser walks up to 8 such headers to the UDP header and drops the rest), and TCP
    SYNs to or from port 853 over either family; IPv6 fragments (a fragment header right after the
    fixed header in the filter, anywhere in the chain in the parser) and IPv4 later fragments are
    dropped. Frames go to a ring of 1024 that drops the oldest, nothing blocks the inform loop.
- `cmd/udeco-ap/staconn.go`: one attempt per station, started at its first anchor. Deltas:
  `assoc_delta` authenticated -> associated, `wpa_auth_delta` associated -> authorized,
  `ip_delta` authorized -> DHCP ACK, `traffic_delta` authorized -> its first frame,
  `radius_auth_delta` EAP start -> result. 802.1X (deco-crosscheck): `auth_delta` EAP-STARTED ->
  EAP-SUCCESS, `wpa_auth_delta` from EAP-SUCCESS to authorized; an EAP rejection or an
  EAP TIMEOUT-FAILURE is `auth_failures` 1 with `radius_auth_status` "failure" (a timeout used to
  count as a 4-way `wpa_auth_failure`). PSK: no `auth_delta` (omitted, as the spec says). `ip_assign_type` "dhcp" (an ACK seen), "roam" (an address used without
  DHCP after a fast transition), "static" (used without DHCP otherwise). Judged at each reading:
  - success: authorized, an address, a frame from the station and a DNS answer (IPv4 or IPv6);
  - DNS: a query is answered by a response of the same address family with the same id on the
    same attempt (the station's MAC); the server address is not compared, for IPv4 as before
    (a response comes from the address the query went to). IPv6 frames count as the station's
    first frame but never as its address: `ip_assign_type`, `ip_failures` and the GARP address
    stay IPv4;
  - soft failure: authorized 30 s ago without that (unanswered queries older than 5 s are
    `dns_timeouts`, no address an `ip_failure`, no frame a `traffic_failure`), or the station left
    before; a success within 2 minutes after a soft failure sends a fixup with the completed
    values and the soft failure's `event_id` (the spec: unique per attempt, reused for fixup);
  - an attempt authorized on the socket after the reading began has its association event in the
    next reading (station events hold it), so its success waits for that reading too: the
    controller never gets the success first;
  - failure: never authorized 30 s after it started and not associated in the reading; PSK
    mismatches and EAPOL timeouts count as `wpa_auth_failures`, a full BSS as `assoc_failures`, an
    EAP rejection sets `radius_auth_status` "failure".
  - `auth_ts` is the attempt's start, made unique per unit; `event_id` is unique per attempt;
    `auth_rssi` is the first reading's signal, `avg_rssi` the latest. A station no reading listed
    (one that failed before it was ever associated in a reading) has no signal: both are omitted,
    never 0 (the controller's -75 dBm gate takes 0 as strong and would count a far neighbour's
    retries). Whether the controller then counts or drops those counters is INFERRED (drops).
- Encrypted DNS cannot be read and no timing is guessed from it. DNS over TLS shows only as
  the station's SYN to port 853 and the server's SYN-ACK: an attempt that would be a soft
  failure only for the missing DNS answer (it has an address and a frame), sent no plaintext
  query and had a DoT server accept its connection is set aside unjudged, no event, as the
  controller counts both a soft failure and a success without `dns_responses` as a failure.
  It stays open for the fixup window: a plaintext DNS answer inside it (Private DNS falling
  back) sends a success, and a leave with no answer sends nothing.
  A roam's soft failure (a success to the controller) and any other gap are still sent; a
  plaintext query left unanswered is still a `dns_timeout`. DNS over HTTPS (TCP or QUIC 443) is
  indistinguishable from other HTTPS: a DoH-only client still reads as a soft failure
  (`dns_responses` 0, `dns_resp_seen` omitted, as no query was seen).
- One event per extra inform, through the same bounded queue (128) as association/sta_leave.
- No attempt is judged on a BSS without a running tap (without DNS every attempt would read as a
  soft failure). A tap that dies with its vif (hostapd restart at an apply) is reopened at the
  next reading and retried at every reading for a minute; an attempt authorized before its BSS's
  tap (re)opened is dropped unjudged, never a soft failure.
- No `sta_roam`, no wifi_caps2 0x2000: the controller needs the AP a client came from, which the
  agent cannot know reliably. With the timing events on, the association event carries
  `auth_algo` ("ft" for a fast transition seen in syslog, "sae" on a WPA3-only SSID served with
  `wpa3`, else "open") and no `auth_rssi`: the deco-crosscheck capability rule (claim 0x2000, or
  send no `auth_rssi` on association) keeps the detector from writing each roam twice; roams
  then come from the controller's inform-based path. `sta_snoop` false keeps the old association
  event (with `auth_rssi`).
- `sta_snoop` false: no follower, no taps, no timing events. Takeover only; refused on jio-mtk.

## Unverified on hardware

- That hostapd 2.9 with the Broadcom driver (driver SME) logs "authenticated", "pairwise key
  handshake completed" and "EAPOL-Key timeout" to syslog (only "associated"/"disassociated" were
  seen live), and sends the PSK-mismatch, EAP and max-station control events.
- That ETH_P_ALL taps on the wl vifs see the clients' unicast DHCP/DNS frames in both directions
  with the flow cache on (fcache may bypass the netdev for accelerated flows; DNS/DHCP are short
  and usually not accelerated), and the CPU cost on a busy BSS.
- How the controller's WiFi Connectivity view shows these events from this agent.
- IPv6 DNS and the DoT handshake (2026-11-20, tests with hand-built frames only): that the wl
  vifs' ETH_P_ALL taps see a client's IPv6 DNS and its TCP 853 SYN/SYN-ACK in both directions,
  that the kernel on the X20 accepts the 48-instruction filter, whether this site advertises an
  IPv6 resolver (RA RDNSS / DHCPv6), and which clients (Android Private DNS) use DoT here.
- DoH-only clients (deferred): still a soft failure on every connection; nothing on the wire
  tells their DNS apart.
