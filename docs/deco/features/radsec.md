# RADIUS over TLS (RadSec) on the Deco agent

Status (2026-11-19): implemented, takeover mode only, not yet tested on a unit.
Capability: fw2_caps `0x80000` (`supportsRadSec`, `hasFirmware2Capability(524288)`
in `com.ubnt.data.XCfthFC`). Claim it in takeover mode only; see "Capability" below.
This replaces the RadSec section of radius-macauth-hs20-radsec.md.

## What the controller sends (Network 11.1.50)

Sources: `com.ubnt.service.config.XHjguBsIf` (the radius server lines and
the per-WLAN TLS certificates) and `com.ubnt.service.config.ubntconf.aoUDgXMlCqEvTSIrOtq`
(the certificate section generator).

- Without the bit, saving a TLS RADIUS profile used by a WLAN on such an AP
  is refused (`BROADCASTING_DEVICE_DOES_NOT_SUPPORT_RADSEC`), and the server
  lines carry no `tls` key.
- With the bit, the certificate section comes before the aaa sections:

  ```
  certs.status=enabled
  certs.<i>.status=enabled
  certs.<i>.comment=<outfile>
  certs.<i>.outfile=ca-<i>.pem | client-<i>.crt | client-<i>.key
  certs.<i>.key=<base64>
  ```

  One index counter runs over the three files, so a single profile gives
  `ca-1.pem`, `client-2.crt` and `client-3.key`. A profile used by several
  WLANs is written once.
  - CA: the controller base64-decodes every CA file of the profile, chomps
    each one, joins them with `"\n"` and base64-encodes the result. So the
    value is base64 of a PEM bundle.
  - Client certificate and key: the profile's stored value as is (the UI
    upload, base64).
- Each server of a TLS profile gets:

  ```
  aaa.N.radius.{auth,acct}.M.{ip,port,secret}
  aaa.N.radius.{auth,acct}.M.tls=enabled
  aaa.N.radius.{auth,acct}.M.ca_cert=ca-1.pem
  aaa.N.radius.{auth,acct}.M.client_cert=client-2.crt
  aaa.N.radius.{auth,acct}.M.private_key=client-3.key
  aaa.N.radius.{auth,acct}.M.private_key_passwd=<password>   (only if set)
  ```

  `ip` is IPv4 (the profile's field regex); the port is whatever the profile has.

## What a real UAP does

From the U6 Pro ubntbox strings (docs/reference/u6pro/actions-scans/strings-ubntbox.txt):

- `do_certs` base64-decodes each `certs.<i>.key` to `/etc/certs/<outfile>`
  ("base64 decode: writing %i/%s").
- `setup_radius` writes `auth_server_type=TLS` plus
  `auth_server_{ca_cert,client_cert,private_key}=/etc/certs/<file>` and
  `auth_server_private_key_passwd`, the same for acct. Its patched hostapd
  speaks RADIUS/TLS itself; there is no radsecproxy.
- It refuses a TLS server without the files: "Radius auth over tls requires
  ca/client certificates".

## What the Deco can do

`/sbin/hostapd` v2.9 on .205 has `auth_server_type` and `auth_server_ca_cert`
0 times, and its TLS backend is `tls_none`. Its RADIUS client is UDP only
(checked read-only on 2026-11-19). The unit has `/usr/bin/openssl` but no
radsecproxy or stunnel. So the agent does the TLS itself.

## Implementation

- `internal/translate/radsec.go`: reads `certs.*` and each server's
  `tls`/`ca_cert`/`client_cert`/`private_key`/`private_key_passwd` into
  `RadiusServer.TLS` (`*RadSecTLS`, whose printing masks the key and password).
  A TLS server with no port gets 2083.
  - A WLAN stays off when a TLS server lacks the CA, the client certificate or
    the key, or is not an IP address (`radsecCheck`). This is the UAP's rule
    plus the IP check.
  - `certs` is a recognised section. `passwd` joined the secret key suffixes,
    so `MaskCfg` masks `private_key_passwd`.
- `internal/radsec`: the proxy.
  - **Local side.** One UDP socket per distinct server (host, port, secret,
    TLS identity) on `127.0.0.1:18120-18519`. The port is chosen by a hash,
    so a restarted agent gets the same one.
  - **Local secret.** It is HMAC-SHA256(server secret, route key), 32 hex
    characters, so hostapd's conf stays the same across restarts and never
    holds the server's secret.
  - **Checking hostapd's requests.** Requests from hostapd must verify with
    the local secret:
    - Access-Request: Message-Authenticator required.
    - Accounting-Request: Request Authenticator.
    - Every other code is dropped.
  - **Re-signing for the server.** The Identifier is remapped, because the
    BSSes share one TLS connection. Then for the server's secret:
    - User-Password is re-encrypted.
    - Message-Authenticator is recomputed.
    - The Accounting-Request authenticator is recomputed.
  - **Answers.** The Response Authenticator must verify with the server's
    secret, and a Message-Authenticator is required on every Access-* answer
    (RFC 3579, BlastRADIUS). The answer must match the request's code.
    - MS-MPPE-Send/Recv-Key and Tunnel-Password are re-encrypted for the
      local secret.
    - The answer is re-signed and sent back to the hostapd socket that asked.
    - Server-initiated codes (Disconnect/CoA) are dropped.
  - **TLS.**
    - Only the controller's CA bundle is trusted: no system roots, never
      `InsecureSkipVerify`.
    - The server certificate must carry the server's IP as an IP SAN. Go
      ignores the CN, and no SNI is sent for an IP.
    - TLS 1.2 or later; the client certificate is always presented.
    - The key may be PKCS#8, PKCS#1 or SEC1, as PEM or DER, plain or base64.
      An encrypted key may be PBES2 (PBKDF2-HMAC-SHA1/256/384/512 with
      AES-CBC or 3DES; checked against OpenSSL 3.5 output) or legacy PEM
      encryption.
    - The key must match the certificate.
  - **Connection life.**
    - The proxy connects on the first request; requests queue while it
      connects.
    - A failed connect drops the queued requests (hostapd fails over or times
      out) and backs off 1 s, doubling up to 60 s.
    - A lost connection is reopened by the next request.
    - hostapd's retransmissions are not sent again on the reliable connection
      (RFC 6614 §2.5). If the server has been silent for 10 s while a
      request waits, the connection is closed and reopened.
    - Unanswered requests are forgotten after 30 s.
    - An idle connection closes after 5 min.
  - **Logging.** Only state changes and rate-limited problems are logged,
    never secrets or packets.
- `cmd/udeco-ap/radsec.go` and hooks:
  - **`desiredFrom`** holds every WLAN that has a TLS server off, so it is
    never sent as plain UDP RADIUS to the server.
  - **`provision`** calls `radsecProvision` after the Enforce gate. It starts
    the proxy when the plan needs it, then `radsecRoute` rewrites each TLS
    server to its local endpoint and turns the WLAN back on as the controller
    asked. A WLAN whose server the proxy refuses stays off, with a note.
  - **Last-good.** Routes from the previous plan are kept one more round, so
    a rollback to last-good still has its endpoints.
  - **Egress.** `decosys.SetEgressAllowTCP` (egressallow.go) adds
    `-d <ip>/32 -p tcp --dport <port> -j RETURN` to UDECO-OUT for servers off
    the LAN. A server on the LAN needs no rule.
  - **`dropToObserve`** closes the proxy and forgets the egress hole.
- Observe mode has no proxy, so a RadSec WLAN stays off. That only matters
  in the logged plan, because observe mode applies nothing.

Not done:

- Status-Server watchdog (RFC 5997).
- FQDN servers. The controller's profile allows IPv4 only.
- Dynamic Authorization over the TLS connection (fw_caps 0x100000 is not
  claimed).
- A single connection carries at most 256 outstanding requests.

## Capability

Claimed (2026-11-19): `models.FW2CapRadSec = 0x80000`, set by
`DecoAgentFeatures.RadSec` and in `DecoAgentTakeoverFW2Caps`. The agent
passes `RadSec: own` (takeover). fw2_caps is sent only when it is
non-zero (`device.session` already does this). Observe mode does not claim
it. A drop to observe clears it with the other takeover bits.
`supportsHotspot2Passpoint` also needs Hotspot 2.0 (fw_caps 0x800000).

## Live test (takeover unit)

1. Set up a RadSec server on the LAN, for example FreeRADIUS 3 with a `listen { type = auth+acct;
   proto = tcp; port = 2083; tls { ... require_client_cert = yes } }` and a
   `clients` entry with `proto = tls` and `secret = radsec`.
   - Its certificate needs `subjectAltName = IP:<server ip>`.
   - Make a client certificate from the same CA.
2. In the controller, create a RADIUS profile with "Use RadSec" on: upload
   the CA, the client certificate and the key (try one with a password too).
   Then make a WPA2-Enterprise WLAN on it.
3. On the unit:
   - `grep -c certs. /tp_data/udeco/session/system_cfg.txt`.
   - The agent log shows `radsec: serving <ip>:2083 on 127.0.0.1:181xx`.
   - `/tmp/udeco/hapd-wl1.conf` has `auth_server_addr=127.0.0.1` with the
     local port.
4. Join with an EAP client (PEAP/MSCHAPv2 or EAP-TLS). Then check:
   - the agent log shows `connected (TLS 1.3, ...)`;
   - FreeRADIUS `-X` shows the TLS client certificate and Access-Accept;
   - the station passes the 4-way handshake, which proves that the MS-MPPE
     re-encryption works.
5. Accounting: FreeRADIUS logs Accounting-Request Start and Stop for the
   station.
6. Failure checks:
   - Stop FreeRADIUS. The log shows `connection lost`, and joins fail and do
     not fall through.
   - Restart FreeRADIUS. The next join reconnects.
   - Use a server certificate without the IP SAN. The log shows
     `connect failed: tls: failed to verify certificate`, and nothing reaches
     the server.
7. If the server is off the LAN with `egress=true`, check
   `iptables -S UDECO-OUT` for the `-p tcp -m tcp --dport 2083` RETURN rule.
