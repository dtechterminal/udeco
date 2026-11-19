# Private pre-shared keys (PPSK) on the Deco agent

Status (2026-11-19): implemented for keys on the SSID's own network. Per-key
VLANs are not possible with this hostapd build. Capability: wifi_caps
`WPA_PSK_FILE` (0x100000), claimed in takeover mode only (see "Capability"
below). Not yet tested on a unit.

## What the controller sends (Network 11.1.50)

Sources: `com.ubnt.service.config.ubntconf.qemBJTmR` (the per-device WLAN
filter), `com.ubnt.service.aF.aoUDgXMlCqEvTSIrOtq` (the PPSK config factory)
and `com.ubnt.service.aF.QdjEeOBh` (key-to-VLAN mapping).

- Without the bit, a WLAN with `private_preshared_keys_enabled` (or a UniFi
  Identity IoT WLAN) is not sent at all. The controller logs "PPSK is not
  supported by <mac> and WiFi[<name>] will be skipped".
- With the bit, the WLAN gets its usual `wpa.key.1.mgmt=WPA-PSK` and
  `wpa.psk=<x_passphrase>`. The factory adds these keys:

  ```
  aaa.N.dynamic_vlan=1
  aaa.N.wpa.psk_file.status=enabled
  aaa.N.wpa.psk_file.M.psk=<passphrase>
  aaa.N.wpa.psk_file.M.vlanid=<VLAN of the key's network>
  ```

  The `vlanid` line is left out when the network's VLAN is 1, the untagged LAN.
  A key is listed only if its network is a local layer-2 network.
- A UAP's ubntbox also reads `.mac` and `.keyid` and writes a hostapd
  `wpa_psk_file` with lines of the form `keyid=%s vlanid=%s <mac> <psk>`
  (docs/reference/u6pro/actions-scans/strings-ubntbox.txt). The agent reads
  both fields too.
- UniFi Identity IoT WLANs send `aaa.N.wpa.psk_radius` instead. This is not
  supported: such a WLAN stays off unless it also has a key file or a
  passphrase.

## What the Deco can do

The hostapd is `/sbin/hostapd` v2.9 on .205. Evidence comes from its strings:
`scratchpad/deco205/hostapd.strings`, copied read-only with `strings -n 3`.

- `wpa_psk_file`, `keyid`, `vlanid`, "PSK keyid too long" and "Invalid PSK"
  are present, so the key file parser is built in.
- hostapd itself runs the 4-way handshake. Its log shows "WPA: pairwise key
  handshake completed (RSN)", with no firmware offload. It therefore tries
  every matching key from the file.
- `dynamic_vlan`, `vlan_file`, `vlan_naming` and `vlan_tagged_interface` occur
  **0 times** in the binary. Its config parser cannot enable dynamic VLANs, so
  the VLAN list stays empty and a key that carries `vlanid` would be refused
  ("Invalid VLAN ..."). Per-key VLANs are therefore
  **not feasible**.

## Implementation

- `internal/translate/ppsk.go`: `wlanPSKFile` reads `aaa.N.wpa.psk_file.M.{psk,vlanid,mac,keyid,status}` into
  `WLANIntent.PSKs`. A missing `vlanid`, or VLAN 1, becomes 0 (untagged).
  The following entries are dropped with a note that gives only the index:
  - a passphrase that is not 8-63 printable characters or 64 hex digits
  - a VLAN outside 1-4094
  - a MAC that cannot be read

  An invalid keyid is left out and the key is kept. The WLAN stays off in two
  cases:
  - the security is WPA3-only, since SAE does not use the key file;
  - no usable key and no WLAN passphrase remain.

  Neither case is ever built open. `wlanSecurity` calls it, and a WPA2 WLAN
  whose only keys are in the file is accepted.
- `internal/bcmwifi/ppsk.go`: `normalizePSKs`, called from `normalizeSSID`,
  keeps only the keys whose VLAN equals the SSID's VLAN. Those keys are written
  without `vlanid` and land on the SSID's own bridge. The other keys are dropped
  with a note: "N private pre-shared keys for another VLAN than the SSID's (V)
  dropped". Their stations fail the handshake and are never placed on the wrong
  network. On WPA2/WPA3 transition the keys apply to WPA2 clients only (noted).
  On WPA3 or enterprise SSIDs the keys are ignored (noted).
- The hostapd conf gains `wpa_psk_file=/tmp/udeco/<vif>.psk` in the BSS. A
  `wpa_passphrase` line is written only when the WLAN has its own passphrase.
  The key file is 0600 and contains lines of the form
  `[keyid=<id> ]<mac or 00:00:00:00:00:00> <passphrase>`.
  `pskSteps` writes the file, or removes a stale one. A changed file counts
  like a changed conf, so the radio's hostapd restarts: 2.9 reads the file only
  at start. The live ACL path (`acllive.go`) gives up on a key-file change for
  the same reason. A hand-back to TP-Link removes the file.
- FT-PSK works with the file, because `ft_psk_generate_local=1` is already
  written.
- Secrets: `PSK.String`/`GoString` mask the passphrase in both packages. The
  public `last-good.json` is written without key passphrases. They go to
  `last-good.secrets.json` (`ssidSecrets.PSKs`) and are joined back for a
  rollback.
- `cmd/udeco-ap/ppsk.go`: `desiredPSKs` maps the keys (one call in
  `desiredFrom`).
- The key table marks `wpa.psk_file.M.*` as read. `dynamic_vlan` and
  `hs20.status` are not-carried settings: they are silent when 0 or disabled,
  and noted otherwise.

## Capability

Claim wifi_caps bit 20 (0x100000, `supportWpaPpsk`) **in takeover mode only**,
following the DecoAgentFeatures pattern: the keys are only applied by
bcmwifi. Limitation: only keys on the WLAN's own network work. With keys on
several networks, which is UniFi's main PPSK use, the keys for other VLANs
are refused, and a note in the event log says so.

## Live test plan (once the unit is free)

1. Create a WPA2 WLAN with PPSK and two keys on the WLAN's own network
   (untagged LAN). Optionally add a third key on another VLAN.
2. On the unit, check `/tmp/udeco/hapd-wl1.conf` for `wpa_psk_file=`. Check
   that `/tmp/udeco/wl1N.psk` is mode 0600 with two lines, and that the agent
   log has the "another VLAN" note.
3. Join with key 1, then with key 2. Both should log "pairwise key handshake
   completed". A wrong key, or the third key, should fail at the 4-way
   handshake.
4. Change a key in the controller. Expect a hostapd restart on that radio,
   after which the old key fails and the new one works.
