# Lock to Access Point (wifi_caps 0x1000000)

Status: implemented in takeover mode (2026-11-19). This note's status is as of
that date; the current one is the "Lock client to AP" row of the
[README](../../../README.md). The bit is claimed in takeover only
(`models.WifiCapLockAP`, one of `models.DecoAgentTakeoverWifiCaps`; see
"Capability bit").

## What the controller does (Network 11.1.50, decompiled)

- **Offer.** `XCfthFC.supportLockAp()` is `hasWifiCapability(16777216)` (bit 24). The client's
  "Lock to Access Point" setting is offered only when **every** AP of the site has the bit
  (`com.ubnt.service.al.vFiJoQiuQjMZUx`: count of APs == count of APs with `supportLockAp`).
  Otherwise the UI shows the "update to UAP 5.76.0" (`CqACYAR.cNSFbnkx`) tooltip.
- **Stored on the client** (user collection): `fixed_ap_enabled` (bool) and `fixed_ap_mac`.
  A change re-provisions every AP of the site (`devmgr.QNAsAi`: lock fields changed ->
  site config changed event).
- **Sent to the APs** (`com.ubnt.service.al.xTNsE`, rendered by
  `config.ubntconf.dwuoZJCFG`): the locked AP gets **nothing**. Every **other** AP gets
  the client in each WLAN's MAC filter, in system_cfg's `macacl` section, one entry per VAP
  (`devname` = the WLAN's `athdev`, the same as `wireless.N.devname`):

  ```
  macacl.status=enabled
  macacl.1.status=enabled
  macacl.1.devname=ath0
  macacl.1.acl.status=enabled
  macacl.1.acl.policy=deny
  macacl.1.acl.1.status=enabled
  macacl.1.acl.1.mac=<client>
  macacl.1.acl.1.type=lock2ap
  ```

  The set is the site's clients with `fixed_ap_enabled`, a non-empty `fixed_ap_mac` that is
  **not** this AP, and whose locked AP is available (`fixed_ap_available`, kept by the
  controller from the AP's connection state). Per WLAN:
  - no MAC filter: policy `deny`, the lock2ap entries (not for a WDS downlink WLAN);
  - a deny filter: the union (a MAC in both keeps `type=user`);
  - an allow filter: the allow list minus the clients locked elsewhere (no lock2ap entry).

  The `wireless.N.mac_acl.{status,policy}` keys are constant (`enabled`, `deny`, no MACs)
  in 11.1.50; the lists are only in `macacl`.
- **Failover.** When the locked AP goes offline (or comes back), the controller re-provisions
  all APs of the site without (or with) the entries (`al.aoUDgXMlCqEvTSIrOtq`: "Device[..]
  changed state .. provisioning all Access Points"). A removed AP has its locks cleared.

So enforcement is entirely "deny the client on every AP but the locked one", and the AP never
needs to know which AP the client is locked to.

## What the agent does

- `translate.wlanMACFilter` -> `macACL` reads the `macacl` section per VAP devname into
  `WLANIntent.MACFilter` (policy, MACs; `type` is ignored: user and lock2ap entries are
  enforced alike). This existed before; `internal/translate/lockap_test.go` pins the
  controller's exact rendering.
- `bcmwifi.computeACL` merges the SSID filter with the block list (`SetBlocked`), so a
  lock2ap deny entry lands in the BSS's hostapd deny list (`/tmp/udeco/wlNx.deny`, live
  `DENY_ACL`) and the driver MAC filter (`wl macmode 1` + `wl mac`), and an allow-list
  removal in hostapd's accept list and `wl macmode 2`.
- **New: live ACL update** (`internal/bcmwifi/acllive.go`). Before, any change of the lists
  rewrote the ACL files and `drv-wlN.json`, and `planRadio` reconciled the radio in full:
  hostapd restarted and every client of every SSID on the radio was dropped, on every AP of
  the site, at each lock change. Now, when the hostapd conf is unchanged and the stored
  driver state differs only in the station ACLs, the radio is updated in place:
  1. the driver MAC filter (planRadio's `macDrift`, without the false "not set by the
     agent" line);
  2. the ACL files and `drv-wlN.json`;
  3. hostapd's lists by difference: `hostapd_cli -p /var/run/udeco-hostapd -i <vif>
     ACCEPT_ACL ADD_MAC`, `DENY_ACL ADD_MAC`, `ACCEPT_ACL DEL_MAC`, `DENY_ACL DEL_MAC`
     (never `CLEAR`). hostapd 2.9 disassociates a station it newly denies
     (`hostapd_disassoc_deny_mac`) or takes off an accept list, so a locked client still on
     this AP is sent away. Accept-list commands go only to a BSS whose conf loads the
     accept file: with RADIUS MAC authentication (`macaddr_acl=2`) an `ACCEPT_ACL` entry
     would admit the station without asking RADIUS;
  4. `fc flush --mac <client>` for each station whose access changed (audit R21).

  The hostapd_cli and flush steps are optional (the files hold the lists for the next
  hostapd start; the driver filter refuses the station meanwhile). Any other change
  (hidden SSID, deny <-> allow, which changes `macaddr_acl`, an unreadable
  `drv-wlN.json`, ...) still reconciles in full.
- **Block list coexistence.** Both paths compute the lists from the same union
  (`computeACL(ssid, blocked)`): unblocking a station that is locked elsewhere keeps it
  denied (`SetBlocked` -> `refreshACLs` diffs against the applied Desired, which has the
  filter), and unlocking a blocked station keeps it blocked (the plan's `driverFor` has the
  block list). Tested in `internal/bcmwifi/acllive_test.go`.

Verified on .205 (read-only, 2026-11-19): `/sbin/hostapd` is v2.9 with `DENY_ACL`,
`ACCEPT_ACL`, `ADD_MAC`, `DEL_MAC`, `hostapd_disassoc_deny_mac`,
`hostapd_disassoc_accept_mac`, `deny_mac_file`, `accept_mac_file`; `/sbin/hostapd_cli` has
the `deny_acl` / `accept_acl` commands.

### The Garage (platform jio-mtk, `internal/mtkwifi`)

The MediaTek drivers hold each BSS's list in memory only (`iwpriv <if> set
AccessPolicy=`, `ACLClearAll=1`, `ACLAddEntry=`; nothing in the profile), so
the agent writes them live, with no restart, and records what it wrote in
`/tmp/udeco/mtk-acl.json`. A driver reload the agent did not do (a module
swap, a crash) makes new netdevs with empty lists: on 2026-11-23 a locked
client joined the Garage's `ra0` after a manual 2.4 GHz module swap, because
the record still said the list was there. Each record now carries the
netdev's ifindex (sysfs) when it was written. A record whose netdev is up
with another index, or with none recorded (an older agent's file), counts
as unknown: a restarted agent plans the rewrite at once, and the running
agent's periodic tick rewrites the lists (outside a restart's settle time;
the agent's own restarts rewrite them anyway). `ifconfig down/up` keeps the
index. The drivers have no read-back the agent could use (`ACLShowAll`
only prints to the kernel log), so the index is the only check. Tested in
`TestLockToAP` (`internal/mtkwifi/mtkwifi_test.go`).

## Capability bit

`wifi_caps` bit 24 (0x1000000, `supportLockAp`): **takeover only**, like RF_SCAN. Observe
mode owns no Wi-Fi and applies no MAC filter, so a lock would not be enforced; a drop to
observe must clear the bit from the next inform. Note that the controller offers the
setting only when all APs claim it, so one Deco in observe mode hides it site-wide.

## Live test (when a second AP is adopted)

1. Two APs adopted (a Deco in takeover and any other AP claiming bit 24), one client.
2. Client settings -> Lock to AP -> the other AP. On the Deco: `cat /tmp/udeco/wl*2.deny`
   lists the client; `wl -i wl02 mac` lists it; the agent log shows `DENY_ACL ADD_MAC` and
   no `hostapd -B` (no restart); other clients stay associated.
3. The client, if it was on the Deco, is disassociated and joins the locked AP; it cannot
   rejoin the Deco (association refused).
4. Unlock: the entry goes (`DENY_ACL DEL_MAC`), no restart; the client may roam back.
5. Failover: power the locked AP off; the controller re-provisions the Deco without the
   entry within its provisioning cycle, and the client can join the Deco.
