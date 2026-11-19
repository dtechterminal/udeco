# Deco X20 V2: what the platform offers the agent

Probed on 192.168.0.205 on 2026-11-18 (kernel 4.1.52, all three units are identical hardware).
The ebtables and tc results come from rules that were added and then removed. They matched only a nonexistent
interface or ran on unused interfaces (`ifb0`, the down primary `wl0`).

## Bridge firewall (guest isolation)

- `ebtables` filter, nat and broute tables are present (built-in; no ebt `.ko` files).
- Work: `-p IPv4 --ip-src/--ip-dst/--ip-proto/--ip-dport`, `-p IPv6 --ip6-dst`, `-s/-d` MAC, `--mark`,
  `-j mark --mark-set`, broute `-j DROP`.
- Missing: `--arp-*`, `--among-*`, `--pkttype-type`, `--limit`, `--log`, and the `redirect` and `dnat` targets.
- No `br_netfilter` (`/proc/sys/net/bridge` is absent), so iptables never sees bridged frames.
- No `ipset` binary and no `nft`.
- Consequences:
  - Guest-to-LAN blocking and cross-AP guest isolation (allow only the gateway MAC) are buildable with plain ebtables
    IP/MAC rules. Authorised-guest lists become per-MAC rules in a chain, since `among` is missing.
  - An AP-side captive-portal redirect is **not** directly possible. ebtables has no redirect/dnat target, and a
    brouted frame keeps the gateway's destination MAC, so the IP stack drops it. The options are a gateway-side
    portal, or building `ebt_redirect`/`ebt_dnat` for this exact vendor kernel (needs a matching vermagic).
- iptables nat `REDIRECT` works for traffic addressed to the AP itself.

## Traffic control (per-client rate limits)

- `tc` is iproute2-ss3.3.0. `ifb0` and `ifb1` exist (both down).
- Work: `htb` root and class, `sfq` leaf, `u32` classifying on IP and on Ethernet source MAC, `ingress` qdisc,
  `action mirred egress redirect dev ifb0`, and `police`.
- So per-client download (htb on the VAP) and upload (ingress, then mirred to ifb, then htb) limits are buildable.
- TP-Link already runs `htb 2:` with an `sfq 202` default on `br-lan` (its own QoS). Leave it, or remove it in takeover.

## Rates

- Rate sets are per BSS: `wl -i wl02 rateset` answers.
- Current 2.4 GHz basic rates are 1, 2, 5.5 and 11, so beacons go out at 1 Mbps.
- 5 GHz basic rates are 6 and 24 on wl1, and 6, 12 and 24 on wl12.
- `wl rateset` also sets values. Setting per-BSS minimum and basic rates is untested (it may need the BSS down).
- `mrate`, `2g_rate` and `5g_rate` exist. `bcnprd` is unsupported.

## Other

- `hostapd_cli` has `deny_acl`, `accept_acl`, `deauthenticate`, `disassociate`, `bss_tm_req` and `raw`.
  So block/unblock via the hostapd ACL works, and 802.11v steering requests are possible.
- LED: ubus `leds` has `conn`, `power`, `off`, `switch`, ... each taking `{state, delay_on, delay_off}`.
  sysfs has `blue`, `green`, `red` and `colorful`, so the LED is RGB.
- No Broadcom band-steering daemon (`bsd`/`wbd`). Band steering would have to be our own (via `bss_tm_req`).
- `crontab` and `ntpd` are present (WLAN schedules).
- TP-Link's own `br-guest` and `br-iptv` bridges exist.
