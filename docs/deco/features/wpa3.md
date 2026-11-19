# WPA3 (SAE): radio_caps2 and the `wpa3` config key

## What the controller does

Network 10.6.109 (`ubntconf.qemBJTmR`, the per-device WLAN filter) keeps WPA3 on
a radio only when that radio's `radio_caps2` has 0x1 (agent-design §3.8). Without
it a WPA2/WPA3 transition WLAN reaches the AP as WPA2 only (`wpa.key.1.mgmt=WPA-PSK`,
no `wpa3.*` keys) and a WPA3-only WLAN is not sent at all ("SAE cannot provision").
wifi_caps WPA3 (bit 17) alone is not enough.

## What the agent does

- Config key `wpa3` (bool, **default false**, takeover only: observe mode serves no
  Wi-Fi of its own; validation refuses it without `takeover`).
- `wpa3=false`: `radio_caps2` is 0 on both radios (as before 2026-11-19), so the
  controller sends no SAE. Should a WPA2/WPA3 SSID arrive anyway (a cached
  system_cfg), bcmwifi serves it as WPA2 (`Options.WPA3` off: `withoutSAE`,
  `internal/bcmwifi/wpa3.go`) and a WPA3-only SSID is not served; the plan notes
  say so. WPA3-Enterprise is EAP, not SAE, and is not affected.
- `wpa3=true` (takeover): `radio_caps2 0x1` on both radios
  (`models.DecoAgentFeatures.WPA3`) and bcmwifi serves SAE: `wpa_key_mgmt=SAE`
  (WPA3) or `WPA-PSK FT-PSK SAE` (transition with 802.11r), `ieee80211w`,
  `sae_require_mfp`. A drop to observe mode clears the bit from the next inform.
- `radio_caps2 0x2` (WPA3 fast roaming, FT-SAE) is claimed with `wpa3` unless the
  config key `ft_sae` is false (default on with `wpa3`; `ft_sae: true` without `wpa3`
  is refused). The agents learn each other's key holders and list them explicitly,
  because hostapd 2.9 cannot use UniFi's wildcard ones; cross-band roams on one unit
  stay a full SAE (per-band mobility domain). docs/deco/features/ft-sae.md.
- The controller re-provisions on the next settings change, not on a capability
  word change alone (§3.6).

## Live test (before turning it on by default)

On .205 in takeover with `"wpa3": true`:

1. The inform's `radio_table[].radio_caps2` is 1; after a settings change the
   system_cfg of the transition WLAN has `wpa3_support`/`wpa3.*` keys.
2. `hostapd_cli -p /var/run/udeco-hostapd -i wl12 get_config` shows
   `key_mgmt=WPA-PSK FT-PSK SAE`; a WPA3 client (Android 10+, iOS 13+) joins with
   SAE (`hostapd_cli ... sta <mac>` shows `AKMSuiteSelector=000fac-8`) and a
   WPA2-only client still joins.
3. The Broadcom driver passes the SAE authentication frames to hostapd (the
   driver does 802.11 auth itself for open/PSK: watch `logread` for
   `SAE: ... commit` lines; a refusal there is the failure to look for).
4. A WPA3-only WLAN comes up and a WPA3 client roams between the two radios.

If 3 fails, leave `wpa3` off: the controller then keeps every WLAN WPA2.
