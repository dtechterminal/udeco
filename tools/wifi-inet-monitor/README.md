# Wi-Fi client internet monitor (runs on the UCG)

`wifi-inet-monitor.py` runs every 2 minutes on the gateway from a systemd
timer that `30-wifi-inet-monitor.sh` (in `/data/on_boot.d`) recreates at
boot. It reads the controller's wireless clients and the gateway's
conntrack and neighbour tables, and classifies each client:

| Status | Meaning |
|---|---|
| ok | a new internet connection since the last run got a reply |
| idle | no new internet connections; answers ping |
| unreachable | no new connections, no ping reply (sleeping phones); reported only |
| no_internet | new internet connections, none replied |
| no_ip | associated 5+ min with no IPv4 (controller or neighbour table) |
| blocked | source of an enabled BLOCK policy with "internet" in its name; expected |

Fixes, never during a WAN outage (the gateway can't reach 1.1.1.1/8.8.8.8/9.9.9.9,
or half the active clients fail at once):

- a client in no_internet/no_ip for 3 runs that worked in the last 24 h gets a
  UniFi reconnect (kick-sta), at most hourly per client, 5 per run;
- a Deco (b0:a7:b9) disconnected from the controller for 10+ min gets a UniFi
  restart, at most hourly.

Files on the gateway: `/data/wifi-inet-monitor/{wifi-inet-monitor.py,
state.json, last.json, monitor.log}`. The summary goes to MQTT
(192.168.0.4:1883, `wifi_inet_monitor/state`) with Home Assistant discovery
(sensors "Wi-Fi clients without internet" and "Wi-Fi clients with internet").
`--dry-run` reports without fixing. Remove: `systemctl disable --now
wifi-inet-monitor.timer; rm /data/on_boot.d/30-wifi-inet-monitor.sh`.
