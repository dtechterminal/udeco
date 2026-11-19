# Persistent install on a Deco X20

Files on each unit (`/tp_data` is flash):

- `/tp_data/udeco/udeco-ap.gz`: the agent, `gzip -9` (about 4 MB; the
  10 MB binary would nearly fill `/tp_data`). `start.sh` unpacks it to RAM.
- `/tp_data/udeco/udeco-ap.json`: config (inform URL, model UAL6, takeover,
  apply, egress, wpa3, `driver_country`).
- `/tp_data/udeco/session/`, `state/`: adoption state and last-good Wi-Fi
  config (written by the agent; secrets, 0600).
- `/tp_data/udeco/start.sh`: this directory's `start.sh`.

One line at the end of `/data/persist_shell.sh` (cron, every minute):

    [ -f /tp_data/udeco/start.sh ] && sh /tp_data/udeco/start.sh

After a reboot the unit is stock TP-Link until the agent's boot gate opens
(at least 120 s, TP-Link's boot finished), then UniFi takes over: about 3
minutes in all (UniFi Restart tested on all three units, 2026-11-19).

Undo: `rm /tp_data/udeco/start.sh` and reboot (stock TP-Link Wi-Fi).
