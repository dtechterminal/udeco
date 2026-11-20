# Persistent install on a Deco X20

`deploy/deco-ap.sh <unit-ip>` makes this install; `deploy/deco-ap.sh --help`
lists its steps, the checks it makes first and the sizes it goes by. This
directory holds no file of its own: the launcher is the `LAUNCH` template
in that script.

Files on each unit (`/tp_data` is flash):

- `/tp_data/udeco/udeco-ap` or `/tp_data/udeco/udeco-ap.gz`: the agent. A
  small enough binary ships as it is. A larger one ships as its `gzip -9`
  copy, to leave `/tp_data` room.
- `/tp_data/udeco/udeco-ap.md5`: the md5 of the agent's binary.
- `/tp_data/udeco/start.sh`: the launcher, written again by every deploy,
  for either form of the agent. It does nothing while an agent runs.
  Otherwise it removes a login lock left behind, unpacks a gzipped agent
  to RAM (`/tmp/udeco-bin`) unless the copy there has that md5, checks the
  md5, and starts the agent with its log in `/tmp/udeco-bin/agent.log`.
- `/tp_data/udeco/udeco-ap.json`: config (inform URL, model UAL6, takeover,
  apply, egress, wpa3, `driver_country`). The script writes one in observe
  mode when the unit has none and never changes one that is there.
- `/tp_data/udeco/session/`, `state/`: adoption state and last-good Wi-Fi
  config (written by the agent; secrets, 0600).

One line in `/data/persist_shell.sh` runs the launcher (cron, every minute,
and the firewall include at boot). The script prints the exact line, which
ends in the marker it finds the line by again, and leaves the file alone;
with `--edit-persist` it writes the line itself.

After a reboot the unit is stock TP-Link until the agent's boot gate opens
(at least 120 s, TP-Link's boot finished), then UniFi takes over: about 3
minutes in all (UniFi Restart tested on all three units, 2026-11-19).

Undo: `rm /tp_data/udeco/start.sh` and reboot (stock TP-Link Wi-Fi). The
script also prints one rollback command, which drops the line from
`/data/persist_shell.sh` as well.
