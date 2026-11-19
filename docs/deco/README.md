# udeco: TP-Link Deco units as UniFi APs

udeco is one daemon that shows each TP-Link Deco unit to a UniFi Network controller as a UniFi AP. The controller then shows the units' status, Wi-Fi clients and traffic. Optionally, udeco also pushes the controller's Wi-Fi settings to the Decos.

It runs off-device, as one Docker container on the Unraid host 192.168.0.4 (`--network host`). It reads the Decos over the same TMP-over-SSH protocol the Deco app uses, and it only ever talks to the mesh master (192.168.0.241).

| Document | What it covers |
|---|---|
| [design.md](design.md) | How it works, and why |
| [deco-tmp-protocol.md](deco-tmp-protocol.md) | The Deco protocol |
| [open-questions.md](open-questions.md) | What has not been verified on a real X20 yet |

## What runs

| Part | Code | Job |
|---|---|---|
| Mesh | `internal/deco/mesh.go` | Holds the only SSH/TMP session, to the master. It polls the device list, client speeds (0x4014) and IoT clients (0x4040) every 15 s, Wi-Fi info every 60 s, port status every 5 min, the block list every 60 s and the slow client list (0x4012, names and last known placement) every 10 min, and caches the results. Every write goes through its queue. |
| Runners | `cmd/udeco/runner.go` | One per unit. Each informs the controller as its own AP (default model `U7PG2`) from the Mesh cache, and has its own SSH adoption port (22201, 22202, 22203). |
| Wi-Fi applier | `internal/deco/wlan.go` | Turns the controller's WLANs into Deco Wi-Fi Sets, with backup, verify and rollback. |
| Block reconciler | `cmd/udeco/blocks.go` | Mirrors the controller's blocked clients into the Deco block list. |

## Setup

### 1. Config

Copy `deploy/udeco.example.json` to `/mnt/osssd/appdata/unifi-deco/udeco.json`. It already lists the three units:

| Name | IP | MAC | `sshd_port` |
|---|---|---|---|
| deco-241 (master) | 192.168.0.241 | b0:a7:b9:3e:16:94 | 22201 |
| deco-205 | 192.168.0.205 | b0:a7:b9:3e:17:00 | 22202 |
| deco-232 | 192.168.0.232 | b0:a7:b9:3e:15:fc | 22203 |

| Key | Default | Meaning |
|---|---|---|
| `inform_url` | required | Controller inform URL. The host must be an IP. |
| `console_ip` | inform host | The only address allowed to SSH-adopt. |
| `daemon_ip` | local IP toward the controller | IP reported to the controller (192.168.0.4). |
| `tplink_id` | `TPLINK_EMAIL` | Exact stored TP-Link ID (casing matters: `md5(id)` must equal the master's TDP owner hash). |
| `mesh.master` | first unit | Master unit, by IP or MAC. |
| `mesh.host_key_sha256` | trust on first use | Pins the master's SSH host key. Without it the first key seen is saved to `master_host_key`. |
| `units[]` | required | `name`, `ip`, `mac`, `sshd_port` (default 22201 + index). |
| `model` | `U7PG2` | UniFi model presented. |
| `wifi_caps` | 0 | Capability bitmap; 131072 claims WPA3. |
| `apply` | `false` | Write to the Decos. Off means plans are only logged. |
| `report_ip` | `daemon` | `deco` reports the Deco's own IP after adoption (untested). |
| `on_remove` | `stop` | After the controller forgets a unit, either stop its runner (`stop`) or show it as pending again (`pending`). |
| `poll` | `15s` | Device list, client speed and IoT client poll interval (minimum 5 s). |
| `clients_every` | `10m` | 0x4012 client-list interval (minimum 10 min): names, client types, last known access Deco and band. Slow (62 s live); never on the inform path. |
| `no_client_list` | `false` | Never read 0x4012. Stations are then placed only by 0x4040 entries. |
| `inform_interval` | controller's | Inform at least this often. |
| `hide_wired` | `false` | Leave wired clients out of the port tables. |
| `state_dir` | config file's directory | Where state lives (`/data` in the container). |

Unknown keys are an error. A `password` key is refused: the password never goes in the JSON.

### 2. Credentials

udeco needs the **owner's** TP-Link ID and its password. It looks for them in this order:

| What | Where it looks, in order |
|---|---|
| TP-Link ID | config `tplink_id`, `$TPLINK_EMAIL`, `TPLINK_EMAIL` in the env file |
| Password | `$TPLINK_PASSWORD`, then the file named by `$TPLINK_PASSWORD_FILE` (or `$UDECO_TPLINK_PASSWORD_FILE`), config `password_file`, `TPLINK_PASSWORD_FILE` in the env file, then `TPLINK_PASSWORD` in the env file |

The env file is `credentials_file`, by default `<state_dir>/credentials.env`, which is `/data/credentials.env` in the container:

```sh
# /mnt/osssd/appdata/unifi-deco/credentials.env  (chown 99:100, chmod 600)
TPLINK_EMAIL=owner@example.com
TPLINK_PASSWORD='the TP-Link password'
```

- It accepts `KEY=VALUE` lines, `#` comments, an optional `export`, and single or double quotes.
- udeco warns when a credentials file is readable by group or others.

### 3. Check offline first

Before any login, check the TP-Link ID against the owner hash (open question 1). This sends nothing to the Decos:

```sh
python3 -c 'import hashlib,sys; print(hashlib.md5(sys.argv[1].encode()).hexdigest())' 'owner@example.com'
# must equal the master's TDP owner hash; try the casing variants here, not against the Deco
```

### 4. Deploy

`deploy/unraid.sh` copies the source to the Unraid host over ssh (`UNRAID_HOST`, default `root@192.168.0.4`) and builds `udeco:latest` there. The container runs as 99:100 with `/mnt/osssd/appdata/unifi-deco` mounted at `/data`.

```sh
deploy/unraid.sh build      # build the image on the host
deploy/unraid.sh discover   # TDP only: no login
deploy/unraid.sh print      # ONE SSH login, read-only, JSON on stdout
deploy/unraid.sh run        # build and start the daemon (--network host --restart unless-stopped)
deploy/unraid.sh logs
deploy/unraid.sh stop
```

The equivalent `docker run` command is:

```sh
docker run -d --name udeco --restart unless-stopped --network host --user 99:100 \
  -v /mnt/osssd/appdata/unifi-deco:/data udeco:latest -config /data/udeco.json
```

### 5. Firewall

| From | To | Port | Why |
|---|---|---|---|
| daemon (192.168.0.4) | UCG 192.168.0.1 | TCP 8080 | Informs. Nothing listens on 8080 locally. |
| UCG 192.168.0.1 | 192.168.0.4 | TCP 22201-22203 | SSH adoption. |
| daemon | master 192.168.0.241 | TCP 20001 | SSH. |
| daemon | all units | UDP 20002 | TDP discovery. |

Never give the container a Deco's MAC on a macvlan: that causes an ARP conflict with the real unit.

### 6. Adopt

The three units show up in UniFi as pending U7PG2 APs, all with the daemon's IP. Adopt them one at a time. The controller SSHes to `192.168.0.4:<sshd_port>`, and udeco accepts only `console_ip`.

## Safety

| Rule | What udeco does |
|---|---|
| Owner check before every login | TDP must show exactly one master: the configured IP, MAC and device_id, not factory-default, SSH (not TLS or TPS). Its owner hash must equal `md5(tplink_id)`, and an empty hash is refused. A refusal at startup stops the daemon; at runtime it latches logins off. |
| One password attempt per login | Logins are at least 60 s apart, backing off 1, 2, 4, 8 then 15 min. A session that lasts 10 min resets the backoff. |
| Auth latch | A rejected password, a BYE "auth changed" (8), or a host-key mismatch stops all further logins **until the process restarts** (TP-Link lockout protection). Runners stop informing after the master session has been down for 120 s. |
| BYE back-off | 10 min for reasons 3 and 7 (the app may hold the session); 3 min for 4 and 6 (reboot or upgrade). |
| Secrets | The TP-Link password lives only in a `deco.Secret`, which prints and marshals as `[redacted]`. The TP-Link ID is never logged. Wi-Fi passphrases are masked in logs (`***` or a short hash) and in `-print`. `TPLINK_PASSWORD` is removed from the environment at start. |
| apply=false by default | Wi-Fi Sets, block and unblock, and reboot are planned and logged as `apply=false, would send ...`. Nothing is written. |
| Firmware | Controller upgrades are answered but never downloaded or applied. |
| Unsupported | Locate, LED, kick, scans and guest portal authorisation are logged and ignored. |

## Apply workflow

Each step needs the previous one to look right. See design.md §10.

1. **`deploy/unraid.sh discover`.**
   - Every unit answers.
   - `owner_matches` is true.
   - `precheck` is `ok`.
2. **`deploy/unraid.sh print`** (one SSH login). Check:
   - `result: ok` and `operation_mode` (should be `AP`);
   - the MAC format in `device_list`;
   - `live`: who is connected now (`clients[].seen`), and where (`device_id`, `link`, `placed_by`); `placed`/`unplaced` counts;
   - each unit's snapshot (radios, stations; `snapshot_source` is `skeleton` when device_list was not read).

   `-only` takes `devices,speeds,iot,wireless,ports,blocks,clients` or opcodes.

   This settles open questions 1-5 and 7-11.
3. **Run with `apply: false`.** Adopt deco-241 first, then the satellites. Over 24 h, check:
   - clients, uptime and radios render in UniFi;
   - the Deco app still works alongside udeco;
   - the logs show no BYE or redial storms.
4. **Read the planned writes in the log.**
   - `deco wlan [deco-241]: plan from system_cfg (apply=false: log only)` shows what would change on the Decos, with passphrases masked.
   - `blocks: apply=false: block [...] not sent` shows block changes.
5. **Set `"apply": true`** and restart (`deploy/unraid.sh run`). Change the **guest** SSID in UniFi first, and watch the log:
   - the backup `/data/backups/wireless-<ts>.json`;
   - the host Set, then the guest Set;
   - the verify, which needs the new Wi-Fi info and every unit back within 3 min.
6. **Then change the main network.**

What the Wi-Fi applier does:

| Step | Behaviour |
|---|---|
| Debounce | Waits 10 s for UniFi's changes to settle. |
| Re-plan | Plans again against a fresh Wi-Fi info read. |
| Backup | Writes a backup (mode 0600), and refuses to apply if that fails. |
| Rate limit | At most one apply per 5 min. |
| Rollback | A failed Set or a failed verify rolls back from the backup: resent every 30 s for up to 30 min. After any rollback, Wi-Fi apply stays off until restart. |
| Not applied | Open, WEP and enterprise networks, per-AP radio settings, and extra UniFi features are logged as not applied. |

Only the master's runner (deco-241) may submit Wi-Fi changes, and the satellites log the same plan. Only MACs that udeco blocked are ever unblocked; it records them in `/data/blocks.json`.

## State (`/data`)

| Path | Contents |
|---|---|
| `udeco.json`, `credentials.env` | Config and credentials |
| `master_host_key` | First-use SSH fingerprint of the master (when not pinned) |
| `units/<mac without colons>/` (mode 0700) | `state.json` (adoption key, mode 0600), `system_cfg.txt` and `system_cfg.history/` (hold Wi-Fi PSKs, mode 0600), SSH-adopt host keys, `unhandled.json` |
| `backups/wireless-<ts>.json` | Wi-Fi info before each apply (holds PSKs, mode 0600) |
| `blocks.json` | Client MACs udeco itself blocked |

To re-adopt a unit from scratch, forget it in UniFi, stop the container, and delete `units/<mac without colons>/state.json`.

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `refusing to log in: TDP owner hash does not match` | `tplink_id` is not the owner's exact stored ID. Fix the casing offline (Setup, step 3). Do not retry against the Deco. |
| `LATCHED OFF ... SSH login rejected` | Wrong password, or the account is locked. **Do not restart in a loop**: each restart costs one attempt. Fix the credentials, wait, then restart once. |
| `LATCHED OFF ... master host key ... is not the pinned one` | The master's key changed (factory reset, or a different device). Verify it, then fix `host_key_sha256` or delete `master_host_key`. |
| `operation_mode is "Router", not AP` | The mesh NATs its clients, so they will not match UniFi's client table. Switch the Decos to Access Point mode. |
| A unit stays pending or disconnected | Check that UDP and TCP reach the right ports (Firewall table). Look for `not informing:` lines: `master session down`, `unit offline` (after 60 s grace), or `refused: <mac> is not in the mesh device_list` (wrong MAC in the config). |
| `HTTP 404 while adopted (forgotten?)` | The unit was removed in UniFi. With `on_remove: stop` the runner stops on `setdefault`. Restart the container to show it as pending again. |
| Clients missing on a satellite | The Deco must report `linked_device_info` per client (open question 10). Run `-print` and look at `mesh.clients`. |
| `opcode 0x.... disabled for this session` | The firmware rejects that read three times in a row. The rest keeps working; port status and the block list are optional. |
| BYE 3 or 7 in the logs | The Deco app holds the session. udeco waits 10 min before logging in again. |

Logs never contain the password, the TP-Link ID or passphrases. Before sharing a `-print` dump, check whether you want to share client names and MACs: those are not removed.

## Development

```sh
go vet ./... && go test -race ./...
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build ./cmd/udeco
```

`cmd/udeco` has an end-to-end test that runs nothing but in-process fakes. It runs the whole daemon against two of them:

- an in-process Deco master: a real SSH server on 127.0.0.1, TMP and business V2, three units;
- a fake UniFi controller: `/inform` decrypts with the default key, adopts with `setparam mgmt_cfg authkey`, then requires the new key.

Set `UDECO_TEST_LOGS=1` to see the daemon's log.
