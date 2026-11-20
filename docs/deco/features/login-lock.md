# Login lock: root logins closed while the controller is healthy (2026-11-20)

## Why

The units' own root logins are reachable from the whole LAN: the Deco
master's dropbear on tcp :22 takes passwords, and the Garage's telnetd on
:23 sends the root password in clear text. A UniFi AP closes its SSH to
the LAN when the site's **Device SSH Authentication** is off. The login
lock does the same while UniFi manages the unit, and opens again when the
controller goes away, so the owner can always get in.

## When it is locked

LOCKED exactly when all of these hold. Anything else is OPEN.

| Condition | Source |
| --- | --- |
| Takeover with `"apply": true`, and `"login_lock"` is not `false` | config, the agent's mode (a hand-back to TP-Link means observe mode) |
| The unit is adopted | the session state |
| The saved `system_cfg` has an `sshd` section and Device SSH is off in it | `translate.SSHD(...).LANLogins()` is false: `sshd.status=disabled`, or only `lo` listeners, or no password and no key |
| The controller's last reply that counts is under `login_lock_failopen_s` old (600 s) | `informOnce`, see below |

OPEN when there is no `sshd` section, Device SSH is on, the unit is not
adopted, the agent observes (configured, forced or after a hand-back),
no reply has counted since the agent started, or the controller has been
silent for the whole window (fail-open).

### Which replies count

Inform is plain HTTP, so someone on the path can answer in the
controller's place. A reply counts as the controller answering only when
all of these hold (`lockReply`):

- It decoded with the device key and is encrypted (an unencrypted reply
  is refused).
- The agent then handled it (`device.Session.Handle` accepted it). A CBC
  frame has no authentication: about 1 random frame in 256 passes the
  padding check and "decodes", but random bytes are never a reply the
  agent can handle.
- Its `server_time_in_utc` is later than that of every reply counted
  before in this run. The real controller puts its time in every reply.
  A sealed reply sent again (a replay) carries its old time, so it does
  not keep the controller "answering" after the controller has died.
  A reply without the field never counts.

A Device SSH change that arrives with a reply that does not count is not
taken: the lock keeps the view it had, and the log says
"a Device SSH change from a reply that is not newer than the last one ...
is not taken". A replay of an old Device SSH on therefore does not open
the lock. The rest of what such a reply carries is handled as before
(see Residual risks).

The decision is in `cmd/udeco-ap/loginlock.go` (`lockDecision`). The 10th
minute of silence opens it: 9 min 59 s after the last reply is still
locked, 10 min is open.

## What is dropped

Chain `UDECO-LOCK`, in IPv4 (`iptables`) and IPv6 (`ip6tables`), jumped
first from `INPUT` while locked. It drops new TCP connections to the root
login ports from every source except the loopback:

```
-A INPUT -j UDECO-LOCK                      (inserted at position 1)
-A UDECO-LOCK -i lo -j RETURN
-A UDECO-LOCK -m conntrack --ctstate ESTABLISHED -j RETURN
-A UDECO-LOCK -p tcp -m tcp --dport 22 -j DROP     (Deco)
-A UDECO-LOCK -p tcp -m tcp --dport 23 -j DROP     (Garage)
-A UDECO-LOCK -p tcp -m tcp --dport 22 -j DROP     (Garage)
```

- **Established sessions are kept.** A session open before the lock
  carries on: its packets RETURN before the DROP. Only ESTABLISHED
  RETURNs, not RELATED: an open session needs nothing more, and RELATED
  would let in a new connection to a login port that a conntrack helper
  expects (an FTP helper fed a PASV reply naming the unit's :23, say).
- **RETURN, not ACCEPT.** A RETURNed packet goes on through the rest of
  `INPUT`, so the lock adds drops and nothing else. On the Deco, the
  inbound fence `UDECO-IN` (sitting right behind the lock) still drops
  TP-Link's management ports for established sessions as before. Its
  rules are not changed: :22 from the LAN, :2222 from the console, and
  the TP-Link ports stay as `docs/deco/agent-design.md` R5 has them.
- **The Deco** (`internal/decosys/loginlock.go`) runs
  `/usr/sbin/iptables -w ...` under the decosys lock. `UDECO-IN` leaves
  `UDECO-LOCK` ahead of it, so the two jumps never move each other.
- **The Garage** (`internal/jiosys/loginlock.go`) runs
  `/pfrm2.0/bin/iptables` and `ip6tables` without `-w` (not known to be
  supported there). The jump goes ahead of Jio's own
  `--dport 23 -m ifgroup --src-group 0x1/0x1 -j ACCEPT`.
- **Idempotent.** A lock in place costs two reads per family
  (`-S UDECO-LOCK`, `-S INPUT`). A chain whose rules differ is flushed and
  refilled. A jump that is missing, not first, or duplicated is inserted
  at 1 before the stale copies are deleted, so the lock is never unhooked.
  A lock that had to be put back is logged.
- **Unlock** removes every `-j UDECO-LOCK` from `INPUT`, then runs
  `-F UDECO-LOCK` and `-X UDECO-LOCK`.

## Who acts

- **The loop**, after every inform: it acts only when the decision
  changed. A switch from UniFi takes effect at the inform that brings the
  new `system_cfg`. The fail-open lands within one inform interval of the
  window, and the failed informs back off to at most 1 min.
- **The tick** (every 60 s in takeover) re-asserts a lock in place:
  rules can be lost.
- **The agent's stop** (SIGTERM; `run` as soon as the inform loop has
  ended, before it waits for the background jobs) removes it, with its
  own 10 s context. From then on nothing locks again, not even a tick
  still running (`lockStop`). Released before the wait because a job
  that hangs would otherwise keep the lock with nothing left to fail it
  open: the process is alive, so no launcher steps in.
- **The hand-back to TP-Link** (`dropToObserve`) removes it before
  `Restore`. Both `decosys.Restore` and `jiosys.Restore` remove it too.
- **The first look** after the start removes any leftover, in case the
  launcher could not.

Each transition is one event in `events.log`, with the reason:

```
LOGIN LOCKED: Device SSH off and controller answering
LOGIN OPEN: Device SSH on
LOGIN OPEN: controller silent 10m
LOGIN OPEN: not adopted
LOGIN OPEN: observe mode
LOGIN OPEN: agent stop
LOGIN OPEN: hand-back
LOGIN OPEN: lock failed: <error>
```

Nothing secret is logged: the reasons, iptables errors and ports only.

## Fail-open

- **Install.** The chain is built in full, loopback and established
  RETURNs first, before its jump goes in. Any error in either family
  takes the lock out of both families again and is logged once ("the
  unit stays open"). The next tick tries again.
- **No iptables on the unit:** no lock. If only `ip6tables` is missing,
  the IPv4 lock is installed alone.
- **A removal that fails** is retried at every look of the loop until it
  works.
- **A failed re-assert of a lock in place** counts as open:
  `LOGIN OPEN: lock failed`.
- **An error before any change** (a read that fails, say because another
  process holds the xtables lock while the Garage runs iptables without
  `-w`, and `-N` then finds the chain there) leaves the unit exactly as
  it was (`decosys.ErrLockUnchanged`): a complete lock stays, nothing is
  removed, no event, and the next tick checks again. Taking a complete
  lock down over a failed read would open it for nothing, and anyone who
  could make another process churn iptables could keep it open.

## Crash safety (launchers)

The agent only removes the lock on its way out when it gets SIGTERM.
Before every (re)start of the agent, both launchers remove the lock
themselves (busybox sh, errors ignored):

- **The Deco**: the launcher `/tp_data/udeco/start.sh` is written by
  `deploy/deco-ap.sh` (the `LAUNCH` template). It removes the lock right
  after its check that no agent runs (never while one runs), before
  anything that can end the run without a start (a missing binary, a gz
  that does not unpack to the deployed md5).
- **The Garage**: `deploy/jio-start.sh`, `unlock` as the first statement
  of the supervisor loop, so a gunzip that fails and retries every
  minute still removes it. `UDECO_IPT` overrides the default
  `/pfrm2.0/bin`.

```sh
for T in iptables ip6tables; do
	for i in 1 2 3; do $T -w -D INPUT -j UDECO-LOCK 2>/dev/null || break; done
	$T -w -F UDECO-LOCK 2>/dev/null
	$T -w -X UDECO-LOCK 2>/dev/null
done
```

On the Garage the same lines run without `-w`, with
`/pfrm2.0/bin/iptables` and `ip6tables`.

A reboot clears iptables on both platforms (nothing persists), and the
agent always starts OPEN: it locks only after a reply has counted.

`deploy/jio-ap.sh` replaces only the agent, not
`/flash2/udeco/start.sh`. Until the Garage's `start.sh` is replaced by
hand with the new `deploy/jio-start.sh`, a SIGKILLed agent's lock stays
until the next reboot. To replace it: copy the new file to
`/flash2/udeco/start.sh.new`, then `mv` it over `start.sh`. The running
loop keeps the old inode, and the new loop takes over at the next reboot.

## Config

| Key | Default | |
| --- | --- | --- |
| `login_lock` | on for takeover with apply, both platforms | `false` never locks. `true` without takeover and apply is a config error. |
| `login_lock_failopen_s` | 600 | How long the controller may be silent before the lock opens (60-3600). It needs the lock on. |

## Deploying while locked

`deploy/deco-ap.sh` (ssh to :22) and `deploy/jio-ap.sh` (telnet to :23)
print this when the port refuses or times out:

```
login lock: turn on Device SSH in UniFi (Settings > System > Advanced > Device SSH Authentication), wait ~1 min, retry
```

1. In UniFi, turn on Settings > System > Advanced > Device SSH
   Authentication.
2. Wait for the next config push to reach the unit (within about a
   minute; `LOGIN OPEN: Device SSH on` in `events.log`).
3. Deploy.
4. Turn Device SSH Authentication off again. The unit locks at the inform
   that brings the change (`LOGIN LOCKED: ...`).

Neither script ever changes the controller's setting itself. A session
already open when the lock comes back stays open.

Device SSH on also turns on the site users' SSH logins on the agent's
port 2222 (`cmd/udeco-ap/sitessh.go`), as on a UniFi AP.

## Residual risks

- **Blocked controller traffic.** An attacker who can block the
  controller's traffic to the unit for the whole window (10 min) makes the
  lock fail open. They still need the root credential: the Deco's
  dropbear password, or the Garage's telnet password, which crosses the
  LAN in clear text whenever someone logs in.
- **A dead agent and a dead launcher.** If the agent is SIGKILLed (or
  crashes) and its launcher is dead too, the lock stays until the next
  reboot. The Deco's cron hook runs the launcher every minute, and the
  Garage's gateway guard restarts the supervisor loop. With both gone,
  the way back in is a power cycle (UniFi's Restart needs a running
  agent).
- **Replayed replies.** A replay cannot keep the controller "answering"
  or change the lock's view of Device SSH (see Which replies count), but
  it is otherwise handled like any reply, as before the lock existed: an
  old `system_cfg` is saved and applied (and the site users' :2222 logins
  follow its Device SSH) until the controller provisions its current
  `cfgversion` again. Limits of the time check: the first reply after the
  agent starts has nothing to compare with, so a replay sent right then
  counts (and its Device SSH view is taken); a sealed reply that an
  attacker held back and never let through counts once when it is
  finally sent, which can stretch the fail-open by about as long as
  replies were held back (the unit was open while they were). If the
  controller's clock steps back, its replies stop counting until it has
  passed the last time seen (or the agent restarts): the lock fails open
  meanwhile.
- **Other ports.** Only :22 (and the Garage's :23) are locked. The agent's
  own :2222 is fenced to the console and the site users already
  (`UDECO-IN`, Deco). TP-Link's :20001 is dropped by `UDECO-IN`.

## Unverified on hardware

This list is the note's state on its date (2026-11-20), before the lock ran
on a unit. The current status is the "Login lock" row of the
[README](../../../README.md), which has the live run of the same day and
names what is still open; where the two differ, the row is right.

Built and tested against fake runners. Not seen on a unit when this was
written:

- the rules on the units' kernels: `-m conntrack` on the Garage (its
  `INPUT` has an ESTABLISHED rule, but which match it uses is not known; a
  failed append leaves the Garage open and logs why), and `ip6tables`
  with conntrack on both platforms;
- that `-S UDECO-LOCK` lists the rules in the form compared against (a
  mismatch would refill the chain every tick: the log shows "had to be put
  back");
- an open dropbear or telnet session surviving the lock;
- the Deco launcher's and the Garage loop's removal on the real busybox;
- `/pfrm2.0/bin/iptables` without `-w` while nothing else holds the
  xtables lock;
- the timing of Device SSH on reaching the unit (expected within one
  inform).
