#!/bin/sh
# udeco-ap (UniFi agent) on the Garage AP, a JioFiber JCOW414 used as a
# UAP-AC-Lite. Started at boot by one line in /flash2/pfrm2.0/etc/customInit
# (backup: customInit.pre-udeco next to it). This loop restarts the agent if
# it exits. Turn it off: rm /flash2/udeco/start.sh, then reboot (the unit's
# own Wi-Fi comes back) or kill $(cat /tmp/udeco-bin/agent.pid).
#
# "start.sh guard" is the gateway guard, started from here. Every 10 s it
# pings the gateway. Thresholds and the gateway can be overridden in
# $D/guard.conf (shell syntax):
#   - Restarts this supervisor when nothing holds its lock (no agent and no
#     loop running).
#   - Gateway silent for ROLLBACK_AFTER s: if the running agent build is not
#     the confirmed one ($D/good.md5) and udeco-ap.gz.prev is, swaps .prev back
#     in (the failed build is kept as .bad) and restarts the agent. A
#     udeco-ap.json.prev (the config the .prev build ran with) is swapped back
#     with it, as the older build may refuse the new config (kept as
#     udeco-ap.json.bad); install it with the .prev build when a deploy
#     changes the config.
#   - Gateway silent for REBOOT_AFTER s, and the unit up for at least
#     MIN_UPTIME s: reboots. On the second guard reboot in a row it writes
#     $D/force-observe first, so the agent comes back observing and leaves
#     the unit's own settings alone.
#   - Gateway answering for HEALTHY_AFTER s: confirms the running build
#     (good.md5), drops udeco-ap.json.prev (it belongs to the build no
#     longer confirmed) and clears the reboot strikes. Each installed build
#     is confirmed on its own: a new udeco-ap.gz (a deploy or a rollback,
#     told by its inode, size and time from ls) starts the HEALTHY_AFTER
#     count again.
# Actions go to $D/guard.events (persistent, last 50 lines) and the guard's
# log to $R/guard.log. A kernel hang is left to the kernel's own watchdog: a
# shell can't run then.
D=${UDECO_D:-/flash2/udeco}
R=${UDECO_R:-/tmp/udeco-bin}
UP=${UDECO_UPTIME:-/proc/uptime}

guard() {
	GW=192.168.0.1
	ROLLBACK_AFTER=180
	REBOOT_AFTER=480
	MIN_UPTIME=1200
	HEALTHY_AFTER=1800
	REBOOT="reboot"
	[ -f $D/guard.conf ] && . $D/guard.conf
	exec 8>$R/guard.lock
	flock -n 8 || exit 0
	upt() { cut -d. -f1 $UP; }
	md5() { md5sum "$1" 2>/dev/null | cut -c1-32; }
	log() { echo "$(date '+%Y-%m-%d %H:%M:%S') up=$(upt) $*" >> $R/guard.log; }
	event() {
		log "$*"
		echo "$(date '+%Y-%m-%d %H:%M:%S') up=$(upt) $*" >> $D/guard.events
		tail -n 50 $D/guard.events > $D/guard.events.tmp && mv $D/guard.events.tmp $D/guard.events
	}
	log "guard start: gw=$GW rollback=${ROLLBACK_AFTER}s reboot=${REBOOT_AFTER}s min_uptime=${MIN_UPTIME}s healthy=${HEALTHY_AFTER}s"
	down_since=""
	up_since=$(upt)
	rolled=""
	confirmed=""
	spawned=""
	# the installed build, cheaply (no md5 every 10 s): a deploy renames a
	# new file into place, a rollback copies over it
	build() { ls -lni $D/udeco-ap.gz 2>/dev/null; }
	built=$(build)
	while [ -f $D/start.sh ]; do
		# the supervisor: restart it when nothing holds its lock (the agent
		# inherits the lock, so an orphaned agent still counts as running)
		now=$(upt)
		if [ $((now - ${spawned:--999})) -ge 60 ] && (flock -n 9) 9>$R/loop.lock 2>/dev/null; then
			# at most once a minute; only the first of a run goes to flash
			if [ -z "$spawned" ]; then event "supervisor not running: starting it"; else log "supervisor not running: starting it again"; fi
			spawned=$now
			nohup sh $D/start.sh 8>&- >/dev/null 2>&1 </dev/null &
		fi
		b=$(build)
		if [ "$b" != "$built" ]; then
			# another build: it is confirmed after its own healthy time
			built=$b
			confirmed=""
			[ -n "$up_since" ] && up_since=$now
			log "udeco-ap.gz changed: the healthy time starts again"
		fi
		if ping -c 2 -w 5 $GW >/dev/null 2>&1; then
			[ -n "$down_since" ] && event "gateway $GW answers again after $((now - down_since))s"
			down_since=""
			rolled=""
			[ -z "$up_since" ] && up_since=$now
			if [ -z "$confirmed" ] && [ $((now - up_since)) -ge $HEALTHY_AFTER ]; then
				cur=$(md5 $D/udeco-ap.gz)
				if [ -n "$cur" ] && [ "$cur" != "$(cat $D/good.md5 2>/dev/null)" ]; then
					echo $cur > $D/good.md5
					event "build $cur confirmed good (gateway reachable for ${HEALTHY_AFTER}s)"
					[ -f $D/udeco-ap.json.prev ] && rm -f $D/udeco-ap.json.prev && event "udeco-ap.json.prev dropped (it went with the build before $cur)"
				fi
				[ -f $D/guard.strikes ] && rm -f $D/guard.strikes && event "reboot strikes cleared"
				confirmed=1
			fi
		else
			up_since=""
			confirmed=""
			if [ -z "$down_since" ]; then
				down_since=$now
				log "gateway $GW not answering"
			fi
			down=$((now - down_since))
			if [ -z "$rolled" ] && [ $down -ge $ROLLBACK_AFTER ]; then
				rolled=1
				cur=$(md5 $D/udeco-ap.gz)
				good=$(cat $D/good.md5 2>/dev/null)
				if [ -n "$good" ] && [ "$cur" != "$good" ] && [ "$(md5 $D/udeco-ap.gz.prev)" = "$good" ]; then
					cp $D/udeco-ap.gz $D/udeco-ap.gz.bad && cp $D/udeco-ap.gz.prev $D/udeco-ap.gz && rm -f $R/udeco-ap
					# the config the confirmed build ran with (an older build
					# exits at once on a config it does not know)
					cfg=""
					if [ -f $D/udeco-ap.json.prev ] && [ "$(md5 $D/udeco-ap.json.prev)" != "$(md5 $D/udeco-ap.json)" ]; then
						cp $D/udeco-ap.json $D/udeco-ap.json.bad && cp $D/udeco-ap.json.prev $D/udeco-ap.json &&
							cfg=", udeco-ap.json replaced by udeco-ap.json.prev (kept as udeco-ap.json.bad)"
					fi
					[ -f $R/agent.pid ] && kill $(cat $R/agent.pid) 2>/dev/null
					event "ROLLBACK: gateway silent ${down}s: build $cur replaced by the confirmed $good (kept as udeco-ap.gz.bad)$cfg, agent restarted"
				else
					log "no rollback: running build ${cur:-none} is the confirmed one or no confirmed .prev"
				fi
			fi
			if [ $down -ge $REBOOT_AFTER ] && [ $now -ge $MIN_UPTIME ]; then
				s=$(($(cat $D/guard.strikes 2>/dev/null || echo 0) + 1))
				echo $s > $D/guard.strikes
				if [ $s -ge 2 ] && [ ! -f $D/force-observe ]; then
					echo "$(date '+%Y-%m-%dT%H:%M:%S') guard: gateway $GW silent through $s reboots" > $D/force-observe
					event "force-observe written (strike $s)"
				fi
				event "REBOOT: gateway $GW silent ${down}s (strike $s)"
				sync
				$REBOOT
				sleep 60
				$REBOOT -f
				down_since=$(upt)
			fi
		fi
		sleep 10
	done
	log "guard stop: $D/start.sh removed"
}

[ "$1" = guard ] && { guard; exit 0; }

[ -f $D/udeco-ap.json ] && [ -f $D/udeco-ap.gz ] || exit 0
mkdir -p $R && chmod 700 $R
# the guard runs on its own (it keeps a lock; a second one exits at once)
nohup sh $D/start.sh guard >/dev/null 2>&1 </dev/null &
exec 9>$R/loop.lock
flock -n 9 || exit 0
while [ -f $D/start.sh ]; do
	if [ ! -x $R/udeco-ap ]; then
		gunzip -c $D/udeco-ap.gz > $R/udeco-ap.tmp && chmod 755 $R/udeco-ap.tmp && mv $R/udeco-ap.tmp $R/udeco-ap || { sleep 60; continue; }
	fi
	# keep the RAM log under 2 MB (the agent appends, so truncating is safe)
	if [ -f $R/agent.log ] && [ $(wc -c < $R/agent.log) -gt 2097152 ]; then
		tail -c 262144 $R/agent.log > $R/agent.log.1; : > $R/agent.log
	fi
	$R/udeco-ap -config $D/udeco-ap.json >> $R/agent.log 2>&1 &
	echo $! > $R/agent.pid
	wait $!
	sleep 10
done
