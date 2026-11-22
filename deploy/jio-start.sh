#!/bin/sh
# udeco-ap (UniFi agent) on the Garage AP, a JioFiber JCOW414 used as a
# UAP-AC-Lite. Started at boot by one line in /flash2/pfrm2.0/etc/customInit
# (backup: customInit.pre-udeco next to it). This loop restarts the agent if
# it exits, and removes the agent's login lock (UDECO-LOCK) before every
# start. Turn it off: rm /flash2/udeco/start.sh, then reboot (the unit's
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
#
# The 2.4 GHz driver (drv2g): with $D/mt7603wpa3.ko.gz present, once per
# boot before the first agent start (a vendor module still in use: again
# before the next start, 3 tries), the vendor's mt7603eap.ko (loaded by
# /usr/script/wlan_load.sh) is replaced by that rebuilt MT7603 module (SAE,
# PMF; mtkwifi WithDriverSAE), and the ra* netdevs that were up come back up
# in the same bridges. Any failure puts the vendor module back and writes
# $D/mt7603wpa3.failed, which turns the swap off until it is removed (a
# vendor module that won't load back reboots the unit, whose next boot then
# keeps the vendor driver). Steps go to $D/guard.events. Off for one boot
# with $D/force-observe; for good: rm $D/mt7603wpa3.ko.gz.
D=${UDECO_D:-/flash2/udeco}
R=${UDECO_R:-/tmp/udeco-bin}
UP=${UDECO_UPTIME:-/proc/uptime}
IPT=${UDECO_IPT:-/pfrm2.0/bin}

# unlock removes the agent's login lock (docs/deco/features/login-lock.md)
# before every start, so none outlives an agent that died without its
# SIGTERM path; errors are ignored (no lock, no iptables).
unlock() {
	for T in $IPT/iptables $IPT/ip6tables; do
		for i in 1 2 3; do $T -D INPUT -j UDECO-LOCK 2>/dev/null || break; done
		$T -F UDECO-LOCK 2>/dev/null
		$T -X UDECO-LOCK 2>/dev/null
	done
	return 0
}

# termed: SIGTERM is logged, not obeyed. At every boot so far (11-19, 11-20,
# 11-22; uptime 281-300 s, as the agent's jiosys first stopped the Jio
# services) the supervisor, the guard and the agent got one SIGTERM at once,
# and nothing restarted them. jiosys signals single PIDs and customInit no
# longer kills; dms and ras, which ignore SIGTERM, lived, and telnetd in its
# own process group was spared, so a stopping Jio process most likely
# signalled its process group, which start.sh shares (busybox has no
# setsid). The agent may still stop: the loop starts it again. To stop the
# shells: rm $D/start.sh (both end on their own) or kill -9.
termed() {
	trap "echo \"\$(date '+%Y-%m-%d %H:%M:%S') up=\$(cut -d. -f1 $UP) ${1:-supervisor}: SIGTERM ignored (rm $D/start.sh or kill -9 to stop)\" >> $D/guard.events" TERM
}

guard() {
	termed guard
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

# drv2g swaps the 2.4 GHz driver for the rebuilt MT7603 module (see the top).
drv2g() {
	K=$D/mt7603wpa3.ko.gz
	OLD=${UDECO_MT7603_VENDOR:-/lib/modules/mt7603eap.ko}
	EVT=${UDECO_WL_EVT:-/pfrm2.0/lib/modules/wl_evt_driver.ko}
	[ -f $K ] && [ ! -f $D/mt7603wpa3.failed ] && [ ! -f $D/force-observe ] && [ ! -f $R/drv2g.done ] || return 0
	: > $R/drv2g.done
	grep -q "^mt7603eap " ${UDECO_PROC_MODULES:-/proc/modules} || return 0
	ev() { echo "$(date '+%Y-%m-%d %H:%M:%S') up=$(cut -d. -f1 $UP) drv2g: $*" >> $D/guard.events; }
	fail() {
		echo "$(date '+%Y-%m-%dT%H:%M:%S') $*" > $D/mt7603wpa3.failed
		ev "FAILED ($*): back to the vendor driver; $D/mt7603wpa3.failed turns the swap off"
	}
	gunzip -c $K > $R/mt7603wpa3.ko || { fail "gunzip"; rm -f $R/mt7603wpa3.ko; return 0; }
	# the BSS netdevs that are up, with their bridges
	st=""
	N=${UDECO_SYSNET:-/sys/class/net}
	for i in ra0 ra1 ra2 ra3; do
		f=$(cat $N/$i/flags 2>/dev/null) || continue
		[ $((f & 1)) -eq 1 ] || continue
		b=$(readlink $N/$i/brport/bridge 2>/dev/null)
		st="$st $i:${b##*/}"
	done
	restore() {
		for e in $st; do
			ifconfig ${e%%:*} up
			[ -n "${e#*:}" ] && brctl addif ${e#*:} ${e%%:*} 2>/dev/null
		done
	}
	for i in ra3 ra2 ra1 ra0 apcli0 wds0; do ifconfig $i down 2>/dev/null; done
	# wl_notifier (Jio) keeps /dev/wl_evt_device open, and wl_evt_driver uses
	# mt7603eap: at boot, before jiosys stops it, neither would unload
	# (2026-11-22, up=286). The agent's dumb-AP mode stops it anyway.
	killall wl_notifier 2>/dev/null && sleep 1 && killall -9 wl_notifier 2>/dev/null
	rmmod wl_evt_driver 2>/dev/null
	if ! rmmod mt7603eap; then
		# still in use: nothing changed, so try again before the next agent
		# start (at most 3 times a boot) rather than turning the swap off
		insmod $EVT; restore
		n=$(($(cat $R/drv2g.busy 2>/dev/null || echo 0) + 1))
		echo $n > $R/drv2g.busy
		use=$(grep -E "^(mt7603eap|wl_evt_driver) " ${UDECO_PROC_MODULES:-/proc/modules} | cut -d' ' -f1,3 | tr '\n' ' ')
		if [ $n -ge 3 ]; then
			fail "rmmod mt7603eap, $n tries (in use: $use)"
		else
			rm -f $R/drv2g.done
			ev "rmmod mt7603eap: in use ($use), try $n of 3; again before the next agent start"
		fi
		return 0
	fi
	if insmod $R/mt7603wpa3.ko; then
		insmod $EVT
		if ifconfig ra0 up; then
			restore
			ev "mt7603wpa3 loaded (was up:$st)"
			rm -f $R/mt7603wpa3.ko
			return 0
		fi
		ifconfig ra0 down
		rmmod wl_evt_driver 2>/dev/null
		if ! rmmod mt76x3_ap; then
			fail "ra0 up, then rmmod mt76x3_ap"
			ev "REBOOT: the vendor driver can't be loaded back"
			sync; reboot; sleep 60; reboot -f
			return 0
		fi
		why="ra0 up"
	else
		why="insmod"
	fi
	insmod $OLD; insmod $EVT; restore
	fail "$why"
	rm -f $R/mt7603wpa3.ko
	return 0
}

[ "$1" = guard ] && { guard; exit 0; }
# "start.sh drv2g": the swap alone (tests; by hand, after rm $R/drv2g.done)
[ "$1" = drv2g ] && { mkdir -p $R; drv2g; exit 0; }

[ -f $D/udeco-ap.json ] && [ -f $D/udeco-ap.gz ] || exit 0
mkdir -p $R && chmod 700 $R
# the guard runs on its own (it keeps a lock; a second one exits at once)
nohup sh $D/start.sh guard >/dev/null 2>&1 </dev/null &
exec 9>$R/loop.lock
flock -n 9 || exit 0
termed
while [ -f $D/start.sh ]; do
	# first: nothing below (a gunzip that waits and retries) skips it
	unlock
	# once a boot (a busy vendor module: again, up to 3 times), never under a running agent
	drv2g
	if [ ! -x $R/udeco-ap ]; then
		gunzip -c $D/udeco-ap.gz > $R/udeco-ap.tmp && chmod 755 $R/udeco-ap.tmp && mv $R/udeco-ap.tmp $R/udeco-ap || { sleep 60; continue; }
	fi
	# keep the RAM log under 2 MB (the agent appends, so truncating is safe)
	if [ -f $R/agent.log ] && [ $(wc -c < $R/agent.log) -gt 2097152 ]; then
		tail -c 262144 $R/agent.log > $R/agent.log.1; : > $R/agent.log
	fi
	$R/udeco-ap -config $D/udeco-ap.json >> $R/agent.log 2>&1 &
	a=$!
	echo $a > $R/agent.pid
	# a trapped SIGTERM ends wait early: wait again while the agent runs
	wait $a
	while kill -0 $a 2>/dev/null; do wait $a; done
	sleep 10
done
