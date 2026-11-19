#!/bin/sh
# udeco-ap boot/watchdog hook, run every minute by /data/persist_shell.sh.
# Starts the UniFi agent when it is not running. To turn it off:
#   rm /tp_data/udeco/start.sh; kill $(cat /tmp/udeco-bin/agent.pid)
# (a reboot then returns the unit to stock TP-Link Wi-Fi).
D=/tp_data/udeco
R=/tmp/udeco-bin
[ -f $D/udeco-ap.json ] && [ -f $D/udeco-ap.gz ] || exit 0
mkdir -p $R && chmod 700 $R
# keep the RAM log under 2 MB (the agent appends, so truncating is safe)
if [ -f $R/agent.log ] && [ $(wc -c < $R/agent.log) -gt 2097152 ]; then
	tail -c 262144 $R/agent.log > $R/agent.log.1; : > $R/agent.log
fi
start-stop-daemon -K -t -q -p $R/agent.pid -x $R/udeco-ap && exit 0
# the binary lives gzipped on flash and runs from RAM
if [ ! -x $R/udeco-ap ]; then
	gunzip -c $D/udeco-ap.gz > $R/udeco-ap.tmp && chmod 755 $R/udeco-ap.tmp && mv $R/udeco-ap.tmp $R/udeco-ap || exit 1
fi
logger -t udeco "starting udeco-ap"
start-stop-daemon -S -b -m -p $R/agent.pid -x /bin/sh -- -c "exec $R/udeco-ap -config $D/udeco-ap.json >> $R/agent.log 2>&1"
