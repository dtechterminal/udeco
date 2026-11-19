#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Build the on-device agent cmd/udeco-ap and install it on ONE rooted Deco
# X20 (docs/deco/agent-design.md §3.5, interference-audit R27-R29). Run from
# any machine with Go and root SSH access to the unit:
#
#   deploy/deco-ap.sh [options] <unit-ip>
#   deploy/deco-ap.sh --build-only
#
# What it does, in order:
#   1. builds dist/udeco-ap-linux-armv7 (linux/arm GOARM=7, CGO off: static;
#      -trimpath -s -w: stripped). Above 6 MiB it also makes a gzip -9 copy
#      and ships that instead: the launcher unpacks it to /tmp/udeco-bin
#      (ramfs) at every start, which costs that much RAM but keeps /tp_data
#      (ubifs, ~11 MB free) roomy. At or below 6 MiB the plain binary ships;
#   2. preflight, read-only (R28). It refuses unless:
#        - the unit is armv7 with /tp_data and /data/persist_shell.sh;
#        - /etc/crontabs/root has a line running /data/persist_shell.sh;
#        - persist_shell.sh re-adds that cron line, and its guard string
#          occurs in the line it adds (a guard that never matches appends a
#          line every minute, audit B2);
#        - uci has the firewall include for /data/persist_shell.sh (the boot
#          hook, audit B1);
#        - /tp_data keeps at least 1 MiB free after the install;
#      and it warns when --udeco-config lists the unit's MAC (the off-device
#      udeco would model the same unit, audit B12);
#   3. if the agent changed: removes the launcher and the old agent (so
#      nothing can restart the old one), stops a running agent with SIGTERM
#      (the agent leaves Wi-Fi as it is on SIGTERM) and waits for it to exit,
#      uploads the new one, verifies its md5 on the unit, renames it into
#      place and writes the launcher /tp_data/udeco/start.sh;
#   4. writes /tp_data/udeco/udeco-ap.json in OBSERVE mode (takeover, apply
#      and egress all false) if there is none; an existing config is never
#      changed;
#   5. supervision: prints the one line /data/persist_shell.sh needs (cron
#      runs that file every minute and the firewall include at boot). The
#      file is the user's: it is changed only with --edit-persist, and then
#      only that line (found by its marker), every other line checked to be
#      byte for byte the same;
#   6. starts the agent if it is not running (unless --no-start), shows its
#      first log lines, the R29 checklist and the one rollback command.
#
# Options:
#   --force-host        allow a unit other than 192.168.0.205 (the only
#                       rooted unit the design allows live tests on, §4)
#   --inform-url URL    inform_url for a NEW config (default
#                       http://192.168.0.1:8080/inform; the host must be an
#                       IPv4 address)
#   --console-ip IP     console_ip for a NEW config (default 192.168.0.1)
#   --udeco-config FILE a copy of the off-device udeco.json, to check that it
#                       does not model this unit too (warning only)
#   --edit-persist      add (or update) the supervise line in
#                       /data/persist_shell.sh instead of only printing it
#   --preflight         build and run the read-only preflight, then stop
#   --no-start          install only: do not stop, restart or start the agent
#   --build-only        build dist/udeco-ap-linux-armv7 and stop (no device)
#   --preflight-file F  (tests) judge a saved preflight answer F; no build,
#                       no device
#
# Environment: DECO_KEY (default ~/.ssh/deco_x20).
#
# Safety: nothing here touches TP-Link's software, Wi-Fi, nvram, port 22's
# dropbear or the telnet line; a reboot still restores stock TP-Link (the
# agent's own changes are volatile). The rollback command it prints deletes
# the supervise line, stops the agent and reboots.
set -euo pipefail

ALLOWED_HOST=192.168.0.205
KEY=${DECO_KEY:-$HOME/.ssh/deco_x20}
DIR=/tp_data/udeco
BIN=$DIR/udeco-ap
GZ=$DIR/udeco-ap.gz
SUM=$DIR/udeco-ap.md5
START=$DIR/start.sh
RAMDIR=/tmp/udeco-bin
CFG=$DIR/udeco-ap.json
PERSIST=/data/persist_shell.sh
CRONTAB=/etc/crontabs/root
MARK='# udeco-ap supervise (deploy/deco-ap.sh)'
LINE="[ -f $START ] && sh $START </dev/null >/dev/null 2>&1 & $MARK"
OUT=dist/udeco-ap-linux-armv7
GZ_ABOVE=$((6 << 20)) # ship gzip only when the stripped binary is larger
MIN_FREE_KB=1024      # /tp_data free after the install (R28)

force_host=0 no_start=0 build_only=0 edit_persist=0 preflight_only=0
inform_url=http://192.168.0.1:8080/inform
console_ip=192.168.0.1
udeco_config= preflight_file=
ip=

usage() { sed -n '3,63p' "$0" | sed 's/^# \{0,1\}//' >&2; exit 2; }
die() { echo "deco-ap: $*" >&2; exit 1; }

is_ipv4() {
	[[ $1 =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] || return 1
	local o
	for o in "${BASH_REMATCH[@]:1}"; do ((10#$o <= 255)) || return 1; done
}

while [ $# -gt 0 ]; do
	case $1 in
	--force-host) force_host=1 ;;
	--no-start) no_start=1 ;;
	--build-only) build_only=1 ;;
	--edit-persist) edit_persist=1 ;;
	--preflight) preflight_only=1 ;;
	--inform-url) [ $# -ge 2 ] || usage; inform_url=$2; shift ;;
	--console-ip) [ $# -ge 2 ] || usage; console_ip=$2; shift ;;
	--udeco-config) [ $# -ge 2 ] || usage; udeco_config=$2; shift ;;
	--preflight-file) [ $# -ge 2 ] || usage; preflight_file=$2; shift ;;
	-h | --help) usage ;;
	-*) echo "deco-ap: unknown option $1" >&2; usage ;;
	*) [ -z "$ip" ] || usage; ip=$1 ;;
	esac
	shift
done

# The values below end up in remote shell commands and in the agent's JSON
# config: accept only strict forms.
[[ $inform_url =~ ^http://([0-9.]+)(:[0-9]{1,5})?/inform$ ]] && is_ipv4 "${BASH_REMATCH[1]}" ||
	die "--inform-url $inform_url: want http://<IPv4>[:port]/inform (the agent blocks DNS outside the LAN)"
is_ipv4 "$console_ip" || die "--console-ip $console_ip: want an IPv4 address"
[ -z "$udeco_config" ] || [ -r "$udeco_config" ] || die "--udeco-config $udeco_config: not readable"

# --- preflight verdict (local, from the unit's read-only answer) -------------
#
# The unit answers one "KEY value" line per fact (preflight_script below);
# judge_preflight checks R28 on it. It sets the globals below and prints one
# line per problem; it returns 1 when the deploy must stop.
pf_arch= pf_avail=0 pf_running=0 pf_mac= pf_old_kb=0 pf_old_md5=- pf_old_form=none
pf_supervise= pf_exit=0

# guard_of / added_of: the quoted string a persist_shell.sh line greps the
# crontab for, and the quoted line it appends to it ("" when none).
guard_of() {
	local re="grep[[:space:]]+(-[a-zA-Z]+[[:space:]]+)*['\"]([^'\"]+)['\"][[:space:]]+[^|&;]*$CRONTAB"
	[[ $1 =~ $re ]] && printf '%s' "${BASH_REMATCH[2]}"
	return 0
}
added_of() {
	local re="echo[[:space:]]+['\"]([^'\"]+)['\"][[:space:]]*>>[[:space:]]*$CRONTAB"
	[[ $1 =~ $re ]] && printf '%s' "${BASH_REMATCH[1]}"
	return 0
}

judge_preflight() { # $1: the unit's answer; $2: new artifact size (kB)
	local new_kb=$2 bad=0 key val g a
	local tpdata=0 persist=0 cron=0 include=0 guards=() added=()
	while IFS= read -r l; do
		key=${l%% *}
		val=${l#* }
		[ "$val" != "$l" ] || val=
		case $key in
		ARCH) pf_arch=$val ;;
		TPDATA) tpdata=$val ;;
		PERSIST) persist=$val ;;
		AVAIL) pf_avail=$val ;;
		RUNNING) pf_running=$val ;;
		MAC) pf_mac=$(printf '%s' "$val" | tr 'A-F' 'a-f') ;;
		OLD) read -r pf_old_form pf_old_md5 pf_old_kb <<<"$val" ;;
		SUPERVISE) pf_supervise=$val ;;
		EXIT) pf_exit=$val ;;
		CRON) case $val in \#*) ;; *"$PERSIST"*) cron=1 ;; esac ;;
		INCLUDE) [ "$val" != "$PERSIST" ] || include=1 ;;
		GUARD)
			g=$(guard_of "$val")
			a=$(added_of "$val")
			[ -z "$g" ] || guards+=("$g")
			[ -z "$a" ] || added+=("$a")
			;;
		esac
	done <<<"$1"
	case $pf_arch in
	armv7*) ;;
	*) echo "  REFUSED: the unit is '${pf_arch:-unknown}', not armv7: wrong unit?"; return 1 ;;
	esac
	[ "$tpdata" = 1 ] || { echo "  REFUSED: no /tp_data mount: not a Deco X20?"; return 1; }
	[ "$persist" = 1 ] || { echo "  REFUSED: no $PERSIST: the root setup's persistence hook is missing; not creating one"; return 1; }
	if [ "$cron" != 1 ]; then
		echo "  REFUSED: $CRONTAB has no line running $PERSIST: nothing would restart a crashed agent (audit B3)"
		bad=1
	fi
	if [ ${#added[@]} -eq 0 ]; then
		echo "  REFUSED: $PERSIST does not re-add its cron line to $CRONTAB: after a reboot nothing supervises the agent"
		bad=1
	elif [ ${#guards[@]} -eq 0 ]; then
		echo "  REFUSED: $PERSIST appends to $CRONTAB without a grep guard: one more line every run (audit B2)"
		bad=1
	else
		for g in "${guards[@]}"; do
			for a in "${added[@]}"; do
				case $a in
				*"$g"*) ;;
				*)
					echo "  REFUSED: $PERSIST guards with grep '$g' but appends '$a', which does not contain it:"
					echo "           every run adds another cron line (audit B2). Change the guard to grep '/data/persist_shell'"
					echo "           yourself; this script does not edit that logic"
					bad=1
					;;
				esac
			done
		done
	fi
	if [ "$include" != 1 ]; then
		echo "  REFUSED: uci has no firewall include for $PERSIST: nothing starts the agent at boot (audit B1, B4)"
		bad=1
	fi
	local free_after=$((pf_avail + pf_old_kb - new_kb))
	if [ "$free_after" -lt "$MIN_FREE_KB" ]; then
		echo "  REFUSED: /tp_data would keep $free_after kB free (has $pf_avail kB, old agent $pf_old_kb kB, new $new_kb kB); need $MIN_FREE_KB kB"
		bad=1
	fi
	if [ -n "$udeco_config" ]; then
		if [ -z "$pf_mac" ]; then
			echo "  WARNING: could not read the unit's MAC; $udeco_config not checked"
		elif tr 'A-F' 'a-f' <"$udeco_config" | grep -qF "$pf_mac"; then
			echo "  WARNING: $udeco_config lists $pf_mac: the off-device udeco models this unit too. Remove the unit"
			echo "           there (and its controller record) before the agent adopts it, or the controller sees one MAC twice"
		fi
	else
		echo "  note: no --udeco-config given: not checked whether the off-device udeco also models ${pf_mac:-this unit}"
	fi
	return $bad
}

# The read-only probe the unit runs (busybox sh). It prints only facts the
# verdict needs: never the persist file itself, just its crontab lines.
preflight_script() {
	cat <<EOF
echo "ARCH \$(uname -m)"
grep -q ' /tp_data ' /proc/mounts && echo "TPDATA 1" || echo "TPDATA 0"
[ -f $PERSIST ] && echo "PERSIST 1" || echo "PERSIST 0"
grep -F '$PERSIST' $CRONTAB 2>/dev/null | sed 's/^/CRON /'
[ -f $PERSIST ] && grep -F '$CRONTAB' $PERSIST | sed 's/^/GUARD /'
[ -f $PERSIST ] && grep -F '$MARK' $PERSIST | head -n 1 | sed 's/^/SUPERVISE /'
[ -f $PERSIST ] && grep -c '^[[:space:]]*exit' $PERSIST | sed 's/^/EXIT /'
uci -q show firewall | sed -n "s/^firewall\\.[^.]*\\.path='\\(.*\\)'\\$/INCLUDE \\1/p"
echo "AVAIL \$(df -k /tp_data | tail -n 1 | awk '{print \$(NF-2)}')"
echo "MAC \$(cat /sys/class/net/br-lan/address 2>/dev/null)"
pidof udeco-ap >/dev/null 2>&1 && echo "RUNNING 1" || echo "RUNNING 0"
kb() { echo \$(( (\$(wc -c <"\$1") + 1023) / 1024 )); }
old=0
for f in $BIN $GZ $START $SUM; do [ -f \$f ] && old=\$((old + \$(kb \$f))); done
if [ -f $GZ ]; then echo "OLD gz \$(md5sum $GZ | cut -d' ' -f1) \$old"
elif [ -f $BIN ]; then echo "OLD bin \$(md5sum $BIN | cut -d' ' -f1) \$old"
else echo "OLD none - \$old"; fi
EOF
}

checklist() {
	cat <<EOF

Your part (audit R29; this script does none of it):
  - keep persist_shell.sh's cron guard grepping '/data/persist_shell' (it must match the line it adds);
  - optionally test dropbear by its listener (netstat -ltn | grep -q ':22 ') instead of pgrep -f /data/dropbear;
  - turn off Auto Update in the Deco app, and make no Deco-app changes (no 'Remove Deco') while a unit is taken over;
  - reserve the Decos' IPs on the UCG;
  - migrate satellites first, then the master soon after;
  - optionally run /data/dropbear with -s (key-only);
  - TP-Link's lan address 192.168.0.1/22 is the UCG's: change it in the app before takeover if it lets you (R31).
EOF
}

if [ -n "$preflight_file" ]; then
	[ -r "$preflight_file" ] || die "--preflight-file $preflight_file: not readable"
	if judge_preflight "$(cat "$preflight_file")" "${PREFLIGHT_NEW_KB:-3100}"; then
		echo "preflight OK"
		exit 0
	fi
	exit 1
fi

cd "$(dirname "$0")/.."

md5_local() {
	if command -v md5sum >/dev/null 2>&1; then md5sum "$1" | cut -d' ' -f1; else md5 -q "$1"; fi
}
kb_local() { echo $((($(wc -c <"$1" | tr -d ' ') + 1023) / 1024)); }

build() {
	echo "building $OUT (linux/arm GOARM=7, static, stripped)"
	mkdir -p dist
	GOOS=linux GOARCH=arm GOARM=7 CGO_ENABLED=0 \
		go build -trimpath -ldflags '-s -w -buildid=' -o "$OUT" ./cmd/udeco-ap
	size=$(wc -c <"$OUT" | tr -d ' ')
	bin_md5=$(md5_local "$OUT")
	echo "  $size bytes, md5 $bin_md5"
	rm -f "$OUT.gz"
	if [ "$size" -gt "$GZ_ABOVE" ]; then
		gzip -9 -n -c "$OUT" >"$OUT.gz"
		form=gz art=$OUT.gz
		echo "  over $GZ_ABOVE bytes: shipping $OUT.gz ($(wc -c <"$OUT.gz" | tr -d ' ') bytes), unpacked to $RAMDIR at start"
	else
		form=bin art=$OUT
		echo "  shipping the plain binary"
	fi
	art_md5=$(md5_local "$art")
	art_kb=$(kb_local "$art")
}

if [ "$build_only" = 1 ]; then
	[ -z "$ip" ] || die "--build-only takes no unit address"
	build
	exit 0
fi

[ -n "$ip" ] || usage
is_ipv4 "$ip" || die "$ip: want the unit's IPv4 address"
if [ "$ip" != "$ALLOWED_HOST" ] && [ "$force_host" != 1 ]; then
	die "refusing $ip: only $ALLOWED_HOST is cleared for the agent (agent-design.md §4); pass --force-host to override"
fi
[ -r "$KEY" ] || die "ssh key $KEY not readable (set DECO_KEY)"

HOST=root@$ip
SSH=(ssh -i "$KEY" -o IdentitiesOnly=yes -o BatchMode=yes -o ConnectTimeout=10 -o ServerAliveInterval=15)
# remote runs a busybox sh script (given on stdin) on the unit
remote() { "${SSH[@]}" "$HOST" 'sh -s'; }

build

# --- 2. preflight (read-only) ------------------------------------------------
echo "checking $HOST (read-only)"
pre=$(preflight_script | remote) || die "preflight: ssh to $HOST failed"
new_kb=$((art_kb + 4)) # + launcher and md5 file
if ! judge_preflight "$pre" "$new_kb"; then
	checklist
	die "preflight failed: nothing was changed on $ip"
fi
echo "  $pf_arch, /tp_data $pf_avail kB free, agent running: $pf_running, installed: $pf_old_form $pf_old_md5, MAC $pf_mac"
if [ "$preflight_only" = 1 ]; then
	echo "preflight OK (--preflight: nothing changed)"
	checklist
	exit 0
fi

# --- 3. agent -----------------------------------------------------------------
if [ "$pf_old_form" = "$form" ] && [ "$pf_old_md5" = "$art_md5" ]; then
	echo "agent unchanged on the unit"
else
	if [ "$pf_running" = 1 ] && [ "$no_start" = 1 ]; then
		die "an agent is running and --no-start was given: the new agent only fits once it has stopped"
	fi
	echo "replacing the agent ($pf_old_form $pf_old_md5 -> $form $art_md5)"
	# remove the launcher and the old agent first, so the supervise line
	# cannot start the old one while we wait; SIGTERM: the agent finishes
	# the job it is in and leaves Wi-Fi as it is. Never SIGKILL: that could
	# cut an apply in half.
	remote <<EOF
set -e
mkdir -p $DIR
chmod 700 $DIR
rm -f $START $BIN $BIN.new $GZ $GZ.new $SUM
rm -rf $RAMDIR
if pidof udeco-ap >/dev/null 2>&1; then
	kill -TERM \$(pidof udeco-ap)
	i=0
	while pidof udeco-ap >/dev/null 2>&1; do
		i=\$((i + 1))
		[ \$i -le 330 ] || { echo "deco-ap: the agent did not exit within 330 s; not killing it" >&2; exit 1; }
		sleep 1
	done
fi
EOF
	dst=$BIN
	[ "$form" = bin ] || dst=$GZ
	echo "  uploading $art_kb kB to $dst"
	"${SSH[@]}" "$HOST" "cat > $dst.new" <"$art"
	got=$(remote <<EOF
md5sum $dst.new | cut -d' ' -f1
EOF
)
	if [ "$got" != "$art_md5" ]; then
		remote <<EOF || true
rm -f $dst.new
EOF
		die "md5 mismatch on the unit (got $got, want $art_md5); removed the upload, NO agent is installed now"
	fi
	remote <<EOF
set -e
chmod 755 $dst.new
mv $dst.new $dst
EOF
	echo "  md5 verified on the unit, installed $dst"
fi

# The launcher and the md5 it checks, rewritten on every deploy (an install
# from before the launcher has neither): persist_shell.sh's supervise line
# runs it every minute and at boot; it exits at once while an agent runs.
remote <<EOF
set -e
echo $bin_md5 >$SUM
cat >$START.tmp <<'LAUNCH'
#!/bin/sh
# udeco-ap launcher, written by deploy/deco-ap.sh: start the agent unless it
# runs. A gzip-shipped agent is unpacked to ramfs ($RAMDIR) and checked
# against the md5 of the binary that was deployed before it is started.
pidof udeco-ap >/dev/null 2>&1 && exit 0
B=$BIN
if [ -f $GZ ]; then
	B=$RAMDIR/udeco-ap
	want=\$(cat $SUM 2>/dev/null)
	[ -n "\$want" ] || exit 1
	if [ "\$(md5sum \$B 2>/dev/null | cut -d' ' -f1)" != "\$want" ]; then
		mkdir -p $RAMDIR && chmod 700 $RAMDIR || exit 1
		T=\$B.\$\$
		if ! gunzip -c $GZ >\$T || [ "\$(md5sum \$T | cut -d' ' -f1)" != "\$want" ]; then
			rm -f \$T
			logger -t udeco-ap "launcher: $GZ does not unpack to the deployed agent; not starting" 2>/dev/null
			exit 1
		fi
		chmod 755 \$T && mv \$T \$B
	fi
fi
[ -x \$B ] || exit 0
# the agent's log lives in RAM next to it, kept under 2 MB (the agent
# appends, so truncating is safe); exec keeps the pid in agent.pid valid
mkdir -p $RAMDIR && chmod 700 $RAMDIR || exit 1
L=$RAMDIR/agent.log
if [ -f \$L ] && [ \$(wc -c <\$L) -gt 2097152 ]; then
	tail -c 262144 \$L >\$L.1; : >\$L
fi
logger -t udeco "starting udeco-ap" 2>/dev/null
echo \$\$ >$RAMDIR/agent.pid
exec \$B -config $CFG </dev/null >>\$L 2>&1
LAUNCH
chmod 755 $START.tmp
mv $START.tmp $START
echo "launcher $START in place ($form agent)"
EOF

# --- 4. default config (observe mode), only if absent ------------------------
remote <<EOF
set -e
if [ -f $CFG ]; then
	echo "keeping the existing $CFG:"
	grep -E '"(takeover|apply|egress|inform_url|console_ip)"' $CFG | sed 's/^/  /' || true
	exit 0
fi
umask 077
cat >$CFG.tmp <<'JSON'
{
  "inform_url": "$inform_url",
  "console_ip": "$console_ip",
  "model": "UAL6",
  "sshd_port": 2222,
  "takeover": false,
  "apply": false,
  "egress": false,
  "log": "syslog"
}
JSON
mv $CFG.tmp $CFG
echo "wrote $CFG (observe mode: takeover, apply and egress false)"
EOF

# --- 5. supervise line in /data/persist_shell.sh -----------------------------
supervised=0
if [ "$pf_supervise" = "$LINE" ]; then
	echo "supervise line already in $PERSIST"
	supervised=1
elif [ "$edit_persist" = 1 ]; then
	# One line, found by its marker; inserted before a top-level "exit",
	# appended otherwise.
	remote <<EOF
set -e
P=$PERSIST
T=\$P.udeco-tmp
MARK='$MARK'
LINE='$LINE'
awk -v mark="\$MARK" -v line="\$LINE" '
	index(\$0, mark) { next }
	!done && /^[ \t]*exit([ \t;]|\$)/ { print line; done = 1 }
	{ print }
	END { if (!done) print line }
' "\$P" >"\$T"
# every line but ours must be unchanged: dropbear/telnet byte for byte, and
# nothing else lost or added
if [ "\$(grep -E 'dropbear|telnet' "\$P" | grep -vF "\$MARK")" != "\$(grep -E 'dropbear|telnet' "\$T" | grep -vF "\$MARK")" ] ||
	[ "\$(grep -vF "\$MARK" "\$P")" != "\$(grep -vF "\$MARK" "\$T")" ] ||
	[ "\$(grep -cF "\$MARK" "\$T")" != 1 ]; then
	rm -f "\$T"
	echo "deco-ap: editing \$P would change other lines; left it alone" >&2
	exit 1
fi
mode=\$(stat -c %a "\$P" 2>/dev/null || echo 755)
chmod "\$mode" "\$T"
mv "\$T" "\$P"
echo "supervise line written to \$P (--edit-persist)"
EOF
	supervised=1
else
	echo
	echo "SUPERVISION NEEDS YOUR APPROVAL. $PERSIST is yours and was not changed."
	if [ -n "$pf_supervise" ]; then
		echo "Replace its line containing '$MARK' with exactly:"
	elif [ "$pf_exit" != 0 ]; then
		echo "Add this one line before its first top-level 'exit':"
	else
		echo "Add this one line at its end:"
	fi
	echo
	echo "$LINE"
	echo
	echo "or re-run with --edit-persist to have this script make exactly that change."
	echo "Until then nothing restarts the agent after a crash or a reboot."
fi

# --- 6. start ----------------------------------------------------------------
rollback="ssh -i $KEY root@$ip \"sed -i '/udeco-ap supervise (deploy\\/deco-ap.sh)/d' $PERSIST; rm -f $START; kill \\\$(pidof udeco-ap) 2>/dev/null; reboot\""
if [ "$no_start" = 1 ]; then
	if [ "$supervised" = 1 ]; then
		echo "not starting (--no-start); the supervise line starts it within a minute"
	else
		echo "not starting (--no-start)"
	fi
else
	remote <<EOF
if pidof udeco-ap >/dev/null 2>&1; then
	echo "agent already running (pid \$(pidof udeco-ap))"
	exit 0
fi
( sh $START </dev/null >/dev/null 2>&1 & )
sleep 3
if pidof udeco-ap >/dev/null 2>&1; then
	echo "agent running (pid \$(pidof udeco-ap))"
else
	echo "deco-ap: the agent is not running; its log:" >&2
fi
logread 2>/dev/null | grep 'udeco-ap' | tail -n 15
EOF
fi
checklist
echo
echo "Rollback (one command: drops the supervise line and the launcher, stops the agent, reboots to stock TP-Link):"
echo "  $rollback"
