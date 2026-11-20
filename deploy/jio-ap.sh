#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Build the on-device agent cmd/udeco-ap for the Garage AP (a JioFiber
# JCOW414 run as a UniFi UAP-AC-Lite, platform jio-mtk) and replace the
# agent binary on it. The unit is reached by telnet only (dropbear and the
# Jio services are kept down), and it cannot reach this machine, so the
# gzip is served to it for a few minutes from the UCG.
#
#   JIO_TELNET_PW=... deploy/jio-ap.sh [options]
#   deploy/jio-ap.sh --build-only
#
# What it does, in order:
#   1. builds dist/udeco-ap-linux-mipsle (linux/mipsle GOMIPS=softfloat: the
#      EN7528 has no FPU; CGO off, -trimpath -s -w) and its gzip -9 copy;
#   2. preflight on the unit, read-only: MIPS, /flash2/udeco with start.sh
#      and udeco-ap.json, wget, room on /flash2 for one more copy;
#      it stops when the installed gzip is already this build;
#   3. copies the gzip to a fresh directory on the UCG, checks its md5 there
#      and serves that directory on <ucg>:<port> (python3 http.server,
#      killed on exit and by `timeout` in any case);
#   4. on the unit: wget to /flash2/udeco/udeco-ap.gz.new, checks the md5 of
#      the download and of what it unpacks to (refuses and removes it on a
#      mismatch: nothing installed changes);
#   5. keeps the installed gzip as udeco-ap.gz.prev (not when .prev is the
#      gateway guard's confirmed build and the installed one is not: the
#      guard's rollback target stays), renames the new one into
#      place, removes the unpacked /tmp/udeco-bin/udeco-ap (start.sh reuses
#      it otherwise, and would restart the old agent) and sends the running
#      agent SIGTERM (it finishes the job it is in and leaves Wi-Fi as it
#      is). start.sh unpacks and starts the new one 10 s after the old exits;
#   6. waits for the new agent (its unpacked md5 checked), checks that it is
#      still running 30 s later, shows its first log lines, and prints the
#      one rollback command.
#
# The config /flash2/udeco/udeco-ap.json is never changed. A new binary that
# rejects the installed config crash-loops (start.sh restarts it every
# 10 s; Wi-Fi keeps running, the AP shows offline in UniFi): step 6 catches
# that, and the rollback puts the previous binary back.
#
# Options:
#   --host IP        the unit (default 192.168.0.51; another needs --force-host)
#   --force-host     allow a unit other than 192.168.0.51
#   --ucg IP         the gateway that serves the file (default 192.168.0.1;
#                    root SSH by key, as for the controller's API)
#   --port N         the UCG port to serve on (default 18080)
#   --preflight      build and run the read-only preflight, then stop
#   --force          install even when the unit already has this build
#   --build-only     build dist/udeco-ap-linux-mipsle{,.gz} and stop
#
# Login lock: while the controller is healthy and its Device SSH
# Authentication is off, the running agent drops new telnet connections
# (docs/deco/features/login-lock.md). A refused or silent :23 prints how to
# open it (Device SSH on in UniFi, wait ~1 min, retry; off again after).
#
# Environment: JIO_TELNET_PW, the unit's telnet root password (GPW is read
# when it is unset). It is passed to the telnet helper through the
# environment only: never on a command line, in a file or in the output.
#
# Disruption: the agent restart takes the AP's UniFi connection away for
# about 20 s. Wi-Fi is not restarted by the restart itself; the new agent
# restarts a radio only if the profile it writes for that radio differs
# byte for byte from the one installed (or the radio does not serve its
# plan). A build that adds profile keys (DTIM, 802.11k/v, U-APSD, ...)
# usually changes the profile, so its first provision restarts each radio
# that serves an SSID once, and every client of that radio reassociates.
# A rollback to an older build (by hand or by the guard) does the same.
set -euo pipefail

ALLOWED_HOST=192.168.0.51
DIR=/flash2/udeco
GZ=$DIR/udeco-ap.gz
RAM=/tmp/udeco-bin
OUT=dist/udeco-ap-linux-mipsle
MIN_SPARE_KB=1024 # /flash2 free after the download, beyond the new gzip
WAIT_EXIT=330     # s: the old agent finishing its job (one Wi-Fi job is at most 5 min)

host=$ALLOWED_HOST ucg=192.168.0.1 port=18080
force_host=0 force=0 preflight_only=0 build_only=0

usage() { sed -n '3,67p' "$0" | sed 's/^# \{0,1\}//' >&2; exit 2; }
die() { echo "jio-ap: $*" >&2; exit 1; }

is_ipv4() {
	[[ $1 =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] || return 1
	local o
	for o in "${BASH_REMATCH[@]:1}"; do ((10#$o <= 255)) || return 1; done
}

while [ $# -gt 0 ]; do
	case $1 in
	--host) [ $# -ge 2 ] || usage; host=$2; shift ;;
	--ucg) [ $# -ge 2 ] || usage; ucg=$2; shift ;;
	--port) [ $# -ge 2 ] || usage; port=$2; shift ;;
	--force-host) force_host=1 ;;
	--force) force=1 ;;
	--preflight) preflight_only=1 ;;
	--build-only) build_only=1 ;;
	-h | --help) usage ;;
	*) echo "jio-ap: unknown argument $1" >&2; usage ;;
	esac
	shift
done
is_ipv4 "$host" || die "--host $host: want an IPv4 address"
is_ipv4 "$ucg" || die "--ucg $ucg: want an IPv4 address"
[[ $port =~ ^[0-9]{4,5}$ ]] && ((port >= 1024 && port <= 65535)) || die "--port $port: want 1024-65535"
if [ "$host" != "$ALLOWED_HOST" ] && [ "$force_host" != 1 ]; then
	die "refusing $host: only $ALLOWED_HOST (the Garage AP) runs platform jio-mtk; pass --force-host to override"
fi

cd "$(dirname "$0")/.."

md5_local() {
	if command -v md5sum >/dev/null 2>&1; then md5sum "$1" | cut -d' ' -f1; else md5 -q "$1"; fi
}

# --- 1. build -----------------------------------------------------------------
echo "building $OUT (linux/mipsle softfloat, static, stripped)"
mkdir -p dist
GOOS=linux GOARCH=mipsle GOMIPS=softfloat CGO_ENABLED=0 \
	go build -trimpath -ldflags '-s -w -buildid=' -o "$OUT" ./cmd/udeco-ap
gzip -9 -n -c "$OUT" >"$OUT.gz"
bin_md5=$(md5_local "$OUT")
gz_md5=$(md5_local "$OUT.gz")
gz_bytes=$(wc -c <"$OUT.gz" | tr -d ' ')
gz_kb=$(((gz_bytes + 1023) / 1024))
echo "  $(wc -c <"$OUT" | tr -d ' ') bytes, md5 $bin_md5; gzip $gz_bytes bytes, md5 $gz_md5"
[ "$build_only" = 1 ] && exit 0

PW=${JIO_TELNET_PW:-${GPW:-}}
[ -n "$PW" ] || die "set JIO_TELNET_PW to the unit's telnet root password (it is read from the environment only)"
export JIO_TELNET_PW=$PW
unset PW

# ap SCRIPT [TIMEOUT]: runs SCRIPT with sh on the unit over telnet and
# prints its output; returns SCRIPT's exit status. The unit's interactive
# ash would mangle a pasted multi-line script (TAB completes, lines are
# capped), so the script is written to a file in /tmp with short printf
# lines, run, and removed. The password comes from the environment
# (JIO_TELNET_PW), never from argv.
TELNET_PY=$(
	cat <<'PY'
import os, random, re, socket, sys, time
host, tmo = sys.argv[1], float(sys.argv[2])
script = sys.stdin.read()
try:
    s = socket.create_connection((host, 23), timeout=10)
except OSError as e:
    sys.stderr.write("jio-ap: telnet %s:23: %s\n" % (host, e))
    if isinstance(e, (ConnectionRefusedError, TimeoutError, socket.timeout)):
        # what the agent's login lock looks like from here
        # (docs/deco/features/login-lock.md); never toggled from here
        sys.stderr.write("jio-ap: login lock: turn on Device SSH in UniFi (Settings > System > Advanced > Device SSH Authentication), wait ~1 min, retry\n")
    sys.exit(1)
buf = b""
def clean(d):
    out, i = bytearray(), 0
    while i < len(d):
        b = d[i]
        if b != 255:
            out.append(b); i += 1; continue
        if i + 1 >= len(d):
            break
        c = d[i + 1]
        if c in (251, 252, 253, 254) and i + 2 < len(d):
            # refuse every option: DO/DONT -> WONT, WILL/WONT -> DONT
            s.sendall(bytes([255, 252 if c in (253, 254) else 254, d[i + 2]]))
            i += 3; continue
        if c == 250:  # subnegotiation: skip to IAC SE
            j = d.find(b"\xff\xf0", i + 2)
            i = len(d) if j < 0 else j + 2; continue
        if c == 255:
            out.append(255)
        i += 2
    return bytes(out)
def until(pat, t):
    global buf
    end = time.time() + t
    while time.time() < end:
        m = re.search(pat, buf)
        if m:
            r = buf[:m.end()]; buf = buf[m.end():]; return r
        s.settimeout(max(0.1, end - time.time()))
        try:
            d = s.recv(65536)
        except socket.timeout:
            continue
        if not d:
            break
        buf += clean(d)
    sys.exit("jio-ap: telnet: timed out waiting for %r" % pat)
def run(line, mark, t):
    s.sendall(line.encode() + b"; echo __" + mark.encode() + b"''__\r\n")
    return until(("__" + mark + "__\r?\n").encode(), t)
def enc(t):
    return t.replace("\\", "\\\\").replace("%", "%%").replace("'", "'\\''").replace("\n", "\\n").replace("\t", "\\t")
until(rb"login: ?$", 20); s.sendall(b"root\r\n")
until(rb"[Pp]assword: ?$", 20); s.sendall(os.environ["JIO_TELNET_PW"].encode() + b"\r\n")
until(rb"(#|\$|>) ?$", 20)
one = script.strip()
if "\n" not in one and "\t" not in one and len(one) < 900:
    # one short line (the read-only preflight): typed as it is, no file
    out = run("echo __S''__; " + one + "; echo __RC''__=$?", "E", tmo)
else:
    f = "/tmp/jio-ap.%08x" % random.getrandbits(32)
    run("umask 077; : > " + f, "K", 20)
    for k in range(0, len(script), 120):
        run("printf '" + enc(script[k:k + 120]) + "' >> " + f, "K", 20)
    out = run("echo __S''__; sh " + f + "; echo __RC''__=$?; rm -f " + f, "E", tmo)
s.sendall(b"exit\r\n"); s.close()
out = out.decode(errors="replace").replace("\r", "")
body = out.split("__S__\n", 1)[-1]
body, rc = body.rsplit("__RC__=", 1)
sys.stdout.write(body)
sys.exit(int(rc.split()[0]))
PY
)
ap() { python3 -c "$TELNET_PY" "$host" "${2:-60}" <<<"$1"; }
ucg_sh() { ssh -o BatchMode=yes -o ConnectTimeout=10 "root@$ucg" "$@"; }

# --- 2. preflight (read-only) ---------------------------------------------------
echo "checking $host (read-only)"
# one line, so nothing is written on the unit (see ap)
pre=$(ap "echo ARCH \$(uname -m); for f in $DIR/start.sh $DIR/udeco-ap.json; do [ -f \$f ] && echo HAVE \$f; done; \
W=\$(which wget 2>/dev/null || ls /pfrm2.0/bin/wget 2>/dev/null); echo WGET \$W; \
echo FREE \$(df -k /flash2 | tail -n 1 | awk '{print \$(NF-2)}'); \
[ -f $GZ ] && echo OLD \$(md5sum $GZ | cut -d' ' -f1); \
P=\$(cat $RAM/agent.pid 2>/dev/null); [ -n \"\$P\" ] && [ -d /proc/\$P ] && echo PID \$P; \
ps | grep -q '[s]h $DIR/start.sh' && echo SUPERVISED 1; true") || die "preflight: telnet to $host failed"
val() { printf '%s\n' "$pre" | sed -n "s/^$1 //p" | head -n 1; }
arch=$(val ARCH) wget_path=$(val WGET) free=$(val FREE) old_md5=$(val OLD) old_pid=$(val PID) supervised=$(val SUPERVISED)
case $arch in mips*) ;; *) die "the unit is '${arch:-unknown}', not MIPS: wrong unit?" ;; esac
printf '%s\n' "$pre" | grep -qx "HAVE $DIR/start.sh" || die "$DIR/start.sh is missing: install the supervisor first (see the garage notes); nothing changed"
printf '%s\n' "$pre" | grep -qx "HAVE $DIR/udeco-ap.json" || die "$DIR/udeco-ap.json is missing; nothing changed"
[ -n "$wget_path" ] || die "no wget on the unit; nothing changed"
[ -n "$free" ] && [ "$free" -ge $((gz_kb + MIN_SPARE_KB)) ] || die "/flash2 has ${free:-?} kB free, need $((gz_kb + MIN_SPARE_KB)); nothing changed"
[ "$supervised" = 1 ] || die "start.sh is not running on the unit: nothing would start the new agent; nothing changed"
echo "  $arch, /flash2 $free kB free, agent pid ${old_pid:-none}, installed gzip ${old_md5:-none}"
if [ "$old_md5" = "$gz_md5" ] && [ "$force" != 1 ]; then
	echo "the unit already has this build (gzip md5 $gz_md5); nothing to do (--force reinstalls)"
	exit 0
fi
if [ "$preflight_only" = 1 ]; then
	echo "preflight OK (--preflight: nothing changed)"
	exit 0
fi

# --- 3. serve the gzip from the UCG ----------------------------------------------
srv=$(ucg_sh 'd=$(mktemp -d /tmp/udeco-serve.XXXXXX) && chmod 755 "$d" && echo "$d"') || die "ssh root@$ucg failed"
[[ $srv =~ ^/tmp/udeco-serve\.[A-Za-z0-9]+$ ]] || die "unexpected directory from the UCG: $srv"
cleanup() {
	ucg_sh "[ -f $srv/http.pid ] && kill \$(cat $srv/http.pid) 2>/dev/null; rm -rf $srv" || echo "jio-ap: could not clean $srv on $ucg" >&2
}
trap cleanup EXIT
ucg_sh "cat > $srv/udeco-ap.gz" <"$OUT.gz"
got=$(ucg_sh "md5sum $srv/udeco-ap.gz | cut -d' ' -f1")
[ "$got" = "$gz_md5" ] || die "md5 on the UCG is $got, want $gz_md5"
# python3's http.server, only this directory, only the LAN address, at
# most 10 minutes even if this script dies before its cleanup
ucg_sh "cd $srv || exit 1; nohup timeout 600 python3 -m http.server $port --bind $ucg </dev/null >/dev/null 2>&1 & echo \$! > $srv/http.pid"
url=http://$ucg:$port/udeco-ap.gz
echo "serving $url"

# --- 4. download on the unit and check it -----------------------------------------
echo "downloading on $host"
ap "
rm -f $GZ.new
i=0
until $wget_path -q -O $GZ.new $url; do
	i=\$((i + 1)); [ \$i -lt 5 ] || { rm -f $GZ.new; echo 'jio-ap: wget failed'; exit 1; }
	sleep 2
done
g=\$(md5sum $GZ.new | cut -d' ' -f1)
b=\$(gunzip -c $GZ.new | md5sum | cut -d' ' -f1)
if [ \"\$g\" != $gz_md5 ] || [ \"\$b\" != $bin_md5 ]; then
	rm -f $GZ.new
	echo \"jio-ap: md5 mismatch on the unit (gzip \$g, unpacked \$b); removed the download\"
	exit 1
fi
echo \"  download verified (gzip \$g, unpacked \$b)\"
" 180 || die "download failed; the installed agent is unchanged"

# --- 5. install and restart ---------------------------------------------------------
echo "installing; restarting the agent (pid ${old_pid:-none})"
ap "
set -e
# the installed agent becomes .prev (not when it is this very build:
# --force), unless .prev is the guard's confirmed build (good.md5) and the
# installed one is not: that .prev (and the udeco-ap.json.prev that goes
# with it) stays the guard's rollback target (jio-start.sh)
cur=\$(md5sum $GZ 2>/dev/null | cut -d' ' -f1)
good=\$(cat $DIR/good.md5 2>/dev/null || true)
prev=\$(md5sum $GZ.prev 2>/dev/null | cut -d' ' -f1)
if [ -n \"\$good\" ] && [ \"\$prev\" = \"\$good\" ] && [ \"\$cur\" != \"\$good\" ]; then
	echo \"  $GZ.prev kept: it is the confirmed build \$good; the installed \${cur:-none} is not confirmed and is replaced without a copy\"
elif [ -n \"\$cur\" ] && [ \"\$cur\" != $gz_md5 ]; then
	cp -p $GZ $GZ.prev
fi
mv $GZ.new $GZ
rm -f $RAM/udeco-ap
P=\$(cat $RAM/agent.pid 2>/dev/null || true)
if [ -n \"\$P\" ] && [ -d /proc/\$P ]; then kill -TERM \$P; echo \"  SIGTERM to \$P\"; fi
" 60 || die "install step failed: check $GZ and $GZ.prev on the unit"

# --- 6. wait for the new agent ------------------------------------------------------
echo "waiting for the new agent (the old one may take up to ${WAIT_EXIT} s to finish its job)"
ap "
old=${old_pid:-0}
i=0
while :; do
	P=\$(cat $RAM/agent.pid 2>/dev/null)
	if [ -n \"\$P\" ] && [ \"\$P\" != \$old ] && [ -d /proc/\$P ] &&
		[ \"\$(md5sum $RAM/udeco-ap 2>/dev/null | cut -d' ' -f1)\" = $bin_md5 ]; then
		break
	fi
	i=\$((i + 1)); [ \$i -le $((WAIT_EXIT + 30)) ] || { echo 'jio-ap: no new agent came up'; exit 1; }
	sleep 1
done
echo \"  new agent pid \$P; checking it is still running in 30 s\"
sleep 30
[ -d /proc/\$P ] || { echo \"jio-ap: the new agent (pid \$P) exited within 30 s; its log:\"; tail -n 20 $RAM/agent.log; exit 1; }
echo '  running; the end of its log:'
tail -n 15 $RAM/agent.log
" $((WAIT_EXIT + 120)) || {
	echo "jio-ap: the new agent is not healthy. Roll back with the command below." >&2
	failed=1
}

echo
echo "Rollback (on the unit, telnet as root): cp -p $GZ.prev $GZ && { [ ! -f $DIR/udeco-ap.json.prev ] || cp -p $DIR/udeco-ap.json.prev $DIR/udeco-ap.json; } && rm -f $RAM/udeco-ap && kill \$(cat $RAM/agent.pid)"
[ "${failed:-0}" = 0 ] || exit 1
echo "deployed $gz_md5 to $host"
