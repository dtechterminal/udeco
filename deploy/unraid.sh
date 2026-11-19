#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Build the udeco image on the Unraid host and run it (docs/deco/README.md).
# Run from the repository root on any machine with ssh access to the host:
#
#   deploy/unraid.sh build      copy the source to the host and build udeco:latest there
#   deploy/unraid.sh discover   TDP only: who answers, does the owner hash match (no login)
#   deploy/unraid.sh print      ONE SSH login, one read-only poll, JSON to stdout (no UniFi traffic);
#                               extra flags go to udeco, e.g. print -only devices,speeds,iot,clients -trace -print-timeout 150s
#   deploy/unraid.sh run        build, then (re)start the daemon container
#   deploy/unraid.sh logs       follow the daemon's log
#   deploy/unraid.sh stop       stop and remove the daemon container
#
# Environment: UNRAID_HOST (default root@192.168.0.4; "local" when run on the
# host itself), APPDATA (default /mnt/osssd/appdata/unifi-deco).
set -euo pipefail

HOST=${UNRAID_HOST:-root@192.168.0.4}
APPDATA=${APPDATA:-/mnt/osssd/appdata/unifi-deco}
SRC=${UDECO_SRC:-/tmp/udeco-src}
IMAGE=udeco:latest
NAME=udeco
RUNAS=99:100 # Unraid nobody:users; the image runs as this user

cd "$(dirname "$0")/.."

remote() {
	if [ "$HOST" = local ]; then
		bash -c "$1"
	else
		ssh -o BatchMode=yes "$HOST" "$1"
	fi
}

build() {
	echo "copying the source to $HOST:$SRC"
	local files=(Dockerfile .dockerignore go.mod go.sum cmd internal)
	if [ "$HOST" = local ]; then
		[ "$(pwd)" = "$SRC" ] || { rm -rf "$SRC" && mkdir -p "$SRC" && tar -cf - "${files[@]}" | tar -xf - -C "$SRC"; }
	else
		tar -cf - "${files[@]}" | ssh -o BatchMode=yes "$HOST" "rm -rf '$SRC' && mkdir -p '$SRC' && tar -xf - -C '$SRC'"
	fi
	echo "building $IMAGE on $HOST"
	remote "docker build -t '$IMAGE' '$SRC'"
}

# prepare makes the appdata directory and refuses to go on without a config
# and credentials. It never prints a credential.
prepare() {
	remote "set -e
mkdir -p '$APPDATA'
chown $RUNAS '$APPDATA'
chmod 700 '$APPDATA'
if [ ! -f '$APPDATA/udeco.json' ]; then
	echo 'no $APPDATA/udeco.json: copy deploy/udeco.example.json there and edit it' >&2
	exit 1
fi
if [ ! -f '$APPDATA/credentials.env' ] && ! grep -q '\"password_file\"' '$APPDATA/udeco.json'; then
	echo 'no credentials: create $APPDATA/credentials.env (TPLINK_EMAIL=..., TPLINK_PASSWORD=...), chown $RUNAS, chmod 600' >&2
	exit 1
fi
chown -R $RUNAS '$APPDATA'
find '$APPDATA' -maxdepth 1 -type f \\( -name credentials.env -o -name '*.pass' -o -name 'tplink_password' \\) -exec chmod 600 {} +"
}

oneshot() {
	remote "docker run --rm --network host --user $RUNAS -v '$APPDATA:/data' '$IMAGE' -config /data/udeco.json $1"
}

case "${1:-}" in
build)
	build
	;;
discover)
	prepare
	oneshot -discover
	;;
print)
	shift
	for a in "$@"; do # passed through a remote shell: plain flags only
		[[ "$a" =~ ^[A-Za-z0-9,._:=-]+$ ]] || { echo "bad -print argument: $a" >&2; exit 2; }
	done
	prepare
	echo "this makes ONE SSH login to the Deco master (TP-Link lockout counts it)" >&2
	oneshot "-print $*"
	;;
run)
	build
	prepare
	remote "docker rm -f '$NAME' >/dev/null 2>&1 || true
docker run -d --name '$NAME' --restart unless-stopped --network host --user $RUNAS \
	-v '$APPDATA:/data' '$IMAGE' -config /data/udeco.json"
	echo "started; follow with: $0 logs"
	;;
logs)
	remote "docker logs -f --tail 200 '$NAME'"
	;;
stop)
	remote "docker rm -f '$NAME'"
	;;
*)
	sed -n '4,15p' "$0" | sed 's/^# \{0,1\}//'
	exit 2
	;;
esac
