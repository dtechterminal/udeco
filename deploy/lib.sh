# SPDX-License-Identifier: GPL-2.0-or-later
#
# What the deploy scripts share. Sourced (bash) by deploy/deco-ap.sh,
# deploy/jio-ap.sh and deploy/unraid.sh on the deploying machine, with
#
#   . "$(dirname "$0")/lib.sh"
#
# before they change directory. It is never copied to a unit: what runs
# there (deploy/jio-start.sh, and the launcher deploy/deco-ap.sh writes)
# stays whole on its own, and Go tests hold it to the values here
# (cmd/udeco-ap deploy_ssot_test.go).

# SITE_GATEWAY is the site's gateway, which runs the UniFi controller too
# (a UCG): the controller of a new Deco config (deploy/deco-ap.sh) and the
# host that serves the Garage AP its download (deploy/jio-ap.sh), unless an
# option names another.
SITE_GATEWAY=192.168.0.1

# WAIT_EXIT (s) is how long a deploy waits for a running agent to exit
# after SIGTERM. The agent finishes the Wi-Fi job it is in first, and one
# job is at most 5 min (defaultJobTimeout in cmd/udeco-ap/agent.go;
# TestDeployWaitsForAJob holds this to it). No script kills the agent after
# the wait.
WAIT_EXIT=330

# header_text FILE [FIRST]: FILE's leading comment block from line FIRST
# (3 unless given: past the #! and SPDX lines) to its last line, without
# the "# ". It is the usage text of each script.
header_text() {
	awk -v first="${2:-3}" 'NR >= first { if (!/^#/) exit; sub(/^# ?/, ""); print }' "$1"
}

# is_ipv4 ADDR: four decimal octets, none above 255.
is_ipv4() {
	[[ $1 =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] || return 1
	local o
	for o in "${BASH_REMATCH[@]:1}"; do ((10#$o <= 255)) || return 1; done
}

# md5_local FILE, size_local FILE (bytes) and kb_local FILE (kB, rounded
# up): of a file on this machine (md5sum on Linux, md5 on macOS).
md5_local() {
	if command -v md5sum >/dev/null 2>&1; then md5sum "$1" | cut -d' ' -f1; else md5 -q "$1"; fi
}
size_local() { wc -c <"$1" | tr -d ' '; }
kb_local() { echo $((($(size_local "$1") + 1023) / 1024)); }

# build_agent OUT GOARCH=... [GOARM=...|GOMIPS=...]: the release build of
# the agent (cmd/udeco-ap) for a unit, run from the repository root: static
# (CGO off) and stripped. -trimpath and the empty build id keep this
# machine's paths and the build's own id out of the binary: a deploy
# compares its md5 with the unit's to tell whether the agent changed.
build_agent() {
	local out=$1
	shift
	env GOOS=linux CGO_ENABLED=0 "$@" \
		go build -trimpath -ldflags '-s -w -buildid=' -o "$out" ./cmd/udeco-ap
}
