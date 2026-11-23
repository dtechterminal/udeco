#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-or-later
#
# build-modules.sh [OUT]: builds the JioFiber JCOW414's optional kernel
# modules in Docker (./Dockerfile; build-in-container.sh says what and from
# which sources) into OUT (default dist/modules):
#
#   mt7603roam.ko{,.gz}  the rebuilt 2.4 GHz driver: WPA3, 802.11r/k/v
#   udeco_rl.ko{,.gz}    the speed-limit policer
#   SHA256SUMS
#
# Neither is needed to run the agent; deploy/jio-ap.sh installs them only
# when asked (--driver, --rate-limit-module). CI runs this same script, and
# the build is reproducible: SOURCE_DATE_EPOCH is the commit's time, so a
# local build of a tagged commit gives the release's bytes.
#
# MODULES_CACHE=DIR keeps the kernel tarball between runs.
set -eu
cd "$(dirname "$0")/../.."
OUT=${1:-dist/modules}
mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd)
SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct 2>/dev/null || echo 0)}
IMG=udeco-econet-build
docker build -q --platform linux/amd64 -t $IMG tools/econet-kernel >/dev/null
set -- -v "$PWD":/src:ro -v "$OUT":/out
[ -n "${MODULES_CACHE:-}" ] && mkdir -p "$MODULES_CACHE" && set -- "$@" -v "$(cd "$MODULES_CACHE" && pwd)":/cache
docker run --rm --platform linux/amd64 "$@" -e SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" $IMG sh /src/tools/econet-kernel/build-in-container.sh
