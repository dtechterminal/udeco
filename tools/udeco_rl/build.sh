#!/bin/sh
# Builds udeco_rl.ko (and the 2.4 GHz driver with it) the way CI and the
# release do: tools/econet-kernel/build-modules.sh, in Docker. The module
# and its gzip land in tools/udeco_rl/out (OUT overrides).
set -e
H=$(cd "$(dirname "$0")" && pwd)
OUT=${OUT:-$H/out}
sh "$H/../econet-kernel/build-modules.sh" "$OUT"
