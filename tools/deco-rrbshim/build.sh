#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-or-later
#
# build.sh [OUT]: builds udeco_rrb.so (udeco_rrb.c: the LD_PRELOAD shim the
# Deco agent starts the X20's hostapd with, docs/deco/features/ft-sae.md)
# in Docker (./Dockerfile) into OUT (default internal/bcmwifi/rrbshim,
# where the agent embeds it). The build is reproducible; CI rebuilds it and
# fails when the committed file differs.
set -eu
cd "$(dirname "$0")/../.."
OUT=${1:-internal/bcmwifi/rrbshim}
mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd)
IMG=udeco-armel-build
docker build -q --platform linux/amd64 -t $IMG tools/deco-rrbshim >/dev/null
docker run --rm --platform linux/amd64 -v "$PWD"/tools/deco-rrbshim:/src:ro -v "$OUT":/out $IMG sh -c '
	set -e
	cd /tmp
	arm-linux-gnueabi-gcc -O2 -Wall -Wextra -Werror -fPIC -shared -fno-stack-protector \
		-march=armv7-a -mfloat-abi=soft -Wl,--build-id=none -Wl,-z,relro \
		-o udeco_rrb.so /src/udeco_rrb.c
	arm-linux-gnueabi-strip --strip-unneeded udeco_rrb.so
	cp udeco_rrb.so /out/udeco_rrb.so
	sha256sum udeco_rrb.so'
