# SPDX-License-Identifier: GPL-2.0-or-later
#
# The toolchain the JioFiber JCOW414's kernel modules are built with:
# Ubuntu 18.04's mipsel gcc 7.5 (a newer gcc cannot build 3.18.21), amd64
# (Ubuntu has no mipsel cross compiler for arm64 in 18.04). Used by
# build-modules.sh, locally and in CI.
#
# The archive is fetched over HTTPS (some networks block port 80). The
# image has no CA bundle yet, so the first fetch skips the TLS peer check;
# apt still verifies every index against Ubuntu's signing key, and once
# ca-certificates is installed nothing else is fetched.
FROM ubuntu:18.04
RUN sed -i 's|http://|https://|' /etc/apt/sources.list && \
	apt-get -o Acquire::https::Verify-Peer=false update && \
	DEBIAN_FRONTEND=noninteractive apt-get -o Acquire::https::Verify-Peer=false install -y --no-install-recommends \
	gcc-mipsel-linux-gnu binutils-mipsel-linux-gnu make bc python3 xz-utils ca-certificates curl \
	git file libc6-dev gcc patch && rm -rf /var/lib/apt/lists/*
