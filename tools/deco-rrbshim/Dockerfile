# SPDX-License-Identifier: GPL-2.0-or-later
#
# The toolchain the Deco X20's RRB shim is built with: Ubuntu 18.04's
# arm-linux-gnueabi gcc 7.5 (soft-float EABI5, as the Deco's glibc 2.26
# userland). Used by build.sh, locally and in CI.
#
# The archive is fetched over HTTPS (some networks block port 80). The
# image has no CA bundle yet, so the first fetch skips the TLS peer check;
# apt still verifies every index against Ubuntu's signing key.
FROM ubuntu:18.04
RUN sed -i 's|http://|https://|' /etc/apt/sources.list && \
	apt-get -o Acquire::https::Verify-Peer=false update && \
	DEBIAN_FRONTEND=noninteractive apt-get -o Acquire::https::Verify-Peer=false install -y --no-install-recommends \
	gcc-arm-linux-gnueabi libc6-dev-armel-cross binutils-arm-linux-gnueabi ca-certificates && rm -rf /var/lib/apt/lists/*
