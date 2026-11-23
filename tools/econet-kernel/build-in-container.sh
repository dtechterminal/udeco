#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Runs inside the image of ./Dockerfile (build-modules.sh starts it), with
# the repository at /src (read-only) and the output directory at /out.
# Builds the JioFiber JCOW414's two optional kernel modules:
#
#   mt7603roam.ko  MediaTek's MT7603 driver (module mt76x3_ap) from
#                  padavan-ng, pinned below, with tools/mt7603/mt7603roam.patch
#   udeco_rl.ko    the agent's speed-limit policer (tools/udeco_rl)
#
# against vanilla linux-3.18.21 from kernel.org (pinned by sha256) with the
# unit's config (linux-3.18.21.config) and its sk_buff layout (econet_skb.py).
# SOURCE_DATE_EPOCH (from build-modules.sh) fixes the driver's __DATE__ and
# __TIME__, so the same commit builds the same bytes anywhere.
set -eu

KVER=3.18.21
KSHA=dc43a66adc474bf737df7789f069c2cb08b250df49393409f7ebe5570a9ca478
PARCHIVE=https://gitlab.com/api/v4/projects/hadzhioglu%2Fpadavan-ng/repository/archive.tar.gz
PCOMMIT=6c0edcbd9ae21001ca43055d185dec5ad402b4ab # branch mt7603_4.1.2.0
PDIR=trunk/proprietary/rt_wifi/rtpci/4.1.X.X
PTREE=0d8ba750d469cd785641bd22fac2de848f0d7f73 # git tree of $PDIR at $PCOMMIT
: "${SOURCE_DATE_EPOCH:?set by build-modules.sh}"
export SOURCE_DATE_EPOCH ARCH=mips CROSS_COMPILE=mipsel-linux-gnu-
W=/work
K=$W/linux-$KVER
mkdir -p $W && cd $W

echo "== kernel: linux-$KVER"
[ -f /cache/linux-$KVER.tar.xz ] && cp /cache/linux-$KVER.tar.xz . ||
	curl -sSfLo linux-$KVER.tar.xz https://cdn.kernel.org/pub/linux/kernel/v3.x/linux-$KVER.tar.xz
echo "$KSHA  linux-$KVER.tar.xz" | sha256sum -c -
[ -d /cache ] && [ -w /cache ] && cp linux-$KVER.tar.xz /cache/ 2>/dev/null || true
tar xJf linux-$KVER.tar.xz
# 3.18 predates gcc 7; gcc 5's header is the one that applies
cp $K/include/linux/compiler-gcc5.h $K/include/linux/compiler-gcc7.h
python3 /src/tools/econet-kernel/econet_skb.py $K/include/linux/skbuff.h
cp /src/tools/econet-kernel/linux-$KVER.config $K/.config

echo "== MT7603 source: padavan-ng $PCOMMIT"
# GitLab's archive of the one directory; its content is checked by the git
# tree hash it has in that commit (git add + write-tree of what unpacked)
[ -f /cache/padavan-$PCOMMIT.tgz ] && cp /cache/padavan-$PCOMMIT.tgz padavan.tgz ||
	curl -sSfLo padavan.tgz "$PARCHIVE?sha=$PCOMMIT&path=$PDIR"
mkdir padavan && tar xzf padavan.tgz -C padavan --strip-components=1
(cd padavan/$PDIR && git init -q . && git add -A && t=$(git write-tree) && rm -rf .git &&
	[ "$t" = $PTREE ]) || { echo "padavan-ng: the archive of $PDIR is not tree $PTREE" >&2; exit 1; }
[ -d /cache ] && [ -w /cache ] && cp padavan.tgz /cache/padavan-$PCOMMIT.tgz 2>/dev/null || true
cd $W
D=$K/drivers/net/wireless/ralink
mkdir -p $D
cp -a padavan/$PDIR/mt76x3 padavan/$PDIR/mt76x3_ap $D/
(cd $D && patch -s -p1 < /src/tools/mt7603/mt7603roam.patch)
cat >> $K/drivers/net/wireless/Kconfig <<'KC'

config RT_FIRST_IF_MT7603E
	bool "MT7603E as first interface"
	default y
config SECOND_IF_NONE
	bool
	default y
source "drivers/net/wireless/ralink/mt76x3/Kconfig"
KC

echo "== configure"
cd $K
scripts/config -e RT_FIRST_IF_MT7603E -m MT7603E_RLT_WIFI -e MT7603E_WIFI_MODE_AP -m MT7603E_RLT_AP_SUPPORT \
	-e MT7603E_MBSS_SUPPORT -e MT7603E_WDS_SUPPORT -e MT7603E_DOT11W_PMF_SUPPORT -e MT7603E_WPA3_SUPPORT \
	-e MT7603E_OWE_SUPPORT -e MT7603E_DOT11K_RRM_SUPPORT -e MT7603E_WNM_SUPPORT -e MT7603E_APCLI_SUPPORT \
	-e MT7603E_MAC_REPEATER_SUPPORT -d MT7603E_ACL_V2_SUPPORT -d MT7603E_RTMP_FLASH_SUPPORT \
	-d MT7603E_LLTD_SUPPORT -e MT7603E_UAPSD -e MT7603E_DOT11R_FT_SUPPORT -d MT7603E_HOTSPOT \
	-d MT7603E_PASSPOINT_R2
make -s olddefconfig
make -s modules_prepare

strip_out() { # strip_out KO NAME: stripped copy, gzip and the imports list in /out
	mipsel-linux-gnu-strip --strip-debug -o /out/$2.ko "$1"
	gzip -9 -n -c /out/$2.ko > /out/$2.ko.gz
	mipsel-linux-gnu-nm -u /out/$2.ko | awk '{print $2}' > /out/$2.undef
	echo "  $2.ko: $(wc -c < /out/$2.ko) bytes, $(wc -l < /out/$2.undef) imports, $(strings /out/$2.ko | grep '^vermagic=')"
}

echo "== build mt7603roam.ko"
make -j"$(nproc)" KCFLAGS="-Wno-error=date-time -DCONFIG_RA_NAT_NONE -DCONFIG_RT_FIRST_IF_RF_OFFSET=0x40000 -DCONFIG_RT_SECOND_IF_RF_OFFSET=0x48000" \
	M=drivers/net/wireless/ralink/mt76x3_ap modules > $W/mt7603.log 2>&1 || { grep -E "error|Error" $W/mt7603.log | head -40; exit 1; }
strip_out drivers/net/wireless/ralink/mt76x3_ap/mt76x3_ap.ko mt7603roam

echo "== build udeco_rl.ko"
mkdir $W/rl && cp /src/tools/udeco_rl/udeco_rl.c /src/tools/udeco_rl/Makefile $W/rl/
make -s M=$W/rl KCFLAGS="-Werror" modules
strip_out $W/rl/udeco_rl.ko udeco_rl

cd /out && sha256sum mt7603roam.ko mt7603roam.ko.gz udeco_rl.ko udeco_rl.ko.gz > SHA256SUMS && cat SHA256SUMS
