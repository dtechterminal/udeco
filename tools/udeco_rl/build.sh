#!/bin/sh
# Build udeco_rl.ko against the prepared EcoNet-layout 3.18.21 tree.
# Runs on the Mac: docker image mt7603build:latest (mipsel gcc 7.5), volume
# mtbuild with /b/linux-3.18.21 (configured, skbuff.h patched to the
# EcoNet layout by econet_skb.py). The tree is mounted read-only: an
# external module build (M=) writes only into its own directory.
set -e
H=$(cd "$(dirname "$0")" && pwd)
OUT=${OUT:-$H/out}
mkdir -p "$OUT"
docker run --rm -v mtbuild:/b:ro -v "$H":/src:ro -v "$OUT":/out mt7603build:latest sh -c '
set -e
rm -rf /tmp/m && mkdir /tmp/m && cp /src/udeco_rl.c /src/Makefile /tmp/m/
cd /b/linux-3.18.21
make -s ARCH=mips CROSS_COMPILE=mipsel-linux-gnu- M=/tmp/m KCFLAGS="-Werror" modules
cp /tmp/m/udeco_rl.ko /out/udeco_rl.ko
mipsel-linux-gnu-strip --strip-debug /out/udeco_rl.ko
mipsel-linux-gnu-nm -u /out/udeco_rl.ko | awk "{print \$2}" > /out/udeco_rl.undef
mipsel-linux-gnu-readelf -r -W /out/udeco_rl.ko | sed -n "/gnu.linkonce.this_module/,/^$/p" > /out/this_module.rel
mipsel-linux-gnu-modinfo /out/udeco_rl.ko 2>/dev/null || strings /out/udeco_rl.ko | grep -E "^(vermagic|license|parm)=" > /out/modinfo.txt
' > "$OUT/build.log" 2>&1 || { grep -v "requested image.s platform" "$OUT/build.log"; exit 1; }
gzip -9 -n -c "$OUT/udeco_rl.ko" > "$OUT/udeco_rl.ko.gz"
echo "built: $(wc -c < "$OUT/udeco_rl.ko") bytes, $(wc -l < "$OUT/udeco_rl.undef") imports"
