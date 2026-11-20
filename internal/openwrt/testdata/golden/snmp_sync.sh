set -e
umask 077
f=/etc/unifi-openwrt/snmpd.conf
cat > "$f.new"
if [ ! -s "$f.new" ]; then
	rm -f "$f.new"
	[ -e "$f" ] || { echo same; exit 0; }
	rm -f "$f"; /etc/init.d/unifi-openwrt reload; echo changed; exit 0
fi
if cmp -s "$f.new" "$f"; then rm -f "$f.new"; echo same; exit 0; fi
mv "$f.new" "$f"
[ -x /usr/sbin/snmpd ] || { echo nosnmpd; exit 0; }
/etc/init.d/unifi-openwrt reload
echo changed