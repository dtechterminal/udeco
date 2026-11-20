set -e
mkdir -p /etc/unifi-openwrt
umask 077
cat > /etc/unifi-openwrt/mesh.conf.new
mv /etc/unifi-openwrt/mesh.conf.new /etc/unifi-openwrt/mesh.conf
# new file + rename: the running watcher keeps reading its own (old) inode
cat > /etc/unifi-openwrt/mesh.sh.new <<'SCRIPT'
#!/bin/sh
C=/etc/unifi-openwrt/mesh.conf
STA=unifi_mesh
wired() {
	for p in $(ubus call network.device status | jsonfilter -e '@["br-lan"]["bridge-members"][*]'); do
		case "$p" in phy*|wlan*|mesh*) continue ;; esac
		[ "$(cat /sys/class/net/$p/carrier 2>/dev/null)" = 1 ] && return 0
	done
	return 1
}
meshing() { [ "$(uci -q get wireless.$STA)" = wifi-iface ]; }
drop() {
	for i in $(ubus call network.wireless status | jsonfilter -e "@.*.interfaces[@.section='$STA'].ifname"); do ip link set "$i" down; done
	uci -q delete wireless.$STA; uci commit wireless; wifi reload
	logger -t unifi-mesh "wired uplink back: wireless uplink removed"
}
join() {
	uci batch <<UCI
set wireless.$STA=wifi-iface
set wireless.$STA.device='$MESH_RADIO'
set wireless.$STA.mode='sta'
set wireless.$STA.network='lan'
set wireless.$STA.ssid='$MESH_SSID'
set wireless.$STA.encryption='psk2+ccmp'
set wireless.$STA.key='$MESH_PSK'
set wireless.$STA.wds='1'
UCI
	# Mesh Parent (mesh.serial1/2): accept only the chosen parents' BSSIDs
	for a in $MESH_ACCEPT; do uci add_list wireless.$STA.bssid_whitelist="$a"; done
	uci commit wireless; wifi reload
	logger -t unifi-mesh "no wired uplink for 20 s: joining the mesh as a wireless uplink"
}
meshing && wired && drop
lost=0
while :; do
	# no config (meshing off in the UniFi, or -mesh-uplink off): no wireless uplink
	if [ ! -s "$C" ]; then
		lost=0
		meshing && drop
		sleep 5
		continue
	fi
	MESH_ACCEPT=
	. "$C"   # MESH_SSID MESH_PSK MESH_RADIO MESH_ACCEPT (written by the daemon; re-read each loop)
	if wired; then
		lost=0
		meshing && drop
	else
		lost=$((lost + 1))
		[ $lost -ge 20 ] && ! meshing && join
	fi
	sleep 1
done
SCRIPT
chmod 755 /etc/unifi-openwrt/mesh.sh.new
cmp -s /etc/unifi-openwrt/mesh.sh.new /etc/unifi-openwrt/mesh.sh && rm -f /etc/unifi-openwrt/mesh.sh.new || mv /etc/unifi-openwrt/mesh.sh.new /etc/unifi-openwrt/mesh.sh
# procd starts the "mesh" instance only if mesh.sh exists at service start:
# on the first sync, reload so it starts (unchanged instances keep running)
if [ "$(ubus call service list '{"name":"unifi-openwrt"}' | jsonfilter -e '@[*].instances.mesh.running')" != true ]; then
	/etc/init.d/unifi-openwrt reload
fi
echo ok