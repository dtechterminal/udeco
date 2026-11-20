if ! { [ -f /var/run/unifi-guest-dns.pid ] && kill -0 $(cat /var/run/unifi-guest-dns.pid) 2>/dev/null; }; then
  dnsmasq --conf-file=/dev/null --port=5300 --listen-address=192.168.1.2 --bind-interfaces --no-hosts --resolv-file=/tmp/resolv.conf.d/resolv.conf.auto --pid-file=/var/run/unifi-guest-dns.pid --user=dnsmasq --group=dnsmasq --cache-size=150 || exit 3
fi
nft -f - <<'NAT'
table ip unifi_guest_nat
delete table ip unifi_guest_nat
table ip unifi_guest_nat {
	chain prerouting { type nat hook prerouting priority dstnat; policy accept;
		meta mark & 0xc0000000 == 0x40000000 meta l4proto { tcp, udp } th dport 53 redirect to :5300
		meta mark & 0x30000000 == 0x10000000 tcp dport 80 redirect to :8085
		meta mark & 0x30000000 == 0x10000000 tcp dport 8882 redirect to :8882
	}
}
NAT
[ -f /var/run/unifi-portal.pid ] && kill $(cat /var/run/unifi-portal.pid) 2>/dev/null; rm -f /var/run/unifi-portal.pid; true
