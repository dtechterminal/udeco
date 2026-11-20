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
mkdir -p /tmp/unifi-portal/cgi-bin
cat > /tmp/unifi-portal/cgi-bin/r <<'CGI'
#!/bin/sh
ip="$REMOTE_ADDR"
mac=$(awk -v ip="$ip" '$1==ip {print $4}' /proc/net/arp | head -1)
ap=$(cat /sys/class/net/br-lan/address)
ssid=""
for o in $(ubus list 'hostapd.*'); do
  ubus call $o get_clients 2>/dev/null | grep -qi "\"$mac\"" && { ssid=$(ubus call $o get_status | jsonfilter -e @.ssid); break; }
done
enc() { printf '%s' "$1" | sed -e 's/%/%25/g' -e 's/ /%20/g' -e 's/&/%26/g' -e 's/?/%3F/g' -e 's/=/%3D/g' -e 's/#/%23/g' -e 's/+/%2B/g' -e 's/"/%22/g'; }
orig="http://$HTTP_HOST$REQUEST_URI"
loc="http://192.168.1.1:8880/guest/s/default/?id=$mac&ap=$ap&t=$(date +%s)&url=$(enc "$orig")&ssid=$(enc "$ssid")"
printf 'Status: 302 Found\r\nLocation: %s\r\nCache-Control: no-cache\r\nContent-Type: text/html\r\n\r\n<a href="%s">Login</a>\n' "$loc" "$loc"
CGI
chmod 755 /tmp/unifi-portal/cgi-bin/r
if ! { [ -f /var/run/unifi-portal.pid ] && kill -0 $(cat /var/run/unifi-portal.pid) 2>/dev/null; }; then
  uhttpd -f -p 0.0.0.0:8085 -h /tmp/unifi-portal -x /cgi-bin -E /cgi-bin/r -D -t 10 -T 5 -A 0 -N 50 &
  echo $! > /var/run/unifi-portal.pid
fi
