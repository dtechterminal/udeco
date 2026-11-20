
echo "=== board"; ubus call system board
echo "=== info"; ubus call system info
echo "=== route"; ip route show default
echo "=== cpu"; head -1 /proc/stat
echo "=== arp"; cat /proc/net/arp
for i in $(ubus call iwinfo devices | jsonfilter -e '@.devices[*]'); do
  case $i in uowscan*) continue;; esac
  p=$(cat /sys/class/net/$i/phy80211/name 2>/dev/null)
  echo "=== iface $i $p"; ubus call iwinfo info "{\"device\":\"$i\"}"
  echo "=== assoc $i"; ubus call iwinfo assoclist "{\"device\":\"$i\"}"
  echo "=== txpw $i"; ubus call iwinfo txpowerlist "{\"device\":\"$i\"}"
  echo "=== ant $i"; iw phy $p info | grep 'Available Antennas'
  echo "=== survey $i"; iw dev $i survey dump | grep -A6 'in use'
  echo "=== stats $i"; for f in rx_bytes tx_bytes rx_packets tx_packets rx_errors tx_errors rx_dropped tx_dropped; do printf '%s=%s\n' $f $(cat /sys/class/net/$i/statistics/$f); done
done
for e in $(ls /sys/class/net); do
  [ -e /sys/class/net/$e/phy80211 ] && continue
  case $e in lo|br-*|eth*) continue;; esac
  [ -e /sys/class/net/$e/device ] || continue # virtual (miireg, tunnels, VLANs)
  echo "=== port $e"; printf 'mac=%s\nspeed=%s\nduplex=%s\noper=%s\n' $(cat /sys/class/net/$e/address) $(cat /sys/class/net/$e/speed 2>/dev/null || echo 0) $(cat /sys/class/net/$e/duplex 2>/dev/null || echo unknown) $(cat /sys/class/net/$e/operstate)
  for f in rx_bytes tx_bytes rx_packets tx_packets; do printf '%s=%s\n' $f $(cat /sys/class/net/$e/statistics/$f); done
  b=$(readlink /sys/class/net/$e/brport/bridge 2>/dev/null)
  [ "${b##*/}" = br-lan ] && printf 'brport=%s\n' $(cat /sys/class/net/$e/brport/port_no)
done
echo "=== fdb"; hexdump -v -e '6/1 "%02x" 1/1 " %u" 1/1 " %u" 1/4 " %u" 1/1 " %u" 3/1 "" "\n"' /sys/class/net/br-lan/brforward 2>/dev/null
echo "=== lldp"; lldpctl -f json0 2>/dev/null || true
echo "=== lan"; ip -4 addr show br-lan; cat /sys/class/net/br-lan/address
