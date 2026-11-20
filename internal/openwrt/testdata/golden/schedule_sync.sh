set -e
mkdir -p /etc/unifi-openwrt
cat > /etc/unifi-openwrt/schedule.sh.new <<'SCRIPT'
#!/bin/sh
C=/etc/unifi-openwrt/schedule.conf
[ -s "$C" ] || exit 0
d=$(date +%a | tr A-Z a-z); t=$(date +%H%M)
changed=0
for l in $(awk -v d="$d" -v t="$t" '
  { if (!($1 in mode)) mode[$1] = $2
    if ($3 == d) { a = $4 + 0; b = $5 + 0; tt = t + 0
      if (a <= b ? (tt >= a && tt <= b) : (tt >= a || tt <= b)) win[$1] = 1 } }
  END { for (s in mode) { up = (mode[s] == "on") ? (s in win) : !(s in win); print s ":" up } }' "$C"); do
  sec=${l%%:*}; up=${l##*:}
  want=1; [ "$up" = 1 ] && want=0
  cur=$(uci -q get wireless.$sec.disabled || echo 0)
  if [ "$cur" != "$want" ]; then
    uci set wireless.$sec.disabled=$want; changed=1
    logger -t unifi-openwrt "schedule: $sec $( [ $want = 0 ] && echo on || echo off )"
  fi
done
[ $changed = 1 ] && { uci commit wireless; wifi reload; }
exit 0
SCRIPT
chmod 755 /etc/unifi-openwrt/schedule.sh.new
mv /etc/unifi-openwrt/schedule.sh.new /etc/unifi-openwrt/schedule.sh
printf '%s' 'unifi_radio0_12 on - 0 0
unifi_radio0_12 on mon 0800 0900
' > /etc/unifi-openwrt/schedule.conf
touch /etc/crontabs/root
old=$(cat /etc/crontabs/root)
grep -v '# unifi-openwrt schedule' /etc/crontabs/root > /etc/crontabs/root.uow || true
[ -s /etc/unifi-openwrt/schedule.conf ] && echo '* * * * * /etc/unifi-openwrt/schedule.sh # unifi-openwrt schedule' >> /etc/crontabs/root.uow
mv /etc/crontabs/root.uow /etc/crontabs/root
[ "$old" = "$(cat /etc/crontabs/root)" ] && pgrep crond >/dev/null || /etc/init.d/cron restart
/etc/unifi-openwrt/schedule.sh
echo ok