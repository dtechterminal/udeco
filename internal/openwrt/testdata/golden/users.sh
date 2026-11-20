set -e
M=/etc/unifi-openwrt/users; mkdir -p /etc/unifi-openwrt; touch $M; chmod 600 $M
want=" "
while IFS=: read -r n h; do
  [ -n "$n" ] || continue
  want="$want$n "
  if grep -q "^$n:" /etc/passwd && ! grep -qx "$n" $M; then echo "skip $n: existing account"; continue; fi
  grep -q "^$n:" /etc/passwd || echo "$n:x:0:0:UniFi device admin:/root:/bin/ash" >> /etc/passwd
  cur=$(grep "^$n:" /etc/shadow | cut -d: -f2 || true)
  if [ "$cur" != "$h" ]; then
    grep -v "^$n:" /etc/shadow > /etc/shadow.uow || true
    echo "$n:$h:$(( $(date +%s) / 86400 )):0:99999:7:::" >> /etc/shadow.uow
    chmod 600 /etc/shadow.uow; mv /etc/shadow.uow /etc/shadow
    echo "set $n"
  fi
  grep -qx "$n" $M || echo "$n" >> $M
done
for n in $(cat $M); do
  case "$want" in *" $n "*) continue;; esac
  grep -v "^$n:" /etc/passwd > /etc/passwd.uow; mv /etc/passwd.uow /etc/passwd; chmod 644 /etc/passwd
  grep -v "^$n:" /etc/shadow > /etc/shadow.uow; chmod 600 /etc/shadow.uow; mv /etc/shadow.uow /etc/shadow
  grep -vx "$n" $M > $M.uow || true; mv $M.uow $M
  echo "removed $n"
done
echo done