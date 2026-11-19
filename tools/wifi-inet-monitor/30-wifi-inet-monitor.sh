#!/bin/sh
# Wi-Fi client internet monitor (/data/wifi-inet-monitor): recreate its
# systemd timer after a firmware update wipes /etc/systemd/system.
cat > /etc/systemd/system/wifi-inet-monitor.service <<"U"
[Unit]
Description=Wi-Fi client internet monitor (reconnects broken clients, restarts lost Decos)
After=network-online.target
[Service]
Type=oneshot
WorkingDirectory=/tmp
ExecStart=/usr/bin/python3 /data/wifi-inet-monitor/wifi-inet-monitor.py
TimeoutStartSec=90
StandardOutput=null
U
cat > /etc/systemd/system/wifi-inet-monitor.timer <<"U"
[Unit]
Description=Run the Wi-Fi client internet monitor every 2 minutes
[Timer]
OnBootSec=4min
OnUnitActiveSec=2min
AccuracySec=10s
[Install]
WantedBy=timers.target
U
systemctl daemon-reload
systemctl enable --now wifi-inet-monitor.timer
