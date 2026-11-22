// SPDX-License-Identifier: GPL-2.0-or-later

// Package mtkft is 802.11r, 802.11k and 802.11v for the Garage's 5 GHz
// radio (MT7663, MediaTek's closed mt_wifi driver built into the EcoNet
// kernel) without a kernel change: the messages of the driver's IAPP
// daemon interface, the FT key hierarchy, hostapd 2.9's RRB-OUI frames
// (so the Garage can exchange PMK-R1s with the Decos), and the ioctl
// bodies of the driver's 802.11k/v daemon interface.
//
// Nothing here is wired into the agent yet. The design, what was found in
// the kernel and the integration spec are in docs/deco/features/garage-ft.md.
//
// Roles:
//
//   - kdp.go: the driver <-> daemon key distribution (KDP signals on
//     EtherType 0xEEEE, the KEY_REQ / KEY_RSP set OIDs and their element).
//   - kdf.go: PMK-R0, PMK-R1 and their names (SHA-256), the PSK, and the
//     RRB key hostapd derives from the controller's iapp_key.
//   - siv.go, rrb.go: hostapd's R0KH-R1KH protocol (PUSH, SEQ_REQ/RESP).
//   - rrm.go: neighbour report responses, BTM requests, and the wireless
//     events that carry neighbour report requests and BTM queries and
//     responses.
//   - profile.go: the FtSupport / FtMdId / FtR0khId profile keys.
package mtkft
