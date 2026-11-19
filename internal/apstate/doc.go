// SPDX-License-Identifier: GPL-2.0-or-later

// Package apstate is the agent-neutral reading of an access point (one
// Snapshot per collect) and its UniFi inform rendering (Fields), shared by
// the OpenWrt collector (internal/openwrt), the Broadcom collector
// (internal/wl) and the Deco agent, which must not link the SSH client.
package apstate
