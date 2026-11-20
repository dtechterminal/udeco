// SPDX-License-Identifier: GPL-2.0-or-later

package snmpagent

import (
	"encoding/json"
	"net"
	"strconv"
)

// View is what the agent knows about itself beyond /proc and /sys: the
// identity and the Wi-Fi state it reports to the controller. The agent
// builds it from each inform's fields (FromFields), so SNMP and the
// controller show the same radio, VAP and port names and counters.
type View struct {
	Hostname string // sysName
	Model    string // display model (the catalogue's, e.g. DefaultDescr)
	Version  string // firmware version reported to the controller
	IP       string // the unit's IPv4 address
	Uplink   string // the uplink interface name the controller sees ("eth0")
	Uptime   int64  // seconds, as reported to the controller

	Radios []RadioRow
	VAPs   []VAPRow
	Ports  []PortRow
}

// RadioRow is one radio_table_stats row (UBNT-UniFi-MIB unifiRadioEntry).
type RadioRow struct {
	Name, Band                  string
	RxPackets, TxPackets        int64 // summed over the radio's VAPs
	CuTotal, CuSelfRx, CuSelfTx int64
	CuInterf                    int64
}

// VAPRow is one vap_table row (unifiVapEntry).
type VAPRow struct {
	Name, Radio, ESSID   string
	BSSID                []byte
	Channel, TxPower     int64
	CCQ, ExtChannel      int64
	NumSta               int64
	Guest, Up            bool
	RxBytes, TxBytes     int64
	RxPackets, TxPackets int64
	RxErrors, TxErrors   int64
	RxDropped, TxDropped int64
	TxRetries            int64
}

// PortRow is one if_table row (unifiIfEntry).
type PortRow struct {
	Name                 string
	MAC                  []byte
	IP                   string
	Up, FullDuplex       bool
	Speed                int64
	RxBytes, TxBytes     int64
	RxPackets, TxPackets int64
	RxErrors, TxErrors   int64
	RxDropped, TxDropped int64
	RxMulticast          int64
}

// FromFields copies the inform fields the UniFi MIB needs out of f (the map
// apstate.Snapshot.Fields returns, after the agent's additions). Nothing in
// f is kept, so f may change afterwards.
func FromFields(f map[string]any) *View {
	v := &View{
		Hostname: str(f["hostname"]), Model: str(f["model_display"]), Version: str(f["version"]),
		IP: str(f["ip"]), Uplink: str(f["uplink"]), Uptime: num(f["uptime"]),
	}
	radioIdx := map[string]int{}
	for _, r := range rows(f["radio_table_stats"]) {
		radioIdx[str(r["name"])] = len(v.Radios)
		v.Radios = append(v.Radios, RadioRow{Name: str(r["name"]), Band: str(r["radio"]),
			CuTotal: num(r["cu_total"]), CuSelfRx: num(r["cu_self_rx"]), CuSelfTx: num(r["cu_self_tx"]), CuInterf: num(r["cu_interf"])})
	}
	for _, r := range rows(f["vap_table"]) {
		row := VAPRow{Name: str(r["name"]), Radio: str(r["radio"]), ESSID: str(r["essid"]),
			Channel: num(r["channel"]), TxPower: num(r["tx_power"]), CCQ: num(r["ccq"]), ExtChannel: num(r["extchannel"]),
			NumSta: num(r["num_sta"]), Guest: boolean(r["is_guest"]), Up: boolean(r["up"]),
			RxBytes: num(r["rx_bytes"]), TxBytes: num(r["tx_bytes"]), RxPackets: num(r["rx_packets"]), TxPackets: num(r["tx_packets"]),
			RxErrors: num(r["rx_errors"]), TxErrors: num(r["tx_errors"]), RxDropped: num(r["rx_dropped"]), TxDropped: num(r["tx_dropped"]),
			TxRetries: num(r["tx_retries"])}
		if hw, err := net.ParseMAC(str(r["bssid"])); err == nil && len(hw) == 6 {
			row.BSSID = hw
		}
		v.VAPs = append(v.VAPs, row)
		if i, ok := radioIdx[str(r["radio_name"])]; ok {
			v.Radios[i].RxPackets += row.RxPackets
			v.Radios[i].TxPackets += row.TxPackets
		}
	}
	for _, r := range rows(f["if_table"]) {
		row := PortRow{Name: str(r["name"]), IP: str(r["ip"]), Up: boolean(r["up"]), FullDuplex: boolean(r["full_duplex"]),
			Speed: num(r["speed"]), RxBytes: num(r["rx_bytes"]), TxBytes: num(r["tx_bytes"]),
			RxPackets: num(r["rx_packets"]), TxPackets: num(r["tx_packets"]), RxErrors: num(r["rx_errors"]), TxErrors: num(r["tx_errors"]),
			RxDropped: num(r["rx_dropped"]), TxDropped: num(r["tx_dropped"]), RxMulticast: num(r["rx_multicast"])}
		if hw, err := net.ParseMAC(str(r["mac"])); err == nil && len(hw) == 6 {
			row.MAC = hw
		}
		v.Ports = append(v.Ports, row)
	}
	return v
}

func rows(x any) []map[string]any {
	switch t := x.(type) {
	case []map[string]any:
		return t
	case []any:
		var out []map[string]any
		for _, e := range t {
			if m, ok := e.(map[string]any); ok {
				out = append(out, m)
			}
		}
		return out
	}
	return nil
}

func str(x any) string {
	switch t := x.(type) {
	case string:
		return t
	case []byte:
		return string(t)
	}
	return ""
}

func boolean(x any) bool {
	switch t := x.(type) {
	case bool:
		return t
	case string:
		return t == "true" || t == "1"
	}
	return num(x) != 0
}

func num(x any) int64 {
	switch t := x.(type) {
	case int:
		return int64(t)
	case int8:
		return int64(t)
	case int16:
		return int64(t)
	case int32:
		return int64(t)
	case int64:
		return t
	case uint:
		return int64(t)
	case uint8:
		return int64(t)
	case uint16:
		return int64(t)
	case uint32:
		return int64(t)
	case uint64:
		if t > 1<<63-1 {
			return 1<<63 - 1
		}
		return int64(t)
	case float32:
		return int64(t)
	case float64:
		return int64(t)
	case json.Number:
		n, err := t.Int64()
		if err != nil {
			f, _ := t.Float64()
			return int64(f)
		}
		return n
	case string:
		if n, err := strconv.ParseInt(t, 10, 64); err == nil {
			return n
		}
		if f, err := strconv.ParseFloat(t, 64); err == nil {
			return int64(f)
		}
	}
	return 0
}
