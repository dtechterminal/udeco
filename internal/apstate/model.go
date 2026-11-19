// SPDX-License-Identifier: GPL-2.0-or-later

package apstate

import (
	"time"
)

// Snapshot is one reading of the AP.
type Snapshot struct {
	Time     time.Time
	Model    string
	Hostname string
	Release  string
	Uptime   int64
	Load     [3]float64
	CPUTotal int64 // /proc/stat jiffies, all states
	CPUIdle  int64 // idle + iowait
	MemTotal int64
	MemFree  int64
	MemBuf   int64
	MemCache int64
	MAC      string // br-lan MAC (the AP's identity)
	IP       string
	Netmask  string
	Gateway  string
	Radios   []Radio
	Ports    []Port
	ARP      map[string]string // mac -> ip
	FDB      []FDBEntry        // br-lan forwarding database
	LLDP     []LLDPNeighbor    // what lldpd hears on the ports (empty without lldpd)
	// UplinkName: the port that is always the uplink (-uplink-port, not
	// read from the AP); empty = found from the gateway's FDB entry.
	UplinkName string
	// RearUplink: the port number the model gives its rear uplink jack
	// (models.Model.RearUplinkPort); 0 = the uplink is port 1.
	RearUplink int
}

// FDBEntry is one row of the br-lan forwarding database
// (/sys/class/net/br-lan/brforward, struct __fdb_entry).
type FDBEntry struct {
	MAC   string
	Port  int   // bridge port number (Port.BridgePort)
	Local bool  // one of the AP's own addresses
	Age   int64 // s since the MAC was last seen
}

type Radio struct {
	Iface, Phy  string
	Mode        string // iwinfo mode: "Master" (AP), "Client" (STA: mesh uplink), ...
	Band        string // "ng" (2.4 GHz) or "na" (5 GHz)
	SSID, BSSID string
	Channel     int
	Width       int // MHz
	TxPower     int
	TxMin       int
	TxMax       int
	Noise       int
	NSS         int
	HWName      string
	Encryption  string
	VHT, HE     bool // hardware supports 802.11ac / ax
	Survey      Survey
	Stats       map[string]int64
	Stations    []Station
	// VAPs: on a phy-level Radio, one entry per AP interface on that radio
	// (each carries its own SSID, BSSID, Stats, Stations).
	VAPs []Radio
}

type Survey struct {
	Active, Busy, Rx, Tx int64 // ms, cumulative since boot
}

type Station struct {
	MAC                  string
	Signal, SignalAvg    int
	Noise                int
	Inactive             int64 // ms
	Connected            int64 // s
	Authorized           bool
	RxBytes, TxBytes     int64
	RxPackets, TxPackets int64
	RxRate, TxRate       int // kbit/s
	TxRetries, TxFailed  int64
	HT, VHT, HE          bool
	MHz                  int
	// NSS: the client's spatial streams in its best mode (HE, else VHT,
	// else HT) from wl sta_info's rate sets; 0 when unknown.
	NSS int
}

type Port struct {
	Name, MAC        string
	Speed            int
	FullDuplex, Up   bool
	RxBytes, TxBytes int64
	RxPkts, TxPkts   int64
	// error/drop/multicast counters (/sys/class/net/<port>/statistics);
	// a real UAP's if_table row carries them (docs/reference/u6pro).
	RxErrors, TxErrors   int64
	RxDropped, TxDropped int64
	RxMulticast          int64
	BridgePort           int // port number in br-lan, 0 = not a br-lan member
}
