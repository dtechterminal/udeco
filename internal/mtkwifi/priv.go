// SPDX-License-Identifier: GPL-2.0-or-later

package mtkwifi

import (
	"errors"
	"unsafe"
)

// The driver's private ioctls (what `iwpriv` sends), in process: an
// AF_INET datagram socket and a struct iwreq per request. The off-channel
// sweep (offchan.go) needs the MIB pre-clear and the visit request within a
// millisecond or two of each other, which an `iwpriv` exec per request on
// the unit's MIPS core cannot give.

// Request numbers (mt7603eap.ko, RTMP_AP_IoctlHandle; checked live
// 2026-11-20 with the mtkprobe tool).
const (
	ioctlOID  = 0x8BE1 // SIOCIWFIRSTPRIV+1: OID query (flags = OID) or set (flags = OID | oidSet)
	ioctlSet  = 0x8BE2 // `iwpriv <if> set <key>=<value>`
	ioctlShow = 0x8BF1 // `iwpriv <if> show <what>`
	oidSet    = 0x8000 // OID_GET_SET_TOGGLE: the OID goes to RTMPAPSetInformation
)

// privIO is the driver's private-ioctl interface of one socket.
type privIO interface {
	// Show is `iwpriv <ifname> show <what>` (output to the kernel log).
	Show(ifname, what string) error
	// Set is `iwpriv <ifname> set <arg>` (arg "Key=value").
	Set(ifname, arg string) error
	// OID fills buf with the reply of OID oid (flags as sent: a set OID
	// has oidSet in it); the length sent is len(buf).
	OID(ifname string, flags uint16, buf []byte) error
	Close() error
}

// iwPoint is struct iw_point: the user pointer, its length and the flags.
type iwPoint struct {
	ptr           uintptr
	length, flags uint16
}

// iwreq is struct iwreq: ifr_name[IFNAMSIZ] and the 16-byte union
// iwreq_data, of which the request uses iw_point. 32 bytes on 32-bit
// (mipsle: pointer u32, length u16, flags u16, 8 bytes of padding) and on
// 64-bit kernels alike; the leading [0]uint64 aligns the union for the
// iw_point written into it.
type iwreq struct {
	_    [0]uint64
	name [16]byte
	data [16]byte
}

// point is the iw_point inside the union.
func (r *iwreq) point() *iwPoint { return (*iwPoint)(unsafe.Pointer(&r.data)) }

var errIfname = errors.New("mtkwifi: interface name too long")

// newIwreq builds the request for ifname over buf (len(buf) >= 1).
func newIwreq(ifname string, buf []byte, flags uint16) (*iwreq, error) {
	if len(ifname) >= 16 {
		return nil, errIfname
	}
	r := &iwreq{}
	copy(r.name[:], ifname)
	p := r.point()
	p.ptr = uintptr(unsafe.Pointer(&buf[0]))
	p.length = uint16(len(buf))
	p.flags = flags
	return r, nil
}

// cstr is s as a writable NUL-terminated buffer (the driver writes into
// a show or set argument it parses).
func cstr(s string) []byte { return append([]byte(s), 0) }
