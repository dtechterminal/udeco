package deco

// TDP discovery (UDP 20002) as used by the Deco app v3.10.666.
//
// TDP wire format: com/tplink/tdp/packet/b.java:50-65 (header), :42-48 (CRC), :155-169 (verify),
// :179-199 (ctor). Request flags: lk/f.java:38-45. Defaults version=2 opcode=1 result=0: lk/f.java:52-54
// (MESH_CONFIG enum args are hidden by jadx: TdpPacketMetadata.java:19-25,108-110 -> INFERRED, LIVE-confirmed).
// Reply JSON: com/tplink/tdp/codec/b.java:21-34 + TDPResult.java:9-11.

import (
	"context"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"net"
	"strconv"
	"strings"
	"time"
)

const (
	TDPPort        = 20002       // lk/g.java:42 (f102713e)
	tdpHeaderLen   = 16          // lk/g.java:45 (f102714f)
	tdpCRCMagic    = 0x5A6B7C8D  // lk/g.java:6 (A = 1516993677); packet/b.java:64,159,192
	TDPVersion2    = 2           // lk/f.java:53
	TDPOpDiscover  = 1           // lk/f.java:53
	TDPFlagBcast   = 0x10 | 0x01 // lk/f.java:39,42 (socket getBroadcast()==true, socket/l.java:347)
	TDPFlagUnicast = 0x20 | 0x01 // lk/f.java:39,42
	tdpMaxSerial   = 268435456   // packet/b.java:67-69 SecureRandom.nextInt(2^28)
)

// TDPHeader is the 16-byte big-endian header (packet/b.java:50-65 write, :201-211 read;
// bj/a.java:27-28,71-73 = BE on little-endian Android).
type TDPHeader struct {
	Version  uint8  // off 0
	Reserved uint8  // off 1 (always 0 in requests, packet/b.java:182)
	Opcode   uint16 // off 2
	Length   uint16 // off 4: payload length
	Flags    uint8  // off 6: request 0x11 bcast / 0x21 unicast; reply 0x00 (LIVE)
	Result   uint8  // off 7: request 0; reply must be 0 or 1 to be accepted (socket/l.java:157-158)
	Serial   uint32 // off 8: random < 2^28, echoed by device; reply matched on serial+version (lk/f.java:45, socket/l.java:161)
	CRC      uint32 // off 12: CRC32(IEEE) over header(with CRC=magic)+payload (packet/b.java:42-48)
}

// EncodeTDP builds a TDP packet exactly as com.tplink.tdp.packet.b(byte,short,byte,byte[],byte) does (packet/b.java:179-199).
func EncodeTDP(version uint8, opcode uint16, flags, result uint8, serial uint32, payload []byte) []byte {
	buf := make([]byte, tdpHeaderLen+len(payload))
	buf[0] = version
	buf[1] = 0
	binary.BigEndian.PutUint16(buf[2:], opcode)
	binary.BigEndian.PutUint16(buf[4:], uint16(len(payload)))
	buf[6] = flags
	buf[7] = result
	binary.BigEndian.PutUint32(buf[8:], serial)
	binary.BigEndian.PutUint32(buf[12:], tdpCRCMagic)
	copy(buf[16:], payload)
	binary.BigEndian.PutUint32(buf[12:], crc32.ChecksumIEEE(buf))
	return buf
}

// DecodeTDP parses one packet and verifies the CRC like packet/b.java:155-169 (rejects length 0, :156-158).
func DecodeTDP(pkt []byte) (TDPHeader, []byte, error) {
	var h TDPHeader
	if len(pkt) < tdpHeaderLen {
		return h, nil, errors.New("tdp: short packet")
	}
	h.Version, h.Reserved = pkt[0], pkt[1]
	h.Opcode = binary.BigEndian.Uint16(pkt[2:])
	h.Length = binary.BigEndian.Uint16(pkt[4:])
	h.Flags, h.Result = pkt[6], pkt[7]
	h.Serial = binary.BigEndian.Uint32(pkt[8:])
	h.CRC = binary.BigEndian.Uint32(pkt[12:])
	end := tdpHeaderLen + int(h.Length)
	if h.Length == 0 || len(pkt) < end {
		return h, nil, errors.New("tdp: bad length")
	}
	chk := make([]byte, end)
	copy(chk, pkt[:end])
	binary.BigEndian.PutUint32(chk[12:], tdpCRCMagic)
	if crc32.ChecksumIEEE(chk) != h.CRC {
		return h, nil, errors.New("tdp: crc mismatch")
	}
	if h.Result != 0 && h.Result != 1 {
		return h, nil, fmt.Errorf("tdp: result byte %d", h.Result)
	}
	return h, pkt[tdpHeaderLen:end], nil
}

// TPAP mirrors LocalTransMetadata ("tpap"; LocalTransMetadata.java:22-39); absent on Deco X20 (LIVE).
type TPAP struct {
	UserHashType int   `json:"user_hash_type"`
	Port         int   `json:"port"`
	TLS          int   `json:"tls"`
	DAC          int   `json:"dac"`
	NOC          int   `json:"noc"`
	Pake         []int `json:"pake"`
}

// DecoInfo mirrors TDPGenericDevice (:34-108) + TDPMeshDevice (:21-58) JSON names.
type DecoInfo struct {
	IP                string     `json:"ip"`
	MAC               string     `json:"mac"`
	DeviceID          string     `json:"device_id"`
	DeviceModel       string     `json:"device_model"`
	DeviceType        string     `json:"device_type"` // "HOMEWIFISYSTEM" (MeshDeviceType.java:21)
	FactoryDefault    bool       `json:"factory_default"`
	GroupID           string     `json:"group_id"`
	GroupNameB64      string     `json:"group_name"` // Base64TypeAdapter (TDPGenericDevice.java:69-73)
	HashVersion       FlexString `json:"hash_version"`
	Owner             string     `json:"owner"` // md5/sha256 hex of cloud username
	Role              string     `json:"role"`  // "master" / "slave"
	TDPVer            *int       `json:"ver"`
	TMPVer            *int       `json:"tmp_ver"`
	BannerType        *int       `json:"banner_type"`     // alt "ssh_banner_type"; 1 => "TPS-" SSH banner
	SSHBannerTypeAlt  *int       `json:"ssh_banner_type"` // alternate name
	TPAP              *TPAP      `json:"tpap"`
	HardwareVersion   string     `json:"hardware_version"`
	FirmwareVer       string     `json:"firmware_ver"`
	FirmwareVersion   string     `json:"firmware_version"` // alternate name
	MasterDeviceID    string     `json:"master_device_id"`
	TMPPorts          []int      `json:"tmp_port"`
	NeedAccountDigest bool       `json:"need_account_digest"` // true => SSH username is sha1hex(cloudUserName) (y.java:375-381)
	Channel2G         FlexString `json:"channel_2g"`
	Channel5G         FlexString `json:"channel_5g"`
	Channel5G2        FlexString `json:"channel_5g_2"`
	Channel6G         FlexString `json:"channel_6g"`
}

type tdpResult struct {
	ErrorCode int             `json:"error_code"`
	Result    json.RawMessage `json:"result"`
}

func (d *DecoInfo) GroupName() string {
	b, err := base64.StdEncoding.DecodeString(d.GroupNameB64)
	if err != nil {
		return d.GroupNameB64
	}
	return string(b)
}

func (d *DecoInfo) IsMaster() bool { return d.Role == "master" } // TDPMeshDevice.java:131-134

// SSHPort = tmp_port[0] when no tpap, else tpap.port, else 22 (TDPMeshDevice.java:100-104, TDPGenericDevice.java:187-193).
func (d *DecoInfo) SSHPort() int {
	if d.TPAP == nil && len(d.TMPPorts) > 0 {
		return d.TMPPorts[0]
	}
	if d.TPAP != nil {
		return d.TPAP.Port
	}
	return 22
}

// UsesTLS: tpap with pake or noc => app uses TLS transport instead of SSH2
// (TDPGenericDevice.java:282-300; LocalTransMetadata.java:151-152,171-172).
func (d *DecoInfo) UsesTLS() bool {
	return d.TPAP != nil && (len(d.TPAP.Pake) > 0 || d.TPAP.NOC > 0)
}

// TPSBanner: banner_type==1 => client version "TPS-2.0-JSCH-0.1.54" (t.java:183, k0.java:136-139).
// Gson alternate names: "banner_type" / "ssh_banner_type" (TDPGenericDevice.java:34-37).
func (d *DecoInfo) TPSBanner() bool {
	if d.BannerType != nil {
		return *d.BannerType == 1
	}
	return d.SSHBannerTypeAlt != nil && *d.SSHBannerTypeAlt == 1
}

// OwnerMatches reproduces TDPGenericDevice.isCloudAccountMatched (:246-252) + isOwnerSha256 (:271-275):
// owner shorter than 2 chars => match; toIntOrNull(hash_version)>=1 => sha256 hex, else md5 hex
// (dj/a.java:187-200 = md5 over String.getBytes(), UTF-8 on Android); case-insensitive compare.
// cloudUserName is the raw TCAccountBean.cloudUserName (TDPMeshDevice.java:123-129 passes accountInfo.i()).
func (d *DecoInfo) OwnerMatches(cloudUserName string) bool {
	if len(d.Owner) <= 1 {
		return true
	}
	hv, err := strconv.Atoi(strings.TrimSpace(string(d.HashVersion)))
	var sum string
	if err == nil && hv >= 1 {
		s := sha256.Sum256([]byte(cloudUserName))
		sum = hex.EncodeToString(s[:])
	} else {
		s := md5.Sum([]byte(cloudUserName))
		sum = hex.EncodeToString(s[:])
	}
	return strings.EqualFold(sum, d.Owner)
}

// SSHUsername reproduces the Deco repository override y.b0() (com/tplink/libtpnetwork/mesh/global/y.java:373-381):
// if the master's TDP has need_account_digest=true (qi/c.java:470-480 via mesh/context/c.java:1377-1379)
// and the TLS path is not in use (context/a.java j0()), the SSH username is the lowercase hex SHA-1 of the
// cloudUserName bytes (dj/a.java:211-221 + :242-254); otherwise it is the raw cloudUserName (t.java:516-521).
func (d *DecoInfo) SSHUsername(cloudUserName string) string {
	if d.NeedAccountDigest && !d.UsesTLS() {
		s := sha1.Sum([]byte(cloudUserName))
		return hex.EncodeToString(s[:])
	}
	return cloudUserName
}

func newSerial() uint32 {
	var b [4]byte
	_, _ = rand.Read(b[:])
	return binary.BigEndian.Uint32(b[:]) % tdpMaxSerial
}

// DiscoverDeco sends one TDP discovery (empty payload: codec/d.java:20-25) to ip:20002 and waits for the reply.
// Pass ip "255.255.255.255" and broadcast=true for LAN-wide discovery (collects until ctx deadline).
func DiscoverDeco(ctx context.Context, ip string, broadcast bool) ([]DecoInfo, error) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{})
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	flags := uint8(TDPFlagUnicast)
	if broadcast {
		flags = TDPFlagBcast // Go sets SO_BROADCAST on udp4 sockets on Linux
	}
	serial := newSerial()
	req := EncodeTDP(TDPVersion2, TDPOpDiscover, flags, 0, serial, nil)
	dst := &net.UDPAddr{IP: net.ParseIP(ip), Port: TDPPort}
	if _, err := conn.WriteToUDP(req, dst); err != nil {
		return nil, err
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetReadDeadline(dl)
	} else {
		_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	}
	var out []DecoInfo
	buf := make([]byte, 8192) // socket/l.java:48,194
	for {
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() && len(out) > 0 {
				return out, nil
			}
			return out, err
		}
		h, body, err := DecodeTDP(buf[:n])
		if err != nil || h.Serial != serial || h.Version != TDPVersion2 {
			continue
		}
		var r tdpResult
		if json.Unmarshal(body, &r) != nil || r.ErrorCode != 0 {
			continue
		}
		var d DecoInfo
		if json.Unmarshal(r.Result, &d) != nil {
			continue
		}
		out = append(out, d)
		if !broadcast {
			return out, nil
		}
	}
}
