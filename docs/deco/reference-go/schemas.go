package deco

// JSON wire schemas of the Deco app's TMP commands (Deco app v3.10.666).
// Paths in comments are relative to deco-jadx/out/sources. Enum spellings come from
// the dex @SerializedName annotations (scratchpad/dexcheck/sn6.txt, sn7.txt), which
// jadx drops from enum constants.

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
)

// ---- Opcodes (com/tplink/libtpnetwork/mesh/global/p.java) ----
const (
	OpNegotiation          uint16 = 0x4001 // p.f65921e:480
	OpGetWireless          uint16 = 0x4009 // f66023m:786
	OpSetWireless          uint16 = 0x4008 // f66011l:750
	OpGetMLO               uint16 = 0x43b0 // f66067p7:918
	OpSetMLO               uint16 = 0x43b1 // f66079q7:954
	OpGetDeviceList        uint16 = 0x400f // f66095s:1002
	OpRebootDevices        uint16 = 0x4016 // f66179z:1254
	OpGetDeviceEthPort     uint16 = 0x4327 // f66069p9:924
	OpGetDeviceSpeedList   uint16 = 0x422f // f66158x2:1191
	OpGetDeviceResource    uint16 = 0x4317 // G8:91
	OpGetSignalLevel       uint16 = 0x4094 // f66037n1:828
	OpGetClientList        uint16 = 0x4012 // f66131v:1110 (app timeout 60 s)
	OpGetClientSpeedList   uint16 = 0x4014 // f66155x:1182
	OpGetClientSpeed       uint16 = 0x4015 // f66167y:1218
	OpBlockClients         uint16 = 0x4017 // A:10
	OpGetBlockList         uint16 = 0x4018 // B:22
	OpUnblockClients       uint16 = 0x4019 // C:34
	OpSetAccessControlMode uint16 = 0x4402 // R7:222  AccessControlModeBean
	OpGetAllowList         uint16 = 0x4403 // S7:234  ClientWhiteListResult
	OpAllowListAdd         uint16 = 0x4404 // T7:246  ClientBlockParams (allow-list add)
	OpAllowListRemove      uint16 = 0x4405 // U7:258  ClientUnblockParams (allow-list remove)
	OpGetClientAccess      uint16 = 0x4406 // V7:270  ClientAccessResult
	OpSetClientAccess      uint16 = 0x4407 // W7:282  ClientAccessSetParams
	OpGetQsWifiStatus      uint16 = 0x4098 // K9:140
	OpGetLED               uint16 = 0x401a // D:46
	OpSetLED               uint16 = 0x401b // E:58
	OpGetLEDDevices        uint16 = 0x42f7 // O8:187
	OpGetBandwidthSwitch   uint16 = 0x42f0 // f66160x4:1197
	OpSetBandwidthSwitch   uint16 = 0x42f1 // f66172y4:1233
	OpGetBandwidthSwStatus uint16 = 0x42f2 // f66184z4:1269
	OpGetChannelLimits     uint16 = 0x4390 // N6:173
	OpSetChannelLimits     uint16 = 0x4391 // O6:185
)

// ---- Envelope (TMPParams/TMPResult/EncodeRequest are in business.go) ----

// Response is TMPResult<T>. Success is error_code == 0 (i0.java:658); anything else is a
// TMPException carrying error_code, msg and the raw payload (i0.java:661-666).
// A null/absent result yields an empty stream in the app (i0.java:679-680).
type Response[T any] struct {
	ErrorCode CompatInt `json:"error_code"`
	Msg       string    `json:"msg,omitempty"`
	Result    *T        `json:"result,omitempty"`
}

// SetResponse keeps the Set result raw: its shape (absent, boolean or object) is unverified.
type SetResponse struct {
	ErrorCode CompatInt       `json:"error_code"`
	Msg       string          `json:"msg,omitempty"`
	Result    json.RawMessage `json:"result,omitempty"`
}

// ---- Base64 strings (mesh/repository/bo/Base64TypeAdapter.java:11-28, dj/a.java:23-25,48-50) ----

var b64re = regexp.MustCompile(`^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{4}|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)$`)

// B64 holds the decoded value. On the wire it is standard base64 with padding and no line breaks.
type B64 string

func (s B64) MarshalJSON() ([]byte, error) {
	if s == "" {
		return []byte(`""`), nil // dj.a.e returns "" for empty input
	}
	return json.Marshal(base64.StdEncoding.EncodeToString([]byte(s)))
}

func (s *B64) UnmarshalJSON(b []byte) error {
	var raw string
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	if raw == "" {
		*s = ""
		return nil
	}
	if b64re.MatchString(raw) {
		if dec, err := base64.StdEncoding.DecodeString(raw); err == nil {
			*s = B64(dec)
			return nil
		}
	}
	*s = B64(raw) // the app keeps a non-base64 string as-is (Base64TypeAdapter.java:18-19)
	return nil
}

// LocB64 mirrors LocationBase64TypeAdapter.java:12-40: like B64, but the literal "basement"
// is never decoded (line 17). The app prefixes non-base64 values with "\f \f " (line 14,27);
// this type keeps them unprefixed.
type LocB64 string

func (s LocB64) MarshalJSON() ([]byte, error) { return B64(s).MarshalJSON() }

func (s *LocB64) UnmarshalJSON(b []byte) error {
	var raw string
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	if raw == "basement" {
		*s = LocB64(raw)
		return nil
	}
	var v B64
	if err := v.UnmarshalJSON(b); err != nil {
		return err
	}
	*s = LocB64(v)
	return nil
}

// ---- Lenient scalars ----

// FlexString accepts a JSON string or number (Gson's String adapter accepts number tokens).
type FlexString string

func (f *FlexString) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, []byte("null")) {
		return nil
	}
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		*f = FlexString(s)
		return nil
	}
	var n json.Number
	if err := json.Unmarshal(b, &n); err != nil {
		return err
	}
	*f = FlexString(n.String())
	return nil
}

// FlexInt accepts a number or a quoted number, like Gson nextInt() used by
// IntegerCompatTypeAdapter (primitive int only, k0.java:24-25) and SafeIntegerTypeAdapter.
// The app maps an unparsable primitive int to Integer.MAX_VALUE and an unparsable boxed
// Integer to null; this type maps both to 0.
type FlexInt int64

func (i *FlexInt) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	if s == "null" || s == "" {
		return nil
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		*i = 0
		return nil
	}
	*i = FlexInt(v)
	return nil
}

// ---- Enum wire values ----
// Read from the @SerializedName annotations in base.apk classes6.dex / classes7.dex
// (dexdump -a). jadx drops these annotations from enum constants. Gson writes the annotation
// value and, on read, accepts only that value (plus alternates) or toString(), never name()
// (gson/internal/bind/TypeAdapters.java:189-227).
const (
	RoleMaster = "master" // EnumDeviceRole.ROLE_MASTER (sn6.txt:375-377)
	RoleSlave  = "slave"  // EnumDeviceRole.ROLE_SLAVE

	EasyMeshController = "controller" // EnumEasyMeshRole
	EasyMeshAgent      = "agent"

	InetOnline  = "online" // EnumDeviceInetStatus
	InetOffline = "offline"

	GroupConnected    = "connected" // EnumGroupStatus
	GroupDisconnected = "disconnected"

	PswNormal = "normal" // WirelessSpecBean.EnumWirelessPswStrength (sn7.txt:602)
	PswStrong = "strong"

	OpModeRouter = "Router" // EnumOperationMode (sn6.txt:393-403); NegotiationResult default
	OpModeAP     = "AP"
)

// Enum is a string enum compared case-insensitively.
type Enum string

func (e Enum) Is(alts ...string) bool {
	for _, a := range alts {
		if strings.EqualFold(string(e), a) {
			return true
		}
	}
	return false
}

// ---- Wireless (0x4009 Get / 0x4008 Set) ----

type WirelessInfo struct {
	Band2G4    *WirelessBand `json:"band2_4,omitempty"`
	Band5G1    *WirelessBand `json:"band5_1,omitempty"`
	Band5G2    *WirelessBand `json:"band5_2,omitempty"`
	Band60G    *WirelessBand `json:"band60,omitempty"`
	Band6G     *WirelessBand `json:"band6,omitempty"`
	Band6G2    *WirelessBand `json:"band6_2,omitempty"`
	ConfigSpec *WirelessSpec `json:"config_spec,omitempty"`
}

type WirelessBand struct {
	AmazonFFS *struct {
		Enable *bool `json:"enable,omitempty"`
	} `json:"amazon_ffs,omitempty"`
	Backhaul *struct {
		Channel FlexInt `json:"channel"` // primitive int
	} `json:"backhaul,omitempty"`
	Guest                 *WirelessGuest `json:"guest,omitempty"`
	Host                  *WirelessHost  `json:"host,omitempty"`
	IoT                   *WirelessIoT   `json:"iot,omitempty"`
	OweSupport            *bool          `json:"owe_support,omitempty"`
	Radio                 *WirelessRadio `json:"radio,omitempty"`
	UnsupportedDeviceList []string       `json:"unsupported_device_list,omitempty"`
}

// encryption_mode values: none, owe, wpa2, wpa2+wpa, wpa3, wpa3+wpa2 (WirelessBandBean.java:30-36)
type WirelessHost struct {
	Enable           *bool   `json:"enable,omitempty"`
	EnableHideSSID   *bool   `json:"enable_hide_ssid,omitempty"`
	EnableWPA3       *bool   `json:"enable_wpa3,omitempty"`
	EncryptionMode   *string `json:"encryption_mode,omitempty"`
	HasSet           *bool   `json:"has_set,omitempty"`
	IsSeparate       *bool   `json:"is_separate,omitempty"`
	Password         *B64    `json:"password,omitempty"`
	ShowCombineGuide *bool   `json:"show_combine_guide,omitempty"`
	SSID             *B64    `json:"ssid,omitempty"`
}

// Merge mirrors WirelessHostBean.merge(enable) (WirelessHostBean.java:120-132): a copy of
// every field with only enable replaced. The app builds each band's host this way.
func (h WirelessHost) Merge(enable bool) *WirelessHost {
	c := h
	c.Enable = &enable
	return &c
}

type GuestBandwidthLimit struct {
	DownstreamBandwidth FlexInt `json:"downstream_bandwidth"`
	Enable              bool    `json:"enable"`
	UpstreamBandwidth   FlexInt `json:"upstream_bandwidth"`
}

type WirelessGuest struct {
	AccessDuration     *int                 `json:"access_duration,omitempty"`
	BandwidthLimit     *GuestBandwidthLimit `json:"bandwidth_limit,omitempty"`
	ClientIsolation    *bool                `json:"client_isolation,omitempty"`
	Enable             *bool                `json:"enable,omitempty"`
	EnableWPA3         *bool                `json:"enable_wpa3,omitempty"`
	EncryptionMode     *string              `json:"encryption_mode,omitempty"`
	HasSetGuestNetwork *bool                `json:"has_set_guest_network,omitempty"`
	HostIsolation      *bool                `json:"host_isolation,omitempty"`
	IsSeparate         *bool                `json:"is_separate,omitempty"`
	NeedSetVlan        *bool                `json:"need_set_vlan,omitempty"`
	Password           *B64                 `json:"password,omitempty"`
	RemainTime         *int                 `json:"remain_time,omitempty"`
	ShowCombineGuide   *bool                `json:"show_combine_guide,omitempty"`
	SSID               *B64                 `json:"ssid,omitempty"`
	VlanID             *int                 `json:"vlan_id,omitempty"`
}

type WirelessIoT struct {
	Enable         *bool   `json:"enable,omitempty"`
	EnableWPA3     *bool   `json:"enable_wpa3,omitempty"`
	EncryptionMode *string `json:"encryption_mode,omitempty"`
	HasSet         *bool   `json:"has_set,omitempty"`
	NeedSetVlan    *bool   `json:"need_set_vlan,omitempty"` // @Expose ignored by this Gson
	Password       *B64    `json:"password,omitempty"`
	SSID           *B64    `json:"ssid,omitempty"`
	VlanID         *int    `json:"vlan_id,omitempty"`
}

type WirelessRadio struct {
	Channel string `json:"channel,omitempty"`
	Enable  bool   `json:"enable"` // primitive boolean: always sent if radio is sent
	HTMode  string `json:"htmode,omitempty"`
	HWMode  string `json:"hwmode,omitempty"`
}

type WirelessSpec struct {
	Password          *B64 `json:"password,omitempty"`
	PasswordStrength  Enum `json:"password_strength,omitempty"` // "normal" | "strong"
	PasswordRequisite *struct {
		MaxDigits          FlexInt  `json:"max_digits"`
		MinDigits          FlexInt  `json:"min_digits"`
		MinOptionalOptions FlexInt  `json:"min_optional_options"`
		OptionalCharset    []string `json:"optional_charset"`
		RequiredCharset    []string `json:"required_charset"`
	} `json:"password_requisite,omitempty"`
	PasswordValidRegx string `json:"password_valid_regx,omitempty"`
	SSID              *B64   `json:"ssid,omitempty"`
}

// BuildHostSet builds a partial 0x4008 body the way the app does
// (MeshWirelessRepository.java:129-133 C0, 274-290 H0, 305-331 I0, 679-680 i2):
// {band: {host: ...}} for every band present in the Get, nothing else.
// host is the desired host object, normally the current band2_4 host from the Get
// with the patched keys applied. Each band keeps its own current enable flag, as the
// advanced UI does with WirelessHostBean.merge(enable) (r4.java:229-267;
// WirelessHostBean.java:120-132), unless host.Enable is set. band60 reuses band5_1's
// host (MeshWirelessRepository.java:283-285).
// Never sends config_spec, backhaul, radio, iot, amazon_ffs, owe_support or
// unsupported_device_list.
func BuildHostSet(get *WirelessInfo, host WirelessHost) *WirelessInfo {
	out := &WirelessInfo{}
	mk := func(cur *WirelessBand) *WirelessBand {
		if cur == nil {
			return nil
		}
		on := true
		switch {
		case host.Enable != nil:
			on = *host.Enable
		case cur.Host != nil && cur.Host.Enable != nil:
			on = *cur.Host.Enable
		}
		return &WirelessBand{Host: host.Merge(on)}
	}
	out.Band2G4 = mk(get.Band2G4)
	out.Band5G1 = mk(get.Band5G1)
	out.Band5G2 = mk(get.Band5G2)
	out.Band6G = mk(get.Band6G)
	out.Band6G2 = mk(get.Band6G2)
	if get.Band60G != nil && out.Band5G1 != nil {
		out.Band60G = &WirelessBand{Host: out.Band5G1.Host}
	}
	return out
}

// BuildGuestSet: guest changes go in their own Set (y2/w2,
// MeshWirelessRepository.java:1104-1120,1153-1165): the same guest ssid/password on
// every band present; band60 mirrors band5_1 (MeshWirelessRepository.java:255-256).
func BuildGuestSet(get *WirelessInfo, guest WirelessGuest) *WirelessInfo {
	out := &WirelessInfo{}
	mk := func(cur *WirelessBand) *WirelessBand {
		if cur == nil {
			return nil
		}
		g := guest
		return &WirelessBand{Guest: &g}
	}
	out.Band2G4 = mk(get.Band2G4)
	out.Band5G1 = mk(get.Band5G1)
	out.Band5G2 = mk(get.Band5G2)
	out.Band6G = mk(get.Band6G)
	out.Band6G2 = mk(get.Band6G2)
	if get.Band60G != nil && out.Band5G1 != nil {
		out.Band60G = &WirelessBand{Guest: out.Band5G1.Guest}
	}
	return out
}

// MLO (0x43b0 / 0x43b1)
type WirelessMloInfo struct {
	ConfigSpec *WirelessSpec `json:"config_spec,omitempty"`
	Mlo        *struct {
		Band           []string   `json:"band,omitempty"` // band2, band5, band5_1, band5_2, band6, band6_1, band6_2
		BandList       [][]string `json:"band_list,omitempty"`
		Enable         *bool      `json:"enable,omitempty"`
		EnableHideSSID bool       `json:"enable_hide_ssid"`
		EncryptionMode *string    `json:"encryption_mode,omitempty"`
		HasSet         *bool      `json:"has_set,omitempty"`
		Password       *B64       `json:"password,omitempty"`
		SSID           *B64       `json:"ssid,omitempty"`
	} `json:"mlo,omitempty"`
}

// ---- Device list (0x400f) ----

type DeviceListResult struct {
	DeviceList        []Deco     `json:"device_list"`
	NonDecoDeviceList []AgentDev `json:"non_deco_device_list,omitempty"`
	Warnings          []struct {
		Msg Enum `json:"msg"` // "indian_cpe_locking"
	} `json:"warnings,omitempty"`
}

// BandStrings is DeviceSignalBean: String fields; FlexString also accepts numbers.
type BandStrings struct {
	Band2G4 FlexString `json:"band2_4,omitempty"`
	Band5   FlexString `json:"band5,omitempty"`
	Band5G1 FlexString `json:"band5_1,omitempty"`
	Band5G2 FlexString `json:"band5_2,omitempty"`
	Band6   FlexString `json:"band6,omitempty"`
	Band6G2 FlexString `json:"band6_2,omitempty"`
}

type DecoBase struct {
	ConnectionType     []Enum       `json:"connection_type,omitempty"` // band2_4|band5|band5_1|band5_2|band6|band6_2|wired|plc|zigbee|bluetooth|band2+band5|...
	CustomNickname     LocB64       `json:"custom_nickname,omitempty"`
	DeviceID           string       `json:"device_id"`
	DeviceModel        string       `json:"device_model,omitempty"`
	EasymeshRole       Enum         `json:"easymesh_role,omitempty"` // controller|agent
	HwID               string       `json:"hw_id,omitempty"`
	IP                 string       `json:"ip,omitempty"`
	MAC                string       `json:"mac,omitempty"` // format unverified; normalise
	OemID              string       `json:"oem_id,omitempty"`
	ParentDeviceID     string       `json:"parent_device_id,omitempty"`
	SignalLevel        *BandStrings `json:"signal_level,omitempty"`
	SignalStrength     *BandStrings `json:"signal_strength,omitempty"`
	SoftwareVer        string       `json:"software_ver,omitempty"`
	SupportEasyMesh    bool         `json:"support_easy_mesh"`
	DeviceType         string       `json:"device_type,omitempty"` // app default "HOMEWIFISYSTEM"
	Nickname           Enum         `json:"nickname,omitempty"`    // app default "custom"
	InetStatus         Enum         `json:"inet_status,omitempty"` // online|offline; app default online
	EthPortInfoSupport bool         `json:"eth_port_info_support"`
}

type Deco struct {
	DecoBase
	DefaultPassword B64    `json:"default_password,omitempty"`
	DefaultSSID     B64    `json:"default_ssid,omitempty"`
	DeviceColor     string `json:"device_color,omitempty"`
	ComboPort       *struct {
		Index    FlexInt `json:"index"`
		Occupied bool    `json:"occupied"`
	} `json:"combo_port,omitempty"`
	DNSModeState         string          `json:"dns_mode_state,omitempty"`
	EthBkhlPorts         []FlexInt       `json:"eth_bkhl_ports,omitempty"`
	ExtraISP             json.RawMessage `json:"extra_isp,omitempty"`
	FixedWanPort         *FlexInt        `json:"fixed_wan_port,omitempty"`
	HardwareVer          string          `json:"hardware_ver,omitempty"`
	IMEI                 string          `json:"imei,omitempty"`
	InetErrorMsg         Enum            `json:"inet_error_msg,omitempty"`
	LastOnlineTimestamp  *FlexInt        `json:"last_online_timestamp,omitempty"`
	MasterDeviceID       string          `json:"master_device_id,omitempty"`
	OnlineTime           *FlexInt        `json:"online_time,omitempty"`
	OversizedFirmware    bool            `json:"oversized_firmware"`
	OwnerTransfer        bool            `json:"owner_transfer"`
	PortCount            *FlexInt        `json:"port_count,omitempty"`
	ResourceInterval     *FlexInt        `json:"resource_interval,omitempty"`
	ResourceSupport      *bool           `json:"resource_support,omitempty"`
	Runtime              *FlexInt        `json:"runtime,omitempty"`
	RxRate               *FlexInt        `json:"rx_rate,omitempty"`
	SecondParentDeviceID string          `json:"second_parent_device_id,omitempty"`
	SpeedDiagnose        *bool           `json:"speed_diagnose,omitempty"`
	SupportPLC           bool            `json:"support_plc"`
	Topology             *struct {
		Auto            *bool    `json:"auto,omitempty"`
		BackhaulMode    string   `json:"backhaul_mode,omitempty"` // wifi|plc
		DeviceID        string   `json:"device_id,omitempty"`
		PlcSignal       string   `json:"plc_signal,omitempty"` // strong|weak
		SupportBackhaul []string `json:"support_backhaul,omitempty"`
	} `json:"topology,omitempty"`
	TxRate       *FlexInt        `json:"tx_rate,omitempty"`
	WlanCertInfo json.RawMessage `json:"wlan_cert_info,omitempty"`
	Role         Enum            `json:"role,omitempty"` // master|slave; app default master
	Detail       *struct {
		DeviceID     string  `json:"device_id"`
		IspErrorCode FlexInt `json:"isp_error_code"`
	} `json:"detail,omitempty"`
	IsWired              bool  `json:"is_wired"`
	GroupStatus          Enum  `json:"group_status,omitempty"`        // connected|disconnected; app default connected
	ZigbeeRole           Enum  `json:"zigbee_role,omitempty"`         // master|slave|none; app default none
	SetGatewaySupport    *bool `json:"set_gateway_support,omitempty"` // app default true
	SpeedGetSupport      bool  `json:"speed_get_support"`
	EnableGatewayFeature *bool `json:"enable_gateway_feature,omitempty"` // app default true
	InetConnectionType   Enum  `json:"inet_connection_type,omitempty"`   // ewan|hotspot_backup|lte_backup|nr_backup|re_lte_backup|re_nr_backup; app default ewan
	IsBackupDevice       bool  `json:"is_backup_device"`
}

// IsMaster applies the app's default (TMPDeviceBean.java:103): an absent role means master.
func (d Deco) IsMaster() bool { return d.Role == "" || d.Role.Is(RoleMaster) }

// IsOnline applies the app's default (TMPDeviceBaseBean.java:72): absent means online.
func (d DecoBase) IsOnline() bool { return d.InetStatus == "" || d.InetStatus.Is(InetOnline) }

type AgentDev struct {
	DecoBase
	IsThirdPartDevice bool `json:"is_third_part_device"`
	RebootSupport     bool `json:"reboot_support"`
	ResetSupport      bool `json:"reset_support"`
}

// ---- Device id params / reboot / eth / speed / resource / signal ----

type DeviceID struct {
	DeviceID string `json:"device_id"`
}
type DeviceIDListParams struct {
	DeviceList []DeviceID `json:"device_list"`
}
type DeviceRebootResult struct {
	RebootTime FlexInt `json:"reboot_time"`
}
type DeviceEthPortResult struct {
	DeviceList []struct {
		DeviceID string `json:"device_id"`
		PortInfo []struct {
			BitErrorRate    *float32 `json:"bit_error_rate,omitempty"`
			Port            FlexInt  `json:"port"`
			PortSpeed       *FlexInt `json:"port_speed,omitempty"`
			PortsStatusInfo []struct {
				Status string `json:"status"` // well|unplugged|no_internet|dial_failed
				Type   string `json:"type"`   // wan|lan|eth_bkhl|iptv|voip
			} `json:"ports_status_info"`
		} `json:"port_info"`
	} `json:"device_list"`
}
type DeviceSpeedListResult struct {
	DeviceListSpeed []struct {
		DeviceID  string  `json:"device_id"`
		DownSpeed FlexInt `json:"down_speed"`
		InHnat    bool    `json:"in_hnat"`
		UpSpeed   FlexInt `json:"up_speed"`
	} `json:"device_list_speed"`
}
type DeviceResourceInfoResult struct {
	DeviceList []struct {
		CPUUsage    *FlexInt `json:"cpu_usage,omitempty"`
		DeviceID    string   `json:"device_id"`
		MemoryTotal *FlexInt `json:"memory_total,omitempty"`
		MemoryUsage *FlexInt `json:"memory_usage,omitempty"`
	} `json:"device_list"`
}
type SignalLevelListResult struct {
	DeviceList []struct {
		DeviceID       string  `json:"device_id"`
		SignalLevel    FlexInt `json:"signal_level"`
		SignalStrength FlexInt `json:"signal_strength"`
	} `json:"device_list"`
}

// ---- Clients ----

// ClientSignalLevel is ClientSignalLevelBean (primitive int fields): keys band2_4, band5,
// band5_1, band5_2, band6, band6_2, band2+band5, band2+band6, band5+band6, band2+band5+band6.
type ClientSignalLevel map[string]FlexInt

type LinkedDevice struct {
	ConnectionType []Enum            `json:"connection_type,omitempty"`
	DeviceID       string            `json:"device_id,omitempty"` // Deco device_id
	RxRateList     ClientSignalLevel `json:"rx_rate_list,omitempty"`
	SignalLevel    ClientSignalLevel `json:"signal_level,omitempty"`
	SignalStrength ClientSignalLevel `json:"signal_strength,omitempty"`
	TxRateList     ClientSignalLevel `json:"tx_rate_list,omitempty"`
	Bandwidth      string            `json:"bandwidth,omitempty"`
	EncryptionMode string            `json:"encryption_mode,omitempty"`
	MIMO           *FlexInt          `json:"mimo,omitempty"`
	WirelessVer    string            `json:"wireless_ver,omitempty"`
}

type SpeedLimit struct {
	IsCustom bool    `json:"is_custom"`
	Speed    FlexInt `json:"speed"`
}

// ClientBean (ClientBean.java:19-96).
type ClientBean struct {
	AccessTime       *FlexInt `json:"access_time,omitempty"`
	Brand            string   `json:"brand,omitempty"`
	ClientMesh       *bool    `json:"client_mesh,omitempty"`
	ClientType       string   `json:"client_type,omitempty"` // entertainment|iot_device|laptop|other|pc|phone|printer|tablet
	CustomClientType string   `json:"custom_client_type,omitempty"`
	EnableIsolation  *bool    `json:"enable_isolation,omitempty"`
	EnablePriority   bool     `json:"enable_priority"`
	ExtraRealtime    []string `json:"extra_realtime_status,omitempty"`
	FirstConnected   *bool    `json:"first_connected,omitempty"`
	HasSetClientType *bool    `json:"has_set_client_type,omitempty"`
	Interface        string   `json:"interface,omitempty"` // main|guest|iot|mlo
	IP               string   `json:"ip,omitempty"`
	LastOnlineTime   *FlexInt `json:"last_online_time,omitempty"`
	LinkPriority     *struct {
		Band       []Enum `json:"band,omitempty"`
		BandAuto   bool   `json:"band_auto"`
		DeviceAuto bool   `json:"device_auto"`
		DeviceID   string `json:"device_id,omitempty"`
	} `json:"link_priority,omitempty"`
	LinkedDeviceInfo *LinkedDevice `json:"linked_device_info,omitempty"`
	MAC              string        `json:"mac"`
	Model            string        `json:"model,omitempty"`
	Name             B64           `json:"name,omitempty"`
	Online           *bool         `json:"online,omitempty"`
	OnlineTime       *FlexInt      `json:"online_time,omitempty"`
	OwnerID          string        `json:"owner_id,omitempty"`
	RemainTime       FlexInt       `json:"remain_time"`
	SpaceID          string        `json:"space_id,omitempty"`
	SpeedLimit       *struct {
		Download *SpeedLimit `json:"download,omitempty"`
		Enable   bool        `json:"enable"`
		Upload   *SpeedLimit `json:"upload,omitempty"`
	} `json:"speed_limit,omitempty"`
	SystemVersion   string   `json:"system_version,omitempty"`
	TimePeriod      *FlexInt `json:"time_period,omitempty"`
	UserSetNameType bool     `json:"user_set_name_type"`
}

type ClientListResult struct {
	ClientList                []ClientBean `json:"client_list"`
	IPv6ClientPrioritySupport bool         `json:"is_ipv6_client_priority_support"`
	PriorityCountMax          FlexInt      `json:"priority_count_max"`
	SpeedLimitCountMax        FlexInt      `json:"speed_limit_count_max"`
}

// ClientSpeed: up/down are kbps (ClientDetailActivity.java:912-921 -> FlowUnitUtils.o:296-304).
type ClientSpeed struct {
	DownSpeed FlexInt `json:"down_speed"`
	InHnat    bool    `json:"in_hnat"`
	MAC       string  `json:"mac"`
	UpSpeed   FlexInt `json:"up_speed"`
}
type ClientSpeedListResult struct {
	ClientListSpeed []ClientSpeed `json:"client_list_speed"`
}
type ClientMacParams struct {
	MAC string `json:"mac"`
}

type ClientBlockEntry struct {
	ClientType string `json:"client_type,omitempty"`
	MAC        string `json:"mac"`
	Name       B64    `json:"name,omitempty"`
}
type ClientBlockParams struct { // 0x4017 block-list add; 0x4404 allow-list add
	ClientList []ClientBlockEntry `json:"client_list"`
}
type ClientBlockListResult struct { // 0x4018; same shape as ClientWhiteListResult (0x4403)
	ClientList []ClientBlockEntry `json:"client_list"`
	MaxCount   *FlexInt           `json:"max_count,omitempty"`
}
type ClientUnblockParams struct { // 0x4019 block-list remove; 0x4405 allow-list remove
	ClientList []string `json:"client_list"` // MACs
}
type AccessControlMode struct { // 0x4402 Set
	AccessControlMode  string `json:"access_control_mode,omitempty"` // block_list|white_list
	GuestNetworkAccess *bool  `json:"guest_network_access,omitempty"`
	NewDeviceNotify    *bool  `json:"new_device_notify,omitempty"`
}

// ---- Quick setup Wi-Fi status (0x4098) ----
type QsWifiStatusResult struct {
	ErrorCode      FlexInt `json:"error_code"` // 0 success, 1 create failed
	ErrorMsg       string  `json:"error_msg,omitempty"`
	State          bool    `json:"state"`
	MaxWaitingTime FlexInt `json:"max_waiting_time"`
}

// ---- LED (0x401a / 0x401b / 0x42f7) ----
type LEDSchedule struct {
	DeviceID        string `json:"device_id,omitempty"`
	Enable          *bool  `json:"enable,omitempty"`
	EnableNightMode *bool  `json:"enable_night_mode,omitempty"`
	TimeBegin       *int   `json:"time_begin,omitempty"`
	TimeEnd         *int   `json:"time_end,omitempty"`
}
type LEDBean struct {
	Enable               *bool         `json:"enable,omitempty"`
	EnableNightMode      *bool         `json:"enable_night_mode,omitempty"`
	LEDIndividualControl *bool         `json:"led_individual_control,omitempty"`
	Schedule             []LEDSchedule `json:"schedule,omitempty"`
	TimeBegin            *int          `json:"time_begin,omitempty"`
	TimeEnd              *int          `json:"time_end,omitempty"`
}
type LEDDeviceResult struct {
	DeviceList []struct {
		DeviceID    string `json:"device_id"`
		LEDCategory *bool  `json:"led_category,omitempty"`
	} `json:"device_list"`
}

// ---- Channel / bandwidth (0x42f0/0x42f1/0x42f2, 0x4390/0x4391) ----
type BandwidthSwitch struct {
	AutoBandwidth       *bool            `json:"auto_bandwidth,omitempty"`
	AutoChannel         *bool            `json:"auto_channel,omitempty"`
	AutoSwitch          *bool            `json:"auto_switch,omitempty"`
	Bandwidth           *int             `json:"bandwidth,omitempty"`           // 20/40/80/160/240/320
	Bandwidth240Status  string           `json:"bandwidth240_status,omitempty"` // selectable|unselectable
	Channel             *int             `json:"channel,omitempty"`
	Band2G4             *BandwidthSwitch `json:"band2_4,omitempty"`
	Band5               *BandwidthSwitch `json:"band5,omitempty"`
	Band5G2             *BandwidthSwitch `json:"band5_2,omitempty"`
	Band6               *BandwidthSwitch `json:"band6,omitempty"`
	Band6G2             *BandwidthSwitch `json:"band6_2,omitempty"`
	ConfiguredBandwidth *int             `json:"configured_bandwidth,omitempty"`
	Notice              *bool            `json:"notice,omitempty"`
	RecommendBandwidth  *int             `json:"recommend_bandwidth,omitempty"`
	SupportBandwidth    []struct {
		AfcChannel     []int `json:"afc_channel,omitempty"`
		Bandwidth      *int  `json:"bandwidth,omitempty"`
		SupportChannel []int `json:"support_channel,omitempty"`
	} `json:"support_bandwidth,omitempty"`
	SwitchLimit       *bool  `json:"switch_limit,omitempty"`
	UsbChannelBackoff string `json:"usb_channel_backoff_status,omitempty"` // plugged_backoff|plugged_no_backoff|unplugged
}
type BandwidthSwitchSettingResult struct {
	Countdown FlexInt `json:"countdown"`
}
type BandwidthSwitchGetResult struct {
	Status string `json:"status"` // success|fail|switching
}
type ChannelLimits struct {
	Enable bool `json:"enable"`
}
