// SPDX-License-Identifier: GPL-2.0-or-later

package bcmwifi

import (
	"slices"
	"strings"
	"testing"

	"github.com/dtechterminal/udeco/internal/repotest"
	"github.com/dtechterminal/udeco/internal/rf"
	"github.com/dtechterminal/udeco/internal/wl"
)

// What bcmwifi takes from the shared packages (rf, unit, wl) and what the
// agent takes from bcmwifi, as each caller sees it.

// parseChanspec is wl's reader of the text form behind the first field;
// its errors read as they always did.
func TestParseChanspecErrors(t *testing.T) {
	for in, want := range map[string]string{
		"":                `empty chanspec`,
		"  \n":            `empty chanspec`,
		"x (0x1006)":      `chanspec "x": bad channel`,
		"0":               `chanspec "0": bad channel`,
		"l":               `chanspec "l": bad channel`,
		"x/80":            `chanspec "x/80": bad channel`,
		"36/x (0xe22a)":   `chanspec "36/x": strconv.Atoi: parsing "x": invalid syntax`,
		"36/80u (0xe22a)": `chanspec "36/80u": strconv.Atoi: parsing "80u": invalid syntax`,
	} {
		if _, err := parseChanspec(in); err == nil || err.Error() != want {
			t.Errorf("parseChanspec(%q): %v, want %q", in, err, want)
		}
	}
	for _, in := range []string{"44/80 (0xe22a)", "2l (0x1804)", "7u", "6", "36/160"} {
		cs, err := parseChanspec(in)
		ctrl, width, werr := wl.ParseChanspecText(strings.Fields(in)[0])
		if err != nil || werr != nil || cs.Ctrl != ctrl || cs.Width != width {
			t.Errorf("parseChanspec(%q) = %+v, %v; wl.ParseChanspecText = %d, %d, %v", in, cs, err, ctrl, width, werr)
		}
	}
}

func TestBandNames(t *testing.T) {
	if !slices.Equal(radioOrder, rf.Bands()) || !slices.Equal(Primaries(), []string{"wl0", "wl1"}) {
		t.Errorf("radioOrder %v, Primaries %v", radioOrder, Primaries())
	}
	// wl's band argument: every radio but the 2.4 GHz one is "5g"
	for band, want := range map[string]string{"ng": "2g", "na": "5g", "6e": "5g", "": "5g"} {
		if got := bandArg(band); got != want {
			t.Errorf("bandArg(%q) = %q, want %q", band, got, want)
		}
	}
	// a band's other name: this unit's two bands only
	for band, want := range map[string]string{"ng": "2g", "na": "5g", "2g": "ng", "5g": "na", "6e": "", "6g": "", "": "", "NG": ""} {
		if got := bandAlias(band); got != want {
			t.Errorf("bandAlias(%q) = %q, want %q", band, got, want)
		}
	}
	// ForBand finds the band's settings under either name
	s := SSID{Security: SecWPA2, PerBand: map[string]BandSettings{"5g": {Security: SecWPA3}, "ng": {Security: SecOpen}}}
	for band, want := range map[string]string{"na": SecWPA3, "5g": SecWPA3, "ng": SecOpen, "2g": SecOpen, "6e": SecWPA2} {
		if got := s.ForBand(band).Security; got != want {
			t.Errorf("ForBand(%q).Security = %q, want %q", band, got, want)
		}
	}
}

// The default width and the widest width are each named once: a radio
// with no width gets DefaultWidth, a wider one than maxWidth gets
// maxWidth and the note says so.
func TestWidthDefaults(t *testing.T) {
	for band, want := range map[string]int{"ng": 20, "na": 80, "6e": 0, "": 0} {
		if got := DefaultWidth(band); got != want {
			t.Errorf("DefaultWidth(%q) = %d, want %d", band, got, want)
		}
	}
	if DefaultWidth("na") != maxWidth {
		t.Errorf("the 5 GHz default %d is not the widest width %d", DefaultWidth("na"), maxWidth)
	}
	if cs, _, _ := desiredChanspec("na", Radio{Channel: 36}, chanspec{44, 40}, nil); cs.Width != DefaultWidth("na") {
		t.Errorf("no width on na: %s", cs)
	}
	if cs, _, _ := desiredChanspec("ng", Radio{Channel: 6}, chanspec{1, 40}, nil); cs.Width != DefaultWidth("ng") {
		t.Errorf("no width on ng: %s", cs)
	}
	if cs, _, _ := desiredChanspec("na", Radio{Channel: 36, Width: 160}, chanspec{44, 40}, nil); cs.Width != maxWidth {
		t.Errorf("160 on na: %s", cs)
	}
	if got, want := radioNotes("na", Radio{Width: 160}), []string{"radio na: width 160 not available, using 80"}; !slices.Equal(got, want) {
		t.Errorf("radioNotes = %q, want %q", got, want)
	}
	if got := radioNotes("na", Radio{Width: 80}); len(got) != 0 {
		t.Errorf("radioNotes at 80: %q", got)
	}
}

func TestSubChannels(t *testing.T) {
	for _, c := range []struct {
		cs   chanspec
		want []int
	}{
		{chanspec{36, 20}, []int{36}}, {chanspec{40, 40}, []int{36, 40}}, {chanspec{48, 80}, []int{36, 40, 44, 48}},
		{chanspec{100, 80}, []int{100, 104, 108, 112}}, {chanspec{124, 80}, []int{116, 120, 124, 128}},
		{chanspec{161, 80}, []int{149, 153, 157, 161}}, {chanspec{165, 20}, []int{165}}, {chanspec{44, 0}, []int{44}},
		{chanspec{104, 160}, []int{100, 104, 108, 112, 116, 120, 124, 128}},
	} {
		if got := subChannels(c.cs); !slices.Equal(got, c.want) {
			t.Errorf("subChannels(%s) = %v, want %v", c.cs, got, c.want)
		}
	}
	if !(chanspec{52, 80}).dfs() || (chanspec{36, 80}).dfs() || (chanspec{149, 80}).dfs() || !dfsChannel("na", 144) || dfsChannel("ng", 60) {
		t.Error("the DFS range is not rf's 52-144 on 5 GHz")
	}
}

// The 5 GHz sideband letter is written as arithmetic in chanspec.String;
// rf's table of 40 MHz blocks must give the same: the first channel of a
// block is the lower one ("l"), the other the upper ("u").
func TestSideband5GFollowsBlocks(t *testing.T) {
	for _, first := range rf.Blocks5G(40) {
		if got, want := (chanspec{first, 40}).String(), (chanspec{first, 20}).String()+"l"; got != want {
			t.Errorf("%d at 40 MHz = %q, want %q", first, got, want)
		}
		if got, want := (chanspec{first + 4, 40}).String(), (chanspec{first + 4, 20}).String()+"u"; got != want {
			t.Errorf("%d at 40 MHz = %q, want %q", first+4, got, want)
		}
	}
}

func TestVLANBridgeNames(t *testing.T) {
	for vid, want := range map[int]string{0: "br-lan", 1: "br-v1", 20: "br-v20", 4094: "br-v4094"} {
		if got := vlanBridge(vid); got != want {
			t.Errorf("vlanBridge(%d) = %q, want %q", vid, got, want)
		}
	}
	// the names readLive takes for the agent's VLAN bridges: up to four digits
	for name, want := range map[string]string{"br-v1": "1", "br-v20": "20", "br-v4094": "4094", "br-v0020": "0020",
		"br-v12345": "", "br-v": "", "br-lan": "", "br-vx": "", "xbr-v1": "", "br-v-1": "", "br-v1 ": ""} {
		got := ""
		if m := vBridgeRe.FindStringSubmatch(name); m != nil {
			got = m[1]
		}
		if got != want {
			t.Errorf("vBridgeRe on %q = %q, want %q", name, got, want)
		}
	}
}

// The agent asks bcmwifi for the conf files that tell it owns Wi-Fi
// (cmd/udeco-ap wifiOwned), and the design document names them.
func TestConfPath(t *testing.T) {
	if got := ConfPath(DefaultRunDir, "wl1"); got != "/tmp/udeco/hapd-wl1.conf" {
		t.Errorf("ConfPath = %q", got)
	}
	repotest.MustContain(t, "docs/deco/agent-design.md", "conf at `"+ConfPath(DefaultRunDir, "wlN")+"`")
	repotest.MustContain(t, "docs/deco/agent-design.md", "(`"+ConfPath("RunDir", "wlN")+"`;")
}
