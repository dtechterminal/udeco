// SPDX-License-Identifier: GPL-2.0-or-later

package mtkwifi

import (
	"context"
	"slices"
	"testing"

	"github.com/antoniocosta/unifi-openwrt/internal/bcmwifi"
	"github.com/antoniocosta/unifi-openwrt/internal/rf"
)

// What mtkwifi takes from the shared packages (rf, unit), as its callers
// see it, and the MediaTek unit's own rules next to the shared ones.

// A band is read by rf.Norm, as bcmwifi reads it: the controller's names
// in any case, and (since the two readers became one) with spaces around
// them. No producer sends padded names.
func TestBandNamesNormalised(t *testing.T) {
	for _, name := range []string{"ng", "2g", "2.4g", "2GHz", "2.4ghz", " ng", "2g "} {
		if !onBand(bcmwifi.SSID{Bands: []string{name}}, "ng") {
			t.Errorf("onBand(%q, ng) = false", name)
		}
		if got := bandValue(map[string]int{name: 7}, "ng"); got != 7 {
			t.Errorf("bandValue(%q, ng) = %d", name, got)
		}
		if got := bandRateOpts(map[string]bcmwifi.RateOpts{name: {NoCCK: true}}, "ng"); !got.NoCCK {
			t.Errorf("bandRateOpts(%q, ng) = %+v", name, got)
		}
		if onBand(bcmwifi.SSID{Bands: []string{name}}, "na") {
			t.Errorf("onBand(%q, na) = true", name)
		}
	}
	for _, name := range []string{"na", "5g", "5GHz", " na "} {
		if !onBand(bcmwifi.SSID{Bands: []string{name}}, "na") {
			t.Errorf("onBand(%q, na) = false", name)
		}
	}
	for _, name := range []string{"", "6e", "6g", "ac", "n g"} {
		if onBand(bcmwifi.SSID{Bands: []string{name}}, "ng") || onBand(bcmwifi.SSID{Bands: []string{name}}, "na") {
			t.Errorf("onBand(%q) = true", name)
		}
	}
}

// AutoChannelSkipList is the unit's 2.4 GHz channels without rf's 1, 6
// and 11: still exactly the value the profile always carried.
func TestACSSkip24(t *testing.T) {
	if acsSkip24 != "2;3;4;5;7;8;9;10" {
		t.Errorf("acsSkip24 = %q", acsSkip24)
	}
	if got := skipList([]int{1, 2, 3}, nil); got != "1;2;3" {
		t.Errorf("skipList with nothing kept = %q", got)
	}
	if got := skipList([]int{1, 6, 11}, rf.NonOverlap24()); got != "" {
		t.Errorf("skipList of the kept channels = %q", got)
	}
}

// The unit's DFS channels are a part of rf's DFS range, and isDFS is that
// list.
func TestDFSSet(t *testing.T) {
	if !slices.Equal(chansDFS, []int{52, 56, 60, 64}) {
		t.Errorf("chansDFS = %v", chansDFS)
	}
	for ch := 30; ch <= 180; ch++ {
		if got, want := isDFS(ch), slices.Contains(chansDFS, ch); got != want {
			t.Errorf("isDFS(%d) = %v", ch, got)
		}
		if isDFS(ch) && !rf.IsDFS("na", ch) {
			t.Errorf("channel %d is DFS here but outside rf's DFS range", ch)
		}
	}
	if isDFS(100) || isDFS(54) || isDFS(48) || isDFS(68) {
		t.Error("isDFS takes a channel outside 52/56/60/64")
	}
}

// radarOut next to the channel's block (rf.SubChannels). At 20 and 80 MHz
// and for the upper channel of a 40 MHz block they agree. For the lower
// channel of a 40 MHz block radarOut gives the pair below it: this unit's
// rule as it has always been, kept as it is (see radarOut).
func TestRadarOut(t *testing.T) {
	for _, c := range []struct {
		ch, width int
		want      []int // radarOut
		block     []int // rf.SubChannels
	}{
		{52, 20, []int{52}, []int{52}},
		{64, 20, []int{64}, []int{64}},
		{56, 40, []int{52, 56}, []int{52, 56}},
		{64, 40, []int{60, 64}, []int{60, 64}},
		{52, 40, []int{48, 52}, []int{52, 56}}, // differs
		{60, 40, []int{56, 60}, []int{60, 64}}, // differs
		{52, 80, []int{52, 56, 60, 64}, []int{52, 56, 60, 64}},
		{60, 80, []int{52, 56, 60, 64}, []int{52, 56, 60, 64}},
		{64, 160, []int{52, 56, 60, 64}, []int{36, 40, 44, 48, 52, 56, 60, 64}}, // never wider than 80 here
	} {
		if got := radarOut(c.ch, c.width); !slices.Equal(got, c.want) {
			t.Errorf("radarOut(%d, %d) = %v, want %v", c.ch, c.width, got, c.want)
		}
		if got := rf.SubChannels(c.ch, c.width); !slices.Equal(got, c.block) {
			t.Errorf("rf.SubChannels(%d, %d) = %v, want %v", c.ch, c.width, got, c.block)
		}
	}
}

// The capability lists leave rf's 20 MHz only channel (165) out of the
// wider widths, with and without the DFS channels, and never hand out the
// package's own channel list.
func TestCapsWideChannels(t *testing.T) {
	for _, dfs := range []bool{false, true} {
		cp, err := NewCollector(CollectorOptions{DFS: dfs}).Caps(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		want20 := []int{36, 40, 44, 48, 149, 153, 157, 161, 165}
		if dfs {
			want20 = []int{36, 40, 44, 48, 52, 56, 60, 64, 149, 153, 157, 161, 165}
		}
		wide := want20[:len(want20)-1]
		ch := cp.Bands["na"].Channels
		if !slices.Equal(ch[20], want20) || !slices.Equal(ch[40], wide) || !slices.Equal(ch[80], wide) {
			t.Errorf("dfs=%v: 20 %v, 40 %v, 80 %v", dfs, ch[20], ch[40], ch[80])
		}
		ch[40][0] = 0
	}
	if !slices.Equal(chans5, []int{36, 40, 44, 48, 149, 153, 157, 161, 165}) {
		t.Errorf("chans5 changed through a capability list: %v", chans5)
	}
	if got := plan165(t); got != 20 {
		t.Errorf("channel 165 at 80 MHz planned at %d MHz", got)
	}
}

// plan165 is the width planned for 5 GHz channel 165 asked at 80 MHz.
func plan165(t *testing.T) int {
	t.Helper()
	d := bcmwifi.Desired{Radios: map[string]bcmwifi.Radio{"na": {Enabled: true, Channel: 165, Width: 80}}}
	p, _ := plans(d, JCOW414, false)
	return p["na"].Width
}

func TestBridgeNames(t *testing.T) {
	if got := New(Options{}).o.Bridge; got != "bdg2" {
		t.Errorf("the applier's LAN bridge = %q", got)
	}
	if got := NewCollector(CollectorOptions{}).o.Bridge; got != "bdg2" {
		t.Errorf("the collector's LAN bridge = %q", got)
	}
	if got := vlanBridge(20); got != "br-v20" {
		t.Errorf("vlanBridge(20) = %q", got)
	}
	// the bridges cleanVLANs takes for the agent's own: any number
	for name, want := range map[string]string{"br-v1": "1", "br-v20": "20", "br-v12345": "12345", "br-v0020": "0020",
		"br-v": "", "bdg2": "", "br-lan": "", "br-vx": "", "xbr-v1": "", "br-v-1": ""} {
		got := ""
		if m := vlanBr.FindStringSubmatch(name); m != nil {
			got = m[1]
		}
		if got != want {
			t.Errorf("vlanBr on %q = %q, want %q", name, got, want)
		}
	}
}

func TestChanFreq24(t *testing.T) {
	for _, c := range []struct {
		band     string
		ch, want int
	}{{"ng", 1, 2412}, {"ng", 11, 2462}, {"ng", 14, 2484}, {"na", 36, 5180}, {"na", 165, 5825}} {
		if got := chanFreq24(c.ch, c.band); got != c.want {
			t.Errorf("chanFreq24(%d, %s) = %d, want %d", c.ch, c.band, got, c.want)
		}
	}
}

// The 5 GHz secondary channel is above for the first channel of a 40 MHz
// block and below for the other. profile writes that as arithmetic; rf's
// table of blocks must say the same for every channel this unit serves.
func TestSideband5GFollowsBlocks(t *testing.T) {
	for _, ch := range slices.Concat(chans5, chansDFS) {
		if rf.Only20MHz("na", ch) {
			continue
		}
		want := "0"
		if rf.BlockStart(ch, 40) == ch {
			want = "1"
		}
		p := profile(baseNA(), JCOW414[1], RadioPlan{Band: "na", On: true, Channel: ch, Width: 40})
		if got, _ := getKey(p, "HT_EXTCHA"); got != want {
			t.Errorf("channel %d at 40 MHz: HT_EXTCHA=%s, want %s", ch, got, want)
		}
	}
}
