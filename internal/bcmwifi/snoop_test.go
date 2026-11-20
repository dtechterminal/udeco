// SPDX-License-Identifier: GPL-2.0-or-later

package bcmwifi

import (
	"context"
	"os"
	"strings"
	"testing"
)

func readKnob(t *testing.T, f *fakeDev, br, knob string) string {
	t.Helper()
	b, err := os.ReadFile(f.path("/sys/class/net/" + br + "/bridge/" + knob))
	if err != nil {
		return "<missing>"
	}
	return strings.TrimSpace(string(b))
}

// The agent's VLAN bridges snoop IGMP/MLD as a U6 Pro's mcsd does on every
// bridge (snooping on, no querier of its own, hash_max 2048); a knob that
// drifts is put back by Tick. br-lan (TP-Link's imsnoop) is not touched.
func TestVLANBridgeSnooping(t *testing.T) {
	ctx := context.Background()
	f := newFakeDev(t)
	a := newTestApplier(f, false)
	d := twoSSIDs() // b-iot on VLAN 20
	p, err := a.Plan(ctx, d)
	if err != nil {
		t.Fatal(err)
	}
	if i, j := stepIndex(t, p, "brctl addbr br-v20"), stepIndex(t, p, "/sys/class/net/br-v20/bridge/multicast_snooping"); j < i {
		t.Errorf("snooping step %d before the bridge exists %d", j, i)
	}
	if err := a.Apply(ctx, p); err != nil {
		t.Fatal(err)
	}
	for knob, want := range map[string]string{"multicast_snooping": "1", "multicast_querier": "0", "hash_max": "2048"} {
		if got := readKnob(t, f, "br-v20", knob); got != want {
			t.Errorf("br-v20 %s = %q, want %q", knob, got, want)
		}
	}
	if p2, _ := a.Plan(ctx, d); !p2.Empty() {
		t.Fatalf("plan after apply:\n%s", p2)
	}
	f.write("/sys/class/net/br-v20/bridge/multicast_snooping", "0\n")
	if r, err := a.Tick(ctx); err != nil || r.NeedsApply {
		t.Fatalf("tick %+v %v", r, err)
	}
	if got := readKnob(t, f, "br-v20", "multicast_snooping"); got != "1" {
		t.Errorf("snooping %q after Tick", got)
	}
	if f.called("br-lan/bridge") || strings.Contains(p.String(), "br-lan/bridge") {
		t.Error("br-lan's snooping touched")
	}
}
