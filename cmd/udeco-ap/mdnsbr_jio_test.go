// SPDX-License-Identifier: GPL-2.0-or-later

package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"

	"github.com/dtechterminal/udeco/internal/apstate"
	"github.com/dtechterminal/udeco/internal/mdnsbr"
)

// fcCount is ebSim that also counts the flow cache commands (`fc`) run.
type fcCount struct {
	*ebSim
	mu sync.Mutex
	fc int
}

func (f *fcCount) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	if name == "fc" {
		f.mu.Lock()
		f.fc++
		f.mu.Unlock()
	}
	return f.ebSim.Run(ctx, name, args...)
}

// The mDNS bridge on platform jio-mtk: the LAN bridge is bdg2 (its wired
// members eth0.P.1 tapped, the served rai0 intercepted, an idle BSS slot
// and the AP-client netdev left alone), no Broadcom flow cache is flushed,
// and the mDNS bridge is claimed with mdns_bridge.
func TestMdnsBridgeJio(t *testing.T) {
	root := t.TempDir()
	for dir, ports := range map[string][]string{"bdg2": {"eth0.1.1", "eth0.4.1", "rai0", "rai1", "apclii0"}, "br-v3": {"eth0.4.3"}} {
		for _, p := range ports {
			if err := os.MkdirAll(filepath.Join(root, "sys/class/net", dir, "brif", p), 0o755); err != nil {
				t.Fatal(err)
			}
		}
	}
	for i, n := range []string{"bdg2", "eth0.1.1", "eth0.4.1", "rai0", "rai1", "apclii0", "eth0.4.3", "br-v3"} {
		d := filepath.Join(root, "sys/class/net", n)
		os.MkdirAll(d, 0o755)
		os.WriteFile(filepath.Join(d, "address"), []byte(fmt.Sprintf("50:91:e3:00:01:%02x\n", i+1)), 0o644)
	}
	path := filepath.Join(root, "system_cfg.txt")
	if err := os.WriteFile(path, []byte(mdnsCfg), 0o600); err != nil {
		t.Fatal(err)
	}
	snap := testSnapshot()
	snap.Radios[1].VAPs[0].Iface = "rai0"
	run := &fcCount{ebSim: &ebSim{}}
	var mu sync.Mutex
	var opened []string
	a := &agent{cfg: &Config{Platform: PlatformJio, Takeover: true, Apply: true, MdnsBridge: true},
		o: options{logf: t.Logf, root: root, run: run}, sysCfgPath: path, infoKey: "1/1", uplink: "eth0.4.1"}
	a.takeover.Store(true)
	a.mdns = &mdnsState{open: func(p mdnsbr.Port) (mdnsbr.Conn, error) {
		mu.Lock()
		defer mu.Unlock()
		opened = append(opened, p.Key())
		return &nullConn{closed: make(chan struct{})}, nil
	}}
	t.Cleanup(a.mdnsShutdown)
	info := apstate.InfoFromCfg(mdnsCfg)
	a.mdnsReconcile(context.Background(), snap, info)
	mu.Lock()
	got := append([]string(nil), opened...)
	mu.Unlock()
	if want := []string{"eth0.1.1", "eth0.4.1", "rai0"}; !reflect.DeepEqual(sortedCopy(got), want) {
		t.Errorf("opened %v, want %v", got, want)
	}
	if fw, chain := run.state(); !chain || !reflect.DeepEqual(fw, []string{"-o rai0 -j UDECO-MDNS"}) {
		t.Errorf("FORWARD %v, chain %t", fw, chain)
	}
	a.mdnsStop(context.Background())
	if fw, chain := run.state(); len(fw) != 0 || chain {
		t.Errorf("after stop: FORWARD %v, chain %t", fw, chain)
	}
	if run.fc != 0 {
		t.Errorf("%d fc commands on the JCOW414 (no flow cache)", run.fc)
	}
	env := a.mdnsEnv(snap, info)
	if env.LANBridge != "bdg2" || env.Uplink != "eth0.4" || len(env.Bridges["bdg2"]) != 5 {
		t.Errorf("env: LAN %q uplink %q bridges %v", env.LANBridge, env.Uplink, env.Bridges)
	}
}

func sortedCopy(s []string) []string {
	out := append([]string(nil), s...)
	for i := range out {
		for j := i + 1; j < len(out); j++ {
			if out[j] < out[i] {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}
