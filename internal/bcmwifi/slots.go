// SPDX-License-Identifier: GPL-2.0-or-later

package bcmwifi

import (
	"encoding/json"
	"os"
	"path"
	"path/filepath"

	"github.com/antoniocosta/unifi-openwrt/internal/atomicfile"
)

// Stable vif slots. An SSID keeps the vif it is on when the SSID set of its
// radio changes (another SSID added, removed, disabled or scheduled off):
// moving it would change its BSSID and drop its clients. The placement in
// force is read from the driver-state files the last apply wrote
// (RunDir/drv-wlN.json, vif -> SSID id); RunDir/slots.json remembers in
// addition where SSIDs that are off now were, so one that comes back gets
// its vif again and a new SSID takes a vif nobody is waiting for while one
// is free. Both are on ramfs: a reboot (stock TP-Link Wi-Fi again) forgets
// them.

func (a *Applier) slotsPath() string { return path.Join(a.o.RunDir, "slots.json") }

// priorSlots is layoutOpts.prior: the remembered slots, overlaid by the
// placement in force (which wins for its vifs and its SSIDs).
func (a *Applier) priorSlots() map[string]string {
	mem := map[string]string{}
	if b, err := a.readFile(a.slotsPath()); err == nil {
		if json.Unmarshal(b, &mem) != nil {
			mem = map[string]string{}
		}
	}
	live := map[string]string{} // vif -> id, from the driver-state files
	for _, prim := range Primaries() {
		b, err := a.readFile(drvPath(a.o.RunDir, prim))
		if err != nil {
			continue
		}
		var drv []vifDriver
		if json.Unmarshal(b, &drv) != nil {
			continue
		}
		for _, d := range drv {
			if d.Vif != "" && d.SSIDID != "" {
				live[d.Vif] = d.SSIDID
			}
		}
	}
	return mergeSlots(mem, live)
}

// mergeSlots overlays live (vif -> id) on mem: an entry of mem whose vif is
// live, or whose SSID is live on the same radio, is dropped.
func mergeSlots(mem, live map[string]string) map[string]string {
	out := map[string]string{}
	liveID := map[string]bool{} // radio prefix + id
	for v, id := range live {
		liveID[radioOf(v)+"|"+id] = true
	}
	for v, id := range mem {
		if _, ok := live[v]; ok || liveID[radioOf(v)+"|"+id] || vifIndex(v) < firstVifIndex {
			continue
		}
		out[v] = id
	}
	for v, id := range live {
		out[v] = id
	}
	return out
}

// radioOf is the primary of a vif (wl13 -> wl1).
func radioOf(v string) string {
	if len(v) < 4 {
		return v
	}
	return v[:3]
}

// Primaries are the radios' primary interfaces (wl0, wl1), in the order
// radios are planned in.
func Primaries() []string {
	var out []string
	for _, b := range radioOrder {
		out = append(out, bandPrimary[b])
	}
	return out
}

// saveSlots records l's placement (it is in force: applied and verified)
// on top of the remembered slots. Best effort: a failure only loses the
// memory of SSIDs that are off.
func (a *Applier) saveSlots(l *layout) {
	live := map[string]string{}
	for _, r := range l.Radios {
		for _, u := range r.Used {
			live[u.Vif] = u.SSID.ID
		}
	}
	mem := map[string]string{}
	if b, err := a.readFile(a.slotsPath()); err == nil {
		_ = json.Unmarshal(b, &mem)
	}
	b, _ := json.Marshal(mergeSlots(mem, live)) // map keys sorted: stable bytes
	if a.sameFile(a.slotsPath(), b) {
		return
	}
	p := a.fsPath(a.slotsPath())
	err := os.MkdirAll(filepath.Dir(p), 0o700)
	if err == nil {
		err = atomicfile.Write(p, p+".tmp", b, 0o600)
	}
	if err != nil {
		a.o.Logf("bcmwifi: recording vif slots: %v (an SSID that is off may get another vif when it returns)", err)
	}
}

// vifFiles are the per-vif files the agent keeps in RunDir: the hostapd
// deny and accept lists and the private-key file.
func vifFiles(runDir, vif string) []string {
	return []string{DenyPath(runDir, vif), acceptPath(runDir, vif), pskPath(runDir, vif)}
}

// staleVifSteps removes the per-vif files of the radio's vifs that carry no
// SSID in rl (an SSID removed, moved or off), so no deny list or key file
// of a vif nobody serves is left on ramfs, and a later SSID on that vif
// never starts from them. The files of the vifs in use are never touched.
// Only files that exist get a step, so a clean RunDir plans nothing.
func (a *Applier) staleVifSteps(prim string, rl *radioLayout) []Step {
	var st []Step
	for i := 1; i <= 9; i++ {
		v := prim + string(rune('0'+i))
		if _, used := findUsed(rl, v); used {
			continue
		}
		for _, f := range vifFiles(a.o.RunDir, v) {
			if a.exists(f) {
				st = append(st, Step{Kind: StepRemove, Desc: "remove stale file of unused " + v, Path: f})
			}
		}
	}
	return st
}
