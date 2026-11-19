package decosys

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
)

// TP-Link's QoS (S99qos → /lib/qos/core_qos.sh) leaves 'htb 2:' as the root
// qdisc of br-lan from boot, with class 2:2 (317440 kbit), leaf 2:202 and an
// sfq 202: under it (topology-and-tplink-scrub.md, audit D13). It only
// shapes the unit's own traffic, but it is TP-Link state and in the way of
// any tc work on br-lan, and 'qos stop/reload' would delete or rebuild it
// behind the agent's back. Enforce saves it and deletes it; Restore replays
// it. /etc/init.d/qos cannot rebuild it in AP/RE mode (its start_service
// returns early there), hence the replay.
const (
	tplinkQdiscHandle = "2:"
	qosBackup         = stateDir + "/qos.br-lan.tplink"
)

// tcShow runs 'tc <what> show dev <LANDev>'.
func (m *Manager) tcShow(ctx context.Context, tc, what string) (string, error) {
	out, err := m.o.Run.Run(ctx, tc, what, "show", "dev", m.o.LANDev)
	if err != nil {
		return "", fmt.Errorf("tc %s show dev %s: %w", what, m.o.LANDev, err)
	}
	return string(out), nil
}

// rootQdisc returns the kind and handle of the root qdisc in 'tc qdisc show'
// output ("", "" for none).
func rootQdisc(show string) (kind, handle string) {
	for _, l := range strings.Split(show, "\n") {
		f := strings.Fields(l)
		if len(f) >= 4 && f[0] == "qdisc" && f[3] == "root" {
			return f[1], f[2]
		}
	}
	return "", ""
}

// isTPLinkRoot reports whether the root qdisc is TP-Link's QoS.
func isTPLinkRoot(kind, handle string) bool { return kind == "htb" && handle == tplinkQdiscHandle }

// qdiscSteps returns the step that saves and deletes TP-Link's root qdisc
// on br-lan, and reports any other non-default root qdisc (not touched).
func (m *Manager) qdiscSteps(ctx context.Context) ([]Step, []Finding, error) {
	tc := m.bin("tc")
	if !strings.HasPrefix(tc, "/") {
		m.note("no-tc", "tc not found: TP-Link's br-lan QoS (R24) is left alone")
		return nil, nil, nil
	}
	show, err := m.tcShow(ctx, tc, "qdisc")
	if err != nil {
		return nil, nil, err
	}
	kind, handle := rootQdisc(show)
	other := kind != "" && !isTPLinkRoot(kind, handle) && !slices.Contains([]string{"noqueue", "pfifo_fast", "mq"}, kind)
	notes := m.edge(WatchQdisc, "qdisc-other", other,
		fmt.Sprintf("root qdisc %s %s on %s is neither TP-Link's nor a default: left alone", kind, handle, m.o.LANDev))
	if !isTPLinkRoot(kind, handle) {
		return nil, notes, nil
	}
	cmd := []string{tc, "qdisc", "del", "dev", m.o.LANDev, "root"}
	return []Step{{Kind: KindQdisc, Target: m.o.LANDev + " htb " + tplinkQdiscHandle,
		Reason: "TP-Link QoS root qdisc (saved for Restore)", Cmd: cmd,
		do: func(ctx context.Context) error {
			if err := m.saveQdisc(ctx, tc, show); err != nil {
				return fmt.Errorf("save: %w (not deleted)", err)
			}
			_, err := m.o.Run.Run(ctx, cmd[0], cmd[1:]...)
			return err
		}}}, notes, nil
}

// saveQdisc records the qdisc, class and filter tree once; a later pass
// (TP-Link rebuilt it) keeps the first record.
func (m *Manager) saveQdisc(ctx context.Context, tc, qdiscs string) error {
	if m.exists(qosBackup) {
		return nil
	}
	classes, err := m.tcShow(ctx, tc, "class")
	if err != nil {
		return err
	}
	filters, err := m.tcShow(ctx, tc, "filter")
	if err != nil {
		return err
	}
	var lines []string
	for _, out := range []string{qdiscs, classes, filters} {
		for _, l := range strings.Split(out, "\n") {
			if strings.TrimSpace(l) != "" {
				lines = append(lines, strings.TrimRight(l, " "))
			}
		}
	}
	return m.writeFile(qosBackup, lines, 0o600)
}

// keep picks the listed "key value" pairs (in order of appearance) from
// tc show fields, applying fix to each value.
func keep(f []string, keys []string, fix func(k, v string) string) []string {
	var out []string
	for i := 0; i+1 < len(f); i++ {
		if slices.Contains(keys, f[i]) {
			out = append(out, f[i], fix(f[i], f[i+1]))
			i++
		}
	}
	return out
}

// replayQdisc turns saved 'tc ... show' lines back into 'tc ... add'
// argument lists: the root qdisc, the classes parents first, then the
// child qdiscs. Only htb and sfq (all TP-Link uses) are understood;
// anything else is returned as a note and skipped.
func replayQdisc(dev string, saved []string) (cmds [][]string, notes []string) {
	noUnit := func(k, v string) string {
		switch k {
		case "limit":
			return strings.TrimSuffix(v, "p")
		case "perturb":
			return strings.TrimSuffix(v, "sec")
		}
		return v
	}
	type class struct {
		id, parent string
		args       []string
	}
	var root []string
	var children [][]string
	var classes []class
	for _, l := range saved {
		f := strings.Fields(l)
		if len(f) < 4 {
			continue
		}
		switch f[0] {
		case "qdisc":
			var args []string
			switch f[1] {
			case "htb":
				args = keep(f[3:], []string{"r2q", "default"}, noUnit)
			case "sfq":
				args = keep(f[3:], []string{"limit", "quantum", "depth", "divisor", "perturb", "flows"}, noUnit)
			default:
				notes = append(notes, "qdisc not restored: "+l)
				continue
			}
			if f[3] == "root" {
				root = append([]string{"qdisc", "add", "dev", dev, "root", "handle", f[2], f[1]}, args...)
			} else if f[3] == "parent" && len(f) >= 5 {
				children = append(children, append([]string{"qdisc", "add", "dev", dev, "parent", f[4], "handle", f[2], f[1]}, args...))
			}
		case "class":
			if f[1] != "htb" {
				notes = append(notes, "class not restored: "+l)
				continue
			}
			c := class{id: f[2], args: keep(f[3:], []string{"prio", "rate", "ceil", "burst", "cburst"}, noUnit)}
			if f[3] == "root" {
				major, _, _ := strings.Cut(c.id, ":")
				c.parent = major + ":"
			} else if f[3] == "parent" && len(f) >= 5 {
				c.parent = f[4]
			}
			classes = append(classes, c)
		case "filter":
			notes = append(notes, "filter not restored: "+l)
		}
	}
	if root == nil {
		return nil, append(notes, "no root qdisc saved")
	}
	cmds = append(cmds, root)
	made := map[string]bool{root[6]: true}
	for len(classes) > 0 {
		n := len(classes)
		classes = slices.DeleteFunc(classes, func(c class) bool {
			if !made[c.parent] {
				return false
			}
			cmds = append(cmds, append([]string{"class", "add", "dev", dev, "parent", c.parent, "classid", c.id, "htb"}, c.args...))
			made[c.id] = true
			return true
		})
		if len(classes) == n {
			for _, c := range classes {
				notes = append(notes, "class without parent not restored: "+c.id)
			}
			break
		}
	}
	return append(cmds, children...), notes
}

// restoreQdisc replays the saved TP-Link QoS onto br-lan when br-lan has no
// root qdisc of its own by then. Each tc command is checked; on a failure
// the rest is skipped and the record kept.
func (m *Manager) restoreQdisc(ctx context.Context) error {
	saved, err := m.readLines(qosBackup)
	if err != nil || len(saved) == 0 {
		return err
	}
	tc := m.bin("tc")
	show, err := m.tcShow(ctx, tc, "qdisc")
	if err != nil {
		return err
	}
	if kind, handle := rootQdisc(show); isTPLinkRoot(kind, handle) {
		return m.dry(func() error { return m.remove(qosBackup) })
	} else if kind != "" && !slices.Contains([]string{"noqueue", "pfifo_fast", "mq"}, kind) {
		return fmt.Errorf("restore qos: %s already has root qdisc %s %s; TP-Link's not replayed", m.o.LANDev, kind, handle)
	}
	cmds, notes := replayQdisc(m.o.LANDev, saved)
	for _, n := range notes {
		m.o.Logf("decosys: restore qos: %s", n)
	}
	for _, c := range cmds {
		if err := m.mutate(ctx, tc, c...); err != nil {
			return fmt.Errorf("restore qos: %w", err)
		}
	}
	if len(cmds) == 0 {
		return errors.New("restore qos: nothing to replay")
	}
	return m.dry(func() error { return m.remove(qosBackup) })
}

// dry runs f unless DryRun.
func (m *Manager) dry(f func() error) error {
	if m.o.DryRun {
		return nil
	}
	return f()
}
