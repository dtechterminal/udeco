// SPDX-License-Identifier: GPL-2.0-or-later

package translate

import (
	"strings"
	"testing"
)

// The controller's nightly dfs-reset cron job (a U6 Pro's syswrapper.sh
// dfs-reset) is carried as Intent.DFSReset; other cron jobs are noted.
func TestIntentDFSReset(t *testing.T) {
	base := "cron.status=enabled\ncron.1.status=enabled\ncron.1.user=admin\ncron.1.job.1.status=enabled\n"
	for _, c := range []struct {
		cfg  string
		want *DailyTime
		note string
	}{
		{"", nil, ""},
		{base + "cron.1.job.1.schedule=0 2 * * *\ncron.1.job.1.cmd=/usr/etc/syswrapper.sh dfs-reset\n", &DailyTime{2, 0}, ""},
		{base + "cron.1.job.1.schedule=30 3 * * *\ncron.1.job.1.cmd=syswrapper.sh dfs-reset\n", &DailyTime{3, 30}, ""},
		{base + "cron.1.job.1.schedule=*/5 * * * *\ncron.1.job.1.cmd=syswrapper.sh dfs-reset\n", &DailyTime{2, 0}, "schedule"},
		{strings.Replace(base, "job.1.status=enabled", "job.1.status=disabled", 1) + "cron.1.job.1.schedule=0 2 * * *\ncron.1.job.1.cmd=syswrapper.sh dfs-reset\n", nil, ""},
		{base + "cron.1.job.1.schedule=0 4 * * *\ncron.1.job.1.cmd=reboot\n", nil, "cron.1.job.1"},
	} {
		in, notes := IntentFromCfg(c.cfg)
		got := in.DFSReset
		if (got == nil) != (c.want == nil) || got != nil && *got != *c.want {
			t.Errorf("%q: DFSReset %+v, want %+v", c.cfg, got, c.want)
		}
		all := strings.Join(notes, "\n")
		if c.note != "" && !strings.Contains(all, c.note) {
			t.Errorf("%q: notes %q, want %q", c.cfg, notes, c.note)
		}
		if strings.Contains(all, "cron.*: section not recognised") {
			t.Errorf("%q: %q", c.cfg, notes)
		}
	}
}
