// SPDX-License-Identifier: GPL-2.0-or-later

package translate

import (
	"sort"
	"strconv"
	"strings"
)

// DailyTime is a time of day (local).
type DailyTime struct{ Hour, Minute int }

// intentDFSReset finds the controller's dfs-reset cron job (cron.N.job.M
// with cmd "syswrapper.sh dfs-reset", schedule "0 2 * * *" as sent to a
// U6 Pro): the 5 GHz radio goes back to the controller's DFS channel it
// left for radar (internal/bcmwifi dfs.go). Other cron jobs are noted, not
// run.
func intentDFSReset(cfg Cfg, nb *noteList) *DailyTime {
	if cfg["cron.status"] == "disabled" {
		return nil
	}
	var jobs []string
	for k := range cfg {
		if strings.HasPrefix(k, "cron.") && strings.HasSuffix(k, ".cmd") && strings.Contains(k, ".job.") {
			jobs = append(jobs, strings.TrimSuffix(k, ".cmd"))
		}
	}
	sort.Strings(jobs)
	var out *DailyTime
	for _, j := range jobs {
		n, _, _ := strings.Cut(strings.TrimPrefix(j, "cron."), ".")
		if cfg["cron."+n+".status"] == "disabled" || cfg[j+".status"] == "disabled" {
			continue
		}
		if !strings.Contains(cfg[j+".cmd"], "dfs-reset") {
			nb.addf("%s: cron job %q not run", j, cfg[j+".cmd"])
			continue
		}
		t, ok := dailyAt(cfg[j+".schedule"])
		if !ok {
			nb.addf("%s: dfs-reset schedule %q is not a daily time: run at 02:00", j, cfg[j+".schedule"])
			t = DailyTime{2, 0}
		}
		out = &t
	}
	return out
}

// dailyAt reads a crontab schedule "M H * * *".
func dailyAt(s string) (DailyTime, bool) {
	f := strings.Fields(s)
	if len(f) != 5 || f[2] != "*" || f[3] != "*" || f[4] != "*" {
		return DailyTime{}, false
	}
	m, err1 := strconv.Atoi(f[0])
	h, err2 := strconv.Atoi(f[1])
	if err1 != nil || err2 != nil || m < 0 || m > 59 || h < 0 || h > 23 {
		return DailyTime{}, false
	}
	return DailyTime{h, m}, true
}
