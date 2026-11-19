// SPDX-License-Identifier: GPL-2.0-or-later

package device

import (
	"strings"
	"testing"
)

// A setparam that also produces an "ignored" event (a second authkey while
// already adopted, a malformed inform_url) makes Handle add the raw reply to
// the events, which the agents log. The raw reply carries system_cfg (WLAN
// passphrases, RADIUS secrets, device password hashes) and mgmt_cfg: none of
// it may reach the events.
func TestRawReplyEventHidesSecrets(t *testing.T) {
	const (
		psk    = "NotARealPassphrase-7Q"
		radius = "NotARealRadiusSecret-9Z"
		hash   = "$6$saltsalt$NotARealCryptHashValue"
		other  = "b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0"
	)
	sysCfg := "aaa.1.wpa.psk=" + psk + "\naaa.2.auth.1.secret=" + radius + "\nusers.1.password=" + hash + "\n"
	for name, mgmt := range map[string]string{
		"second authkey":       `cfgversion=0000000000000002\nauthkey=` + other + `\n`,
		"malformed inform_url": `cfgversion=0000000000000002\ninform_url=ftp:/nope\n`,
	} {
		t.Run(name, func(t *testing.T) {
			x := newSession(t)
			x.S.Key, x.S.Adopted = newKey, true
			reply := `{"_type":"setparam","mgmt_cfg":"` + mgmt + `","system_cfg":` + jsonString(sysCfg) + `}`
			o := handle(t, x, reply)
			ev := strings.Join(o.Events, "\n")
			if !strings.Contains(ev, "ignored") {
				t.Fatalf("scenario did not produce an ignored event: %s", ev)
			}
			for _, s := range []string{psk, radius, hash, "NotARealCryptHashValue"} {
				if strings.Contains(ev, s) {
					t.Errorf("secret %q in the events:\n%s", s, ev)
				}
			}
		})
	}
}

func jsonString(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)
	return `"` + r.Replace(s) + `"`
}
