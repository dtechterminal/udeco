// SPDX-License-Identifier: GPL-2.0-or-later

package openwrt

import (
	"path"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/antoniocosta/unifi-openwrt/internal/device"
	"github.com/antoniocosta/unifi-openwrt/internal/repotest"
)

// The package's files, which run on the AP and cannot read paths.go.
const (
	initScriptFile = "packaging/files/etc/init.d/unifi-openwrt"
	installFile    = "packaging/install.sh"
	makefileFile   = "packaging/openwrt/unifi-openwrt/Makefile"
)

// The init script is the AP's half of what mesh.go and snmp.go do: SyncMesh
// installs MeshScript and asks procd whether the instance meshInstance
// runs, SyncSNMP writes SNMPConf, and both reload the service so that the
// script starts or stops the instance. A name changed on one side only
// would leave the watcher or snmpd never started, without an error.
func TestInitScriptNames(t *testing.T) {
	script := repotest.Read(t, initScriptFile)
	if got := path.Base(initScriptFile); got != Service || initScript != "/etc/init.d/"+got {
		t.Errorf("the init script is %s; the Go code reloads %s (service %s)", initScriptFile, initScript, Service)
	}
	for _, want := range []string{
		// the service's UCI config and its reload trigger carry its name
		"\tconfig_load " + Service + "\n",
		"\tprocd_add_reload_trigger " + Service + "\n",
		// the mesh watcher: started when SyncMesh has installed it
		"[ -x " + MeshScript + " ]; then\n" +
			"\t\tprocd_open_instance " + meshInstance + "\n" +
			"\t\tprocd_set_param command " + MeshScript + "\n",
		// snmpd: started while SyncSNMP's config is there
		"[ -s " + SNMPConf + " ] && [ -x " + snmpdBin + " ]; then\n" +
			"\t\tmkdir -p /var/lib/snmp\n" +
			"\t\tprocd_open_instance " + snmpInstance + "\n" +
			"\t\tprocd_set_param command " + snmpdBin + " -f -C -Lsd -c " + SNMPConf + "\n",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("%s does not have\n%s", initScriptFile, want)
		}
	}

	// its instances: the daemon (procd's unnamed one) and the two above
	var named []string
	for _, m := range regexp.MustCompile(`(?m)^\s*procd_open_instance(?: (\S+))?$`).FindAllStringSubmatch(script, -1) {
		named = append(named, m[1])
	}
	sort.Strings(named)
	if want := []string{"", meshInstance, snmpInstance}; strings.Join(named, ",") != strings.Join(want, ",") {
		t.Errorf("%s opens the instances %q, the Go code knows %q", initScriptFile, named, want)
	}

	// every path it names under ConfDir is one of the Go code's, or its
	// own state directory
	state := repotest.ShellVar(t, script, "STATE")
	known := map[string]bool{ConfDir: true, state: true, MeshScript: true, SNMPConf: true}
	for _, p := range regexp.MustCompile(regexp.QuoteMeta(ConfDir)+`[A-Za-z0-9._/-]*`).FindAllString(script, -1) {
		if !known[p] {
			t.Errorf("%s names %s, which the Go code does not", initScriptFile, p)
		}
	}

	// what the scripts in this package ask of the service
	for name, sh := range map[string]string{"meshSyncScript": meshSyncScript, "snmpSyncScript": snmpSyncScript} {
		if !strings.Contains(sh, initScript+" reload") {
			t.Errorf("%s does not reload %s", name, initScript)
		}
	}
	if want := `'{"name":"` + Service + `"}' | jsonfilter -e '@[*].instances.` + meshInstance + `.running'`; !strings.Contains(meshSyncScript, want) {
		t.Errorf("meshSyncScript does not ask procd for %s", want)
	}
}

// The daemon's state directory on the AP is the init script's STATE, a
// directory of ConfDir. Each way of installing must work alone, so the
// directory is also made (mode 700, with ConfDir) by packaging/install.sh
// and by the package's postinst: three copies, held to the init script's.
func TestStateDirWhereItIsMade(t *testing.T) {
	script := repotest.Read(t, initScriptFile)
	state := repotest.ShellVar(t, script, "STATE")
	if path.Dir(state) != ConfDir {
		t.Fatalf("%s: STATE=%s is not a directory of %s", initScriptFile, state, ConfDir)
	}
	const root = `"$${IPKG_INSTROOT}` // the Makefile's ${IPKG_INSTROOT}, $ escaped for make
	for rel, lines := range map[string][]string{
		initScriptFile: {
			"-state \"$STATE\" ",
			"\tmkdir -p \"$STATE\"; chmod 700 " + ConfDir + " \"$STATE\"\n",
		},
		installFile: {
			"\nmkdir -p " + state + " && chmod 700 " + ConfDir + " " + state + "\n",
		},
		makefileFile: {
			"\nmkdir -p " + root + state + "\"\n" +
				"chmod 700 " + root + ConfDir + "\" " + root + state + "\"\n",
		},
	} {
		for _, l := range lines {
			repotest.MustContain(t, rel, l)
		}
	}
}

// docs/internals.md tells the reader where to look on the AP.
func TestDocsAPPaths(t *testing.T) {
	state := repotest.ShellVar(t, repotest.Read(t, initScriptFile), "STATE")
	for _, p := range []string{
		"`" + state + "/" + device.UnhandledFile + "`",
		"AP-side cron script `" + scheduleSh + "`",
		"only accounts listed in `" + usersFile + "` are touched",
		"`" + SNMPConf + "` (mode 600)",
		"The daemon writes `" + meshConf + "` (mode 600",
		"`" + path.Base(MeshScript) + "` as its own instance",
	} {
		repotest.MustContain(t, "docs/internals.md", p)
	}
}
