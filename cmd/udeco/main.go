// SPDX-License-Identifier: GPL-2.0-or-later

// udeco makes TP-Link Deco units appear as UniFi APs (docs/deco/design.md).
// One process holds one deco.Mesh (the only TMP session, to the mesh
// master) and one runner per Deco unit. Each runner informs the UniFi
// controller as its own AP from the Mesh cache; nothing on the inform path
// talks to a Deco.
//
// Safety:
//   - apply:false (the default) only logs what would be written to the Decos;
//   - before any login the master's TDP owner hash must equal md5(tplink_id);
//   - a rejected SSH login latches all further logins off until restart
//     (TP-Link account lockout); logins are at least 60 s apart, backing off
//     to 15 min;
//   - the TP-Link password is never in the config, logs, errors, state or
//     -print output; Wi-Fi passphrases are masked;
//   - Ubiquiti firmware upgrades are answered but never downloaded.
//
// Modes:
//
//	udeco -config /data/udeco.json            run the daemon
//	udeco -config /data/udeco.json -discover  TDP only: who answers, owner check (no login)
//	udeco -config /data/udeco.json -print     one login, one read-only poll, JSON to stdout (no UniFi traffic)
//	      [-only devices,speeds,iot,clients] [-print-timeout 90s] [-trace]
//	udeco ... -trace                          also log every TMP frame, V2 packet and request timing
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/dtechterminal/udeco/internal/deco"
	"github.com/dtechterminal/udeco/internal/device"
	"github.com/dtechterminal/udeco/internal/inform"
	"github.com/dtechterminal/udeco/internal/models"
)

const (
	// defaultConfigPath is where the image keeps its config: the Dockerfile's
	// CMD and deploy/unraid.sh pass the same path (TestContainerContract).
	defaultConfigPath = "/data/udeco.json"
	// defaultPrintTimeout is -print's overall deadline, login included.
	defaultPrintTimeout = 90 * time.Second
)

func main() {
	cfgPath := flag.String("config", defaultConfigPath, "JSON config")
	doPrint := flag.Bool("print", false, "one login and one read-only poll of the mesh, printed as JSON (secrets removed); no UniFi traffic")
	doDiscover := flag.Bool("discover", false, "TDP discovery of the configured units and the login precheck; no login")
	doTrace := flag.Bool("trace", false, "log every TMP frame, business packet and request (headers, lengths, timings; never payloads or credentials)")
	only := flag.String("only", "", "with -print: poll only these, in this order (comma list of "+onlyNames+" or opcodes like 0x4014)")
	printTimeout := flag.Duration("print-timeout", defaultPrintTimeout, "with -print: overall deadline, login included (one login at most, whatever the value)")
	flag.Parse()
	log.SetFlags(log.Ldate | log.Ltime)
	h := hooks{printTimeout: *printTimeout}
	if *doTrace {
		log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds)
		h.trace = log.Printf
	}
	if *only != "" {
		if !*doPrint {
			log.Fatalf("-only needs -print")
		}
		ops, err := parseOnly(*only)
		if err != nil {
			log.Fatal(err)
		}
		h.only = ops
	}

	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	sec, err := loadSecrets(cfg, os.Getenv, log.Printf)
	if err != nil {
		log.Fatalf("credentials: %v", err)
	}
	// Keep the password out of anything that inherits or dumps the environment.
	os.Unsetenv(envTPLinkPassword)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	switch {
	case *doDiscover:
		err = discoverOnly(ctx, cfg, sec, h, os.Stdout)
	case *doPrint:
		err = printOnce(ctx, cfg, sec, h, os.Stdout)
	default:
		var d *daemon
		if d, err = newDaemon(cfg, sec, h); err == nil {
			err = d.run(ctx)
		}
	}
	if err != nil && !errors.Is(err, context.Canceled) {
		log.Printf("udeco: %v", err)
		stop()
		os.Exit(1)
	}
}

// hooks replace the edges that tests cannot run for real. Zero values take
// the production defaults.
type hooks struct {
	discover      func(ctx context.Context, ip string) (*deco.DecoInfo, error) // TDP probe
	heartbeat     time.Duration                                                // TMP heartbeat
	sshListenHost string                                                       // SSH-adopt bind host; "" = all
	httpClient    *http.Client
	minWait       time.Duration            // floor of the inform interval; default device.MinInformWait
	immediateWait time.Duration            // after an "inform now" reply; default device.ImmediateInformWait
	gatedWait     time.Duration            // re-check while not informing; default 5s
	offlineGrace  time.Duration            // a unit offline this long stops informing; default 60s
	masterDownMax time.Duration            // master session down this long stops all; default 120s
	printTimeout  time.Duration            // -print deadline; default defaultPrintTimeout
	trace         func(string, ...any)     // -trace: frame/packet/request lines; nil = off
	only          []uint16                 // -print -only: the Gets to poll, in order
	maxLogins     int                      // 0 = unlimited; -print sets 1
	once          bool                     // -print: each Get until it succeeds once (MeshConfig.Once)
	opTimeouts    map[uint16]time.Duration // per-opcode request budgets (tests)
}

func (h *hooks) fill() {
	def := func(d *time.Duration, v time.Duration) {
		if *d <= 0 {
			*d = v
		}
	}
	def(&h.minWait, device.MinInformWait)
	def(&h.immediateWait, device.ImmediateInformWait)
	def(&h.gatedWait, 5*time.Second)
	def(&h.offlineGrace, 60*time.Second)
	def(&h.masterDownMax, 120*time.Second)
	def(&h.printTimeout, defaultPrintTimeout)
	if h.httpClient == nil {
		h.httpClient = &http.Client{Timeout: 10 * time.Second}
	}
}

// newMesh builds the Mesh for cfg. apply=false makes every write a logged plan.
func newMesh(cfg *Config, sec Secrets, h hooks, apply bool) (*deco.Mesh, error) {
	if sec.Password == "" {
		return nil, errors.New("no TP-Link password: set " + envTPLinkPasswordFile + ", password_file or " + envTPLinkPassword + " in " + credentialsFileName)
	}
	if err := os.MkdirAll(cfg.StateDir, 0o700); err != nil {
		return nil, err
	}
	m := cfg.master()
	return deco.NewMesh(deco.MeshConfig{
		MasterIP:      m.IP,
		MasterMAC:     m.MAC,
		UnitIPs:       cfg.unitIPs(),
		TPLinkID:      sec.TPLinkID,
		Password:      sec.Password,
		HostKeySHA256: cfg.Mesh.HostKeySHA256,
		StateDir:      cfg.StateDir,
		Apply:         apply,
		Poll:          time.Duration(cfg.Poll),
		ClientsEvery:  cfg.clientsEvery(),
		Heartbeat:     h.heartbeat,
		Discover:      h.discover,
		Trace:         h.trace,
		Only:          h.only,
		MaxLogins:     h.maxLogins,
		Once:          h.once,
		OpTimeouts:    h.opTimeouts,
	})
}

// meshAPI is what the runners and the block reconciler use of the Mesh.
type meshAPI interface {
	Snapshot() deco.MeshState
	Submit(deco.Command) <-chan deco.CommandResult
	RequestPoll(op uint16)
}

type daemon struct {
	cfg      *Config
	h        hooks
	daemonIP string
	profile  inform.Profile
	mesh     *deco.Mesh
	wlan     *deco.WLANApplier
	blocks   *blockSync
	runners  []*runner
}

// maxAge is how old device_list and the client list may be and still count
// as current: three polls.
func (d *daemon) maxAge() time.Duration {
	var poll time.Duration // 0: the default poll
	if d.cfg != nil {
		poll = time.Duration(d.cfg.Poll)
	}
	return deco.MaxAge(poll)
}

func newDaemon(cfg *Config, sec Secrets, h hooks) (*daemon, error) {
	h.fill()
	model, _ := models.Lookup(cfg.Model)
	d := &daemon{cfg: cfg, h: h, profile: models.Profile(model), daemonIP: cfg.DaemonIP}
	if d.daemonIP == "" {
		ip, err := inform.LocalIPToward(cfg.InformURL)
		if err != nil {
			return nil, fmt.Errorf("daemon_ip: %w", err)
		}
		d.daemonIP = ip
	}
	var err error
	if d.mesh, err = newMesh(cfg, sec, h, cfg.Apply); err != nil {
		return nil, err
	}
	backups := filepath.Join(cfg.StateDir, "backups")
	if err := os.MkdirAll(backups, 0o700); err != nil {
		return nil, err
	}
	d.wlan = deco.NewWLANApplier(deco.WLANConfig{Apply: cfg.Apply, BackupDir: backups, Units: cfg.unitMACs()}, d.mesh)
	d.blocks = newBlockSync(d.mesh, cfg.Apply, filepath.Join(cfg.StateDir, "blocks.json"), log.Printf)
	if cfg.KickEmulation {
		log.Printf("kick_emulation is not implemented: kick-sta is logged only")
	}
	for i, u := range cfg.Units {
		r, err := newRunner(d, u, i == cfg.masterIdx)
		if err != nil {
			return nil, fmt.Errorf("unit %s: %w", u.Name, err)
		}
		d.runners = append(d.runners, r)
	}
	return d, nil
}

// run checks the mesh (refusing to start on a definite TDP violation),
// starts the Mesh, the Wi-Fi applier, the block reconciler and the runners,
// and returns when ctx ends.
func (d *daemon) run(ctx context.Context) error {
	m := d.cfg.master()
	log.Printf("udeco: %d unit(s), master %s %s, model %s, apply=%v, report_ip=%s, daemon ip %s, inform %s",
		len(d.cfg.Units), m.IP, m.MAC, d.profile.Model, d.cfg.Apply, d.cfg.ReportIP, d.daemonIP, d.cfg.InformURL)
	if !d.cfg.Apply {
		log.Printf("udeco: apply=false: Wi-Fi, block and reboot requests are logged, never sent")
	}
	if _, err := d.mesh.Precheck(ctx); err != nil {
		var re *deco.RefusedError
		if errors.As(err, &re) {
			return err
		}
		log.Printf("udeco: %v; starting anyway, the Mesh retries before any login", err)
	}
	for _, r := range d.runners {
		if err := r.start(); err != nil {
			for _, s := range d.runners {
				s.close()
			}
			return fmt.Errorf("unit %s: %w", r.u.Name, err)
		}
	}
	var wg sync.WaitGroup
	goRun := func(f func(context.Context)) {
		wg.Add(1)
		go func() { defer wg.Done(); f(ctx) }()
	}
	goRun(func(ctx context.Context) { _ = d.mesh.Run(ctx) })
	goRun(func(ctx context.Context) { _ = d.wlan.Run(ctx) })
	goRun(d.blocks.Run)
	for _, r := range d.runners {
		goRun(r.loop)
	}
	<-ctx.Done()
	wg.Wait()
	log.Printf("udeco: stopped")
	return ctx.Err()
}
