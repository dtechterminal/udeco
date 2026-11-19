// SPDX-License-Identifier: GPL-2.0-or-later
package main

import (
	"context"
	"os/exec"
	"sync"
	"testing"
	"time"
)

// Two concurrent Closes (forwardSyslogOnce's ctx hook and its defer) both
// return: a second exec.Cmd.Wait used to block forever and kept the agent
// from exiting on SIGTERM.
func TestCmdStreamDoubleClose(t *testing.T) {
	// CommandContext as logFollow uses: its context watcher hands its
	// result to exactly one Wait, so a second Wait blocks on that channel
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cmd := exec.CommandContext(ctx, "sleep", "30")
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	s := &cmdStream{ReadCloser: out, cmd: cmd}
	var wg sync.WaitGroup
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); s.Close() }()
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Close blocked")
	}
}
