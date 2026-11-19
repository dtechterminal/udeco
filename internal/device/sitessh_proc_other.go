// SPDX-License-Identifier: GPL-2.0-or-later

//go:build !linux && !darwin

package device

import (
	"errors"
	"io"
)

type siteProc struct{}

func startSiteProc(procSpec, io.ReadWriter, io.Writer) (*siteProc, error) {
	return nil, errors.New("site shells are not supported on this platform")
}

func (p *siteProc) wait() exitState          { return exitState{code: 255} }
func (p *siteProc) hangup()                  {}
func (p *siteProc) signal(string) bool       { return false }
func (p *siteProc) resize(cols, rows uint32) {}
