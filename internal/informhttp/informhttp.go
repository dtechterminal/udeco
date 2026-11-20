// SPDX-License-Identifier: GPL-2.0-or-later

// Package informhttp is the inform POST over net/http, for the daemons
// that inform from a host with room for it (cmd/udeco, upstream's uow). It is a
// package of its own because internal/device is linked into the AP agent
// (cmd/udeco-ap), which must stay without net/http and brings its own
// small client (cmd/udeco-ap/post.go).
package informhttp

import (
	"bytes"
	"io"
	"net/http"

	"github.com/dtechterminal/udeco/internal/device"
	"github.com/dtechterminal/udeco/internal/inform"
)

// Poster returns the inform POST through c, for device.InformOnce: the
// packet goes out as inform.ContentType, and at most inform.MaxReply
// bytes of the answer are read. The User-Agent stays net/http's own (the
// AP agent alone sends inform.UserAgent).
func Poster(c *http.Client) device.PostFunc {
	return func(url string, pkt []byte) (int, []byte, error) {
		req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(pkt))
		if err != nil {
			return 0, nil, err
		}
		req.Header.Set("Content-Type", inform.ContentType)
		resp, err := c.Do(req)
		if err != nil {
			return 0, nil, err
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, inform.MaxReply))
		resp.Body.Close()
		return resp.StatusCode, body, nil
	}
}
