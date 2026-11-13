// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

package harness

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// HTTPResponse is the answer to one request: its status code and body.
type HTTPResponse struct {
	Status int
	Body   []byte
}

// HTTP sends one request from inside the container, through the probe, so
// it reaches a server on an internal network, or one whose ports are not
// published, and needs no allow_url_fopen. headers are "Name: value"
// lines, and a body goes form-encoded. It returns whatever status comes
// back; the error is for a request that got no answer.
func (p *Probe) HTTP(ctx context.Context, method, url string, headers []string, body string) (HTTPResponse, error) {
	res, err := p.Output(ctx, "http-request", method, url, strings.Join(headers, "\n"), body)
	if err != nil {
		return HTTPResponse{}, err
	}
	if res.Code != 0 {
		return HTTPResponse{}, fmt.Errorf("%s %s from inside container %s: exit status %d: %s", method, url, p.c, res.Code, combined(res))
	}
	resp, err := parseHTTP(res.Stdout)
	if err != nil {
		return HTTPResponse{}, fmt.Errorf("%s %s from inside container %s: %w", method, url, p.c, err)
	}
	return resp, nil
}

// errNoStatus means the probe's http-request printed no status line.
var errNoStatus = errors.New("no HTTP status line")

// parseHTTP reads http-request's output: the status code on the first
// line, then the body.
func parseHTTP(out []byte) (HTTPResponse, error) {
	status, body, ok := bytes.Cut(out, []byte("\n"))
	code, err := strconv.Atoi(string(status))
	if !ok || err != nil || len(status) != 3 {
		return HTTPResponse{}, fmt.Errorf("%w: %q", errNoStatus, out)
	}
	return HTTPResponse{Status: code, Body: body}, nil
}

// WaitHTTP sends GET url from inside the container, once a second, until
// any status comes back, which it returns: an answer is all serving means
// here, and a check asserts the status itself. A container that stops
// first, or one still not serving after within, is an error carrying the
// container's log, so a server that died says why.
func (p *Probe) WaitHTTP(ctx context.Context, url string, within time.Duration) (HTTPResponse, error) {
	deadline := time.Now().Add(within)
	for {
		resp, err := p.HTTP(ctx, http.MethodGet, url, nil, "")
		if err == nil {
			return resp, nil
		}
		ins, ierr := p.c.Inspect(ctx)
		switch {
		case ierr != nil:
			return HTTPResponse{}, fmt.Errorf("%w; and then: %w", err, ierr)
		case !ins.State.Running:
			return HTTPResponse{}, WithLog(ctx, p.c, fmt.Errorf("container %s stopped, exit status %d, before %s answered", p.c, ins.State.ExitCode, url))
		case !time.Now().Before(deadline):
			return HTTPResponse{}, WithLog(ctx, p.c, fmt.Errorf("%s did not answer within %s: %w", url, within, err))
		}
		if err := Pause(ctx, time.Second); err != nil {
			return HTTPResponse{}, err
		}
	}
}

// hostTimeout bounds one request from the host.
const hostTimeout = 30 * time.Second

// HostClient returns a client for requests from the host to a published
// port. It never follows a redirect, since the status is what a check
// asserts: a 302 to an install wizard is a failure, not a hop on the way
// to a 200. Each request is bounded.
func HostClient() *http.Client {
	return &http.Client{
		Timeout: hostTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}
