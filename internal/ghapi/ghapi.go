// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

// Package ghapi calls the GitHub REST API through the gh CLI, which brings
// its own authentication: GH_TOKEN, GITHUB_TOKEN or the user's login.
package ghapi

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/textproto"
	"strconv"
	"strings"
	"time"

	"github.com/divbast/ci/internal/execx"
)

// timeout is how long one call to gh may take when a Client sets no
// Timeout of its own.
const timeout = time.Minute

// Client calls the GitHub API through gh.
type Client struct {
	// Run runs gh.
	Run execx.Runner
	// Repo, as owner/name, fills the {owner} and {repo} placeholders in a
	// path. Left empty, they are gh's to fill, from GH_REPO or the current
	// directory's repository.
	Repo string
	// Timeout bounds each call to gh, so that a gh that hangs fails the
	// call rather than holding the job until the job's own timeout. Zero
	// means a minute.
	Timeout time.Duration
}

// Response is what GitHub answered a request with.
type Response struct {
	// Status is the HTTP status.
	Status int
	// Message is GitHub's own word on a status outside 2xx, the message
	// field of its error body, such as "Package not found.", and "" when
	// the body has none.
	Message string
}

// API sends a GET for path, such as "orgs/divbast/packages/container/x",
// and returns the HTTP status GitHub answered with. A 2xx body is decoded
// as JSON into v, unless v is nil or the body empty.
//
// Any other status is the caller's to judge: a 404 or a 403 returns that
// status and a nil error, and leaves v alone, since the body is GitHub's
// error rather than the resource. The error is for a request that got no
// response at all (gh missing, a network failure, ctx done), for output
// that does not parse, and for a 2xx that gh failed on or whose body is
// not the JSON v expects. A call that runs past the Client's Timeout gets
// no response, and an error that says so and wraps
// [context.DeadlineExceeded].
func (c Client) API(ctx context.Context, path string, v any) (status int, err error) {
	resp, err := c.Get(ctx, path, v)
	return resp.Status, err
}

// Get is [Client.API], and also returns GitHub's message for a status
// outside 2xx. That is what tells one 404 from another: a package that
// does not exist from a path that names nothing at all.
func (c Client) Get(ctx context.Context, path string, v any) (Response, error) {
	path, err := c.expand(path)
	if err != nil {
		return Response{}, err
	}

	limit := c.Timeout
	if limit == 0 {
		limit = timeout
	}
	callCtx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()

	// gh exits 1 on a 4xx or 5xx but, with -i, still prints the status
	// line, the headers and the body, so the response is read from stdout
	// whatever the exit status.
	res, err := c.Run.Run(callCtx, "gh", "api", "-i", path)
	if err != nil {
		// Only the Client's own limit is the Client's to name: a deadline
		// of the caller's, reached first, is the caller's to report.
		if ctx.Err() == nil && errors.Is(callCtx.Err(), context.DeadlineExceeded) {
			return Response{}, fmt.Errorf("gh api %s gave up after %v: %w", path, limit, err)
		}
		return Response{}, fmt.Errorf("gh api %s: %w", path, err)
	}
	status, body, err := parse(res.Stdout)
	if err != nil {
		if res.Code != 0 {
			return Response{}, fmt.Errorf("gh api %s: no response, exit status %d: %s", path, res.Code, bytes.TrimSpace(res.Stderr))
		}
		return Response{}, fmt.Errorf("gh api %s: %w", path, err)
	}
	resp := Response{Status: status}
	if status < 200 || status > 299 {
		var e struct {
			Message string `json:"message"`
		}
		// A body that is not GitHub's JSON, such as a proxy's HTML error
		// page, carries no message, and the status says all there is.
		if json.Unmarshal(body, &e) == nil {
			resp.Message = e.Message
		}
		return resp, nil
	}
	if res.Code != 0 {
		return resp, fmt.Errorf("gh api %s: exit status %d after HTTP %d: %s", path, res.Code, status, bytes.TrimSpace(res.Stderr))
	}
	if v == nil || len(bytes.TrimSpace(body)) == 0 {
		return resp, nil
	}
	if err = json.Unmarshal(body, v); err != nil {
		return resp, fmt.Errorf("gh api %s: decode the HTTP %d response: %w", path, status, err)
	}
	return resp, nil
}

// expand fills path's {owner} and {repo} placeholders from c.Repo.
func (c Client) expand(path string) (string, error) {
	if c.Repo == "" {
		return path, nil
	}
	owner, repo, ok := strings.Cut(c.Repo, "/")
	if !ok || owner == "" || repo == "" || strings.Contains(repo, "/") {
		return "", fmt.Errorf("repository %q is not owner/name", c.Repo)
	}
	return strings.NewReplacer("{owner}", owner, "{repo}", repo).Replace(path), nil
}

// parse splits what gh api -i prints into the status code and the body.
// gh writes the status line, such as "HTTP/2.0 404 Not Found", then the
// headers and a blank line, then the body. It ends the status line with LF
// and the headers with CRLF; textproto takes either.
func parse(out []byte) (status int, body []byte, err error) {
	br := bufio.NewReader(bytes.NewReader(out))
	tp := textproto.NewReader(br)

	line, err := tp.ReadLine()
	if err != nil {
		return 0, nil, fmt.Errorf("no HTTP status line in gh's output: %w", err)
	}
	proto, rest, _ := strings.Cut(line, " ")
	code, _, _ := strings.Cut(rest, " ")
	status, err = strconv.Atoi(code)
	if !strings.HasPrefix(proto, "HTTP/") || err != nil || status < 100 || status > 999 {
		return 0, nil, fmt.Errorf("gh's output starts %q, not an HTTP status line", line)
	}

	// io.EOF here is a response that ended with its headers: no body.
	if _, err = tp.ReadMIMEHeader(); err != nil && !errors.Is(err, io.EOF) {
		return 0, nil, fmt.Errorf("read the HTTP %d headers gh printed: %w", status, err)
	}
	body, err = io.ReadAll(br)
	if err != nil {
		return 0, nil, fmt.Errorf("read the HTTP %d body gh printed: %w", status, err)
	}
	return status, body, nil
}
