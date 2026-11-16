// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

package probekit

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// httpTimeout bounds the connection and the whole exchange.
const httpTimeout = 10 * time.Second

var (
	// methodPattern is a method as a request line carries it.
	methodPattern = regexp.MustCompile(`\A[A-Z]+\z`)
	// headerLine is one "Name: value" line: the name a token, as RFC 9110
	// section 5.6.2 has it, and the value with no line break in it.
	headerLine = regexp.MustCompile("\\A[!#$%&'*+.^_`|~0-9A-Za-z-]+:[^\r\n]*\\z")
	// statusLine is the start of an answer, and its status code.
	statusLine = regexp.MustCompile(`\AHTTP/\d\.\d (\d{3})`)
)

// Response is the answer to one [Request]: its status code and body.
type Response struct {
	Status int
	Body   []byte
}

// Request sends one request over a bare socket, as a proxy in front of
// the server would, and returns the status and the body that came back.
// The target goes exactly as url gives it, never cleaned or escaped, so a
// check can send a path a client library would rewrite. headers are
// "Name: value" lines, and a body goes form-encoded. HTTP/1.0 keeps the
// answer unchunked, ending where the server closes the connection.
//
// A method, URL or header it cannot send is refused before anything is
// sent. The error is for a request that got no answer.
func Request(ctx context.Context, method, url string, headers []string, body string) (Response, error) {
	if !methodPattern.MatchString(method) {
		return Response{}, fmt.Errorf("'%s' is not a method", method)
	}
	host, port, target, err := splitURL(url)
	if err != nil {
		return Response{}, err
	}
	lines := []string{method + " " + target + " HTTP/1.0", "Host: " + host + ":" + port, "Connection: close"}
	for _, h := range headers {
		if h == "" {
			continue
		}
		if !headerLine.MatchString(h) {
			return Response{}, fmt.Errorf("'%s' is not a header line", h)
		}
		lines = append(lines, h)
	}
	if body != "" {
		lines = append(lines, "Content-Type: application/x-www-form-urlencoded")
	}
	if body != "" || method == "POST" {
		lines = append(lines, "Content-Length: "+strconv.Itoa(len(body)))
	}
	request := strings.Join(lines, "\r\n") + "\r\n\r\n" + body

	ctx, cancel := context.WithTimeout(ctx, httpTimeout)
	defer cancel()
	addr := net.JoinHostPort(strings.Trim(host, "[]"), port)
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return Response{}, fmt.Errorf("cannot connect to %s: %w", addr, err)
	}
	defer func() { _ = conn.Close() }()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	if _, err = io.WriteString(conn, request); err != nil {
		return Response{}, fmt.Errorf("the exchange with %s broke off: %w", addr, err)
	}
	answer, err := io.ReadAll(conn)
	if err != nil {
		return Response{}, fmt.Errorf("the exchange with %s broke off: %w", addr, err)
	}

	head, rest, _ := bytes.Cut(answer, []byte("\r\n\r\n"))
	m := statusLine.FindSubmatch(head)
	if m == nil {
		return Response{}, fmt.Errorf("no HTTP status line in the answer: %q", head[:min(len(head), 80)])
	}
	status, err := strconv.Atoi(string(m[1]))
	if err != nil {
		return Response{}, fmt.Errorf("no HTTP status line in the answer: %w", err)
	}
	return Response{Status: status, Body: rest}, nil
}

// splitURL returns an http:// URL's host, as the Host header carries it,
// its port, 80 when it names none, and the request target: the path,
// "/" when there is none, and the query, without the fragment.
func splitURL(url string) (host, port, target string, err error) {
	rest, ok := strings.CutPrefix(url, "http://")
	authority := rest
	if i := strings.IndexAny(rest, "/?#"); i >= 0 {
		authority, rest = rest[:i], rest[i:]
	} else {
		rest = ""
	}
	if !ok || authority == "" {
		return "", "", "", fmt.Errorf("'%s' is not an http:// URL", url)
	}
	host, port = authority, "80"
	if i := strings.LastIndexByte(authority, ':'); i >= 0 && !strings.HasSuffix(authority, "]") {
		host, port = authority[:i], authority[i+1:]
		if _, err := strconv.ParseUint(port, 10, 16); err != nil || host == "" {
			return "", "", "", fmt.Errorf("'%s' is not an http:// URL", url)
		}
	}
	target, _, _ = strings.Cut(rest, "#")
	if !strings.HasPrefix(target, "/") {
		target = "/" + target
	}
	return host, port, target, nil
}
