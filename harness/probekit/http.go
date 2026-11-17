// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

package probekit

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// httpTimeout bounds the connection, and then the request's write and
// each read of the answer, each on its own, as the PHP probe's
// stream_set_timeout does.
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
// It allows ten seconds to connect, and then ten seconds for the write
// and for each read of the answer, so a slow answer arrives whole while a
// silent server breaks the exchange off. A method, URL or header it cannot
// send is refused before anything is sent. The error is for a request
// that got no answer.
func Request(ctx context.Context, method, url string, headers []string, body string) (Response, error) {
	return request(ctx, (&net.Dialer{}).DialContext, method, url, headers, body)
}

// dialFunc makes a connection, as net.Dialer.DialContext does.
type dialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// request is [Request], over a connection dial makes.
func request(ctx context.Context, dial dialFunc, method, url string, headers []string, body string) (Response, error) {
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
	msg := strings.Join(lines, "\r\n") + "\r\n\r\n" + body

	dialCtx, cancel := context.WithTimeout(ctx, httpTimeout)
	defer cancel()
	addr := net.JoinHostPort(strings.Trim(host, "[]"), port)
	conn, err := dial(dialCtx, "tcp", addr)
	if err != nil {
		return Response{}, fmt.Errorf("cannot connect to %s: %w", addr, err)
	}
	defer func() { _ = conn.Close() }()
	answer, err := exchange(ctx, conn, msg)
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

// exchange sends msg over conn and reads the answer until the server
// closes the connection. The write, and each read, has httpTimeout from
// when it starts, never past ctx's own deadline, so an answer that comes
// in pieces arrives however long it takes in all, while a silence of
// httpTimeout breaks the exchange off.
func exchange(ctx context.Context, conn net.Conn, msg string) ([]byte, error) {
	if err := conn.SetDeadline(nextDeadline(ctx)); err != nil {
		return nil, err
	}
	if _, err := io.WriteString(conn, msg); err != nil {
		return nil, err
	}
	var answer bytes.Buffer
	buf := make([]byte, 32<<10)
	for {
		if err := conn.SetReadDeadline(nextDeadline(ctx)); err != nil {
			return nil, err
		}
		n, err := conn.Read(buf)
		answer.Write(buf[:n])
		switch {
		case errors.Is(err, io.EOF):
			return answer.Bytes(), nil
		case err != nil:
			return nil, err
		}
	}
}

// nextDeadline is httpTimeout from now, or ctx's own deadline when that
// comes first.
func nextDeadline(ctx context.Context) time.Time {
	next := time.Now().Add(httpTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(next) {
		return d
	}
	return next
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
