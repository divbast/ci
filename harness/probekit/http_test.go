// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

package probekit_test

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"net/textproto"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/divbast/ci/harness/probekit"
)

// rawServer is a TCP listener that keeps each request exactly as it
// arrived, and answers every one with answer.
type rawServer struct {
	addr     string
	requests chan []byte
	accepted atomic.Int32
}

func newRawServer(t *testing.T, answer string) *rawServer {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &rawServer{addr: ln.Addr().String(), requests: make(chan []byte, 8)}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			s.accepted.Add(1)
			s.requests <- readRequest(conn)
			_, _ = io.WriteString(conn, answer)
			_ = conn.Close()
		}
	}()
	return s
}

// readRequest reads one request's head and, by its Content-Length, body.
func readRequest(conn net.Conn) []byte {
	var raw bytes.Buffer
	r := bufio.NewReader(io.TeeReader(conn, &raw))
	head, err := textproto.NewReader(r).ReadMIMEHeader()
	if err != nil && !strings.Contains(raw.String(), "\r\n\r\n") {
		return raw.Bytes()
	}
	if n, err := strconv.Atoi(head.Get("Content-Length")); err == nil && n > 0 {
		_, _ = io.ReadFull(r, make([]byte, n))
	}
	return raw.Bytes()
}

func TestRequest(t *testing.T) {
	t.Parallel()

	s := newRawServer(t, "HTTP/1.1 418 I'm a teapot\r\nServer: x\r\n\r\nshort and stout")
	resp, err := probekit.Request(t.Context(), "GET", "http://"+s.addr+"/a/../b", nil, "")
	if err != nil {
		t.Fatalf("Request() error = %v", err)
	}
	if resp.Status != 418 || string(resp.Body) != "short and stout" {
		t.Errorf("Request() = %d %q, want 418 %q", resp.Status, resp.Body, "short and stout")
	}
	got := string(<-s.requests)
	want := "GET /a/../b HTTP/1.0\r\nHost: " + s.addr + "\r\nConnection: close\r\n\r\n"
	if got != want {
		t.Errorf("sent %q, want %q", got, want)
	}
}

func TestRequestTarget(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name, path, want string
	}{
		{name: "root-when-empty", path: "", want: "GET / HTTP/1.0\r\n"},
		{name: "query-kept", path: "/x?a=1&b=2", want: "GET /x?a=1&b=2 HTTP/1.0\r\n"},
		{name: "query-alone-gets-a-root", path: "?a=1", want: "GET /?a=1 HTTP/1.0\r\n"},
		{name: "fragment-dropped", path: "/x#frag", want: "GET /x HTTP/1.0\r\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			s := newRawServer(t, "HTTP/1.0 200 OK\r\n\r\n")
			if _, err := probekit.Request(t.Context(), "GET", "http://"+s.addr+tt.path, nil, ""); err != nil {
				t.Fatalf("Request() error = %v", err)
			}
			if got := string(<-s.requests); !strings.HasPrefix(got, tt.want) {
				t.Errorf("sent %q, want it to open %q", got, tt.want)
			}
		})
	}
}

func TestRequestBodyAndHeaders(t *testing.T) {
	t.Parallel()

	s := newRawServer(t, "HTTP/1.0 200 OK\r\n\r\n")
	_, err := probekit.Request(t.Context(), "POST", "http://"+s.addr+"/login", []string{"X-Forwarded-For: 10.0.0.1", "Cookie: a=b"}, "user=a&pass=b")
	if err != nil {
		t.Fatalf("Request() error = %v", err)
	}
	got := string(<-s.requests)
	want := "POST /login HTTP/1.0\r\nHost: " + s.addr + "\r\nConnection: close\r\n" +
		"X-Forwarded-For: 10.0.0.1\r\nCookie: a=b\r\n" +
		"Content-Type: application/x-www-form-urlencoded\r\nContent-Length: 13\r\n\r\nuser=a&pass=b"
	if got != want {
		t.Errorf("sent %q, want %q", got, want)
	}
}

func TestRequestEmptyPOSTHasLength(t *testing.T) {
	t.Parallel()

	s := newRawServer(t, "HTTP/1.0 204 No Content\r\n\r\n")
	if _, err := probekit.Request(t.Context(), "POST", "http://"+s.addr+"/", nil, ""); err != nil {
		t.Fatalf("Request() error = %v", err)
	}
	got := string(<-s.requests)
	if !strings.Contains(got, "\r\nContent-Length: 0\r\n") || strings.Contains(got, "Content-Type") {
		t.Errorf("sent %q, want Content-Length: 0 and no Content-Type", got)
	}
}

func TestRequestRefusals(t *testing.T) {
	t.Parallel()

	s := newRawServer(t, "HTTP/1.0 200 OK\r\n\r\n")
	tests := []struct {
		name, method, url string
		headers           []string
		want              string
	}{
		{name: "bad-header", method: "GET", url: "http://" + s.addr + "/", headers: []string{"No colon here"}, want: "is not a header line"},
		{name: "header-with-cr", method: "GET", url: "http://" + s.addr + "/", headers: []string{"X: a\rb"}, want: "is not a header line"},
		{name: "header-name-not-a-token", method: "GET", url: "http://" + s.addr + "/", headers: []string{"X Y: z"}, want: "is not a header line"},
		{name: "https", method: "GET", url: "https://" + s.addr + "/", want: "is not an http:// URL"},
		{name: "no-host", method: "GET", url: "http:///x", want: "is not an http:// URL"},
		{name: "lowercase-method", method: "get", url: "http://" + s.addr + "/", want: "is not a method"},
	}
	// After every subtest, parallel ones included
	t.Cleanup(func() {
		if n := s.accepted.Load(); n != 0 {
			t.Errorf("the server saw %d connections, want none: a refused request sends nothing", n)
		}
	})
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := probekit.Request(t.Context(), tt.method, tt.url, tt.headers, "")
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("Request() error = %v, want one saying %q", err, tt.want)
			}
		})
	}
}

func TestRequestNoStatusLine(t *testing.T) {
	t.Parallel()

	s := newRawServer(t, "garbage\r\n\r\n")
	if _, err := probekit.Request(t.Context(), "GET", "http://"+s.addr+"/", nil, ""); err == nil || !strings.Contains(err.Error(), "no HTTP status line") {
		t.Errorf("Request() error = %v, want no HTTP status line", err)
	}
}

func TestRequestNoServer(t *testing.T) {
	t.Parallel()

	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	if _, err := probekit.Request(t.Context(), "GET", "http://"+addr+"/", nil, ""); err == nil || !strings.Contains(err.Error(), "cannot connect to "+addr) {
		t.Errorf("Request() error = %v, want cannot connect to %s", err, addr)
	}
}
