// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

package coreprobe

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"testing/fstest"
	"testing/synctest"
	"time"
)

// fixture reads a file from testdata.
func fixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name)) //nolint:gosec // G304: the test's own fixture
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// socketProc is a /proc whose socket tables are the testdata files named,
// and whose process 1 holds a descriptor for each target in proc-net-fds.
func socketProc(t *testing.T, tcp, tcp6, udp, udp6 string) fstest.MapFS {
	t.Helper()
	proc := fstest.MapFS{
		"net/tcp":  file(fixture(t, tcp)),
		"net/tcp6": file(fixture(t, tcp6)),
		"net/udp":  file(fixture(t, udp)),
		"net/udp6": file(fixture(t, udp6)),
		"1/comm":   file("frankenphp\n"),
	}
	for i, target := range strings.Split(strings.TrimSpace(fixture(t, "proc-net-fds")), "\n") {
		proc[fmt.Sprintf("1/fd/%d", i)] = &fstest.MapFile{Mode: fs.ModeSymlink, Data: []byte(target)}
	}
	return proc
}

func TestAssertListeners(t *testing.T) {
	t.Parallel()

	const (
		tcpRecord = "TCP ports a process in the container listens on"
		udpRecord = "UDP ports a process in the container holds a socket on"
		fdRecord  = "processes in the container whose descriptors the probe cannot read"
	)
	tests := []struct {
		name     string
		udp      string
		ports    []string
		wantCode int
		want     string
	}{
		{
			// Docker's resolver listens at 127.0.0.11 in the same
			// namespace, held from outside: it does not count.
			name:  "the-app-and-health-ports",
			udp:   "proc-net-udp6",
			ports: []string{"8081", "8080"},
			want:  record(true, tcpRecord, "8080 8081", "8080 8081") + record(true, udpRecord, "none", "none") + record(true, fdRecord, "none", "none"),
		},
		{
			name:     "a-listener-not-named",
			udp:      "proc-net-udp6",
			ports:    []string{"8080"},
			wantCode: 1,
			want:     record(false, tcpRecord, "8080", "8080 8081") + record(true, udpRecord, "none", "none") + record(true, fdRecord, "none", "none"),
		},
		{
			name:     "a-held-udp-socket",
			udp:      "proc-net-udp",
			ports:    []string{"8080", "8081"},
			wantCode: 1,
			want:     record(true, tcpRecord, "8080 8081", "8080 8081") + record(false, udpRecord, "none", "5353") + record(true, fdRecord, "none", "none"),
		},
		{
			name:  "ports-given-twice",
			udp:   "proc-net-udp6",
			ports: []string{"8080", "8081", "8080"},
			want:  record(true, tcpRecord, "8080 8081", "8080 8081") + record(true, udpRecord, "none", "none") + record(true, fdRecord, "none", "none"),
		},
		{name: "port-zero", udp: "proc-net-udp6", ports: []string{"0"}, wantCode: 1, want: record(false, "assert-listeners completed", "no exception", "'0' is not a TCP port")},
		{name: "port-too-big", udp: "proc-net-udp6", ports: []string{"65536"}, wantCode: 1, want: record(false, "assert-listeners completed", "no exception", "'65536' is not a TCP port")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			env := testEnv(t, socketProc(t, "proc-net-tcp", "proc-net-tcp6", tt.udp, "proc-net-udp6"), "")
			code, stdout, stderr := probe(t, env, append([]string{"assert-listeners"}, tt.ports...)...)
			if code != tt.wantCode || stdout != tt.want {
				t.Errorf("assert-listeners %q = exit %d, stdout %q, stderr %q; want exit %d, stdout %q", tt.ports, code, stdout, stderr, tt.wantCode, tt.want)
			}
		})
	}
}

// TestAssertListenersUnreadable has a process whose descriptors cannot be
// read, which fails: whatever it listened on would go unseen. It is
// looked at again, 20 times in all, before it counts.
func TestAssertListenersUnreadable(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		proc := socketProc(t, "proc-net-tcp", "proc-net-tcp6", "proc-net-udp6", "proc-net-udp6")
		proc["7/fd"] = file("not a directory, so it cannot be read as one")
		proc["7/comm"] = file("sleep\n")
		start := time.Now()
		code, stdout, _ := probe(t, testEnv(t, proc, ""), "assert-listeners", "8080", "8081")
		want := record(true, "TCP ports a process in the container listens on", "8080 8081", "8080 8081") +
			record(true, "UDP ports a process in the container holds a socket on", "none", "none") +
			record(false, "processes in the container whose descriptors the probe cannot read", "none", "7 (sleep)")
		if code != 1 || stdout != want {
			t.Errorf("assert-listeners = exit %d, stdout %q; want exit 1, stdout %q", code, stdout, want)
		}
		if waited := time.Since(start); waited != 19*100*time.Millisecond {
			t.Errorf("assert-listeners waited %s for the unreadable process, want 19 retries 100ms apart", waited)
		}
	})
}

func TestAssertListenersMalformed(t *testing.T) {
	t.Parallel()

	env := testEnv(t, socketProc(t, "proc-net-malformed", "proc-net-tcp6", "proc-net-udp6", "proc-net-udp6"), "")
	code, stdout, _ := probe(t, env, "assert-listeners", "8080")
	want := record(false, "assert-listeners completed", "no exception", "/proc/net/tcp has a line that is not a socket: this is not a socket")
	if code != 1 || stdout != want {
		t.Errorf("assert-listeners = exit %d, stdout %q; want exit 1, stdout %q", code, stdout, want)
	}
}

// TestParseListeners runs the socket parsing over tables taken from the
// LibreSpeed fixture under Docker, on an internal network, where Docker's
// resolver keeps a TCP listener and a UDP socket at 127.0.0.11 that no
// process in the container holds. proc-net-udp adds, by hand, a UDP
// socket that one does hold, at port 5353. The resolver's UDP port,
// 60327, sorts after it, so only the whole of what the parser printed
// shows it was left out.
func TestParseListeners(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		tcp, udp string
		wantCode int
		want     string
	}{
		{name: "held-udp-reported-resolver-ignored", tcp: "proc-net-tcp", udp: "proc-net-udp", want: "udp 5353\n"},
		{name: "held-tcp-listeners", tcp: "proc-net-tcp6", udp: "proc-net-udp6", want: "tcp 8080\ntcp 8081\n"},
		{
			name: "malformed-table", tcp: "proc-net-malformed", udp: "proc-net-udp6", wantCode: 1,
			want: record(false, "parse-listeners completed", "no exception",
				"testdata/proc-net-malformed has a line that is not a socket: this is not a socket"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			code, stdout, stderr := probe(t, testEnv(t, fstest.MapFS{}, ""), "parse-listeners",
				filepath.Join("testdata", tt.tcp), filepath.Join("testdata", tt.udp), filepath.Join("testdata", "proc-net-fds"))
			if code != tt.wantCode || stdout != tt.want {
				t.Errorf("parse-listeners = exit %d, stdout %q, stderr %q; want exit %d, stdout %q", code, stdout, stderr, tt.wantCode, tt.want)
			}
		})
	}
}

// conn is a connection that was made.
type conn struct{ net.Conn }

func (conn) Close() error { return nil }

func TestProbeEgress(t *testing.T) {
	t.Parallel()

	const what = "outbound TCP to 9.9.9.9:443 is refused"
	refused := fmt.Errorf("dial tcp 9.9.9.9:443: connect: %w", syscall.ECONNREFUSED)
	tests := []struct {
		name     string
		dial     error
		wantCode int
		want     string
	}{
		{
			name: "refused",
			dial: refused,
			want: record(true, what, "no connection", fmt.Sprintf("no connection (errno %d: Connection refused)", int(syscall.ECONNREFUSED))),
		},
		{
			name: "timed-out",
			dial: context.DeadlineExceeded,
			want: record(true, what, "no connection", "no connection (context deadline exceeded)"),
		},
		{name: "connected", wantCode: 1, want: record(false, what, "no connection", "CONNECTED")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			env := testEnv(t, fstest.MapFS{}, "")
			env.Dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
				deadline, ok := ctx.Deadline()
				if network != "tcp" || addr != "9.9.9.9:443" || !ok || time.Until(deadline) > 3*time.Second {
					return nil, fmt.Errorf("dialled %s %s with deadline %v (%v), want tcp 9.9.9.9:443 within 3s", network, addr, deadline, ok)
				}
				if tt.dial != nil {
					return nil, tt.dial
				}
				return conn{}, nil
			}
			code, stdout, _ := probe(t, env, "probe-egress")
			if code != tt.wantCode || stdout != tt.want {
				t.Errorf("probe-egress = exit %d, stdout %q; want exit %d, stdout %q", code, stdout, tt.wantCode, tt.want)
			}
		})
	}
}

func TestHTTPRequest(t *testing.T) {
	t.Parallel()

	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	got := make(chan string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		buf := make([]byte, 4096)
		n, _ := c.Read(buf)
		got <- string(buf[:n])
		_, _ = io.WriteString(c, "HTTP/1.0 418 I'm a teapot\r\n\r\nshort\nand stout")
		_ = c.Close()
	}()

	url := "http://" + ln.Addr().String() + "/x"
	code, stdout, stderr := probe(t, testEnv(t, fstest.MapFS{}, ""), "http-request", "GET", url, "X-A: 1\nX-B: 2", "")
	if code != 0 || stdout != "418\nshort\nand stout" {
		t.Errorf("http-request = exit %d, stdout %q, stderr %q; want exit 0, stdout %q", code, stdout, stderr, "418\nshort\nand stout")
	}
	if req := <-got; !strings.Contains(req, "\r\nX-A: 1\r\nX-B: 2\r\n") {
		t.Errorf("sent %q, want both header lines", req)
	}
}

func TestHTTPRequestRefused(t *testing.T) {
	t.Parallel()

	code, stdout, _ := probe(t, testEnv(t, fstest.MapFS{}, ""), "http-request", "GET", "ftp://x/", "", "")
	want := record(false, "http-request completed", "no exception", "'ftp://x/' is not an http:// URL")
	if code != 1 || stdout != want {
		t.Errorf("http-request = exit %d, stdout %q; want exit 1, stdout %q", code, stdout, want)
	}
}
