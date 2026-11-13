// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

package harness

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/textproto"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/divbast/ci/internal/execx"
)

// withPorts is `container inspect` output for a container whose published
// ports are bound on the host as ports says, keyed by the container's
// port, such as 8080/tcp, each at 127.0.0.1.
func withPorts(status string, running bool, code int, ports map[string]string) []byte {
	type binding struct{ HostIP, HostPort string }
	bound := make(map[string][]binding, len(ports))
	for port, hostPort := range ports {
		bound[port] = []binding{{HostIP: "127.0.0.1", HostPort: hostPort}}
	}
	out, err := json.Marshal([]any{map[string]any{
		"State":           map[string]any{"Status": status, "Running": running, "ExitCode": code, "StartedAt": startedAt},
		"NetworkSettings": map[string]any{"Ports": bound},
	}})
	if err != nil {
		panic(err)
	}
	return out
}

// script is an engine that answers each command by what it is, and keeps
// every command it was given, in order, for tests whose commands carry a
// name the harness made up.
type script struct {
	mu    sync.Mutex
	calls [][]string
	// inspect is what each `container inspect` prints, in turn. The last
	// is printed again once they run out; with none, there is no
	// container to inspect.
	inspect [][]byte
	logs    string
}

func (s *script) RunStdin(_ context.Context, _ io.Reader, name string, args ...string) (execx.Result, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	argv := append([]string{name}, args...)
	s.calls = append(s.calls, argv)
	switch {
	case slices.Equal(args[:min(2, len(args))], []string{"network", "inspect"}):
		return execx.Result{Stdout: []byte("false\n")}, nil
	case args[0] == "run":
		return execx.Result{Stdout: []byte("abc\n")}, nil
	case slices.Equal(args[:min(2, len(args))], []string{"container", "inspect"}) && len(s.inspect) == 0:
		return execx.Result{Code: 1, Stderr: []byte("Error: No such container: " + args[len(args)-1] + "\n")}, nil
	case slices.Equal(args[:min(2, len(args))], []string{"container", "inspect"}):
		out := s.inspect[0]
		if len(s.inspect) > 1 {
			s.inspect = s.inspect[1:]
		}
		return execx.Result{Stdout: out}, nil
	case args[0] == "logs":
		return execx.Result{Stderr: []byte(s.logs)}, nil
	default:
		return execx.Result{}, nil
	}
}

// commands returns every command s was given whose arguments start with
// prefix.
func (s *script) commands(prefix ...string) [][]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var found [][]string
	for _, argv := range s.calls {
		if len(argv) > len(prefix) && slices.Equal(argv[1:1+len(prefix)], prefix) {
			found = append(found, argv)
		}
	}
	return found
}

// flagValues returns each value argv gives flag, in order.
func flagValues(argv []string, flag string) []string {
	var values []string
	for i, a := range argv[:len(argv)-1] {
		if a == flag {
			values = append(values, argv[i+1])
		}
	}
	return values
}

// TestStartServingPublishes starts a container to serve: each port it
// serves on is published on the host's loopback at a port the engine
// picks, and read back from the engine, and the health port only when
// one is given. A container given no network gets one of its own, and
// one given a network keeps it.
func TestStartServingPublishes(t *testing.T) {
	t.Parallel()

	both := withPorts("running", true, 0, map[string]string{"8080/tcp": "40001", "8081/tcp": "40002"})
	tests := []struct {
		name        string
		sp          ServeSpec
		inspect     []byte
		wantPublish []string
		wantBase    string
		wantHealth  string
		// ownNetwork is whether StartServing must make the network
		ownNetwork bool
	}{
		{
			name:        "app-and-health",
			sp:          ServeSpec{Run: RunSpec{Image: "img", Network: "net", Confine: Contract("16m")}, AppPort: 8080, HealthPort: 8081},
			inspect:     both,
			wantPublish: []string{"127.0.0.1::8080", "127.0.0.1::8081"},
			wantBase:    "http://127.0.0.1:40001",
			wantHealth:  "http://127.0.0.1:40002",
		},
		{
			name:        "health-unpublished",
			sp:          ServeSpec{Run: RunSpec{Image: "img", Network: "net", Confine: Contract("16m")}, AppPort: 8080},
			inspect:     withPorts("running", true, 0, map[string]string{"8080/tcp": "40001"}),
			wantPublish: []string{"127.0.0.1::8080"},
			wantBase:    "http://127.0.0.1:40001",
		},
		{
			name:        "a-network-of-its-own",
			sp:          ServeSpec{Run: RunSpec{Image: "img", Confine: Contract("16m")}, AppPort: 8080, HealthPort: 8081},
			inspect:     both,
			wantPublish: []string{"127.0.0.1::8080", "127.0.0.1::8081"},
			wantBase:    "http://127.0.0.1:40001",
			wantHealth:  "http://127.0.0.1:40002",
			ownNetwork:  true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			sc := &script{inspect: [][]byte{tt.inspect}}

			s, err := newEngine("docker", sc).StartServing(t.Context(), t, &tt.sp)
			if err != nil {
				t.Fatalf("StartServing() error = %v", err)
			}
			if s.Base != tt.wantBase || s.HealthBase != tt.wantHealth {
				t.Errorf("StartServing() Base, HealthBase = %q, %q; want %q, %q", s.Base, s.HealthBase, tt.wantBase, tt.wantHealth)
			}
			if s.C == nil || s.C.ID != "abc" || s.Probe != nil {
				t.Errorf("StartServing() = %+v, want container abc and no probe yet: it does not wait", s)
			}

			runs := sc.commands("run")
			if len(runs) != 1 {
				t.Fatalf("ran %q, want one docker run", runs)
			}
			if got := flagValues(runs[0], "-p"); !slices.Equal(got, tt.wantPublish) {
				t.Errorf("docker run published %q, want %q", got, tt.wantPublish)
			}
			network := flagValues(runs[0], "--network")
			created := sc.commands("network", "create")
			switch {
			case !tt.ownNetwork && (len(created) != 0 || !slices.Equal(network, []string{"net"})):
				t.Errorf("made networks %q and ran on %q, want none made and the spec's own, net", created, network)
			case tt.ownNetwork && (len(created) != 1 || len(network) != 1 || created[0][len(created[0])-1] != network[0] ||
				!strings.HasPrefix(network[0], "divbast-")):
				t.Errorf("made networks %q and ran on %q, want one made and the container run on it", created, network)
			}
		})
	}
}

// TestStartServingRefuses refuses a spec it would run as something other
// than it says, before it asks the engine for anything.
func TestStartServingRefuses(t *testing.T) {
	t.Parallel()

	run := RunSpec{Image: "img", Network: "net", Confine: Contract("16m")}
	published := run
	published.Publish = []string{"127.0.0.1:18080:8080"}
	tests := []struct {
		name    string
		sp      ServeSpec
		wantErr string
	}{
		{name: "publish-set", sp: ServeSpec{Run: published, AppPort: 8080}, wantErr: "Serve publishes"},
		{name: "no-app-port", sp: ServeSpec{Run: run}, wantErr: "AppPort is 0"},
		{name: "app-port-too-high", sp: ServeSpec{Run: run, AppPort: 65536}, wantErr: "AppPort is 65536"},
		{name: "health-port-negative", sp: ServeSpec{Run: run, AppPort: 8080, HealthPort: -1}, wantErr: "HealthPort is -1"},
		{name: "one-port-twice", sp: ServeSpec{Run: run, AppPort: 8080, HealthPort: 8080}, wantErr: "both 8080"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			sc := &script{}
			s, err := newEngine("docker", sc).StartServing(t.Context(), t, &tt.sp)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("StartServing() = %+v, %v; want an error containing %q", s, err, tt.wantErr)
			}
			if len(sc.calls) != 0 {
				t.Errorf("StartServing() ran %q, want nothing run for a spec it refuses", sc.calls)
			}
		})
	}
}

// TestStartServingPortsMissing reads the ports of a container that has
// none to read: one that already stopped, whose log says why, and one
// running without the port, which the engine's own report names.
func TestStartServingPortsMissing(t *testing.T) {
	t.Parallel()

	sp := ServeSpec{Run: RunSpec{Image: "img", Network: "net", Confine: Contract("16m")}, AppPort: 8080, HealthPort: 8081}
	tests := []struct {
		name     string
		inspect  []byte
		wantText []string
	}{
		{
			name:     "stopped-at-once",
			inspect:  withPorts("exited", false, 3, nil),
			wantText: []string{"stopped, exit status 3", "8080/tcp", "refusing: on purpose"},
		},
		{
			name:     "health-port-missing",
			inspect:  withPorts("running", true, 0, map[string]string{"8080/tcp": "40001"}),
			wantText: []string{"no host port for 8081/tcp", "8080/tcp:127.0.0.1:40001"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			sc := &script{inspect: [][]byte{tt.inspect}, logs: "refusing: on purpose\n"}
			s, err := newEngine("docker", sc).StartServing(t.Context(), t, &sp)
			for _, want := range tt.wantText {
				if err == nil || !strings.Contains(err.Error(), want) {
					t.Errorf("StartServing() = %+v, %v; want an error containing %q", s, err, want)
				}
			}
		})
	}
}

// roundTrip is an http.RoundTripper that answers from a function, so a
// test inside a synctest bubble opens no connection.
type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// errConnRefused is what dialling a port nothing listens on returns.
var errConnRefused = errors.New("dial tcp 127.0.0.1:40001: connect: connection refused")

// replying returns a transport that answers each request with the next of
// replies, and keeps each request's URL; past the last, it repeats the
// last. A reply is a status, answered with an empty body, an error, or a
// function that answers the request itself.
func replying(replies ...any) (rt http.RoundTripper, urls func() []string) {
	var (
		mu   sync.Mutex
		sent []string
	)
	rt = roundTrip(func(r *http.Request) (*http.Response, error) {
		mu.Lock()
		sent = append(sent, r.URL.String())
		reply := replies[0]
		if len(replies) > 1 {
			replies = replies[1:]
		}
		mu.Unlock()
		switch v := reply.(type) {
		case int:
			return &http.Response{StatusCode: v, Header: http.Header{}, Body: http.NoBody}, nil
		case error:
			return nil, v
		case func(*http.Request) (*http.Response, error):
			return v(r)
		default:
			panic("replying: a reply is a status, an error or a function")
		}
	})
	return rt, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return slices.Clone(sent)
	}
}

// installCalls is what InstallProbe runs in container abc for app.
func installCalls(app []byte) []execx.Call {
	install := func(file string) []string {
		return []string{"docker", "exec", "-i", "abc", FrankenPHP, "php-cli", "-r", installCode(file)}
	}
	calls := []execx.Call{{Argv: install("/tmp/divbast-probe/core.php"), Stdin: coreProbe}}
	if len(app) > 0 {
		calls = append(calls, execx.Call{Argv: install("/tmp/divbast-probe/app.php"), Stdin: app})
	}
	return calls
}

// TestServingWait waits for a container to serve: any status from the
// host will do, and then the probe goes in. A container that stops first,
// or that never answers within ServeWithin, is an error carrying its log,
// and each request is bounded on its own, so one that hangs is given up
// and asked again.
func TestServingWait(t *testing.T) {
	t.Parallel()

	inspect := []string{"docker", "container", "inspect", "abc"}
	running := execx.Call{Argv: inspect, Result: execx.Result{Stdout: state("running", true, 0, startedAt, "")}}
	logs := execx.Call{Argv: []string{"docker", "logs", "abc"}, Result: execx.Result{Stderr: []byte("refusing: TRUSTED_PROXIES holds '::/0'\n")}}
	app := []byte("<?php return [];\n")
	hangs := func(r *http.Request) (*http.Response, error) {
		<-r.Context().Done()
		return nil, r.Context().Err()
	}
	tests := []struct {
		name     string
		path     string
		app      []byte
		replies  []any
		calls    []execx.Call
		wantText []string
		wantWait time.Duration
	}{
		{
			name:     "serves-once-started",
			path:     "/",
			replies:  []any{errConnRefused, http.StatusUnauthorized},
			calls:    slices.Concat([]execx.Call{running}, installCalls(nil)),
			wantWait: time.Second,
		},
		{
			// A 500 is an answer: what it should have been is the check's
			name:    "any-status-with-an-app-probe",
			path:    "/backend/getIP.php",
			app:     app,
			replies: []any{http.StatusInternalServerError},
			calls:   installCalls(app),
		},
		{
			name:     "stops-instead",
			path:     "/",
			replies:  []any{errConnRefused},
			calls:    []execx.Call{{Argv: inspect, Result: execx.Result{Stdout: state("exited", false, 1, startedAt, "")}}, logs},
			wantText: []string{"stopped, exit status 1, before GET / answered", "TRUSTED_PROXIES holds '::/0'"},
		},
		{
			name:     "never-serves",
			path:     "/",
			replies:  []any{errConnRefused},
			calls:    slices.Concat(slices.Repeat([]execx.Call{running}, 61), []execx.Call{logs}),
			wantText: []string{"GET http://127.0.0.1:40001/ got no answer within 1m0s", "connection refused", "TRUSTED_PROXIES"},
			wantWait: ServeWithin,
		},
		{
			name:     "an-attempt-that-hangs",
			path:     "/",
			replies:  []any{hangs, http.StatusOK},
			calls:    slices.Concat([]execx.Call{running}, installCalls(nil)),
			wantWait: attemptWithin + time.Second,
		},
		{
			// Asking again would only ask the same wrong question
			name:     "a-path-that-cannot-go-out-as-written",
			path:     "/a b",
			replies:  []any{http.StatusOK},
			wantText: []string{"would go out as /a%20b"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			synctest.Test(t, func(t *testing.T) {
				rt, _ := replying(tt.replies...)
				s := &Serving{
					C:         &Container{ID: "abc", engine: newEngine("docker", execx.NewFake(t, tt.calls...))},
					Base:      "http://127.0.0.1:40001",
					probeApp:  tt.app,
					transport: rt,
				}

				start := time.Now()
				err := s.Wait(t.Context(), tt.path)
				if waited := time.Since(start); waited != tt.wantWait {
					t.Errorf("Wait() took %s, want %s", waited, tt.wantWait)
				}
				if len(tt.wantText) == 0 {
					if err != nil || s.Probe == nil {
						t.Errorf("Wait() = %v, probe %v; want nil and the probe installed", err, s.Probe)
					}
					return
				}
				for _, want := range tt.wantText {
					if err == nil || !strings.Contains(err.Error(), want) {
						t.Errorf("Wait() = %v, want an error containing %q", err, want)
					}
				}
				if s.Probe != nil {
					t.Errorf("Wait() failed and installed the probe all the same")
				}
			})
		})
	}
}

// TestServingRestartSteps restarts a serving container in place: its ports
// are read again, since Docker binds others, it is waited for at its
// ready path on the port it is at now, and the probe, which went with the
// old tmpfs, goes in again. One that does not come back is an error
// carrying its log, and leaves no probe that would only fail.
func TestServingRestartSteps(t *testing.T) {
	t.Parallel()

	restart := execx.Call{Argv: []string{"docker", "restart", "ctr"}, Result: execx.Result{Stdout: []byte("ctr\n")}}
	inspect := []string{"docker", "container", "inspect", "abc"}
	moved := execx.Call{Argv: inspect, Result: execx.Result{
		Stdout: withPorts("running", true, 0, map[string]string{"8080/tcp": "40003", "8081/tcp": "40004"}),
	}}
	app := []byte("<?php return [];\n")
	tests := []struct {
		name     string
		replies  []any
		calls    []execx.Call
		wantURLs []string
		wantText []string
	}{
		{
			name:     "serves-again-elsewhere",
			replies:  []any{http.StatusOK},
			calls:    slices.Concat([]execx.Call{restart, moved, moved}, installCalls(app)),
			wantURLs: []string{"http://127.0.0.1:40003/ready"},
		},
		{
			name:    "does-not-come-back",
			replies: []any{errConnRefused},
			calls: []execx.Call{
				restart, moved, moved,
				{Argv: inspect, Result: execx.Result{Stdout: state("exited", false, 1, startedAt, "")}},
				{Argv: []string{"docker", "logs", "abc"}, Result: execx.Result{Stderr: []byte("refusing: the database is gone\n")}},
			},
			wantURLs: []string{"http://127.0.0.1:40003/ready"},
			wantText: []string{"stopped, exit status 1", "the database is gone"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			synctest.Test(t, func(t *testing.T) {
				rt, urls := replying(tt.replies...)
				old := &Probe{}
				s := &Serving{
					C:          &Container{ID: "abc", Name: "ctr", engine: newEngine("docker", execx.NewFake(t, tt.calls...))},
					Probe:      old,
					Base:       "http://127.0.0.1:40001",
					HealthBase: "http://127.0.0.1:40002",
					appPort:    8080,
					healthPort: 8081,
					readyPath:  "/ready",
					probeApp:   app,
					transport:  rt,
				}

				err := s.Restart(t.Context())
				if got := urls(); !slices.Equal(got, tt.wantURLs) {
					t.Errorf("Restart() asked for %q, want %q", got, tt.wantURLs)
				}
				if s.Base != "http://127.0.0.1:40003" || s.HealthBase != "http://127.0.0.1:40004" {
					t.Errorf("after Restart(), Base, HealthBase = %q, %q; want the ports the engine reports now", s.Base, s.HealthBase)
				}
				if len(tt.wantText) == 0 {
					if err != nil || s.Probe == nil || s.Probe == old {
						t.Errorf("Restart() = %v, probe %p (was %p); want nil and a probe installed again", err, s.Probe, old)
					}
					return
				}
				for _, want := range tt.wantText {
					if err == nil || !strings.Contains(err.Error(), want) {
						t.Errorf("Restart() = %v, want an error containing %q", err, want)
					}
				}
				if s.Probe != nil {
					t.Errorf("Restart() failed and left probe %p, whose files the restart took", s.Probe)
				}
			})
		})
	}
}

// rawServer serves on loopback, keeps every request exactly as it came
// over the wire, headers and body, and answers each 200 with "ok". It
// returns its base URL, and the requests it has kept.
func rawServer(t *testing.T) (base string, requests func() []string) {
	t.Helper()
	ln, err := new(net.ListenConfig).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var (
		mu   sync.Mutex
		kept []string
		wg   sync.WaitGroup
	)
	t.Cleanup(func() {
		if err := ln.Close(); err != nil {
			t.Error(err)
		}
		wg.Wait()
	})
	wg.Go(func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			raw, err := readRaw(conn)
			if err != nil {
				t.Error(err)
			}
			mu.Lock()
			kept = append(kept, raw)
			mu.Unlock()
			if _, err := io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nX-Answer: yes\r\n"+
				"Content-Length: 2\r\nConnection: close\r\n\r\nok"); err != nil {
				t.Error(err)
			}
			if err := conn.Close(); err != nil {
				t.Error(err)
			}
		}
	})
	return "http://" + ln.Addr().String(), func() []string {
		mu.Lock()
		defer mu.Unlock()
		return slices.Clone(kept)
	}
}

// readRaw reads one request from conn as it was sent: the head up to its
// blank line, then as many bytes of body as its Content-Length says.
func readRaw(conn net.Conn) (string, error) {
	r := bufio.NewReader(conn)
	var b strings.Builder
	length := 0
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return b.String(), err
		}
		b.WriteString(line)
		if line == "\r\n" {
			break
		}
		if name, value, ok := strings.Cut(strings.TrimSpace(line), ":"); ok &&
			textproto.CanonicalMIMEHeaderKey(name) == "Content-Length" {
			if length, err = strconv.Atoi(strings.TrimSpace(value)); err != nil {
				return b.String(), err
			}
		}
	}
	body := make([]byte, length)
	_, err := io.ReadFull(r, body)
	b.Write(body)
	return b.String(), err
}

// TestServingDo sends requests from the host as curl --path-as-is would:
// the path and query exactly as written, no dot segment resolved and no
// escape undone, and every header name in the case it was given, as a
// server that tells them apart sees them. A path that cannot go out as
// written is an error, and is never sent.
func TestServingDo(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		method string
		path   string
		header http.Header
		body   []byte
		// wantSent holds what the request must carry, line by line, and
		// wantErr what the error must say instead
		wantSent []string
		wantErr  string
		// wantOne is a header the request must carry exactly once, its
		// name in any case
		wantOne string
	}{
		{
			name:   "path-as-is",
			method: http.MethodGet,
			path:   "/a/./b/../c%2Fd?x=%2e&y",
			header: http.Header{"x-lower-case": {"1"}, "X-MiXeD-Case": {"2"}},
			wantSent: []string{
				"GET /a/./b/../c%2Fd?x=%2e&y HTTP/1.1\r\n",
				"\r\nx-lower-case: 1\r\n",
				"\r\nX-MiXeD-Case: 2\r\n",
			},
		},
		{
			name:   "a-body",
			method: "PROPFIND",
			path:   "/dav.php/",
			header: http.Header{"Depth": {"0"}, "Content-Type": {"application/xml"}},
			body:   []byte("<x/>"),
			wantSent: []string{
				"PROPFIND /dav.php/ HTTP/1.1\r\n",
				"\r\nDepth: 0\r\n",
				"\r\nContent-Length: 4\r\n",
				"\r\n\r\n<x/>",
			},
		},
		{
			// Go sends Host from the request's own field, and never from its
			// headers, which would drop it without a word
			name:     "host",
			method:   http.MethodGet,
			path:     "/",
			header:   http.Header{"host": {"dav.example"}},
			wantSent: []string{"\r\nHost: dav.example\r\n"},
			wantOne:  "Host",
		},
		{name: "a-space", method: http.MethodGet, path: "/a b", wantErr: "GET /a b would go out as /a%20b"},
		{name: "a-bad-escape", method: http.MethodGet, path: "/%zz", wantErr: "invalid URL escape"},
		{name: "no-leading-slash", method: http.MethodGet, path: "index.php", wantErr: "index.php"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			base, requests := rawServer(t)
			s := &Serving{Base: base}

			resp, err := s.Do(t.Context(), nil, tt.method, tt.path, tt.header, tt.body)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) || !errors.Is(err, errUnsendable) {
					t.Errorf("Do(%s %q) = %+v, %v; want an error wrapping errUnsendable and containing %q", tt.method, tt.path, resp, err, tt.wantErr)
				}
				if sent := requests(); len(sent) != 0 {
					t.Errorf("Do(%s %q) sent %q, want nothing sent", tt.method, tt.path, sent)
				}
				return
			}
			if err != nil {
				t.Fatalf("Do(%s %q) error = %v", tt.method, tt.path, err)
			}
			if resp.Status != http.StatusOK || string(resp.Body) != "ok" || resp.Header.Get("X-Answer") != "yes" {
				t.Errorf("Do(%s %q) = %+v, want 200, the server's header and body ok", tt.method, tt.path, resp)
			}
			sent := requests()
			if len(sent) != 1 {
				t.Fatalf("Do(%s %q) sent %q, want one request", tt.method, tt.path, sent)
			}
			for _, want := range tt.wantSent {
				if !strings.Contains(sent[0], want) {
					t.Errorf("Do(%s %q) sent %q, which does not hold %q", tt.method, tt.path, sent[0], want)
				}
			}
			if tt.wantOne != "" {
				head, _, _ := strings.Cut(sent[0], "\r\n\r\n")
				var n int
				for l := range strings.SplitSeq(head, "\r\n") {
					if name, _, ok := strings.Cut(l, ":"); ok && strings.EqualFold(name, tt.wantOne) {
						n++
					}
				}
				if n != 1 {
					t.Errorf("Do(%s %q) sent %q, with %d %s headers, want one", tt.method, tt.path, sent[0], n, tt.wantOne)
				}
			}
		})
	}
}

// TestServingHealth sends through Health to the health port, with Get,
// Do and StatusIs alike, and leaves the Serving it was taken from on the
// app port. With the health port unpublished, every request the copy
// would send fails, saying so, Wait among them, and none reaches the app
// port in its place.
func TestServingHealth(t *testing.T) {
	t.Parallel()

	t.Run("published", func(t *testing.T) {
		t.Parallel()
		ctx := t.Context()
		app, toApp := rawServer(t)
		health, toHealth := rawServer(t)
		s := &Serving{Base: app, HealthBase: health}

		h := s.Health()
		if h.Base != health || h.HealthBase != health || s.Base != app {
			t.Errorf("Health() Base, HealthBase = %q, %q, and the Serving's Base is then %q; want %q, %q, and %q kept",
				h.Base, h.HealthBase, s.Base, health, health, app)
		}
		if resp, err := h.Get(ctx, "/healthz", nil); err != nil || resp.Status != http.StatusOK {
			t.Errorf("Health().Get(/healthz) = %+v, %v; want 200", resp, err)
		}
		if resp, err := h.Do(ctx, nil, http.MethodHead, "/healthz", nil, nil); err != nil || resp.Status != http.StatusOK {
			t.Errorf("Health().Do(HEAD /healthz) = %+v, %v; want 200", resp, err)
		}
		tb := &recTB{t: t}
		StatusIs(tb, h, "health", http.StatusOK, "/healthz")
		recorded(t, tb, []string{"ok   health (200)"})

		if got := toHealth(); len(got) != 3 || !strings.HasPrefix(got[0], "GET /healthz ") || !strings.HasPrefix(got[1], "HEAD /healthz ") {
			t.Errorf("the health port got %q, want GET, HEAD and GET /healthz", got)
		}
		if got := toApp(); len(got) != 0 {
			t.Errorf("the app port got %q, want nothing", got)
		}
	})

	t.Run("unpublished", func(t *testing.T) {
		t.Parallel()
		ctx := t.Context()
		app, toApp := rawServer(t)
		h := (&Serving{Base: app}).Health()

		const why = "GET /healthz was not sent: the health port is unpublished"
		if resp, err := h.Get(ctx, "/healthz", nil); err == nil || !strings.Contains(err.Error(), why) || !errors.Is(err, errUnsendable) {
			t.Errorf("Health().Get(/healthz) = %+v, %v; want an error wrapping errUnsendable and holding %q", resp, err, why)
		}
		if resp, err := h.Do(ctx, nil, http.MethodPost, "/healthz", nil, []byte("x")); err == nil || !strings.Contains(err.Error(), "the health port is unpublished") {
			t.Errorf("Health().Do(POST /healthz) = %+v, %v; want an error saying the health port is unpublished", resp, err)
		}
		// At once: there is no port to wait for
		if err := h.Wait(ctx, "/healthz"); err == nil || !strings.Contains(err.Error(), why) {
			t.Errorf("Health().Wait(/healthz) = %v, want an error holding %q", err, why)
		}
		tb := &recTB{t: t}
		StatusIs(tb, h, "health", http.StatusOK, "/healthz")
		recorded(t, tb, nil, []string{"FAIL health: " + why})

		if got := toApp(); len(got) != 0 {
			t.Errorf("the app port got %q, want nothing: a request for the health port must never reach it", got)
		}
	})

	// Not a copy Health made: a Serving no Serve or StartServing set up
	t.Run("no-base", func(t *testing.T) {
		t.Parallel()
		const why = "GET / was not sent: the Serving has no Base"
		if resp, err := (&Serving{}).Get(t.Context(), "/", nil); err == nil || !strings.Contains(err.Error(), why) || !errors.Is(err, errUnsendable) {
			t.Errorf("Get(/) with no Base = %+v, %v; want an error wrapping errUnsendable and holding %q", resp, err, why)
		}
	})
}

// TestServingHealthAcrossRestart restarts a serving container with a
// health copy taken before, once through the Serving it was taken from
// and once through the copy itself. Either way the copy's requests then
// go to the health port where the engine has it now, which Docker moves
// on a restart, and never to the app port, whose answer a check through
// the copy could otherwise pass on; and the Serving the copy was taken
// from is the one restarted, its ports read again.
func TestServingHealthAcrossRestart(t *testing.T) {
	t.Parallel()

	restart := execx.Call{Argv: []string{"docker", "restart", "ctr"}, Result: execx.Result{Stdout: []byte("ctr\n")}}
	moved := execx.Call{Argv: []string{"docker", "container", "inspect", "abc"}, Result: execx.Result{
		Stdout: withPorts("running", true, 0, map[string]string{"8080/tcp": "40003", "8081/tcp": "40004"}),
	}}
	for _, tt := range []struct {
		name    string
		through bool
	}{{name: "the-serving-restarts"}, {name: "the-copy-restarts", through: true}} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			synctest.Test(t, func(t *testing.T) {
				ctx := t.Context()
				rt, urls := replying(http.StatusOK)
				s := &Serving{
					C:          &Container{ID: "abc", Name: "ctr", engine: newEngine("docker", execx.NewFake(t, slices.Concat([]execx.Call{restart, moved, moved}, installCalls(nil))...))},
					Base:       "http://127.0.0.1:40001",
					HealthBase: "http://127.0.0.1:40002",
					appPort:    8080,
					healthPort: 8081,
					readyPath:  "/ready",
					transport:  rt,
				}
				h := s.Health()
				// A copy of the copy is a copy of s
				hh := h.Health()
				restarted := s
				if tt.through {
					restarted = h
				}

				if err := restarted.Restart(ctx); err != nil {
					t.Fatalf("Restart() error = %v", err)
				}
				for _, c := range []*Serving{h, hh} {
					if _, err := c.Get(ctx, "/healthz", nil); err != nil {
						t.Fatalf("Health().Get(/healthz) after the restart: %v", err)
					}
				}
				want := []string{"http://127.0.0.1:40003/ready", "http://127.0.0.1:40004/healthz", "http://127.0.0.1:40004/healthz"}
				if got := urls(); !slices.Equal(got, want) {
					t.Errorf("asked for %q, want the app port's ready path and then the health port, each where it is now: %q", got, want)
				}
				if s.Base != "http://127.0.0.1:40003" || s.HealthBase != "http://127.0.0.1:40004" || s.Probe == nil {
					t.Errorf("the Serving the copy was taken from has Base, HealthBase = %q, %q and probe %p; want it restarted: the ports now, and a probe", s.Base, s.HealthBase, s.Probe)
				}
			})
		})
	}
}

// TestServingHealthWait waits through a health copy: it asks the health
// port, and the probe it installs is the Serving's too, since both are
// the one container's.
func TestServingHealthWait(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		rt, urls := replying(http.StatusOK)
		s := &Serving{
			C:          &Container{ID: "abc", engine: newEngine("docker", execx.NewFake(t, installCalls(nil)...))},
			Base:       "http://127.0.0.1:40001",
			HealthBase: "http://127.0.0.1:40002",
			transport:  rt,
		}
		h := s.Health()
		if err := h.Wait(t.Context(), "/healthz"); err != nil {
			t.Fatalf("Health().Wait(/healthz) error = %v", err)
		}
		if got := urls(); !slices.Equal(got, []string{"http://127.0.0.1:40002/healthz"}) {
			t.Errorf("Health().Wait(/healthz) asked for %q, want the health port's /healthz", got)
		}
		if h.Probe == nil || s.Probe != h.Probe {
			t.Errorf("after Health().Wait(), the copy's probe is %p and the Serving's %p; want one probe, both", h.Probe, s.Probe)
		}
	})
}

// TestServingGetUnfollowed answers GET from the host with a redirect,
// which Get returns as it is, as HostClient does: a 302 to an install
// wizard is a failure, not a hop on the way to a 200.
func TestServingGetUnfollowed(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		rt, urls := replying(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusFound, Header: http.Header{"Location": {"/admin/install/"}}, Body: http.NoBody}, nil
		})
		s := &Serving{Base: "http://127.0.0.1:40001", transport: rt}
		resp, err := s.Get(t.Context(), "/dav.php", http.Header{"Depth": {"0"}})
		if err != nil || resp.Status != http.StatusFound {
			t.Errorf("Get() = %+v, %v; want the 302 itself", resp, err)
		}
		if got := urls(); !slices.Equal(got, []string{"http://127.0.0.1:40001/dav.php"}) {
			t.Errorf("Get() asked for %q, want only /dav.php", got)
		}
	})
}

func TestPHPIn(t *testing.T) {
	t.Parallel()

	run := []string{"docker", "exec", "abc", FrankenPHP, "php-cli", "-r", "echo 1;"}
	tests := []struct {
		name    string
		res     execx.Result
		want    string
		wantErr string
	}{
		{name: "prints", res: execx.Result{Stdout: []byte("1"), Stderr: []byte("PHP Notice: n\n")}, want: "1PHP Notice: n\n"},
		{name: "fails", res: phpFatal, wantErr: "exit status 255: PHP Fatal error"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			c := &Container{ID: "abc", engine: newEngine("docker", execx.NewFake(t, execx.Call{Argv: run, Result: tt.res}))}
			got, err := PHPIn(t.Context(), c, "echo 1;")
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("PHPIn() = %q, %v; want an error containing %q", got, err, tt.wantErr)
				}
				return
			}
			if err != nil || got != tt.want {
				t.Errorf("PHPIn() = %q, %v; want %q, nil", got, err, tt.want)
			}
		})
	}
}

func TestWithLog(t *testing.T) {
	t.Parallel()

	logs := []string{"docker", "logs", "abc"}
	boom := errors.New("boom")
	tests := []struct {
		name string
		res  execx.Result
		want string
	}{
		{name: "a-log", res: execx.Result{Stdout: []byte("starting\n"), Stderr: []byte("refusing: why\n")}, want: "boom; its log:\nstarting\nrefusing: why"},
		{name: "an-empty-log", res: execx.Result{}, want: "boom; its log is empty"},
		{name: "no-log", res: execx.Result{Code: 1, Stderr: []byte("Error: No such container: abc\n")}, want: "boom; its log could not be read: docker logs abc: exit status 1: Error: No such container: abc"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			c := &Container{ID: "abc", engine: newEngine("docker", execx.NewFake(t, execx.Call{Argv: logs, Result: tt.res}))}
			err := WithLog(t.Context(), c, boom)
			if !errors.Is(err, boom) || err.Error() != tt.want {
				t.Errorf("WithLog() = %q, want %q, wrapping the error it was given", err, tt.want)
			}
		})
	}
}

func TestPause(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		start := time.Now()
		if err := Pause(t.Context(), 3*time.Second); err != nil || time.Since(start) != 3*time.Second {
			t.Errorf("Pause(3s) = %v after %s, want nil after 3s", err, time.Since(start))
		}

		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		defer cancel()
		start = time.Now()
		if err := Pause(ctx, time.Hour); !errors.Is(err, context.DeadlineExceeded) || time.Since(start) != time.Second {
			t.Errorf("Pause(1h) under a 1s deadline = %v after %s, want the deadline after 1s", err, time.Since(start))
		}
	})
}
