// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

package harness

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/divbast/ci/internal/execx"
)

// recTB is a fakeTB that also has what the assertions use beyond Checks:
// the running test's context and cleanups, and whether a record failed.
type recTB struct {
	fakeTB

	t *testing.T
}

func (r *recTB) Context() context.Context { return r.t.Context() }

func (r *recTB) Cleanup(f func()) { r.t.Cleanup(f) }

func (r *recTB) Failed() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.errs) > 0
}

// recorded fails t unless tb logged exactly wantLogs, the ok lines, and
// reported exactly one failure for each of wantErrs, holding every part
// of it.
func recorded(t *testing.T, tb *recTB, wantLogs []string, wantErrs ...[]string) {
	t.Helper()
	tb.mu.Lock()
	defer tb.mu.Unlock()
	if !slices.Equal(tb.logs, wantLogs) {
		t.Errorf("logged %q, want %q", tb.logs, wantLogs)
	}
	if len(tb.errs) != len(wantErrs) {
		t.Errorf("reported %q, want %d failures holding %q", tb.errs, len(wantErrs), wantErrs)
		return
	}
	for i, parts := range wantErrs {
		for _, part := range parts {
			if !strings.Contains(tb.errs[i], part) {
				t.Errorf("failure %d = %q, want it to hold %q", i, tb.errs[i], part)
			}
		}
	}
}

// closedPort returns the address of a loopback port nothing listens on.
func closedPort(t *testing.T) string {
	t.Helper()
	ln, err := new(net.ListenConfig).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	return addr
}

// TestStatusIs asks a server for a path from the host: only the exact
// status passes, and a request that got no answer, or could not be sent
// as written, fails with why.
func TestStatusIs(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/dav.php" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	closed := "http://" + closedPort(t)

	tests := []struct {
		name       string
		base, path string
		wantLogs   []string
		wantErrs   [][]string
	}{
		{name: "holds", base: srv.URL, path: "/dav.php", wantLogs: []string{"ok   GET it (401)"}},
		{name: "another-status", base: srv.URL, path: "/", wantErrs: [][]string{{"FAIL GET it: got 200, want 401"}}},
		{name: "no-answer", base: closed, path: "/", wantErrs: [][]string{{`FAIL GET it: Get "` + closed + `/"`, "connection refused"}}},
		{name: "not-as-written", base: srv.URL, path: "/a b", wantErrs: [][]string{{"FAIL GET it: ", "would go out as /a%20b"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			tb := &recTB{t: t}
			StatusIs(tb, &Serving{Base: tt.base}, "GET it", http.StatusUnauthorized, tt.path)
			recorded(t, tb, tt.wantLogs, tt.wantErrs...)
		})
	}
}

func TestAnswers(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		resp     Response
		err      error
		wantLogs []string
		wantErrs [][]string
	}{
		{name: "holds", resp: Response{Status: 207}, wantLogs: []string{"ok   PROPFIND (207)"}},
		{name: "another-status", resp: Response{Status: 401}, wantErrs: [][]string{{"FAIL PROPFIND: got 401, want 207"}}},
		// The error is what counts, whatever came back with it
		{name: "no-answer", resp: Response{Status: 207}, err: errors.New("EOF"), wantErrs: [][]string{{"FAIL PROPFIND: EOF"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			tb := &recTB{t: t}
			Answers(tb, "PROPFIND", http.StatusMultiStatus, tt.resp, tt.err)
			recorded(t, tb, tt.wantLogs, tt.wantErrs...)
		})
	}
}

// TestContainsLacks looks for a needle in a text: each says what it
// found, quoting a long text only in part, and Lacks fails on an empty
// text, which lacks anything.
func TestContainsLacks(t *testing.T) {
	t.Parallel()

	long := strings.Repeat("x", 700)
	tests := []struct {
		name     string
		check    func(tb testing.TB, what, needle, text string)
		needle   string
		text     string
		wantLogs []string
		wantErrs [][]string
	}{
		{name: "contains", check: Contains, needle: "ok", text: "it is ok\n", wantLogs: []string{`ok   it (holds "ok")`}},
		{name: "contains-not", check: Contains, needle: "ok", text: "no\n", wantErrs: [][]string{{`FAIL it: "ok" is not in "no\n"`}}},
		{
			name: "contains-not-long", check: Contains, needle: "ok", text: long,
			wantErrs: [][]string{{`FAIL it: "ok" is not in "` + strings.Repeat("x", 600) + `"... (700 bytes)`}},
		},
		{name: "lacks", check: Lacks, needle: "secret", text: "nothing\n", wantLogs: []string{`ok   it (no "secret" in 8 bytes)`}},
		{name: "lacks-not", check: Lacks, needle: "secret", text: "a secret\n", wantErrs: [][]string{{`FAIL it: "secret" is in "a secret\n"`}}},
		{name: "lacks-nothing", check: Lacks, needle: "secret", text: "", wantErrs: [][]string{{"FAIL it: there is nothing to look through"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			tb := &recTB{t: t}
			tt.check(tb, "it", tt.needle, tt.text)
			recorded(t, tb, tt.wantLogs, tt.wantErrs...)
		})
	}
}

// TestLogContainsLacks looks for a needle in a container's log, and a
// log that cannot be read fails either, with why.
func TestLogContainsLacks(t *testing.T) {
	t.Parallel()

	logs := []string{"docker", "logs", "abc"}
	said := execx.Result{Stdout: []byte("starting\n"), Stderr: []byte("created /data/db\n")}
	unread := execx.Result{Code: 1, Stderr: []byte("Error: No such container: abc\n")}
	tests := []struct {
		name     string
		check    func(tb testing.TB, c *Container, what, needle string)
		res      execx.Result
		wantLogs []string
		wantErrs [][]string
	}{
		{name: "contains", check: LogContains, res: said, wantLogs: []string{`ok   the log (holds "created /data/db")`}},
		{name: "contains-not", check: LogContains, res: execx.Result{Stdout: []byte("starting\n")}, wantErrs: [][]string{{`FAIL the log: "created /data/db" is not in "starting\n"`}}},
		{name: "contains-unread", check: LogContains, res: unread, wantErrs: [][]string{{"FAIL the log: docker logs abc: exit status 1: Error: No such container: abc"}}},
		{name: "lacks", check: LogLacks, res: execx.Result{Stdout: []byte("starting\n")}, wantLogs: []string{`ok   the log (no "created /data/db" in 9 bytes)`}},
		{name: "lacks-not", check: LogLacks, res: said, wantErrs: [][]string{{`FAIL the log: "created /data/db" is in "starting\ncreated /data/db\n"`}}},
		{name: "lacks-unread", check: LogLacks, res: unread, wantErrs: [][]string{{"FAIL the log: docker logs abc: exit status 1"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			tb := &recTB{t: t}
			c := &Container{ID: "abc", engine: newEngine("docker", execx.NewFake(t, execx.Call{Argv: logs, Result: tt.res}))}
			tt.check(tb, c, "the log", "created /data/db")
			recorded(t, tb, tt.wantLogs, tt.wantErrs...)
		})
	}
}

// TestIsFile asks the container's PHP whether a path is there. The path
// goes to PHP as a single-quoted string, in which nothing is
// interpolated, and a want other than present or absent, which no check
// could find, fails as such.
func TestIsFile(t *testing.T) {
	t.Parallel()

	const path = `/data/it's $HOME`
	exec := []string{"docker", "exec", "abc", FrankenPHP, "php-cli", "-r", `echo file_exists('/data/it\'s $HOME') ? "present" : "absent";`}
	tests := []struct {
		name     string
		want     string
		calls    []execx.Call
		wantLogs []string
		wantErrs [][]string
	}{
		{
			name:     "present",
			want:     "present",
			calls:    []execx.Call{{Argv: exec, Result: execx.Result{Stdout: []byte("present")}}},
			wantLogs: []string{`ok   the file ("present")`},
		},
		{
			name:     "absent-not-present",
			want:     "present",
			calls:    []execx.Call{{Argv: exec, Result: execx.Result{Stdout: []byte("absent")}}},
			wantErrs: [][]string{{`FAIL the file: got "absent", want "present"`}},
		},
		{
			name:     "php-fails",
			want:     "absent",
			calls:    []execx.Call{{Argv: exec, Result: phpFatal}},
			wantErrs: [][]string{{"FAIL the file: php-cli -r in container abc: exit status 255"}},
		},
		{
			name:     "neither",
			want:     "exists",
			wantErrs: [][]string{{`FAIL the file: want is "exists", and a path is present or absent`}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			tb := &recTB{t: t}
			c := &Container{ID: "abc", engine: newEngine("docker", execx.NewFake(t, tt.calls...))}
			IsFile(tb, c, "the file", tt.want, path)
			recorded(t, tb, tt.wantLogs, tt.wantErrs...)
		})
	}
}

// TestRunRecords reports each of a probe subcommand's records as a check
// of its own. A subcommand that could not run, and a probe never
// installed, are failures that say so.
func TestRunRecords(t *testing.T) {
	t.Parallel()

	okRecord := "ok\tCapEff, every capability bit clear\t0\t0\n"
	failRecord := "FAIL\tCapBnd, every capability bit clear\t0\t2000\n"
	tests := []struct {
		name     string
		res      *execx.Result
		wantLogs []string
		wantErrs [][]string
	}{
		{
			name:     "all-ok",
			res:      &execx.Result{Stdout: []byte(okRecord)},
			wantLogs: []string{"ok   CapEff, every capability bit clear (0)"},
		},
		{
			name:     "a-fail",
			res:      &execx.Result{Code: 1, Stdout: []byte(okRecord + failRecord)},
			wantLogs: []string{"ok   CapEff, every capability bit clear (0)"},
			wantErrs: [][]string{{`FAIL CapBnd, every capability bit clear: got "2000", want "0"`}},
		},
		{
			name:     "cannot-run",
			res:      &execx.Result{Code: 2, Stderr: []byte("unknown subcommand 'assert-caps'\n")},
			wantErrs: [][]string{{"FAIL probe assert-caps in container abc: ", "unknown subcommand"}},
		},
		{name: "no-probe", wantErrs: [][]string{{"FAIL probe assert-caps: no probe is installed"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			tb := &recTB{t: t}
			var p *Probe
			if tt.res != nil {
				p = &Probe{c: &Container{ID: "abc", engine: newEngine("docker", execx.NewFake(t,
					execx.Call{Argv: probeArgv("assert-caps", "x"), Result: *tt.res},
				))}}
			}
			RunRecords(tb, p, "assert-caps", "x")
			recorded(t, tb, tt.wantLogs, tt.wantErrs...)
		})
	}
}

// TestRefusesRecords runs a container that must refuse to start: it passes only
// for one that exits non-zero within ServeWithin, with the needle in its
// log, and each half is a record of its own. One that exits 0, one still
// running at the deadline, one whose log says something else and one the
// engine never ran each fail the half they break, with why.
func TestRefusesRecords(t *testing.T) {
	t.Parallel()

	const what, needle = "TRUSTED_PROXIES=::/0", "TRUSTED_PROXIES holds"
	exits, says := what+": the container exits", what+": the log says '"+needle+"'"
	refusing := "refusing: TRUSTED_PROXIES holds '::/0'\n"
	tests := []struct {
		name     string
		run      execx.Result
		states   [][]byte
		logs     string
		wantLogs []string
		wantErrs [][]string
		wantWait time.Duration
	}{
		{
			name:     "refuses",
			states:   [][]byte{state("running", true, 0, startedAt, ""), state("exited", false, 1, startedAt, "")},
			logs:     refusing,
			wantLogs: []string{"ok   " + exits + " (exit status 1)", "ok   " + says + ` (holds "` + needle + `")`},
			wantWait: pollInterval,
		},
		{
			name:     "exits-0",
			states:   [][]byte{state("exited", false, 0, startedAt, "")},
			logs:     refusing,
			wantLogs: []string{"ok   " + says + ` (holds "` + needle + `")`},
			wantErrs: [][]string{{"FAIL " + exits + ": exit status 0"}},
		},
		{
			name:     "still-running",
			states:   [][]byte{state("running", true, 0, startedAt, "")},
			logs:     "serving\n",
			wantErrs: [][]string{{"FAIL " + exits + ": ", "still running after 1m0s"}, {"FAIL " + says + `: "` + needle + `" is not in "serving\n"`}},
			wantWait: ServeWithin,
		},
		{
			name:     "says-something-else",
			states:   [][]byte{state("exited", false, 1, startedAt, "")},
			logs:     "refusing: TELEMETRY=maybe\n",
			wantLogs: []string{"ok   " + exits + " (exit status 1)"},
			wantErrs: [][]string{{"FAIL " + says + `: "` + needle + `" is not in "refusing: TELEMETRY=maybe\n"`}},
		},
		{
			name:     "never-run",
			run:      execx.Result{Code: 125, Stderr: []byte("docker: Error response from daemon: pull access denied for img\n")},
			states:   [][]byte{[]byte("[]")},
			wantErrs: [][]string{{"FAIL " + exits + ": ", "refused by the engine", "pull access denied"}, {"FAIL " + says + ": ", "refused by the engine"}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			synctest.Test(t, func(t *testing.T) {
				states := tt.states
				e := newEngine("docker", runFunc(func(argv []string) execx.Result {
					switch {
					case argv[1] == "run" && tt.run.Code != 0:
						return tt.run
					case argv[1] == "run":
						return execx.Result{Stdout: []byte("abc\n")}
					case argv[1] == "container" && slices.Contains(argv, "{{.Id}}"):
						// whether a run that failed made the container
						return execx.Result{Code: 1, Stderr: []byte("Error: No such container: ctr\n")}
					case argv[1] == "container":
						s := states[0]
						if len(states) > 1 {
							states = states[1:]
						}
						return execx.Result{Stdout: s}
					case argv[1] == "logs":
						return execx.Result{Stderr: []byte(tt.logs)}
					default:
						return execx.Result{}
					}
				}))
				tb := &recTB{t: t}

				start := time.Now()
				Refuses(tb, e, &RunSpec{Image: "img", Name: "ctr", Network: "none", Confine: Contract("16m")}, what, needle)
				if waited := time.Since(start); waited != tt.wantWait {
					t.Errorf("Refuses() took %s, want %s", waited, tt.wantWait)
				}
				recorded(t, tb, tt.wantLogs, tt.wantErrs...)
			})
		})
	}
}

// TestAssertionsLogNames runs assertions with the check log set: each
// names its records there by the what it was given, as a suite ported
// from bash shows it still makes every check the bash made.
func TestAssertionsLogNames(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(CheckLogEnv, filepath.Join(dir, "checks.log"))
	e := newEngine("docker", runFunc(func(argv []string) execx.Result {
		switch argv[1] {
		case "run":
			return execx.Result{Stdout: []byte("abc\n")}
		case "container":
			return execx.Result{Stdout: state("exited", false, 1, startedAt, "")}
		case "logs":
			return execx.Result{Stderr: []byte("refusing: x\n")}
		default:
			return execx.Result{}
		}
	}))
	tb := &recTB{t: t}

	Answers(tb, "answers", http.StatusOK, Response{Status: http.StatusOK}, nil)
	Contains(tb, "contains", "x", "x")
	Lacks(tb, "lacks", "y", "x")
	Refuses(tb, e, &RunSpec{Image: "img", Network: "none", Confine: Contract("16m")}, "refuses", "x")

	want := "answers\ncontains\nlacks\nrefuses: the container exits\nrefuses: the log says 'x'\n"
	if got := readLog(t, dir); string(got) != want {
		t.Errorf("the check log holds %q, want %q", got, want)
	}
	recorded(t, tb, []string{
		"ok   answers (200)", `ok   contains (holds "x")`, `ok   lacks (no "y" in 1 bytes)`,
		"ok   refuses: the container exits (exit status 1)", `ok   refuses: the log says 'x' (holds "x")`,
	})
}
