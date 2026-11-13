// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

package testcount_test

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/divbast/ci/internal/testcount"
)

// The streams in testdata are go test -json's own, from Go 1.27.4:
//
//	all-skip       LibreSpeed's acceptance suite with IMAGE unset, by
//	               go test -count=1 -json ./test/acceptance/ in its clone
//	empty          nothing at all
//	one-fail       a package that passes and one with a failed subtest
//	build-fail     a package that passes and one that does not compile
//	pass-and-skip  one package, with a test that passes and one that skips
//	all-pass       two packages, with subtests
//	panic          a package that passes and one whose TestMain panics,
//	               so that it fails with no test events at all
//	pass-without-tests
//	               a package that passes and one whose TestMain exits 0
//	               before m.Run when IMAGE is unset, so that it passes
//	               with no test events at all
//
// Every one but all-skip comes from a module made up for them, whose
// path in the panic's stack trace reads /src/fixtures.

// fixture returns the stream testdata/name holds.
func fixture(t *testing.T, name string) []byte {
	t.Helper()
	root, err := os.OpenRoot("testdata")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	data, err := root.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// outcome is what Count wrote to stdout and stderr, the error it
// returned, and the exit code its result maps to.
type outcome struct {
	stdout, stderr string
	err            error
	code           int
}

// count runs Count over stream.
func count(t *testing.T, stream []byte) outcome {
	t.Helper()
	var out, errOut bytes.Buffer
	res, err := testcount.Count(bytes.NewReader(stream), &out, &errOut)
	return outcome{stdout: out.String(), stderr: errOut.String(), err: err, code: testcount.Code(res, err)}
}

const prefix = "divbast-testcount: "

// The packages the streams name.
const (
	acceptance = "github.com/divbast/librespeed-oci-image/test/acceptance"
	alpha      = "example.com/fixtures/alpha"
	beta       = "example.com/fixtures/beta"
	flaky      = "example.com/fixtures/flaky"
	broken     = "example.com/fixtures/broken"
	partial    = "example.com/fixtures/partial"
	boom       = "example.com/fixtures/boom"
	notests    = "example.com/fixtures/notests"
	gated      = "example.com/fixtures/gated"
)

// rule is the last line stderr holds for a run that did not pass.
const rule = prefix + "a run passes only when a test passed in every package, none failed or skipped, and every package built and passed\n"

func TestCount(t *testing.T) {
	t.Parallel()
	tests := []struct {
		fixture string
		code    int
		summary string   // the summary line, empty when the stream could not be read through
		reasons []string // each a line stderr must hold, after the prefix
	}{
		{
			fixture: "all-skip.jsonl",
			code:    1,
			summary: "0 passed, 22 skipped, 0 failed in 1 package(s)",
			reasons: []string{
				"skipped: TestContract in " + acceptance,
				"skipped: TestTelemetryOff in " + acceptance,
				"package ran no tests: " + acceptance,
				"no test passed",
			},
		},
		{fixture: "empty.jsonl", code: 2},
		{
			fixture: "one-fail.jsonl",
			code:    1,
			summary: "6 passed, 0 skipped, 2 failed in 2 package(s)",
			reasons: []string{
				"failed: TestUploads/large in " + flaky,
				"failed: TestUploads in " + flaky,
				"package failed: " + flaky,
			},
		},
		{
			fixture: "build-fail.jsonl",
			code:    1,
			summary: "4 passed, 0 skipped, 0 failed in 2 package(s)",
			reasons: []string{
				"did not build: " + broken + " [" + broken + ".test]",
				"package failed: " + broken,
			},
		},
		{
			fixture: "pass-and-skip.jsonl",
			code:    1,
			summary: "1 passed, 1 skipped, 0 failed in 1 package(s)",
			reasons: []string{"skipped: TestRootless in " + partial},
		},
		{
			fixture: "all-pass.jsonl",
			code:    0,
			summary: "8 passed, 0 skipped, 0 failed in 2 package(s)",
		},
		{
			fixture: "panic.jsonl",
			code:    1,
			summary: "4 passed, 0 skipped, 0 failed in 2 package(s)",
			reasons: []string{"package failed: " + boom},
		},
		{
			fixture: "pass-without-tests.jsonl",
			code:    1,
			summary: "4 passed, 0 skipped, 0 failed in 2 package(s)",
			reasons: []string{"package ran no tests: " + gated},
		},
	}
	for _, tt := range tests {
		t.Run(tt.fixture, func(t *testing.T) {
			t.Parallel()
			got := count(t, fixture(t, tt.fixture))
			stdout, stderr, err, code := got.stdout, got.stderr, got.err, got.code
			if code != tt.code {
				t.Errorf("exit %d, want %d (err %v)\nstderr:\n%s", code, tt.code, err, stderr)
			}
			if tt.summary == "" {
				if !errors.Is(err, testcount.ErrInput) {
					t.Errorf("err = %v, want one wrapping ErrInput", err)
				}
				if strings.Contains(stdout, prefix) {
					t.Errorf("printed a summary of a stream it could not read through:\n%s", stdout)
				}
				return
			}
			if err != nil {
				t.Errorf("err = %v, want nil", err)
			}
			if want := "\n" + prefix + tt.summary + "\n"; !strings.HasSuffix(stdout, want) {
				t.Errorf("stdout ends\n%s\nwant it to end with the line %q", tail(stdout), want[1:])
			}
			if strings.Count(stdout, prefix) != 1 {
				t.Errorf("stdout holds more than the one summary line:\n%s", stdout)
			}
			if tt.code == 0 {
				if stderr != "" {
					t.Errorf("a run that passed printed on stderr:\n%s", stderr)
				}
				return
			}
			for _, reason := range tt.reasons {
				if !strings.Contains(stderr, prefix+reason+"\n") {
					t.Errorf("stderr\n%s\nwant the line %q", stderr, prefix+reason)
				}
			}
			if !strings.HasSuffix(stderr, rule) {
				t.Errorf("stderr\n%s\nwant it to end with %q", stderr, rule)
			}
		})
	}
}

// TestRefusals runs streams that each break one rule and no other, so
// that each check is seen to fail a run on its own. They are go test
// -json's events, from Go 1.27.4, cut down or put together by hand.
func TestRefusals(t *testing.T) {
	t.Parallel()
	pass := event("start", alpha, "") + event("run", alpha, "TestA") + event("pass", alpha, "TestA") + event("pass", alpha, "")
	tests := []struct {
		name    string
		stream  string
		summary string
		reason  string
	}{
		{
			name:    "a test failed in a package that passed",
			stream:  pass + event("start", beta, "") + event("pass", beta, "TestC") + event("fail", beta, "TestB") + event("pass", beta, ""),
			summary: "2 passed, 0 skipped, 1 failed in 2 package(s)",
			reason:  "failed: TestB in " + beta,
		},
		{
			name:    "a subtest skipped",
			stream:  pass + event("start", beta, "") + event("skip", beta, "TestB/rootless") + event("pass", beta, "TestB") + event("pass", beta, ""),
			summary: "2 passed, 1 skipped, 0 failed in 2 package(s)",
			reason:  "skipped: TestB/rootless in " + beta,
		},
		{
			name:    "a build failed and nothing else said so",
			stream:  `{"ImportPath":"` + broken + ` [` + broken + `.test]","Action":"build-fail"}` + "\n" + pass,
			summary: "1 passed, 0 skipped, 0 failed in 1 package(s)",
			reason:  "did not build: " + broken + " [" + broken + ".test]",
		},
		{
			name: "a package had no test files",
			stream: pass + event("start", notests, "") +
				`{"Action":"output","Package":"` + notests + `","Output":"?   \t` + notests + `\t[no test files]\n"}` + "\n" +
				event("skip", notests, ""),
			summary: "1 passed, 0 skipped, 0 failed in 2 package(s)",
			reason:  "package ran no tests: " + notests,
		},
		{
			name:    "a package never finished",
			stream:  pass + event("start", beta, "") + event("run", beta, "TestB") + event("pass", beta, "TestB"),
			summary: "2 passed, 0 skipped, 0 failed in 2 package(s)",
			reason:  "package never finished: " + beta,
		},
		{
			// go test -json -run NoSuchTest: the package passes, and no test ran
			name: "a package passed and ran no tests",
			stream: pass + event("start", beta, "") +
				`{"Action":"output","Package":"` + beta + `","Output":"testing: warning: no tests to run\n"}` + "\n" +
				`{"Action":"output","Package":"` + beta + `","Output":"ok  \t` + beta + `\t0.004s [no tests to run]\n"}` + "\n" +
				event("pass", beta, ""),
			summary: "1 passed, 0 skipped, 0 failed in 2 package(s)",
			reason:  "package ran no tests: " + beta,
		},
		{
			// Made up: every stream go test writes names a package. This
			// is the backstop for one that names none.
			name:    "no test passed",
			stream:  `{"Action":"output","Output":"PASS\n"}` + "\n",
			summary: "0 passed, 0 skipped, 0 failed in 0 package(s)",
			reason:  "no test passed",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := count(t, []byte(tt.stream))
			stdout, stderr, err, code := got.stdout, got.stderr, got.err, got.code
			if err != nil || code != 1 {
				t.Errorf("exit %d, err %v; want 1 and nil\nstderr:\n%s", code, err, stderr)
			}
			if want := prefix + tt.summary + "\n"; !strings.HasSuffix(stdout, want) {
				t.Errorf("stdout ends\n%s\nwant it to end with the line %q", tail(stdout), want)
			}
			if got, want := stderr, prefix+tt.reason+"\n"+rule; got != want {
				t.Errorf("stderr\n%s\nwant\n%s", got, want)
			}
		})
	}
}

// TestPasses runs streams that pass, so that no check refuses more than it
// should.
func TestPasses(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		stream  string
		summary string
	}{
		{
			name:    "one test in one package",
			stream:  event("start", alpha, "") + event("run", alpha, "TestA") + event("pass", alpha, "TestA") + event("pass", alpha, ""),
			summary: "1 passed, 0 skipped, 0 failed in 1 package(s)",
		},
		{
			name:    "the last line has no newline",
			stream:  strings.TrimSuffix(event("start", alpha, "")+event("pass", alpha, "TestA")+event("pass", alpha, ""), "\n"),
			summary: "1 passed, 0 skipped, 0 failed in 1 package(s)",
		},
		{
			// t.Attr's events, new in Go 1.25, and any action a later Go adds
			name: "an action this does not know",
			stream: event("start", alpha, "") + `{"Action":"attr","Package":"` + alpha + `","Test":"TestA","Key":"k","Value":"v"}` + "\n" +
				event("pass", alpha, "TestA") + event("pass", alpha, ""),
			summary: "1 passed, 0 skipped, 0 failed in 1 package(s)",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := count(t, []byte(tt.stream))
			stdout, stderr, err, code := got.stdout, got.stderr, got.err, got.code
			if err != nil || code != 0 {
				t.Errorf("exit %d, err %v; want 0 and nil\nstderr:\n%s", code, err, stderr)
			}
			if want := prefix + tt.summary + "\n"; stdout != want {
				t.Errorf("stdout\n%s\nwant\n%s", stdout, want)
			}
			if stderr != "" {
				t.Errorf("stderr\n%s\nwant nothing", stderr)
			}
		})
	}
}

// TestInputErrors runs streams that are not go test -json's, and a reader
// that fails. Each must be an ErrInput, which exits 2, with no summary:
// what could not be read is not a run that passed, nor one that failed.
func TestInputErrors(t *testing.T) {
	t.Parallel()
	good := event("start", alpha, "") + event("pass", alpha, "TestA")
	tests := []struct {
		name   string
		stream string
		want   string // in the error
	}{
		{name: "not JSON", stream: good + "ok  \texample.com/fixtures/alpha\t0.004s\n" + event("pass", alpha, ""), want: "line 3"},
		{name: "no action", stream: good + "{}\n", want: "line 3"},
		{name: "null", stream: "null\n", want: "line 1"},
		{name: "an array", stream: "[]\n", want: "line 1"},
		{name: "a blank line", stream: good + "\n" + event("pass", alpha, ""), want: "line 3"},
		{name: "two events on one line", stream: strings.TrimSuffix(good, "\n") + event("pass", alpha, ""), want: "line 2"},
		{name: "test without package", stream: good + `{"Action":"pass","Test":"TestA"}` + "\n", want: "line 3"},
		{name: "build-fail without import path", stream: `{"Action":"build-fail"}` + "\n", want: "line 1"},
		{name: "no events", stream: "", want: "no events"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := count(t, []byte(tt.stream))
			stdout, err, code := got.stdout, got.err, got.code
			if code != 2 || !errors.Is(err, testcount.ErrInput) {
				t.Errorf("exit %d, err %v; want 2 and an ErrInput", code, err)
			}
			if err != nil && !strings.Contains(err.Error(), tt.want) {
				t.Errorf("err %q does not say %q", err, tt.want)
			}
			if strings.Contains(stdout, prefix) {
				t.Errorf("printed a summary:\n%s", stdout)
			}
		})
	}

	t.Run("unreadable", func(t *testing.T) {
		t.Parallel()
		read := errors.New("read went wrong")
		res, err := testcount.Count(iotest.ErrReader(read), &bytes.Buffer{}, &bytes.Buffer{})
		if !errors.Is(err, testcount.ErrInput) || !errors.Is(err, read) {
			t.Errorf("err = %v, want an ErrInput wrapping the read's", err)
		}
		if code := testcount.Code(res, err); code != 2 {
			t.Errorf("exit %d, want 2", code)
		}
	})
}

// TestWriteFailure has Count write to a stdout or stderr that fails one
// write, the one holding the text named, and takes every other. A write
// that fails is a failure, exit 1, and not bad input.
func TestWriteFailure(t *testing.T) {
	t.Parallel()
	noOutput := event("start", alpha, "") + event("pass", alpha, "TestA") + event("pass", alpha, "")
	tests := []struct {
		name      string
		stream    []byte
		out, errs failingWriter
	}{
		{name: "the output", stream: fixture(t, "all-pass.jsonl"), out: failingWriter{on: "=== RUN   TestContract\n"}},
		{name: "the summary", stream: []byte(noOutput), out: failingWriter{on: prefix}},
		{name: "a reason", stream: fixture(t, "all-skip.jsonl"), errs: failingWriter{on: "skipped: TestTelemetryOff"}},
		{name: "the rule", stream: fixture(t, "all-skip.jsonl"), errs: failingWriter{on: rule}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			res, err := testcount.Count(bytes.NewReader(tt.stream), tt.out, tt.errs)
			if err == nil || errors.Is(err, testcount.ErrInput) {
				t.Errorf("err = %v, want a write error that is no ErrInput", err)
			}
			if code := testcount.Code(res, err); code != 1 {
				t.Errorf("exit %d, want 1", code)
			}
		})
	}
}

// TestOutputPassesThrough checks that stdout is every event's Output, in
// the stream's order and unchanged, then the summary line, so the log
// reads as go test -v's would.
func TestOutputPassesThrough(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"all-skip.jsonl", "one-fail.jsonl", "build-fail.jsonl", "pass-and-skip.jsonl", "all-pass.jsonl", "panic.jsonl", "pass-without-tests.jsonl"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			stream := fixture(t, name)
			var want strings.Builder
			lines := bufio.NewScanner(bytes.NewReader(stream))
			for lines.Scan() {
				var e struct{ Output string }
				if err := json.Unmarshal(lines.Bytes(), &e); err != nil {
					t.Fatal(err)
				}
				want.WriteString(e.Output)
			}
			if err := lines.Err(); err != nil {
				t.Fatal(err)
			}
			if want.Len() == 0 {
				t.Fatal("the fixture has no output to pass through")
			}

			stdout := count(t, stream).stdout
			body, summary, ok := cutLastLine(stdout)
			if !ok || !strings.HasPrefix(summary, prefix) {
				t.Fatalf("stdout does not end with a summary line:\n%s", tail(stdout))
			}
			if body != want.String() {
				t.Errorf("stdout before the summary\n%s\nwant\n%s", body, want.String())
			}
		})
	}
}

// event is one go test -json event, with its newline. An empty test is
// the package's own.
func event(action, pkg, test string) string {
	e := map[string]string{"Action": action, "Package": pkg}
	if test != "" {
		e["Test"] = test
	}
	b, err := json.Marshal(e)
	if err != nil {
		panic(err)
	}
	return string(b) + "\n"
}

// cutLastLine splits s, which ends with a newline, before its last line,
// and returns that line without the newline.
func cutLastLine(s string) (before, last string, ok bool) {
	s, ok = strings.CutSuffix(s, "\n")
	if !ok {
		return "", "", false
	}
	i := strings.LastIndexByte(s, '\n')
	return s[:i+1], s[i+1:], true
}

// tail is the last few lines of s, for a message.
func tail(s string) string {
	lines := strings.SplitAfter(s, "\n")
	return strings.Join(lines[max(0, len(lines)-4):], "")
}

// failingWriter fails a write that holds on, and takes every other. With
// on empty it takes every write.
type failingWriter struct{ on string }

func (w failingWriter) Write(p []byte) (int, error) {
	if w.on != "" && strings.Contains(string(p), w.on) {
		return 0, errors.New("the pipe is gone")
	}
	return len(p), nil
}
