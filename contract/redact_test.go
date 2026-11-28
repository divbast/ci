// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

package contract

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/divbast/ci/harness"
)

// recorder is a testing.TB that keeps what reaches its log, and stops
// nothing: what a redactor passes on, or, with none, what a test prints.
type recorder struct {
	testing.TB

	got []string
	out bytes.Buffer
}

func (*recorder) Helper() {}

func (r *recorder) keep(s string) { r.got = append(r.got, s) }

func (r *recorder) Log(args ...any) { r.keep(line(args...)) }

func (r *recorder) Logf(format string, args ...any) { r.keep(fmt.Sprintf(format, args...)) }

func (r *recorder) Error(args ...any) { r.keep(line(args...)) }

func (r *recorder) Errorf(format string, args ...any) { r.keep(fmt.Sprintf(format, args...)) }

func (r *recorder) Fatal(args ...any) { r.keep(line(args...)) }

func (r *recorder) Fatalf(format string, args ...any) { r.keep(fmt.Sprintf(format, args...)) }

func (r *recorder) Skip(args ...any) { r.keep(line(args...)) }

func (r *recorder) Skipf(format string, args ...any) { r.keep(fmt.Sprintf(format, args...)) }

func (r *recorder) Attr(key, value string) { r.got = append(r.got, key+"="+value) }

func (r *recorder) Output() io.Writer { return &r.out }

// TestRedacting passes every way a test prints through the redact it is
// given: its messages, failures, skips and attributes, and its Output.
// With no redact, it is the TB it was given, and prints as that does.
func TestRedacting(t *testing.T) {
	t.Parallel()
	const secret = "s3cret-value"
	hide := func(s string) string { return strings.ReplaceAll(s, secret, "<hidden>") }
	printAll := func(tb testing.TB) {
		tb.Helper()
		tb.Log("read", secret)
		tb.Logf("read %s", secret)
		tb.Error("found", secret)
		tb.Errorf("found %s", secret)
		tb.Fatal("gave up on", secret)
		tb.Fatalf("gave up on %s", secret)
		tb.Skip("skipped", secret)
		tb.Skipf("skipped %s", secret)
		tb.Attr("token", secret)
		if _, err := fmt.Fprintf(tb.Output(), "wrote %s\n", secret); err != nil {
			t.Fatal(err)
		}
	}

	rec := &recorder{TB: t}
	printAll(redacting(rec, hide))
	all := strings.Join(rec.got, "\n") + "\n" + rec.out.String()
	if strings.Contains(all, secret) || strings.Count(all, "<hidden>") != 10 {
		t.Errorf("a redacting TB passed on %q, want each of the 10 secrets hidden", all)
	}

	plain := &recorder{TB: t}
	if got := redacting(plain, nil); got != testing.TB(plain) {
		t.Errorf("redacting(tb, nil) = %T, want tb itself", got)
	}
	printAll(redacting(plain, nil))
	if all := strings.Join(plain.got, "\n") + "\n" + plain.out.String(); strings.Count(all, secret) != 10 {
		t.Errorf("with no redact, the TB passed on %q, want each of the 10 secrets as it was", all)
	}
}

// The variables that have TestReportAllHelper report its results, with a
// Redact or without, and the secret its results hold.
const (
	reportHelperEnv = "DIVBAST_CONTRACT_REPORT_HELPER"
	reportSecretEnv = "DIVBAST_CONTRACT_REPORT_SECRET"
)

// TestReportAllRedacts reports, as Run does, results that hold a secret:
// a failure's detail, a failing record's finding and a passing one's,
// each in a subtest of its own, in a test binary of its own, since the
// failures fail the test that reports them. With a Redact that hides the
// secret, nothing the binary printed holds it; with none, it shows. It
// needs no engine.
func TestReportAllRedacts(t *testing.T) {
	t.Parallel()

	for _, mode := range []string{"redacted", "plain"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			secret := "secret-" + rand.Text()
			cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestReportAllHelper$", "-test.count=1", "-test.v") //nolint:gosec // G204: this test binary, run again
			cmd.Env = append(os.Environ(), reportHelperEnv+"="+mode, reportSecretEnv+"="+secret)
			b, err := cmd.CombinedOutput()
			out := string(b)
			if exit := (*exec.ExitError)(nil); !errors.As(err, &exit) || !strings.Contains(out, "--- FAIL: TestReportAllHelper") {
				t.Fatalf("TestReportAllHelper, %s: %v, want its failures to fail it; it printed:\n%s", mode, err, out)
			}
			secrets, hidden := strings.Count(out, secret), strings.Count(out, "<hidden>")
			switch {
			case mode == "redacted" && (secrets != 0 || hidden != 3):
				t.Errorf("with Redact, the report printed the secret %d times and <hidden> %d times, want 0 and 3; it printed:\n%s",
					secrets, hidden, out)
			case mode == "plain" && (secrets != 3 || hidden != 0):
				t.Errorf("with no Redact, the report printed the secret %d times and <hidden> %d times, want 3 and 0; it printed:\n%s",
					secrets, hidden, out)
			}
		})
	}
}

// TestReportAllHelper is TestReportAllRedacts' report, in a test binary of
// its own. It skips unless TestReportAllRedacts runs it.
func TestReportAllHelper(t *testing.T) {
	mode := os.Getenv(reportHelperEnv)
	if mode == "" {
		t.Skip("only TestReportAllRedacts runs this, in a test binary of its own")
	}
	t.Parallel()
	secret := os.Getenv(reportSecretEnv)
	var redact func(string) string
	if mode == "redacted" {
		redact = func(s string) string { return strings.ReplaceAll(s, secret, "<hidden>") }
	}
	reportAll(t, []Result{
		resultOf(checkCaps, nil, errors.New("the probe found "+secret)),
		resultOf(checkPID1, []harness.Record{{OK: false, What: "PID 1's argv", Expected: "server", Found: secret}}, nil),
		resultOf(checkNoShell, []harness.Record{{OK: true, What: "/bin/sh is absent", Expected: "absent", Found: "absent, beside " + secret}}, nil),
	}, redact)
}

// TestWithoutLog cuts from an error's message the container's log, in
// each form harness.WithLog adds it, and leaves one without it as it is.
// What it wraps is still there for errors.Is.
func TestWithoutLog(t *testing.T) {
	t.Parallel()
	stoppedEarly := errors.New("container c stopped, exit status 3, before http://127.0.0.1:8080/ answered")
	const said = "; the harness prints its log once, when the test ends failed"

	for _, tt := range []struct {
		name string
		err  error
		want string
	}{
		{"a-log", fmt.Errorf("%w; its log:\n%s", stoppedEarly, "token=s3cret\nmarker=m"), stoppedEarly.Error() + said},
		{"an-empty-log", fmt.Errorf("%w; its log is empty", stoppedEarly), stoppedEarly.Error() + said},
		{"a-log-not-read", fmt.Errorf("%w; its log could not be read: %w", stoppedEarly, errors.New("no such container")), stoppedEarly.Error() + said},
		{"no-log", stoppedEarly, stoppedEarly.Error()},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := fmt.Errorf("did not come up: %w", withoutLog{tt.err})
			if got, want := err.Error(), "did not come up: "+tt.want; got != want {
				t.Errorf("error = %q, want %q", got, want)
			}
			if !errors.Is(err, stoppedEarly) {
				t.Errorf("errors.Is(%v, the error it wraps) = false", err)
			}
		})
	}
}

// helperEnv names the variable that has TestRunHelper run the contract,
// redacted or not, and the token and marker its container prints.
const (
	helperEnv       = "DIVBAST_CONTRACT_RUN_HELPER"
	helperTokenEnv  = "DIVBAST_CONTRACT_RUN_TOKEN"
	helperMarkerEnv = "DIVBAST_CONTRACT_RUN_MARKER"
)

// helperRun runs TestRunHelper in a test binary of its own, redacting the
// token or not, and returns all it printed with the token and the marker
// its container printed. Its contract run fails, as it must, so it fails
// the binary.
func helperRun(t *testing.T, mode string) (out, token, marker string) {
	t.Helper()
	token, marker = "token-"+rand.Text(), "marker-"+rand.Text()
	cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestRunHelper$", "-test.count=1", "-test.v") //nolint:gosec // G204: this test binary, run again
	cmd.Env = append(os.Environ(), helperEnv+"="+mode, helperTokenEnv+"="+token, helperMarkerEnv+"="+marker)
	b, err := cmd.CombinedOutput()
	out = string(b)
	if exit := (*exec.ExitError)(nil); !errors.As(err, &exit) || !strings.Contains(out, "--- FAIL: TestRunHelper") {
		t.Fatalf("TestRunHelper, %s: %v, want its contract run to fail; it printed:\n%s", mode, err, out)
	}
	return out, token, marker
}

// TestRunRedacts runs the contract through Run against an image whose
// server prints a token it was given and a marker, then exits before it
// serves, so that every check that needs its container fails and the
// harness prints its log. With a Redact that hides the token, nothing the
// run printed holds it, though the log was printed; with no Redact, the
// run prints it as before.
func TestRunRedacts(t *testing.T) {
	t.Parallel()
	integration(t)

	for _, mode := range []string{"redacted", "plain"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			out, token, marker := helperRun(t, mode)
			tokens, markers, hidden := strings.Count(out, token), strings.Count(out, marker), strings.Count(out, "<hidden>")
			switch {
			case markers == 0:
				t.Errorf("the run printed its container's marker 0 times, want its log printed; it printed:\n%s", out)
			case mode == "redacted" && (tokens != 0 || hidden == 0):
				t.Errorf("with Redact, the run printed the token %d times and <hidden> %d times, want 0 and some; it printed:\n%s",
					tokens, hidden, out)
			case mode == "plain" && (tokens == 0 || hidden != 0):
				t.Errorf("with no Redact, the run printed the token %d times and <hidden> %d times, want some and 0; it printed:\n%s",
					tokens, hidden, out)
			}
		})
	}
}

// TestRunPrintsLogOnce runs the contract as TestRunRedacts does, with no
// Redact: the container's log, its marker and its token with it, is in
// what the run printed exactly once, however many checks needed the
// container, and each of those says why it did not come up.
func TestRunPrintsLogOnce(t *testing.T) {
	t.Parallel()
	integration(t)

	out, token, marker := helperRun(t, "plain")
	if markers, tokens := strings.Count(out, marker), strings.Count(out, token); markers != 1 || tokens != 1 {
		t.Errorf("the run printed its container's marker %d times and its token %d times, want each once; it printed:\n%s",
			markers, tokens, out)
	}
	if n := strings.Count(out, "the container under the contract did not come up"); n < 2 {
		t.Errorf("the run said %d times that the container did not come up, want it for each check that needed it; it printed:\n%s",
			n, out)
	}
}

// TestRunHelper is the contract run of TestRunRedacts and
// TestRunPrintsLogOnce, in a test binary of its own, since a run whose
// checks fail fails the test that makes it. It skips unless one of them
// runs it.
func TestRunHelper(t *testing.T) {
	mode := os.Getenv(helperEnv)
	if mode == "" {
		t.Skip("only TestRunRedacts and TestRunPrintsLogOnce run this, in a test binary of its own")
	}
	t.Parallel()
	e := integration(t)
	image, err := e.Build(t.Context(), t, filepath.Join("testdata", "logs", "Containerfile"), nil)
	if err != nil {
		t.Fatal(err)
	}
	token := os.Getenv(helperTokenEnv)
	cfg := &Config{
		Image: image, AppPort: 8080, HealthPort: 8081, HealthOnly404: []string{"/"}, TmpfsSize: "8m",
		PID1: []string{"sh"}, Exec: []string{"/bin/true"}, HealthCmd: []string{"/bin/true"},
		Healthcheck: Healthcheck{Test: []string{"CMD", "/bin/true"}},
		Env:         map[string]string{"APP_TOKEN": token, "APP_MARKER": os.Getenv(helperMarkerEnv)},
	}
	if mode == "redacted" {
		cfg.Redact = func(s string) string { return strings.ReplaceAll(s, token, "<hidden>") }
	}
	Run(t, cfg)
}
