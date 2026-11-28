// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

package harness

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"testing/synctest"

	"github.com/divbast/ci/internal/execx"
)

// frankenphp is the PHP divbast's PHP images run, which the tests here
// use as an app's binary.
const frankenphp = "/usr/local/bin/frankenphp"

// probeArgv is how the harness runs one core probe subcommand in
// container abc.
func probeArgv(args ...string) []string {
	return slices.Concat([]string{"docker", "exec", "abc", "/divbast/probe/core"}, args)
}

// probedContainer is container abc on a docker engine running calls,
// started with spec's probe.
func probedContainer(t *testing.T, spec ProbeSpec, calls ...execx.Call) *Container {
	t.Helper()
	return &Container{ID: "abc", engine: newEngine("docker", execx.NewFake(t, calls...)), probe: &spec}
}

func TestProbeRun(t *testing.T) {
	t.Parallel()

	okRecord := "ok\tCapEff, every capability bit clear\t0\t0\n"
	failRecord := "FAIL\tCapBnd, every capability bit clear\t0\t2000\n"
	tests := []struct {
		name     string
		res      execx.Result
		want     int
		wantText string
	}{
		{name: "all-ok", res: execx.Result{Stdout: []byte(okRecord + okRecord)}, want: 2},
		// A FAIL is the caller's to report, not an error.
		{name: "a-fail", res: execx.Result{Code: 1, Stdout: []byte(okRecord + failRecord)}, want: 2},
		{name: "fail-but-exit-0", res: execx.Result{Stdout: []byte(failRecord)}, wantText: "disagrees"},
		{name: "exit-1-but-all-ok", res: execx.Result{Code: 1, Stdout: []byte(okRecord)}, wantText: "disagrees"},
		{name: "usage", res: execx.Result{Code: 2, Stderr: []byte("unknown subcommand 'assert-caps'\n")}, wantText: "unknown subcommand"},
		{name: "no-records", res: execx.Result{Code: 1, Stderr: []byte("Error response from daemon: container abc is not running\n")}, wantText: "not running"},
		{name: "not-records", res: execx.Result{Stdout: []byte(okRecord + "Warning: something\n")}, wantText: "not a record"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			p := &Probe{c: probedContainer(t, ProbeSpec{}, execx.Call{Argv: probeArgv("assert-caps"), Result: tt.res})}
			got, err := p.Run(t.Context(), "assert-caps")
			if tt.wantText != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantText) {
					t.Errorf("Run() = %+v, %v; want an error containing %q", got, err, tt.wantText)
				}
				return
			}
			if err != nil || len(got) != tt.want {
				t.Errorf("Run() = %+v, %v; want %d records", got, err, tt.want)
			}
		})
	}
}

func TestRunAppArgv(t *testing.T) {
	t.Parallel()

	ok := execx.Result{Stdout: []byte("ok\tthe page\ta\ta\n")}
	c := probedContainer(t, ProbeSpec{AppPackage: "./test/probe"},
		execx.Call{Argv: []string{"docker", "exec", "abc", "/divbast/probe/app", "assert-page", "x"}, Result: ok})
	p := &Probe{c: c, spec: *c.probe}
	if got, err := p.RunApp(t.Context(), "assert-page", "x"); err != nil || len(got) != 1 || !got[0].OK {
		t.Errorf("RunApp() = %+v, %v; want one ok record", got, err)
	}
}

func TestRunPHPArgv(t *testing.T) {
	t.Parallel()

	ok := execx.Result{Stdout: []byte("ok\tseeded\ta\ta\n")}
	c := probedContainer(t, ProbeSpec{PHP: &PHPProbe{Binary: frankenphp, Probe: []byte("<?php return [];")}},
		execx.Call{Argv: []string{"docker", "exec", "abc", frankenphp, "php-cli", "/tmp/divbast-probe/probe.php", "seed-user", "a", "b"}, Result: ok})
	p := &Probe{c: c, spec: *c.probe}
	if got, err := p.RunPHP(t.Context(), "seed-user", "a", "b"); err != nil || len(got) != 1 {
		t.Errorf("RunPHP() = %+v, %v; want one record", got, err)
	}
}

// TestProbeWithoutTheAppKind asks a probe for the kind of app subcommand
// its container was not started with: an error that says what to set,
// and nothing run.
func TestProbeWithoutTheAppKind(t *testing.T) {
	t.Parallel()

	p := &Probe{c: probedContainer(t, ProbeSpec{})}
	if _, err := p.RunApp(t.Context(), "assert-page"); err == nil || !strings.Contains(err.Error(), "AppPackage") {
		t.Errorf("RunApp() with no app probe = %v; want an error naming AppPackage", err)
	}
	if _, err := p.RunPHP(t.Context(), "seed-user"); err == nil || !strings.Contains(err.Error(), "PHP") {
		t.Errorf("RunPHP() with no PHP probe = %v; want an error naming PHP", err)
	}
}

func TestAttachProbeRefusesUnmounted(t *testing.T) {
	t.Parallel()

	c := &Container{ID: "abc", engine: newEngine("docker", execx.NewFake(t))}
	if p, err := AttachProbe(t.Context(), c); err == nil || !strings.Contains(err.Error(), "RunSpec.Probe") {
		t.Errorf("AttachProbe() = %v, %v; want an error saying to set RunSpec.Probe", p, err)
	}
}

// installArgv is how AttachProbe writes file into container abc through
// binary's PHP.
func installArgv(binary, file string) []string {
	return []string{"docker", "exec", "-i", "abc", binary, "php-cli", "-r", installCode(file)}
}

func TestAttachProbe(t *testing.T) {
	t.Parallel()

	app := []byte("<?php return [];\n")
	php := &PHPProbe{Binary: "/opt/php", Probe: app}
	tests := []struct {
		name    string
		spec    ProbeSpec
		calls   []execx.Call
		wantErr string
	}{
		// The core probe and a Go app probe are on the volume already
		{name: "core-only"},
		{name: "go-app", spec: ProbeSpec{AppPackage: "./test/probe"}},
		{
			name: "php",
			spec: ProbeSpec{PHP: php},
			calls: []execx.Call{
				{Argv: installArgv("/opt/php", "/tmp/divbast-probe/probe.php"), Stdin: phpProbe},
				{Argv: installArgv("/opt/php", "/tmp/divbast-probe/app.php"), Stdin: app},
			},
		},
		{
			name: "write-fails",
			spec: ProbeSpec{PHP: php},
			calls: []execx.Call{{Argv: installArgv("/opt/php", "/tmp/divbast-probe/probe.php"), Stdin: phpProbe, Result: execx.Result{
				Code: 1, Stderr: []byte("cannot write /tmp/divbast-probe/probe.php: No space left on device\n"),
			}}},
			wantErr: "No space left on device",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			p, err := AttachProbe(t.Context(), probedContainer(t, tt.spec, tt.calls...))
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("AttachProbe() = %v, %v; want an error containing %q", p, err, tt.wantErr)
				}
				return
			}
			if err != nil || p == nil {
				t.Errorf("AttachProbe() = %v, %v; want a probe", p, err)
			}
		})
	}
}

// TestAttachProbeRetries writes the PHP probe through an engine that
// refuses the exec, as Docker once did to a container still starting: the
// write rides on Exec's retry, which feeds the file again, and once the
// third attempt is refused too, the error says what was being written.
func TestAttachProbeRetries(t *testing.T) {
	t.Parallel()

	install := execx.Call{Argv: installArgv(frankenphp, "/tmp/divbast-probe/probe.php"), Stdin: phpProbe}
	app := execx.Call{Argv: installArgv(frankenphp, "/tmp/divbast-probe/app.php"), Stdin: []byte("<?php return [];")}
	refused := install
	refused.Result = stoppedRefusal
	tests := []struct {
		name     string
		calls    []execx.Call
		wantText []string
	}{
		{
			name:  "engine-refused-then-written",
			calls: []execx.Call{refused, install, app},
		},
		{
			name:     "engine-refuses-every-time",
			calls:    []execx.Call{refused, refused, refused},
			wantText: []string{"installing /tmp/divbast-probe/probe.php", "attempt 3 of 3", "cannot exec in a stopped container"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			synctest.Test(t, func(t *testing.T) {
				c := probedContainer(t, ProbeSpec{PHP: &PHPProbe{Binary: frankenphp, Probe: []byte("<?php return [];")}}, tt.calls...)
				p, err := AttachProbe(t.Context(), c)
				if len(tt.wantText) == 0 {
					if err != nil || p == nil {
						t.Errorf("AttachProbe() = %v, %v; want a probe", p, err)
					}
					return
				}
				for _, want := range tt.wantText {
					if err == nil || !strings.Contains(err.Error(), want) {
						t.Errorf("AttachProbe() = %v, %v; want an error containing %q", p, err, want)
					}
				}
			})
		})
	}
}

// TestStartMountsTheProbe starts a container that asks for the probe:
// the probe volume for its image's architecture goes on read-only at
// /divbast/probe, after the spec's own mounts, and the container keeps
// the probe it asked for, for AttachProbe.
func TestStartMountsTheProbe(t *testing.T) {
	t.Parallel()

	run := []string{
		"docker", "run", "-d", "--label", ownLabel, "--label", ownRun, "--name", "ctr", "--cap-drop", "ALL",
		"-v", "data:/data", "-v", "probe-vol:/divbast/probe:ro", "img",
	}
	e := newEngine("docker", execx.NewFake(t,
		execx.Call{Argv: run, Result: execx.Result{Stdout: []byte("abc\n")}},
		execx.Call{Argv: []string{"docker", "rm", "-f", "-v", "ctr"}},
	))
	probed(e, "", "probe-vol")
	spec := &RunSpec{
		Image: "img", Name: "ctr", Confine: Confinement{CapDropAll: true},
		Mounts: []Mount{{Source: "data", Target: "/data", Volume: true}},
		Probe:  &ProbeSpec{},
	}
	c, err := e.Start(t.Context(), t, spec)
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if c.probe == nil {
		t.Error("Start() kept no probe on the container")
	}
	if len(spec.Mounts) != 1 {
		t.Errorf("Start() changed the caller's spec: Mounts = %+v", spec.Mounts)
	}
}

// php returns the host's php, skipping t without one: the PHP probe runs
// as the container's PHP in the integration tests, and here as the
// host's.
func php(t *testing.T) string {
	t.Helper()
	bin, err := exec.LookPath("php")
	switch {
	case err == nil:
	case os.Getenv("GITHUB_ACTIONS") == "true":
		// CI sets PHP up, and a skip there would leave the probe untested.
		t.Fatalf("no php on PATH, which CI provides: %v", err)
	default:
		t.Skip("no php on PATH to run the probe with")
	}
	return bin
}

// runPHP runs the probe script with php and arguments.
func runPHP(t *testing.T, script string, args ...string) execx.Result {
	t.Helper()
	res, err := execx.OS{}.Run(t.Context(), php(t), append([]string{script}, args...)...)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func TestPHPProbeDispatch(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		app      string // app.php beside probe.php; none when empty
		args     []string
		wantCode int
		want     string // the start of stdout, or of stderr when wantCode is 2
	}{
		{name: "no-subcommand", wantCode: 2, want: "no subcommand given"},
		{name: "unknown", args: []string{"assert-caps"}, wantCode: 2, want: "unknown subcommand 'assert-caps'"},
		{
			name: "app-subcommand",
			app:  `<?php return ['app-echo' => static function (array $operands): void { Assertions::equals('app operands', 'a b', implode(' ', $operands)); }];`,
			args: []string{"app-echo", "a", "b"},
			want: "ok\tapp operands\ta b\ta b\n",
		},
		{
			name:     "app-subcommand-throws",
			app:      `<?php return ['boom' => static function (array $operands): void { readOrThrow('/nonexistent'); }];`,
			args:     []string{"boom"},
			wantCode: 1,
			want:     "FAIL\tboom completed\tno exception\tRuntimeException: cannot read /nonexistent\n",
		},
		{
			name:     "app-returns-no-commands",
			app:      `<?php return 'nothing';`,
			args:     []string{"anything"},
			wantCode: 2,
			want:     "cannot load the subcommands",
		},
		{
			name:     "app-does-not-parse",
			app:      `<?php return [`,
			args:     []string{"anything"},
			wantCode: 2,
			want:     "cannot load the subcommands",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "probe.php"), phpProbe, 0o600); err != nil {
				t.Fatal(err)
			}
			if tt.app != "" {
				if err := os.WriteFile(filepath.Join(dir, "app.php"), []byte(tt.app), 0o600); err != nil {
					t.Fatal(err)
				}
			}

			res := runPHP(t, filepath.Join(dir, "probe.php"), tt.args...)
			got := res.Stdout
			if tt.wantCode == 2 {
				got = res.Stderr
			}
			if res.Code != tt.wantCode || !strings.HasPrefix(string(got), tt.want) {
				t.Errorf("probe.php %q = exit %d, stdout %q, stderr %q; want exit %d, starting %q",
					tt.args, res.Code, res.Stdout, res.Stderr, tt.wantCode, tt.want)
			}
		})
	}
}
