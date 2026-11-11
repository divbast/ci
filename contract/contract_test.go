// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

package contract

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/divbast/ci/harness"
	"github.com/divbast/ci/internal/testfixture"
)

// healthCmd is LibreSpeed's health probe, as its HEALTHCHECK runs it and
// as a Podman user passes it.
var healthCmd = []string{"/usr/local/bin/frankenphp", "php-cli", "/usr/local/bin/librespeed-health"}

// libreSpeed is LibreSpeed's contract, as its Containerfile and README
// state it, for image.
func libreSpeed(image string) Config {
	return Config{
		Image:      image,
		AppPort:    8080,
		HealthPort: 8081,
		TmpfsSize:  "16m",
		// What its bootstrap hands over to: pcntl_exec(SERVER_BIN, ['run',
		// '--config', CADDYFILE])
		PID1:      []string{"/usr/local/bin/frankenphp", "run", "--config", "/etc/frankenphp/Caddyfile"},
		HealthCmd: healthCmd,
		Healthcheck: Healthcheck{
			Test:        slices.Concat([]string{"CMD"}, healthCmd),
			Interval:    30 * time.Second,
			Timeout:     10 * time.Second,
			StartPeriod: 60 * time.Second,
			Retries:     3,
		},
		HealthOnly404: []string{"/", "/backend/getIP.php", "/index.php"},
	}
}

// integration returns the engine $ENGINE names, and skips t when it is
// unset.
func integration(t *testing.T) harness.Engine {
	t.Helper()
	if os.Getenv("ENGINE") == "" {
		t.Skip("ENGINE is unset: set it to docker or podman to run containers")
	}
	e, err := harness.EngineFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// crashed returns the records a probe subcommand made by throwing rather
// than checking.
func crashed(records []harness.Record) []harness.Record {
	var out []harness.Record
	for _, r := range records {
		if strings.HasSuffix(r.What, " completed") {
			out = append(out, r)
		}
	}
	return out
}

// checkNames returns the names of results, in order.
func checkNames(results []Result) []string {
	names := make([]string, len(results))
	for i, r := range results {
		names[i] = r.Check
	}
	return names
}

// TestContractOnFixture runs the whole contract against the published
// LibreSpeed image, which keeps it, as LibreSpeed's suite will: in the
// scenario its bash suite named "telemetry off".
func TestContractOnFixture(t *testing.T) {
	t.Parallel()
	e := integration(t)

	cfg := libreSpeed(testfixture.LibreSpeed)
	cfg.Scenario = "telemetry off"
	results := Check(t.Context(), t, &cfg)
	want := make([]string, len(allChecks))
	for i, name := range allChecks {
		want[i] = "telemetry off: " + name
	}
	if got := checkNames(results); !slices.Equal(got, want) {
		t.Fatalf("Check() ran %q, want %q", got, want)
	}

	made := make(map[string]bool)
	for _, r := range results {
		for _, rec := range r.Records {
			made[rec.What] = true
			t.Logf("%s: ok=%t %s (expected %q, found %q)", r.Check, rec.OK, rec.What, rec.Expected, rec.Found)
		}
		if !r.OK || len(r.Records) == 0 {
			t.Errorf("%s: OK = %t with %d records, want OK: %s", r.Check, r.OK, len(r.Records), r.Detail)
		}
		if c := crashed(r.Records); len(c) > 0 {
			t.Errorf("%s: a probe crashed: %+v", r.Check, c)
		}
	}

	// The names LibreSpeed's bash suite gave these checks in its sections
	// 2, 3, 17 and 19, which its Go suite must keep making: section 17
	// named its health checks for the scenario, and nothing else.
	engineHealthy := "telemetry off: docker reports it healthy within the 60 s start period"
	if e.Name() == "podman" {
		engineHealthy = "telemetry off: podman healthcheck run"
	}
	for _, what := range []string{
		"the image runs as uid/gid 65532 by default",
		"/usr/local/bin/frankenphp runs under --cap-drop ALL, so it carries no file capability",
		"CapEff, every capability bit clear",
		"CapPrm, every capability bit clear",
		"PID 1 comm",
		"/bin/sh is absent from the image",
		"/bin/bash is absent from the image",
		"/bin/dash is absent from the image",
		"TCP ports a process in the container listens on",
		"test network really is internal",
		"outbound TCP to 9.9.9.9:443 is refused",
		"the image's HEALTHCHECK: the probe in exec form, with no shell, at Baikal's timings",
		"telemetry off: /usr/local/bin/librespeed-health exits 0",
		"telemetry off: /usr/local/bin/librespeed-health prints nothing",
		engineHealthy,
		"GET :8081/",
		"GET :8081/backend/getIP.php",
		"GET :8081/index.php",
		"GET :8080/healthz",
	} {
		if !made[what] {
			t.Errorf("no record named %q", what)
		}
	}
}

func TestValidate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		change func(*Config)
		want   string // in the error; empty for none
	}{
		{name: "libreSpeed", change: func(*Config) {}},
		{name: "no-image", change: func(c *Config) { c.Image = "" }, want: "image"},
		{name: "no-app-port", change: func(c *Config) { c.AppPort = 0 }, want: "AppPort"},
		{name: "port-too-high", change: func(c *Config) { c.HealthPort = 65536 }, want: "HealthPort"},
		{name: "one-port-for-both", change: func(c *Config) { c.HealthPort = c.AppPort }, want: "same port"},
		{name: "no-tmpfs-size", change: func(c *Config) { c.TmpfsSize = "" }, want: "TmpfsSize"},
		{name: "no-pid1", change: func(c *Config) { c.PID1 = nil }, want: "PID1"},
		{name: "no-health-cmd", change: func(c *Config) { c.HealthCmd = nil }, want: "HealthCmd"},
		{name: "scenario", change: func(c *Config) { c.Scenario = "telemetry off" }},
		{
			// A record is one line; a scenario that broke one would split it.
			name:   "scenario-on-two-lines",
			change: func(c *Config) { c.Scenario = "telemetry\noff" },
			want:   "Scenario",
		},
		{
			// The shell form needs /bin/sh, which no divbast image has.
			name:   "shell-form",
			change: func(c *Config) { c.Healthcheck.Test = []string{"CMD-SHELL", strings.Join(healthCmd, " ")} },
			want:   "exec form",
		},
		{
			// Docker would run one command and a Podman user another.
			name:   "another-command",
			change: func(c *Config) { c.Healthcheck.Test = []string{"CMD", "/usr/local/bin/frankenphp", "version"} },
			want:   "exec form",
		},
		{
			// An empty HEALTHCHECK would match an image that has none.
			name:   "no-healthcheck",
			change: func(c *Config) { c.Healthcheck = Healthcheck{} },
			want:   "exec form",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cfg := libreSpeed("img")
			tt.change(&cfg)
			err := cfg.validate()
			switch {
			case tt.want == "" && err != nil:
				t.Errorf("validate() error = %v, want nil", err)
			case tt.want != "" && (err == nil || !strings.Contains(err.Error(), tt.want)):
				t.Errorf("validate() error = %v, want one naming %q", err, tt.want)
			}
		})
	}
}

// TestCheckRefusesConfig shows a Config that cannot be checked fails
// every check, and runs nothing: there is no engine call to make.
func TestCheckRefusesConfig(t *testing.T) {
	t.Setenv("IMAGE", "")

	cfg := libreSpeed("")
	results := Check(t.Context(), t, &cfg)
	if got := checkNames(results); !slices.Equal(got, allChecks) {
		t.Fatalf("Check() reported %q, want every check: %q", got, allChecks)
	}
	for _, r := range results {
		if r.OK || !strings.Contains(r.Detail, "image") {
			t.Errorf("%s: OK = %t, Detail %q; want a failure naming the missing image", r.Check, r.OK, r.Detail)
		}
	}
}

func TestHostConfigRecords(t *testing.T) {
	t.Parallel()

	no, yes := false, true
	// What each engine reported for a container run under the contract on
	// a named internal network: Docker leaves what was not asked for null
	// and names the network; Podman prints empty lists, a false Init and
	// bridge for any named network.
	docker := harness.HostConfig{ReadonlyRootfs: true, NetworkMode: "divbast-net"}
	podman := harness.HostConfig{CapAdd: []string{}, ReadonlyRootfs: true, SecurityOpt: []string{}, Init: &no, NetworkMode: "bridge"}

	const (
		capAdd     = "the engine adds no capability (HostConfig.CapAdd)"
		privileged = "the container is not privileged (HostConfig.Privileged)"
		readOnly   = "the engine mounts the root filesystem read-only (HostConfig.ReadonlyRootfs)"
		security   = "no security option turns off seccomp, AppArmor or SELinux confinement (HostConfig.SecurityOpt)"
		withInit   = "the engine puts no init before the entrypoint (HostConfig.Init)"
		network    = "the container shares no other network namespace (HostConfig.NetworkMode)"
	)
	with := func(h harness.HostConfig, change func(*harness.HostConfig)) harness.HostConfig {
		change(&h)
		return h
	}

	tests := []struct {
		name string
		h    harness.HostConfig
		fail string // the one record that must FAIL; empty for none
	}{
		{name: "docker", h: docker},
		{name: "podman", h: podman},
		{
			// Docker and Podman print the same for this, and Docker keeps a
			// capability's name as CAP_<NAME> since 29.
			name: "cap-add", h: with(docker, func(h *harness.HostConfig) { h.CapAdd = []string{"CAP_NET_RAW"} }),
			fail: capAdd,
		},
		{name: "privileged", h: with(podman, func(h *harness.HostConfig) { h.Privileged = true }), fail: privileged},
		{name: "writable-root", h: with(docker, func(h *harness.HostConfig) { h.ReadonlyRootfs = false }), fail: readOnly},
		{
			name: "docker-seccomp-unconfined",
			h:    with(docker, func(h *harness.HostConfig) { h.SecurityOpt = []string{"seccomp=unconfined"} }), fail: security,
		},
		{
			// Docker keeps the option as it was typed, and takes a colon too.
			name: "docker-seccomp-colon",
			h:    with(docker, func(h *harness.HostConfig) { h.SecurityOpt = []string{"seccomp:unconfined"} }), fail: security,
		},
		{
			// A profile of one's own replaces the engine's, and nothing here
			// can tell whether it is any tighter.
			name: "docker-seccomp-profile",
			h:    with(docker, func(h *harness.HostConfig) { h.SecurityOpt = []string{`seccomp={"defaultAction":"SCMP_ACT_ALLOW"}`} }),
			fail: security,
		},
		{
			name: "podman-apparmor-unconfined",
			h: with(podman, func(h *harness.HostConfig) {
				h.SecurityOpt = []string{"no-new-privileges", "apparmor=unconfined"}
			}),
			fail: security,
		},
		{
			name: "podman-label-disable",
			h:    with(podman, func(h *harness.HostConfig) { h.SecurityOpt = []string{"label=disable"} }), fail: security,
		},
		{
			// no-new-privileges tightens; it is no loosening.
			name: "no-new-privileges",
			h:    with(podman, func(h *harness.HostConfig) { h.SecurityOpt = []string{"no-new-privileges"} }),
		},
		{
			// Docker's Init is null unless --init was given.
			name: "docker-init", h: with(docker, func(h *harness.HostConfig) { h.Init = &yes }), fail: withInit,
		},
		{name: "podman-init", h: with(podman, func(h *harness.HostConfig) { h.Init = &yes }), fail: withInit},
		{name: "host-network", h: with(docker, func(h *harness.HostConfig) { h.NetworkMode = "host" }), fail: network},
		{
			name: "another-containers-network",
			h:    with(podman, func(h *harness.HostConfig) { h.NetworkMode = "container:0123abcd" }), fail: network,
		},
		{
			// Podman alone joins a namespace by its path, the host's
			// included.
			name: "podman-namespace-path",
			h:    with(podman, func(h *harness.HostConfig) { h.NetworkMode = "ns:/proc/1/ns/net" }), fail: network,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			records := hostConfigRecords(&tt.h)
			whats := make([]string, len(records))
			for i, r := range records {
				whats[i] = r.What
				if want := r.What != tt.fail; r.OK != want {
					t.Errorf("%s: OK = %t, want %t (found %q)", r.What, r.OK, want, r.Found)
				}
			}
			if want := []string{capAdd, privileged, readOnly, security, withInit, network}; !slices.Equal(whats, want) {
				t.Errorf("hostConfigRecords() made %q, want %q", whats, want)
			}
		})
	}
}

func TestHealthcheckRecord(t *testing.T) {
	t.Parallel()

	want := libreSpeed("img").Healthcheck
	with := func(change func(*Healthcheck)) *Healthcheck {
		h := want
		h.Test = slices.Clone(want.Test)
		change(&h)
		return &h
	}

	tests := []struct {
		name string
		got  *Healthcheck
		ok   bool
	}{
		{name: "same", got: with(func(*Healthcheck) {}), ok: true},
		{name: "none", got: nil},
		{name: "interval", got: with(func(h *Healthcheck) { h.Interval = 31 * time.Second })},
		{name: "timeout", got: with(func(h *Healthcheck) { h.Timeout = 5 * time.Second })},
		{name: "start-period", got: with(func(h *Healthcheck) { h.StartPeriod = 0 })},
		{name: "start-interval", got: with(func(h *Healthcheck) { h.StartInterval = time.Second })},
		{name: "retries", got: with(func(h *Healthcheck) { h.Retries = 4 })},
		{name: "shell-form", got: with(func(h *Healthcheck) { h.Test = []string{"CMD-SHELL", strings.Join(healthCmd, " ")} })},
		{name: "another-probe", got: with(func(h *Healthcheck) { h.Test[3] = "/usr/local/bin/other-health" })},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			r := healthcheckRecord(want, tt.got)
			if r.What != "the image's HEALTHCHECK: the probe in exec form, with no shell, at Baikal's timings" {
				t.Errorf("healthcheckRecord().What = %q", r.What)
			}
			if r.OK != tt.ok {
				t.Errorf("healthcheckRecord() OK = %t, want %t: expected %q, found %q", r.OK, tt.ok, r.Expected, r.Found)
			}
		})
	}
}

func TestResultOf(t *testing.T) {
	t.Parallel()

	ok := harness.Record{OK: true, What: "a", Expected: "x", Found: "x"}
	bad := harness.Record{What: "b", Expected: "x", Found: "y"}
	tests := []struct {
		name    string
		records []harness.Record
		err     error
		ok      bool
		detail  string // in Detail
	}{
		{name: "all-ok", records: []harness.Record{ok, ok}, ok: true},
		{name: "one-fails", records: []harness.Record{ok, bad}, detail: `b: got "y", want "x"`},
		{name: "nothing-asserted", detail: "asserted nothing"},
		{name: "could-not-run", err: errors.New("the container under the contract did not come up"), detail: "did not come up"},
		{
			// Records made before the check stopped stay, and its error is
			// still a failure.
			name: "stopped-part-way", records: []harness.Record{ok}, err: errors.New("no answer"),
			detail: "no answer",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			r := resultOf("c", tt.records, tt.err)
			if r.Check != "c" || r.OK != tt.ok || len(r.Records) != len(tt.records) || !strings.Contains(r.Detail, tt.detail) {
				t.Errorf("resultOf() = %+v, want OK %t and a Detail holding %q", r, tt.ok, tt.detail)
			}
		})
	}
}

// recordingTB is a testing.TB that keeps what a report says, so a test
// can see a failure reported without failing itself.
type recordingTB struct {
	testing.TB
	errors, logs []string
}

func (r *recordingTB) Helper() {}

func (r *recordingTB) Errorf(format string, args ...any) {
	r.errors = append(r.errors, fmt.Sprintf(format, args...))
}

func (r *recordingTB) Logf(format string, args ...any) {
	r.logs = append(r.logs, fmt.Sprintf(format, args...))
}

// TestReport runs its cases in turn, in one test: the check log is set
// in the environment, which no parallel test may share.
func TestReport(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(harness.CheckLogEnv, filepath.Join(dir, "checks.log"))

	ok := harness.Record{OK: true, What: "PID 1 comm", Expected: "frankenphp", Found: "frankenphp"}
	bad := harness.Record{What: "PID 1 argv", Expected: "[a]", Found: "[b]"}
	down := errors.New("the container under the contract did not come up")
	tests := []struct {
		name   string
		result Result
		errors int
	}{
		{name: "ok", result: Result{Check: "pid1", OK: true, Records: []harness.Record{ok}}},
		{
			// The failing record is the report; nothing is said twice.
			name:   "record-fails",
			result: resultOf("pid1", []harness.Record{ok, bad}, nil),
			errors: 1,
		},
		{name: "could-not-run", result: resultOf("pid1", nil, down), errors: 1},
		{
			// Every record ok, and the check failed all the same: the error
			// must still be reported.
			name:   "ok-records-then-an-error",
			result: resultOf("no-egress", []harness.Record{ok}, down),
			errors: 1,
		},
	}
	for _, tt := range tests {
		tb := &recordingTB{TB: t}
		report(tb, tt.result)
		if len(tb.errors) != tt.errors {
			t.Errorf("%s: report() reported %d failures, want %d: %q", tt.name, len(tb.errors), tt.errors, tb.errors)
		}
	}

	// The parity hook: every record's name reaches the check log, a failing
	// one too.
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if cerr := root.Close(); cerr != nil {
			t.Error(cerr)
		}
	})
	got, err := root.ReadFile("checks.log")
	if err != nil {
		t.Fatal(err)
	}
	if want := "PID 1 comm\nPID 1 comm\nPID 1 argv\nPID 1 comm\n"; string(got) != want {
		t.Errorf("the check log holds %q, want %q", got, want)
	}
}

// TestScenarioPrefix shows a Config's Scenario reaching every name a
// suite sees: each Result's check, the subtests Run makes, and the records
// of the health checks, in the check log too. The confinement checks'
// records keep their names, as LibreSpeed's bash suite gave them. It sets
// the check log in the environment, so it runs alone.
func TestScenarioPrefix(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(harness.CheckLogEnv, filepath.Join(dir, "checks.log"))

	// One ok record per check, named for it, as a check makes them.
	results := make([]Result, len(allChecks))
	for i, name := range allChecks {
		results[i] = resultFor("telemetry off", name, []harness.Record{{OK: true, What: "of " + name, Found: "x", Expected: "x"}}, nil)
	}

	var wantLog strings.Builder
	for i, name := range allChecks {
		r := results[i]
		if want := "telemetry off: " + name; r.Check != want {
			t.Errorf("Result.Check = %q, want %q", r.Check, want)
		}
		wantWhat := "of " + name
		if name == checkHealthProbe || name == checkEngineHealthy {
			wantWhat = "telemetry off: of " + name
		}
		if got := r.Records[0].What; got != wantWhat {
			t.Errorf("%s: record named %q, want %q", r.Check, got, wantWhat)
		}
		if !r.OK {
			t.Errorf("%s: OK = false: %s", r.Check, r.Detail)
		}
		wantLog.WriteString(wantWhat + "\n")
	}

	reportAll(t, results)

	// A subtest named as one before it gets a #01 suffix, which shows the
	// name reportAll gave it.
	t.Run("telemetry off: health-probe", sawSubtest)

	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if cerr := root.Close(); cerr != nil {
			t.Error(cerr)
		}
	})
	got, err := root.ReadFile("checks.log")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != wantLog.String() {
		t.Errorf("the check log holds\n%s\nwant\n%s", got, wantLog.String())
	}

	// No scenario, no prefix anywhere.
	plain := resultFor("", checkHealthProbe, []harness.Record{{OK: true, What: "of health-probe"}}, nil)
	if plain.Check != checkHealthProbe || plain.Records[0].What != "of health-probe" {
		t.Errorf("resultFor(no scenario) = %q with record %q, want both unchanged", plain.Check, plain.Records[0].What)
	}
}

// sawSubtest fails t unless a subtest of its name ran before it, which
// testing marks by adding #01 to the second's name.
func sawSubtest(t *testing.T) {
	if !strings.HasSuffix(t.Name(), "#01") {
		t.Errorf("subtest %q is the first of its name: reportAll made no subtest of that name", t.Name())
	}
}
