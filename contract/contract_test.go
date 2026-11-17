// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

package contract

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/divbast/ci/harness"
	"github.com/divbast/ci/internal/testfixture"
)

// healthCmd is LibreSpeed's health probe, as its HEALTHCHECK runs it and
// as a Podman user passes it.
// frankenphp is the PHP divbast's PHP images run, and the binary their
// Exec runs.
const frankenphp = "/usr/local/bin/frankenphp"

// phpApp is an app.php with one subcommand, which records one ok, and
// phpReady runs it, as a PHP app's ReadyProbe asks its app through its
// own PHP.
var phpApp = []byte("<?php\nreturn ['app-ok' => static function (array $operands): void { Assertions::equals('the PHP probe runs', 'yes', 'yes'); }];\n")

func phpReady(ctx context.Context, _ *harness.Container, p *harness.Probe) error {
	records, err := p.RunPHP(ctx, "app-ok")
	if err != nil {
		return err
	}
	if len(records) != 1 || !records[0].OK {
		return fmt.Errorf("app-ok recorded %+v, want one ok record", records)
	}
	return nil
}

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
		Exec:      []string{frankenphp, "version"},
		PHP:       &PHP{Binary: frankenphp, Probe: phpApp},
		HealthCmd: healthCmd,
		Healthcheck: Healthcheck{
			Test:        slices.Concat([]string{"CMD"}, healthCmd),
			Interval:    30 * time.Second,
			Timeout:     10 * time.Second,
			StartPeriod: 60 * time.Second,
			Retries:     3,
		},
		HealthOnly404: []string{"/", "/backend/getIP.php", "/index.php"},
		ReadyProbe:    phpReady,
	}
}

// baikalHealthCmd is Baikal's health probe, as its HEALTHCHECK runs it and
// as a Podman user passes it.
var baikalHealthCmd = []string{"/usr/local/bin/frankenphp", "php-cli", "/usr/local/bin/baikal-health"}

// baikal is Baikal's contract, as its Containerfile and README state it,
// for image. It asks no more of the image than the core probe does: Baikal's
// own suite adds a probe that asks DAV itself, and that stays there.
func baikal(tb testing.TB, e harness.Engine, image string) Config {
	tb.Helper()
	volume, err := e.Volume(tb.Context(), tb, "")
	if err != nil {
		tb.Fatal(err)
	}
	return Config{
		Image:      image,
		AppPort:    8080,
		HealthPort: 8081,
		TmpfsSize:  "512m",
		// What its bootstrap hands over to: pcntl_exec(SERVER_BIN, ['run',
		// '--config', CADDYFILE])
		PID1:      []string{"/usr/local/bin/frankenphp", "run", "--config", "/etc/caddy/Caddyfile"},
		Exec:      []string{frankenphp, "version"},
		PHP:       &PHP{Binary: frankenphp, Probe: phpApp},
		HealthCmd: baikalHealthCmd,
		Healthcheck: Healthcheck{
			Test:        slices.Concat([]string{"CMD"}, baikalHealthCmd),
			Interval:    30 * time.Second,
			Timeout:     10 * time.Second,
			StartPeriod: 60 * time.Second,
			Retries:     3,
		},
		// A first start on an empty volume refuses without the password
		Env: map[string]string{"BAIKAL_ADMIN_PASSWORD": "fixture-admin-password"},
		Mounts: func(testing.TB) []harness.Mount {
			return []harness.Mount{{Source: volume, Target: "/data", Volume: true}}
		},
		// The health port's root, and DAV's own entry point: neither may
		// answer there
		HealthOnly404: []string{"/", "/dav.php"},
		ReadyProbe:    phpReady,
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
// image of each app ci keeps one for. LibreSpeed's keeps it, as its suite
// will, in the scenario its bash suite named "telemetry off".
func TestContractOnFixture(t *testing.T) {
	t.Parallel()
	e := integration(t)

	t.Run("librespeed", func(t *testing.T) {
		t.Parallel()
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
		// named its health checks for the scenario, and nothing else. Beside
		// them are the records the contract adds, and the three it names for
		// what they show, engine-healthy's the same on both engines.
		for _, what := range []string{
			"the image runs as uid/gid 65532 by default",
			"PID 1's real, effective, saved and filesystem uids",
			"PID 1's real, effective, saved and filesystem gids",
			"/usr/local/bin/frankenphp runs under --cap-drop ALL, so it carries no effective file capability",
			xattrRecord,
			"CapEff, every capability bit clear",
			"CapPrm, every capability bit clear",
			"PID 1 comm",
			volumeRecord,
			mountsRecordWhat,
			"/bin/sh is absent from the image",
			"/bin/bash is absent from the image",
			"/bin/dash is absent from the image",
			"TCP ports a process in the container listens on",
			"test network really is internal",
			"outbound TCP to 9.9.9.9:443 is refused",
			"the image's HEALTHCHECK: the probe in exec form, with no shell, at the timings Config.Healthcheck states",
			"telemetry off: /usr/local/bin/librespeed-health exits 0",
			"telemetry off: /usr/local/bin/librespeed-health prints nothing",
			"telemetry off: the engine reports the container healthy within the start period and three intervals",
			"GET :8081/",
			"GET :8081/backend/getIP.php",
			"GET :8081/index.php",
			"GET :8080/healthz",
		} {
			if !made[what] {
				t.Errorf("no record named %q", what)
			}
		}
	})

	t.Run("baikal", func(t *testing.T) {
		t.Parallel()

		cfg := baikal(t, e, testfixture.Baikal)
		results := Check(t.Context(), t, &cfg)
		if got := checkNames(results); !slices.Equal(got, allChecks) {
			t.Fatalf("Check() ran %q, want %q", got, allChecks)
		}
		for _, r := range results {
			for _, rec := range r.Records {
				t.Logf("%s: ok=%t %s (expected %q, found %q)", r.Check, rec.OK, rec.What, rec.Expected, rec.Found)
			}
			if !r.OK || len(r.Records) == 0 {
				t.Errorf("%s: OK = %t with %d records, want OK: %s", r.Check, r.OK, len(r.Records), r.Detail)
			}
			if c := crashed(r.Records); len(c) > 0 {
				t.Errorf("%s: a probe crashed: %+v", r.Check, c)
			}
		}
	})
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
		{name: "no-exec", change: func(c *Config) { c.Exec = nil }, want: "Config.Exec"},
		{name: "exec-relative", change: func(c *Config) { c.Exec = []string{"frankenphp", "version"} }, want: "Config.Exec"},
		{
			name:   "health path, no health port",
			change: func(c *Config) { c.HealthPort, c.HealthPath, c.HealthOnly404 = 0, "/ping", nil },
		},
		{name: "both health port and path", change: func(c *Config) { c.HealthPath = "/ping" }, want: "set one"},
		{
			name:   "neither health port nor path",
			change: func(c *Config) { c.HealthPort, c.HealthOnly404 = 0, nil },
			want:   "Config.HealthPort",
		},
		{
			name:   "neither health port nor path, naming the path",
			change: func(c *Config) { c.HealthPort, c.HealthOnly404 = 0, nil },
			want:   "Config.HealthPath",
		},
		{
			name:   "relative health path",
			change: func(c *Config) { c.HealthPort, c.HealthPath, c.HealthOnly404 = 0, "ping", nil },
			want:   "absolute",
		},
		{
			name:   "HealthOnly404 with no health port",
			change: func(c *Config) { c.HealthPort, c.HealthPath = 0, "/ping" },
			want:   "no health port",
		},
		{
			// The app port is the health port's own, which a zero one is not
			name: "extra port is zero in app-port mode",
			change: func(c *Config) {
				c.HealthPort, c.HealthPath, c.HealthOnly404, c.ExtraTCPPorts = 0, "/ping", nil, []int{0}
			},
			want: "Config.ExtraTCPPorts",
		},
		{name: "extra-port", change: func(c *Config) { c.ExtraTCPPorts = []int{7070} }},
		{name: "extra-port-zero", change: func(c *Config) { c.ExtraTCPPorts = []int{0} }, want: "Config.ExtraTCPPorts"},
		{name: "extra-port-too-high", change: func(c *Config) { c.ExtraTCPPorts = []int{65536} }, want: "Config.ExtraTCPPorts"},
		{name: "extra-port-twice", change: func(c *Config) { c.ExtraTCPPorts = []int{7070, 7070} }, want: "Config.ExtraTCPPorts"},
		{name: "extra-port-is-app-port", change: func(c *Config) { c.ExtraTCPPorts = []int{c.AppPort} }, want: "Config.ExtraTCPPorts"},
		{name: "extra-port-is-health-port", change: func(c *Config) { c.ExtraTCPPorts = []int{c.HealthPort} }, want: "Config.ExtraTCPPorts"},
		{name: "php", change: func(c *Config) { c.PHP = &PHP{Binary: frankenphp, Probe: []byte("<?php return [];")} }},
		{name: "php-no-binary", change: func(c *Config) { c.PHP = &PHP{Probe: []byte("<?php return [];")} }, want: "Config.PHP"},
		{name: "php-relative-binary", change: func(c *Config) { c.PHP = &PHP{Binary: "frankenphp", Probe: []byte("<?php return [];")} }, want: "Config.PHP"},
		{name: "php-no-probe", change: func(c *Config) { c.PHP = &PHP{Binary: frankenphp} }, want: "Config.PHP"},
		{name: "app-probe", change: func(c *Config) { c.AppProbe = "./test/probe" }},
		{name: "scenario", change: func(c *Config) { c.Scenario = "telemetry off" }},
		{
			name: "ready-probe",
			change: func(c *Config) {
				c.ReadyProbe = func(context.Context, *harness.Container, *harness.Probe) error { return nil }
			},
		},
		{
			// Only one of them would run, and which is anyone's guess.
			name: "ready-and-ready-probe",
			change: func(c *Config) {
				c.Ready = func(context.Context, *harness.Container) error { return nil }
				c.ReadyProbe = func(context.Context, *harness.Container, *harness.Probe) error { return nil }
			},
			want: "ReadyProbe",
		},
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

// TestValidateRefusesEmptyHealthOnly404 shows a Config naming no path for
// the health port to refuse is refused: health-port-only would then check
// only the app port, and prove nothing of the health port at all.
func TestValidateRefusesEmptyHealthOnly404(t *testing.T) {
	t.Parallel()

	for _, paths := range [][]string{nil, {}} {
		cfg := libreSpeed("img")
		cfg.HealthOnly404 = paths
		if err := cfg.validate(); err == nil || !strings.Contains(err.Error(), "Config.HealthOnly404 is empty") {
			t.Errorf("validate() with HealthOnly404 %#v: error = %v, want one saying Config.HealthOnly404 is empty", paths, err)
		}
	}
}

// TestChecksFor shows the checks a Config runs: every one in health-port
// mode, and in app-port mode health-on-app-port in the place of
// health-port-only.
func TestChecksFor(t *testing.T) {
	t.Parallel()

	appPort := minimalGo("img")
	appPort.HealthPort, appPort.HealthPath, appPort.HealthOnly404 = 0, "/ping", nil
	want := slices.Clone(allChecks)
	i := slices.Index(want, checkHealthPortOnly)
	if i < 0 {
		t.Fatalf("allChecks %q has no %s", allChecks, checkHealthPortOnly)
	}
	want[i] = checkHealthOnAppPort

	healthPort := minimalGo("img")
	for _, tt := range []struct {
		name string
		cfg  *Config
		want []string
	}{
		{"health-port", &healthPort, allChecks},
		{"app-port", &appPort, want},
	} {
		if got := checksFor(tt.cfg); !slices.Equal(got, tt.want) {
			t.Errorf("%s: checksFor() = %q, want %q", tt.name, got, tt.want)
		}
	}
}

// TestPorts shows the ports listeners allows: AppPort, HealthPort when
// the Config has one, and ExtraTCPPorts.
func TestPorts(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name string
		cfg  Config
		want []string
	}{
		{"health-port", Config{AppPort: 8080, HealthPort: 8081, ExtraTCPPorts: []int{7070}}, []string{"8080", "8081", "7070"}},
		{"app-port", Config{AppPort: 8080, HealthPath: "/ping", ExtraTCPPorts: []int{7070}}, []string{"8080", "7070"}},
		{"app-port-alone", Config{AppPort: 9696, HealthPath: "/ping"}, []string{"9696"}},
	} {
		if got := ports(&tt.cfg); !slices.Equal(got, tt.want) {
			t.Errorf("%s: ports() = %q, want %q", tt.name, got, tt.want)
		}
	}
}

// TestRecordNames pins the names of the records this package renamed, or
// added, since LibreSpeed's bash suite named the rest. An app's suite logs
// each name to $DIVBAST_CHECK_LOG, so a name that moves reads there as a
// check lost and another gained.
func TestRecordNames(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct{ got, want string }{
		{fileCapabilityRecord(frankenphp), "/usr/local/bin/frankenphp runs under --cap-drop ALL, so it carries no effective file capability"},
		{probeMountRecordWhat, "the probe's volume is mounted read-only at /divbast/probe, and only there"},
		{noNewPrivilegesRecordWhat, "the engine sets no-new-privileges (HostConfig.SecurityOpt)"},
		{
			healthcheckRecord(libreSpeed("img").Healthcheck, nil).What,
			"the image's HEALTHCHECK: the probe in exec form, with no shell, at the timings Config.Healthcheck states",
		},
		{engineHealthyRecord, "the engine reports the container healthy within the start period and three intervals"},
		{runtimeUIDRecord, "PID 1's real, effective, saved and filesystem uids"},
		{runtimeGIDRecord, "PID 1's real, effective, saved and filesystem gids"},
	} {
		if tt.got != tt.want {
			t.Errorf("record named %q, want %q", tt.got, tt.want)
		}
	}
}

// TestRuntimeUser reads what the probe's user subcommand prints, PID 1's
// Uid: and Gid: lines, into runtime-user's two records: each of the four
// IDs on a line must be the contract's, and anything but those two lines,
// each once, is an error rather than a record.
func TestRuntimeUser(t *testing.T) {
	t.Parallel()

	const contract = "65532:65532"
	tests := []struct {
		name     string
		user     string
		out      string
		uid, gid string // the IDs each record finds, when it FAILs; empty for ok
		wantErr  string
	}{
		{name: "the-contracts", user: contract, out: "Uid:\t65532\t65532\t65532\t65532\nGid:\t65532\t65532\t65532\t65532\n"},
		{
			// --user 65532:0, as a run looser than the contract would give
			name: "group-root", user: contract,
			out: "Uid:\t65532\t65532\t65532\t65532\nGid:\t0\t0\t0\t0\n",
			gid: "0 0 0 0",
		},
		{
			// Only the saved set uid is root, which a server that dropped
			// root badly would keep, and could take back.
			name: "saved-root", user: contract,
			out: "Uid:\t65532\t65532\t0\t65532\nGid:\t65532\t65532\t65532\t65532\n",
			uid: "65532 65532 0 65532",
		},
		{name: "another-contract", user: "1000:1000", out: "Uid:\t1000\t1000\t1000\t1000\nGid:\t1000\t1000\t1000\t1000\n"},
		{name: "no-gid-line", user: contract, out: "Uid:\t65532\t65532\t65532\t65532\n", wantErr: "one Uid: and one Gid: line"},
		{name: "three-ids", user: contract, out: "Uid:\t65532\t65532\t65532\nGid:\t65532\t65532\t65532\t65532\n", wantErr: "four IDs"},
		{
			name: "twice", user: contract,
			out:     "Uid:\t65532\t65532\t65532\t65532\nUid:\t65532\t65532\t65532\t65532\nGid:\t65532\t65532\t65532\t65532\n",
			wantErr: "one Uid: and one Gid: line",
		},
		{name: "something-else", user: contract, out: "Groups:\t65532\n", wantErr: "one Uid: and one Gid: line"},
		{name: "nothing", user: contract, wantErr: "one Uid: and one Gid: line"},
		{name: "a-user-that-is-not-uid-gid", user: "65532", out: "Uid:\t65532\t65532\t65532\t65532\nGid:\t65532\t65532\t65532\t65532\n", wantErr: "uid:gid"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			records, err := runtimeUserRecords(tt.user, tt.out)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("runtimeUserRecords() = %+v, %v; want an error saying %q", records, err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("runtimeUserRecords() error = %v", err)
			}
			if len(records) != 2 || records[0].What != runtimeUIDRecord || records[1].What != runtimeGIDRecord {
				t.Fatalf("runtimeUserRecords() = %+v, want the uid record and then the gid record", records)
			}
			for i, failing := range []string{tt.uid, tt.gid} {
				r := records[i]
				if want := failing == ""; r.OK != want || (!want && r.Found != failing) {
					t.Errorf("%s: ok %t, found %q, expected %q; want ok %t, found %q", r.What, r.OK, r.Found, r.Expected, want, failing)
				}
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

	// What each engine printed as HostConfig, cut to the fields the check
	// reads, for a container run under the contract on a named internal
	// network: Docker 29 prints null for a list nothing was given for,
	// leaves Init out unless --init was given, and names the network;
	// Podman prints empty lists, a false Init and bridge for any named
	// network.
	docker := map[string]any{
		"CapAdd": nil, "Privileged": false, "ReadonlyRootfs": true, "SecurityOpt": []string{"no-new-privileges"}, "NetworkMode": "divbast-net",
	}
	podman := map[string]any{
		"CapAdd": []string{}, "Privileged": false, "ReadonlyRootfs": true, "SecurityOpt": []string{"no-new-privileges"}, "Init": false,
		"NetworkMode": "bridge",
	}

	const (
		capAdd     = "the engine adds no capability (HostConfig.CapAdd)"
		privileged = "the container is not privileged (HostConfig.Privileged)"
		readOnly   = "the engine mounts the root filesystem read-only (HostConfig.ReadonlyRootfs)"
		security   = "no security option turns off seccomp, AppArmor or SELinux confinement (HostConfig.SecurityOpt)"
		nnp        = "the engine sets no-new-privileges (HostConfig.SecurityOpt)"
		withInit   = "the engine puts no init before the entrypoint (HostConfig.Init)"
		network    = "the container shares no other network namespace (HostConfig.NetworkMode)"
	)
	// with returns h with key set to value, and without with key left out.
	with := func(h map[string]any, key string, value any) map[string]any {
		h = maps.Clone(h)
		h[key] = value
		return h
	}
	without := func(h map[string]any, key string) map[string]any {
		h = maps.Clone(h)
		delete(h, key)
		return h
	}

	tests := []struct {
		name  string
		h     map[string]any
		fail  string // the one record that must FAIL; empty for none
		also  string // another that must FAIL beside it, for a field two records read
		found string // in that record's finding
	}{
		{name: "docker", h: docker},
		{name: "podman", h: podman},
		{
			// Docker and Podman print the same for this, and Docker keeps a
			// capability's name as CAP_<NAME> since 29.
			name: "cap-add", h: with(docker, "CapAdd", []string{"CAP_NET_RAW"}),
			fail: capAdd, found: "CAP_NET_RAW",
		},
		{name: "privileged", h: with(podman, "Privileged", true), fail: privileged, found: "true"},
		{name: "writable-root", h: with(docker, "ReadonlyRootfs", false), fail: readOnly, found: "false"},
		{
			name: "docker-seccomp-unconfined",
			h:    with(docker, "SecurityOpt", []string{"no-new-privileges", "seccomp=unconfined"}), fail: security, found: "seccomp=unconfined",
		},
		{
			// Docker keeps the option as it was typed, and takes a colon too.
			name: "docker-seccomp-colon",
			h:    with(docker, "SecurityOpt", []string{"no-new-privileges", "seccomp:unconfined"}), fail: security, found: "seccomp:unconfined",
		},
		{
			// A profile of one's own replaces the engine's, and nothing here
			// can tell whether it is any tighter.
			name: "docker-seccomp-profile",
			h:    with(docker, "SecurityOpt", []string{"no-new-privileges", `seccomp={"defaultAction":"SCMP_ACT_ALLOW"}`}),
			fail: security, found: "SCMP_ACT_ALLOW",
		},
		{
			name: "podman-apparmor-unconfined",
			h:    with(podman, "SecurityOpt", []string{"no-new-privileges", "apparmor=unconfined"}),
			fail: security, found: "apparmor=unconfined",
		},
		{
			name: "podman-label-disable",
			h:    with(podman, "SecurityOpt", []string{"no-new-privileges", "label=disable"}), fail: security, found: "label=disable",
		},
		{
			// no-new-privileges tightens; it is no loosening.
			name: "no-new-privileges",
			h:    with(podman, "SecurityOpt", []string{"no-new-privileges"}),
		},
		{name: "docker-init", h: with(docker, "Init", true), fail: withInit, found: "true"},
		{name: "podman-init", h: with(podman, "Init", true), fail: withInit, found: "true"},
		{name: "host-network", h: with(docker, "NetworkMode", "host"), fail: network, found: "host"},
		{
			name: "another-containers-network",
			h:    with(podman, "NetworkMode", "container:0123abcd"), fail: network, found: "container:0123abcd",
		},
		{
			// Podman alone joins a namespace by its path, the host's
			// included.
			name: "podman-namespace-path",
			h:    with(podman, "NetworkMode", "ns:/proc/1/ns/net"), fail: network, found: "ns:/proc/1/ns/net",
		},
		// A field left out reads as its zero value, which for these is the
		// value the contract wants, so each must be there to pass. Docker
		// leaves Init out on its own, and Init's absence is no failure.
		{name: "no-cap-add", h: without(docker, "CapAdd"), fail: capAdd, found: "absent"},
		{name: "no-privileged", h: without(podman, "Privileged"), fail: privileged, found: "absent"},
		{name: "no-readonly-rootfs", h: without(docker, "ReadonlyRootfs"), fail: readOnly, found: "absent"},
		{name: "no-security-opt", h: without(podman, "SecurityOpt"), fail: security, also: nnp, found: "absent"},
		{name: "no-network-mode", h: without(docker, "NetworkMode"), fail: network, found: "absent"},
		{name: "podman-no-init", h: without(podman, "Init")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			raw, err := json.Marshal(tt.h)
			if err != nil {
				t.Fatal(err)
			}
			records, err := hostConfigRecords(raw)
			if err != nil {
				t.Fatalf("hostConfigRecords(%s) error = %v", raw, err)
			}
			whats := make([]string, len(records))
			for i, r := range records {
				whats[i] = r.What
				if want := r.What != tt.fail && r.What != tt.also; r.OK != want {
					t.Errorf("%s: OK = %t, want %t (found %q)", r.What, r.OK, want, r.Found)
				}
				if r.What == tt.fail && !strings.Contains(r.Found, tt.found) {
					t.Errorf("%s: found %q, which does not say %q", r.What, r.Found, tt.found)
				}
			}
			if want := []string{capAdd, privileged, readOnly, security, nnp, withInit, network}; !slices.Equal(whats, want) {
				t.Errorf("hostConfigRecords() made %q, want %q", whats, want)
			}
		})
	}

	// What is not a HostConfig at all is an error, not a pass.
	for _, raw := range []string{``, `null`, `[]`, `{"Privileged": "no"}`} {
		if records, err := hostConfigRecords(json.RawMessage(raw)); err == nil {
			t.Errorf("hostConfigRecords(%q) = %+v, nil; want an error", raw, records)
		}
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
			if r.What != healthcheckRecordWhat {
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
		says   string // in one of the failures; empty for no matter
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
		{
			// A failing record, and then the error that stopped the check:
			// the record says only what it found, so the error is reported
			// beside it rather than lost.
			name:   "a-failing-record-then-an-error",
			result: resultOf("no-egress", []harness.Record{bad}, down),
			errors: 2,
			says:   "did not come up",
		},
	}
	for _, tt := range tests {
		tb := &recordingTB{TB: t}
		report(tb, &tt.result)
		if len(tb.errors) != tt.errors {
			t.Errorf("%s: report() reported %d failures, want %d: %q", tt.name, len(tb.errors), tt.errors, tb.errors)
		}
		if tt.says != "" && !slices.ContainsFunc(tb.errors, func(e string) bool { return strings.Contains(e, tt.says) }) {
			t.Errorf("%s: report() reported %q, and none says %q", tt.name, tb.errors, tt.says)
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
	if want := "PID 1 comm\nPID 1 comm\nPID 1 argv\nPID 1 comm\nPID 1 argv\n"; string(got) != want {
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

// TestReadyBounded shows the app's own Ready bounded as the wait for its
// ports is: one that waits for its context gets readyWithin, and not a
// moment longer, rather than holding the suite until go test's own
// timeout kills it.
func TestReadyBounded(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		s := &suite{cfg: &Config{Ready: func(ctx context.Context, _ *harness.Container) error {
			<-ctx.Done()
			return ctx.Err()
		}}}
		start := time.Now()
		err := s.awaitReady(t.Context(), &harness.Container{}, &harness.Probe{})
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("awaitReady() error = %v, want the deadline", err)
		}
		if waited := time.Since(start); waited != readyWithin {
			t.Errorf("awaitReady() returned after %s, want %s", waited, readyWithin)
		}
	})
}

// TestReadyProbe shows ReadyProbe given the container and the probe the
// contract installed in it, so an app needs no second probe of its own to
// ask its app anything, and bounded as Ready is.
func TestReadyProbe(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		c, p := &harness.Container{ID: "abc"}, &harness.Probe{}
		var gotC *harness.Container
		var gotP *harness.Probe
		s := &suite{cfg: &Config{ReadyProbe: func(ctx context.Context, c *harness.Container, p *harness.Probe) error {
			gotC, gotP = c, p
			<-ctx.Done()
			return ctx.Err()
		}}}
		start := time.Now()
		if err := s.awaitReady(t.Context(), c, p); !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("awaitReady() error = %v, want the deadline", err)
		}
		if waited := time.Since(start); waited != readyWithin {
			t.Errorf("awaitReady() returned after %s, want %s", waited, readyWithin)
		}
		if gotC != c || gotP != p {
			t.Errorf("ReadyProbe was given %p and %p, want the container %p and its probe %p", gotC, gotP, c, p)
		}
	})
}

func TestMountsRecord(t *testing.T) {
	t.Parallel()

	// What each engine printed for a container run under the contract,
	// with a named volume at /data: Docker 29 and Podman both list a volume
	// or a bind in Mounts, and a --tmpfs only in HostConfig.Tmpfs, with
	// options of their own.
	data := harness.Mount{Source: "divbast-abc", Target: "/data", Volume: true}
	docker := harness.Inspect{
		HostConfig: harness.HostConfig{Tmpfs: map[string]string{"/tmp": "size=16m"}},
		Mounts:     []harness.MountPoint{{Type: "volume", Name: "divbast-abc", Destination: "/data", RW: true}},
	}
	podman := harness.Inspect{
		HostConfig: harness.HostConfig{Tmpfs: map[string]string{"/tmp": "rw,rprivate,nosuid,nodev,tmpcopyup,size=16m"}},
		Mounts:     []harness.MountPoint{{Type: "volume", Name: "divbast-abc", Destination: "/data", RW: true}},
	}
	with := func(ins harness.Inspect, change func(*harness.Inspect)) harness.Inspect {
		ins.HostConfig.Tmpfs = maps.Clone(ins.HostConfig.Tmpfs)
		ins.Mounts = slices.Clone(ins.Mounts)
		change(&ins)
		return ins
	}

	tests := []struct {
		name  string
		given []harness.Mount
		ins   harness.Inspect
		found string // the finding, when the record must FAIL
	}{
		{name: "docker", given: []harness.Mount{data}, ins: docker},
		{name: "podman", given: []harness.Mount{data}, ins: podman},
		{
			// The probe's own volume, which the harness mounts to run the
			// checks, is set aside
			name:  "the-probe-volume",
			given: []harness.Mount{data},
			ins: with(docker, func(ins *harness.Inspect) {
				ins.Mounts = append(ins.Mounts, harness.MountPoint{Type: "volume", Name: "divbast-probe-x", Destination: "/divbast/probe"})
			}),
		},
		{
			name:  "the-probe-volume-writable",
			given: []harness.Mount{data},
			ins: with(docker, func(ins *harness.Inspect) {
				ins.Mounts = append(ins.Mounts, harness.MountPoint{Type: "volume", Name: "divbast-probe-x", Destination: "/divbast/probe", RW: true})
			}),
			found: "tmpfs /tmp, volume /data, volume /divbast/probe",
		},
		{
			// Only once: a second mount there is no probe's
			name:  "the-probe-volume-twice",
			given: []harness.Mount{data},
			ins: with(docker, func(ins *harness.Inspect) {
				ins.Mounts = append(ins.Mounts,
					harness.MountPoint{Type: "volume", Name: "divbast-probe-x", Destination: "/divbast/probe"},
					harness.MountPoint{Type: "bind", Destination: "/divbast/probe"})
			}),
			found: "bind /divbast/probe (read-only), tmpfs /tmp, volume /data",
		},
		{
			name: "no-mounts",
			ins:  with(docker, func(ins *harness.Inspect) { ins.Mounts = nil }),
		},
		{
			// An image's VOLUME, which Docker names with a hash
			name: "anonymous-volume",
			ins: with(docker, func(ins *harness.Inspect) {
				ins.Mounts = []harness.MountPoint{{Type: "volume", Name: "0123abcd", Destination: "/data", RW: true}}
			}),
			found: "tmpfs /tmp, volume /data",
		},
		{
			name: "another-tmpfs", given: []harness.Mount{data},
			ins:   with(podman, func(ins *harness.Inspect) { ins.HostConfig.Tmpfs["/run"] = "rw" }),
			found: "tmpfs /run, tmpfs /tmp, volume /data",
		},
		{
			// --mount type=tmpfs, which Docker lists in Mounts instead
			name: "tmpfs-mount", given: []harness.Mount{data},
			ins: with(docker, func(ins *harness.Inspect) {
				ins.Mounts = append(ins.Mounts, harness.MountPoint{Type: "tmpfs", Destination: "/var/tmp", RW: true})
			}),
			found: "tmpfs /tmp, tmpfs /var/tmp, volume /data",
		},
		{
			name:  "no-tmpfs",
			given: []harness.Mount{data},
			ins:   with(docker, func(ins *harness.Inspect) { ins.HostConfig.Tmpfs = nil }),
			found: "volume /data",
		},
		{
			// The volume given read-only, mounted writable
			name:  "writable",
			given: []harness.Mount{{Source: "divbast-abc", Target: "/data", Volume: true, ReadOnly: true}},
			ins:   docker,
			found: "tmpfs /tmp, volume /data",
		},
		{
			name: "read-only-as-given",
			given: []harness.Mount{
				{Source: "divbast-abc", Target: "/data", Volume: true, ReadOnly: true},
				{Source: "/srv/conf", Target: "/etc/app"},
			},
			ins: with(docker, func(ins *harness.Inspect) {
				ins.Mounts = []harness.MountPoint{
					{Type: "volume", Name: "divbast-abc", Destination: "/data"},
					{Type: "bind", Source: "/srv/conf", Destination: "/etc/app", RW: true},
				}
			}),
		},
		{
			name: "a-bind-for-a-volume", given: []harness.Mount{data},
			ins: with(docker, func(ins *harness.Inspect) {
				ins.Mounts = []harness.MountPoint{{Type: "bind", Source: "/srv/data", Destination: "/data", RW: true}}
			}),
			found: "bind /data, tmpfs /tmp",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			r := mountsRecord(tt.given, &tt.ins)
			if r.What != mountsRecordWhat {
				t.Errorf("mountsRecord().What = %q", r.What)
			}
			if r.OK != (tt.found == "") || (tt.found != "" && r.Found != tt.found) {
				t.Errorf("mountsRecord() = ok %t, found %q, expected %q; want ok %t, found %q",
					r.OK, r.Found, r.Expected, tt.found == "", tt.found)
			}
		})
	}
}

// TestHostConfigNoNewPrivileges reads no-new-privileges as each engine
// records it: Docker keeps the option as it was typed, the bare word or
// with a value after ":" or "=", which it reads with strconv.ParseBool,
// and Podman 5.7 writes the bare word for each and drops one set false.
// Set false anywhere, a value Docker could not read, or not there at all,
// fails.
func TestHostConfigNoNewPrivileges(t *testing.T) {
	t.Parallel()

	tests := []struct {
		opts []string
		ok   bool
	}{
		{opts: []string{"no-new-privileges"}, ok: true},
		{opts: []string{"no-new-privileges:true"}, ok: true},
		{opts: []string{"no-new-privileges=true"}, ok: true},
		{opts: []string{"label=type:x", "no-new-privileges"}, ok: true},
		{opts: []string{"no-new-privileges=false"}},
		{opts: []string{"no-new-privileges:false"}},
		{opts: []string{"no-new-privileges", "no-new-privileges=false"}},
		{opts: []string{"no-new-privileges:1"}, ok: true},
		{opts: []string{"no-new-privileges=TRUE"}, ok: true},
		{opts: []string{"no-new-privileges", "no-new-privileges=0"}},
		{opts: []string{"no-new-privileges:F"}},
		{opts: []string{"no-new-privileges:yes"}},
		{opts: []string{"no-new-privileges="}},
		{opts: []string{}},
		{opts: nil},
	}
	for _, tt := range tests {
		t.Run(strings.Join(tt.opts, ","), func(t *testing.T) {
			t.Parallel()

			var r harness.Record
			for _, rec := range hostConfigValues(&harness.HostConfig{ReadonlyRootfs: true, SecurityOpt: tt.opts}) {
				if rec.What == noNewPrivilegesRecordWhat {
					r = rec
				}
			}
			if r.What == "" || r.OK != tt.ok {
				t.Errorf("SecurityOpt %q: the no-new-privileges record = %+v, want ok %t", tt.opts, r, tt.ok)
			}
		})
	}
}

// TestProbeMountRecord checks the probe's own volume is there, read-only,
// once: a writable one would let a container change the probe the checks
// run, and one missing means no check ran it.
func TestProbeMountRecord(t *testing.T) {
	t.Parallel()

	probe := harness.MountPoint{Type: "volume", Name: "divbast-probe-x", Destination: "/divbast/probe"}
	writable := probe
	writable.RW = true
	data := harness.MountPoint{Type: "volume", Name: "d", Destination: "/data", RW: true}
	tests := []struct {
		name   string
		mounts []harness.MountPoint
		found  string // when the record must FAIL
	}{
		{name: "read-only", mounts: []harness.MountPoint{data, probe}},
		{name: "absent", mounts: []harness.MountPoint{data}, found: "none"},
		{name: "writable", mounts: []harness.MountPoint{writable}, found: "volume /divbast/probe"},
		{name: "twice", mounts: []harness.MountPoint{probe, probe}, found: "volume /divbast/probe (read-only), volume /divbast/probe (read-only)"},
		{name: "a-bind", mounts: []harness.MountPoint{{Type: "bind", Destination: "/divbast/probe"}}, found: "bind /divbast/probe (read-only)"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			r := probeMountRecord(&harness.Inspect{Mounts: tt.mounts})
			if r.What != probeMountRecordWhat || r.Expected != "volume /divbast/probe (read-only)" {
				t.Fatalf("probeMountRecord() = %+v, want the probe mount's record", r)
			}
			if want := tt.found == ""; r.OK != want || (!want && r.Found != tt.found) {
				t.Errorf("probeMountRecord() = ok %t, found %q; want ok %t, found %q", r.OK, r.Found, want, tt.found)
			}
		})
	}
}

// TestFileCapabilityRecord names the binary Config.Exec runs, so for a
// PHP app's FrankenPHP it reads exactly as it did before Exec existed.
func TestFileCapabilityRecord(t *testing.T) {
	t.Parallel()

	if got, want := fileCapabilityRecord("/usr/local/bin/frankenphp"),
		"/usr/local/bin/frankenphp runs under --cap-drop ALL, so it carries no effective file capability"; got != want {
		t.Errorf("fileCapabilityRecord() = %q, want %q", got, want)
	}
	if got := fileCapabilityRecord("/usr/local/bin/writefreely"); !strings.HasPrefix(got, "/usr/local/bin/writefreely runs under") {
		t.Errorf("fileCapabilityRecord() = %q, want it to name the binary", got)
	}
	for _, tt := range []struct {
		out  string
		want bool
	}{
		{"exec /usr/local/bin/x: operation not permitted", true},
		{"exec container process `/usr/local/bin/x`: Operation not permitted", true},
		{"exec /usr/local/bin/other: operation not permitted", false},
		{"exec /usr/local/bin/x: no such file or directory", false},
	} {
		if got := execRefused(tt.out, "/usr/local/bin/x"); got != tt.want {
			t.Errorf("execRefused(%q) = %t, want %t", tt.out, got, tt.want)
		}
	}
}
