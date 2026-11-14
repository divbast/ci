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

// TestRecordNames pins the names of the records this package renamed, or
// added, since LibreSpeed's bash suite named the rest. An app's suite logs
// each name to $DIVBAST_CHECK_LOG, so a name that moves reads there as a
// check lost and another gained.
func TestRecordNames(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct{ got, want string }{
		{fileCapabilityRecord, "/usr/local/bin/frankenphp runs under --cap-drop ALL, so it carries no effective file capability"},
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
		"CapAdd": nil, "Privileged": false, "ReadonlyRootfs": true, "SecurityOpt": nil, "NetworkMode": "divbast-net",
	}
	podman := map[string]any{
		"CapAdd": []string{}, "Privileged": false, "ReadonlyRootfs": true, "SecurityOpt": []string{}, "Init": false,
		"NetworkMode": "bridge",
	}

	const (
		capAdd     = "the engine adds no capability (HostConfig.CapAdd)"
		privileged = "the container is not privileged (HostConfig.Privileged)"
		readOnly   = "the engine mounts the root filesystem read-only (HostConfig.ReadonlyRootfs)"
		security   = "no security option turns off seccomp, AppArmor or SELinux confinement (HostConfig.SecurityOpt)"
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
			h:    with(docker, "SecurityOpt", []string{"seccomp=unconfined"}), fail: security, found: "seccomp=unconfined",
		},
		{
			// Docker keeps the option as it was typed, and takes a colon too.
			name: "docker-seccomp-colon",
			h:    with(docker, "SecurityOpt", []string{"seccomp:unconfined"}), fail: security, found: "seccomp:unconfined",
		},
		{
			// A profile of one's own replaces the engine's, and nothing here
			// can tell whether it is any tighter.
			name: "docker-seccomp-profile",
			h:    with(docker, "SecurityOpt", []string{`seccomp={"defaultAction":"SCMP_ACT_ALLOW"}`}),
			fail: security, found: "SCMP_ACT_ALLOW",
		},
		{
			name: "podman-apparmor-unconfined",
			h:    with(podman, "SecurityOpt", []string{"no-new-privileges", "apparmor=unconfined"}),
			fail: security, found: "apparmor=unconfined",
		},
		{
			name: "podman-label-disable",
			h:    with(podman, "SecurityOpt", []string{"label=disable"}), fail: security, found: "label=disable",
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
		{name: "no-security-opt", h: without(podman, "SecurityOpt"), fail: security, found: "absent"},
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
				if want := r.What != tt.fail; r.OK != want {
					t.Errorf("%s: OK = %t, want %t (found %q)", r.What, r.OK, want, r.Found)
				}
				if r.What == tt.fail && !strings.Contains(r.Found, tt.found) {
					t.Errorf("%s: found %q, which does not say %q", r.What, r.Found, tt.found)
				}
			}
			if want := []string{capAdd, privileged, readOnly, security, withInit, network}; !slices.Equal(whats, want) {
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
