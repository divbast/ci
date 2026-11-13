// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

// Package contract is the confinement contract every divbast image makes,
// as checks an app's acceptance suite runs against its image. An app
// supplies a short [Config], and [Run] makes each check a subtest. Each
// checks exactly this, and no more:
//
//   - default-user: the image's own configuration names 65532:65532 as
//     its user;
//   - runtime-user: PID 1 runs as 65532:65532, in each of the real,
//     effective, saved and filesystem IDs its status gives for each;
//   - file-capability: /usr/local/bin/frankenphp runs under --cap-drop ALL,
//     which the kernel refuses to a binary whose file capability has the
//     effective bit;
//   - no-file-capability-xattr: no file in any layer of the image, as the
//     engine saves it, carries a security.capability extended attribute,
//     with the effective bit or without, on whatever file;
//   - caps: PID 1 holds no capability, in any of its five sets;
//   - read-only: creating /.divbast-write-probe fails because the root is
//     mounted read-only;
//   - no-volume: the image declares no VOLUME, and the mounts the engine
//     reports (Mounts and HostConfig.Tmpfs) are exactly tmpfs /tmp plus
//     Config.Mounts. Podman's --read-only adds writable tmpfs mounts of its
//     own, /run and /var/tmp among them, which it does not report;
//   - pid1: PID 1's comm is the file name of Config.PID1's first word, as
//     the kernel cuts it to 15 bytes, and its whole argv is Config.PID1;
//   - no-shell: nothing is at /bin/sh, /bin/bash or /bin/dash, and a path
//     the probe may not look up counts as one that is there;
//   - listeners: the processes in the container listen on Config.AppPort
//     and Config.HealthPort alone, hold no UDP socket, and the probe can
//     read the descriptors of every one of them;
//   - no-egress: the container's network is one the engine reports
//     internal, and a TCP connect from it to 9.9.9.9:443 fails;
//   - healthcheck-config: its HEALTHCHECK is Config.Healthcheck, in exec
//     form, in every field;
//   - health-probe: Config.HealthCmd, run in the container, exits 0 and
//     prints nothing;
//   - engine-healthy: the engine runs the health check on its own
//     schedule, Docker from the image's HEALTHCHECK and Podman from the
//     systemd timer its --health-cmd sets up, and reports the container
//     healthy within the image's start period and three of the intervals
//     it runs the check at;
//   - health-port-only: each path in Config.HealthOnly404 answers 404 on
//     the health port, and /healthz answers 404 on the app port;
//   - host-config: the engine reports adding no capability, no
//     --privileged, a read-only root, no security option that loosens
//     seccomp, AppArmor or SELinux, no init before the entrypoint, and a
//     network namespace of the container's own, and leaves none of those
//     fields out but Init.
//
// Every container a check runs is run under exactly the confinement the
// contract claims, so no check can pass under a looser one. The container
// the checks share is on a network with no route out, so its serving
// there, and being healthy there, shows the image needs none. The records
// keep the names LibreSpeed's bash suite gave them, so an app's suite
// ported from bash still makes every check it made, and logs each one to
// $DIVBAST_CHECK_LOG through [harness.Checks]. no-volume's,
// no-file-capability-xattr's and runtime-user's are the contract's own:
// that suite had none of those checks. Three more are named for what they
// show: file-capability's, healthcheck-config's, and engine-healthy's,
// which has one name on both engines.
package contract

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/divbast/ci/harness"
)

// Healthcheck is an image's HEALTHCHECK: its command, starting "CMD" for
// the exec form, and its timings, zero for one left unset.
type Healthcheck = harness.Healthcheck

// Config is what an app's contract says about its image.
type Config struct {
	// Image is the image under test. Empty takes $IMAGE.
	Image string
	// AppPort is the port the app serves on, and HealthPort the one only
	// /healthz answers on.
	AppPort, HealthPort int
	// TmpfsSize sizes the one tmpfs the contract grants, at /tmp.
	TmpfsSize string
	// PID1 is PID 1's whole argv once the image has started: the server,
	// as its bootstrap hands over to it.
	PID1 []string
	// HealthCmd is the image's health command, as a Podman user passes it
	// with --health-cmd.
	HealthCmd []string
	// Healthcheck is the image's HEALTHCHECK, exactly: "CMD" followed by
	// HealthCmd, and the timings.
	Healthcheck Healthcheck
	// Env is set in the container the checks run in.
	Env map[string]string
	// Mounts, when set, returns the mounts that container needs, such as
	// a volume made with [harness.Engine.Volume]. It may fail tb.
	Mounts func(tb testing.TB) []harness.Mount
	// Ready, when set, returns once the app in c is ready to be checked,
	// after both ports answer, or an error saying why it never was. Its
	// context ends a minute after it is called, as long as each port had
	// to answer.
	Ready func(ctx context.Context, c *harness.Container) error
	// ReadyProbe is Ready, given as well the probe the contract installed
	// in c, with ProbeApp beside it, for an app that asks its app through
	// the probe: one installed again would be the same files. Set Ready or
	// ReadyProbe, not both.
	ReadyProbe func(ctx context.Context, c *harness.Container, p *harness.Probe) error
	// ProbeApp is the app's own probe subcommands, installed beside the
	// core probe as app.php. Empty installs none.
	ProbeApp []byte
	// HealthOnly404 holds the paths that must answer 404 on HealthPort.
	HealthOnly404 []string
	// Scenario, when set, names the configuration the container under the
	// contract runs in, such as "telemetry off", for a suite that runs the
	// contract once for each configuration it supports. Each check's name
	// gains the prefix "<Scenario>: ", and so do the records of the two
	// checks that judge the app's health in that configuration,
	// health-probe and engine-healthy, as LibreSpeed's bash suite named
	// them. The records of the confinement checks hold whatever the
	// configuration, and keep their names.
	Scenario string
}

// validate refuses a Config that cannot be checked, or whose checks
// would prove nothing.
func (c *Config) validate() error {
	var errs []error
	if c.Image == "" {
		errs = append(errs, errors.New("no image to check: set Config.Image, or IMAGE"))
	}
	for _, p := range []struct {
		name string
		port int
	}{{"AppPort", c.AppPort}, {"HealthPort", c.HealthPort}} {
		if p.port < 1 || p.port > 65535 {
			errs = append(errs, fmt.Errorf("the port in Config.%s, %d, is not a TCP port", p.name, p.port))
		}
	}
	if c.AppPort == c.HealthPort {
		errs = append(errs, fmt.Errorf("Config.AppPort and Config.HealthPort are the same port, %d", c.AppPort))
	}
	if strings.ContainsAny(c.Scenario, "\t\n\r") {
		errs = append(errs, fmt.Errorf("Config.Scenario is %q: a record's name is one line", c.Scenario))
	}
	if c.TmpfsSize == "" {
		errs = append(errs, errors.New("Config.TmpfsSize is empty: the contract's one tmpfs, /tmp, needs its size"))
	}
	if c.Ready != nil && c.ReadyProbe != nil {
		errs = append(errs, errors.New("Config.Ready and Config.ReadyProbe are both set: set one"))
	}
	if len(c.PID1) == 0 {
		errs = append(errs, errors.New("Config.PID1 is empty"))
	}
	if len(c.HealthCmd) == 0 {
		errs = append(errs, errors.New("Config.HealthCmd is empty"))
	}
	if want := slices.Concat([]string{"CMD"}, c.HealthCmd); len(c.HealthCmd) > 0 && !slices.Equal(c.Healthcheck.Test, want) {
		errs = append(errs, fmt.Errorf("Config.Healthcheck.Test is %q, want %q: the exec form, since no divbast image has a shell, "+
			"and the command a Podman user is given", c.Healthcheck.Test, want))
	}
	return errors.Join(errs...)
}

// Result is one check's outcome.
type Result struct {
	// Check is the check's name, such as caps.
	Check string
	// OK is true when the check ran and every record it made is ok.
	OK bool
	// Detail says what failed, or why the check could not run.
	Detail string
	// Records are the assertions the check made, each named as the bash
	// suites named it. A check that could not run may have made none.
	Records []harness.Record

	// err is why the check stopped, if it did: a failing record says only
	// what it found, so a report gives err beside it.
	err error
}

// The checks, by name.
const (
	checkDefaultUser           = "default-user"
	checkRuntimeUser           = "runtime-user"
	checkFileCapability        = "file-capability"
	checkCaps                  = "caps"
	checkReadOnly              = "read-only"
	checkPID1                  = "pid1"
	checkNoShell               = "no-shell"
	checkListeners             = "listeners"
	checkNoEgress              = "no-egress"
	checkHealthcheckConfig     = "healthcheck-config"
	checkHealthProbe           = "health-probe"
	checkEngineHealthy         = "engine-healthy"
	checkHealthPortOnly        = "health-port-only"
	checkHostConfig            = "host-config"
	checkNoVolume              = "no-volume"
	checkNoFileCapabilityXattr = "no-file-capability-xattr"
)

// scenarioChecks are the checks whose records a Scenario names: those
// that judge the app's health in the configuration it runs in.
var scenarioChecks = map[string]bool{checkHealthProbe: true, checkEngineHealthy: true}

// allChecks is every check, in the order Check runs and returns them.
var allChecks = []string{
	checkDefaultUser, checkRuntimeUser, checkFileCapability, checkNoFileCapabilityXattr, checkCaps, checkReadOnly,
	checkNoVolume, checkPID1, checkNoShell, checkListeners, checkNoEgress, checkHealthcheckConfig, checkHealthProbe,
	checkEngineHealthy, checkHealthPortOnly, checkHostConfig,
}

// Check runs every check against cfg's image, under the engine $ENGINE
// names, and returns a Result for each, in order. It never fails tb
// itself: [Run] reports the results. Everything it starts is removed when
// tb ends.
func Check(ctx context.Context, tb testing.TB, cfg *Config) []Result {
	tb.Helper()
	return check(ctx, tb, cfg, nil)
}

// check is [Check], with loosen given to the container the checks run in
// as raw run flags: how a test shows host-config catches a run looser
// than the contract.
func check(ctx context.Context, tb testing.TB, given *Config, loosen []string) []Result {
	tb.Helper()
	cfg := *given
	if cfg.Image == "" {
		cfg.Image = os.Getenv("IMAGE")
	}
	engine, err := harness.EngineFromEnv()
	if err == nil {
		err = cfg.validate()
	}
	if err != nil {
		results := make([]Result, len(allChecks))
		for i, name := range allChecks {
			results[i] = resultFor(cfg.Scenario, name, nil, fmt.Errorf("the contract cannot be checked: %w", err))
		}
		return results
	}

	s := &suite{cfg: &cfg, engine: engine}
	s.image, s.imageErr = engine.ImageConfig(ctx, tb, cfg.Image)
	s.up(ctx, tb, loosen)

	run := map[string]func(context.Context, testing.TB) ([]harness.Record, error){
		checkDefaultUser:           s.defaultUser,
		checkRuntimeUser:           s.runtimeUser,
		checkFileCapability:        s.fileCapability,
		checkNoFileCapabilityXattr: s.noFileCapabilityXattr,
		checkCaps:                  s.probeCheck("assert-caps"),
		checkReadOnly:              s.probeCheck("assert-read-only"),
		checkNoVolume:              s.noVolume,
		checkPID1:                  s.probeCheck("assert-pid1", cfg.PID1...),
		checkNoShell:               s.probeCheck("assert-no-shell"),
		checkListeners:             s.probeCheck("assert-listeners", strconv.Itoa(cfg.AppPort), strconv.Itoa(cfg.HealthPort)),
		checkNoEgress:              s.noEgress,
		checkHealthcheckConfig:     s.healthcheckConfig,
		checkHealthProbe:           s.healthProbe,
		checkEngineHealthy:         s.engineHealthy,
		checkHealthPortOnly:        s.healthPortOnly,
		checkHostConfig:            s.hostConfig,
	}
	results := make([]Result, 0, len(allChecks))
	for _, name := range allChecks {
		records, err := run[name](ctx, tb)
		results = append(results, resultFor(cfg.Scenario, name, records, err))
	}
	return results
}

// resultFor is the Result of the check name in scenario, which made
// records and then stopped with err, if err is not nil. A scenario prefixes
// the check's name, and the names of its records if it judges the app's
// health.
func resultFor(scenario, name string, records []harness.Record, err error) Result {
	if scenario == "" {
		return resultOf(name, records, err)
	}
	prefix := scenario + ": "
	if scenarioChecks[name] {
		named := make([]harness.Record, len(records))
		for i, rec := range records {
			rec.What = prefix + rec.What
			named[i] = rec
		}
		records = named
	}
	return resultOf(prefix+name, records, err)
}

// resultOf is the Result of the check name, which made records and then
// stopped with err, if err is not nil.
func resultOf(name string, records []harness.Record, err error) Result {
	r := Result{Check: name, Records: records, err: err}
	var problems []string
	for _, rec := range records {
		if !rec.OK {
			problems = append(problems, fmt.Sprintf("%s: got %q, want %q", rec.What, rec.Found, rec.Expected))
		}
	}
	switch {
	case err != nil:
		problems = append(problems, err.Error())
	case len(records) == 0:
		problems = append(problems, "the check asserted nothing, which proves nothing")
	}
	if len(problems) == 0 {
		r.OK = true
		r.Detail = fmt.Sprintf("%d records, every one ok", len(records))
		return r
	}
	r.Detail = strings.Join(problems, "; ")
	return r
}

// Run runs every check against cfg's image, as [Check] does, and reports
// each as a subtest of t named for it: a record that fails, fails the
// subtest, and every record's name goes to $DIVBAST_CHECK_LOG.
func Run(t *testing.T, cfg *Config) {
	t.Helper()
	reportAll(t, Check(t.Context(), t, cfg))
}

// reportAll reports each of results as a subtest of t named for its
// check.
func reportAll(t *testing.T, results []Result) {
	t.Helper()
	for i := range results {
		t.Run(results[i].Check, func(t *testing.T) {
			t.Helper()
			report(t, &results[i])
		})
	}
}

// report reports r's records through [harness.Checks], and r's failure
// itself when no failing record already says it: when none failed, or
// when the check also stopped on an error, which no record holds.
func report(tb testing.TB, r *Result) {
	tb.Helper()
	if len(r.Records) > 0 {
		harness.NewChecks(tb).Records(r.Records)
	}
	failed := slices.ContainsFunc(r.Records, func(rec harness.Record) bool { return !rec.OK })
	switch {
	case r.OK:
	case !failed:
		tb.Errorf("FAIL %s: %s", r.Check, r.Detail)
	case r.err != nil:
		tb.Errorf("FAIL %s: %v", r.Check, r.err)
	}
}

// readyWithin bounds how long the container's two ports may take to
// answer, as LibreSpeed's bash suite bounded it.
const readyWithin = time.Minute
