// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

package contract

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/divbast/ci/harness"
)

// suite is one run of the checks against one image.
type suite struct {
	cfg    *Config
	engine harness.Engine

	// image is the image's own configuration, unless imageErr says why it
	// could not be read.
	image    harness.Config
	imageErr error

	// The container the checks run in, on an internal network, with the
	// probe installed and both ports answering. ctrErr says why it did
	// not come up, if it did not; network is set if that much worked.
	network string
	ctr     *harness.Container
	probe   *harness.Probe
	ctrErr  error
	// mounts are those the app's Config gave that container.
	mounts []harness.Mount
}

// up starts the container the checks run in: under the contract, on a
// network with no route out, so every check also shows the image works
// without one. loosen goes to the engine as raw flags.
func (s *suite) up(ctx context.Context, tb testing.TB, loosen []string) {
	tb.Helper()
	if err := s.start(ctx, tb, loosen); err != nil {
		s.ctrErr = fmt.Errorf("the container under the contract did not come up: %w", err)
	}
}

// start is up, returning why the container did not come up.
func (s *suite) start(ctx context.Context, tb testing.TB, loosen []string) error {
	tb.Helper()
	network, err := s.engine.Network(ctx, tb, "", "", true)
	if err != nil {
		return err
	}
	s.network = network

	var mounts []harness.Mount
	if s.cfg.Mounts != nil {
		mounts = s.cfg.Mounts(tb)
	}
	s.mounts = mounts
	c, err := s.engine.Start(ctx, tb, &harness.RunSpec{
		Image:     s.cfg.Image,
		Network:   network,
		Confine:   harness.Contract(s.cfg.TmpfsSize),
		Env:       s.cfg.Env,
		Mounts:    mounts,
		HealthCmd: s.cfg.HealthCmd,
		Extra:     loosen,
	})
	if err != nil {
		return err
	}
	p, err := harness.InstallProbe(ctx, c, s.cfg.ProbeApp)
	if err != nil {
		return stopped(ctx, c, fmt.Errorf("installing the probe: %w", err))
	}
	for _, port := range []int{s.cfg.AppPort, s.cfg.HealthPort} {
		if _, err := p.WaitHTTP(ctx, fmt.Sprintf("http://127.0.0.1:%d/", port), readyWithin); err != nil {
			return err
		}
	}
	if err := s.awaitReady(ctx, c, p); err != nil {
		return stopped(ctx, c, fmt.Errorf("the app never became ready: %w", err))
	}
	s.ctr, s.probe = c, p
	return nil
}

// awaitReady returns once the app's own Ready or ReadyProbe says the app
// in c, with the probe p installed, is ready: within readyWithin, as its
// ports had to answer.
func (s *suite) awaitReady(ctx context.Context, c *harness.Container, p *harness.Probe) error {
	if s.cfg.Ready == nil && s.cfg.ReadyProbe == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, readyWithin)
	defer cancel()
	if s.cfg.ReadyProbe != nil {
		return s.cfg.ReadyProbe(ctx, c, p)
	}
	return s.cfg.Ready(ctx, c)
}

// stopped adds to err how c ended and what it logged, if it is no longer
// running, which is most often why err happened at all.
func stopped(ctx context.Context, c *harness.Container, err error) error {
	ins, ierr := c.Inspect(ctx)
	if ierr != nil || ins.State.Running {
		return err
	}
	logs, lerr := c.Logs(ctx)
	if lerr != nil {
		return fmt.Errorf("%w; it had stopped, exit status %d, and its log could not be read: %w", err, ins.State.ExitCode, lerr)
	}
	if logs = strings.TrimSpace(logs); logs == "" {
		logs = "(empty)"
	}
	return fmt.Errorf("%w; it had stopped, exit status %d; its log: %s", err, ins.State.ExitCode, logs)
}

// container returns the probe, or why the container it runs in did not
// come up.
func (s *suite) container() (*harness.Probe, error) {
	if s.ctrErr != nil {
		return nil, s.ctrErr
	}
	return s.probe, nil
}

// defaultUser checks the user the image runs as when no --user is given,
// which no container run under the contract can show, since each passes
// --user.
func (s *suite) defaultUser(context.Context, testing.TB) ([]harness.Record, error) {
	if s.imageErr != nil {
		return nil, s.imageErr
	}
	return []harness.Record{
		equal("the image runs as uid/gid 65532 by default", harness.Contract("").User, s.image.User),
	}, nil
}

// fileCapability runs the FrankenPHP binary under the contract. A binary
// carrying a file capability that --cap-drop ALL leaves out of the
// bounding set cannot be executed at all: the kernel answers EPERM before
// a line of PHP runs. It runs in the foreground, since crun reports that
// refusal nowhere else.
func (s *suite) fileCapability(ctx context.Context, tb testing.TB) ([]harness.Record, error) {
	tb.Helper()
	res, err := s.engine.Run(ctx, tb, &harness.RunSpec{
		Image:      s.cfg.Image,
		Network:    "none",
		Confine:    harness.Contract(s.cfg.TmpfsSize),
		Entrypoint: []string{harness.FrankenPHP},
		Args:       []string{"version"},
	})
	if err != nil {
		return nil, err
	}
	found := "exit status 0"
	if res.Code != 0 {
		out := strings.TrimSpace(string(res.Stdout) + string(res.Stderr))
		found = fmt.Sprintf("exit status %d: %s", res.Code, out)
		if execRefused(out) {
			found = "the kernel refused to execute it, as it does a binary carrying a file capability: " + found
		}
	}
	return []harness.Record{{
		OK:       res.Code == 0,
		What:     harness.FrankenPHP + " runs under --cap-drop ALL, so it carries no file capability",
		Expected: "exit status 0",
		Found:    found,
	}}, nil
}

// execRefused reports whether a run's output says the kernel refused to
// execute the FrankenPHP binary, in any runtime's words: runc's "exec
// /usr/local/bin/frankenphp: operation not permitted", or crun's "exec
// container process `/usr/local/bin/frankenphp`: Operation not permitted".
func execRefused(out string) bool {
	return strings.Contains(strings.ToLower(out), "operation not permitted") && strings.Contains(out, harness.FrankenPHP)
}

// xattrRecord is the record no-file-capability-xattr makes.
const xattrRecord = "no file in any layer of the image carries a security.capability extended attribute"

// noFileCapabilityXattr reads the image's layers, as the engine saves
// them, for any file carrying a file capability. fileCapability can see
// only one with the effective bit, which the kernel refuses to exec, and
// only on the FrankenPHP binary: a capability with no effective bit runs,
// as does any binary nothing runs.
func (s *suite) noFileCapabilityXattr(ctx context.Context, tb testing.TB) ([]harness.Record, error) {
	tb.Helper()
	caps, err := s.engine.FileCapabilities(ctx, tb, s.cfg.Image)
	if err != nil {
		return nil, err
	}
	return []harness.Record{equal(xattrRecord, "none", listOrNone(caps))}, nil
}

// probeCheck returns a check that runs one probe subcommand in the
// container, and takes its records.
func (s *suite) probeCheck(sub string, args ...string) func(context.Context, testing.TB) ([]harness.Record, error) {
	return func(ctx context.Context, _ testing.TB) ([]harness.Record, error) {
		p, err := s.container()
		if err != nil {
			return nil, err
		}
		return p.Run(ctx, sub, args...)
	}
}

// noEgress checks the container cannot connect out, from a network the
// engine reports internal. The container serving there at all, and being
// healthy there, is what shows the image needs no route out.
func (s *suite) noEgress(ctx context.Context, _ testing.TB) ([]harness.Record, error) {
	if s.network == "" {
		return nil, s.ctrErr
	}
	// harness.Network reads back what the engine made, and refuses a
	// network that is not internal.
	internal := harness.Record{
		OK:       true,
		What:     "test network really is internal",
		Expected: "true",
		Found:    "true, as " + s.engine.Name() + " network inspect reads it back",
	}
	p, err := s.container()
	if err != nil {
		return []harness.Record{internal}, err
	}
	egress, err := p.Run(ctx, "probe-egress")
	return slices.Concat([]harness.Record{internal}, egress), err
}

// healthcheckConfig checks the image's own HEALTHCHECK, which the engine
// runs on Docker. Podman never reads it from an image published as OCI,
// which is why its users pass --health-cmd, but a Docker user gets it.
func (s *suite) healthcheckConfig(context.Context, testing.TB) ([]harness.Record, error) {
	if s.imageErr != nil {
		return nil, s.imageErr
	}
	return []harness.Record{healthcheckRecord(s.cfg.Healthcheck, s.image.Healthcheck)}, nil
}

// healthcheckRecord checks got, the image's HEALTHCHECK, is want, in
// every field. want is in exec form: validate refuses a Config whose is
// not.
func healthcheckRecord(want Healthcheck, got *Healthcheck) harness.Record {
	r := harness.Record{
		What:     "the image's HEALTHCHECK: the probe in exec form, with no shell, at Baikal's timings",
		Expected: describe(&want),
		Found:    describe(got),
	}
	r.OK = got != nil && slices.Equal(got.Test, want.Test) && got.Interval == want.Interval &&
		got.Timeout == want.Timeout && got.StartPeriod == want.StartPeriod &&
		got.StartInterval == want.StartInterval && got.Retries == want.Retries
	return r
}

// describe says what a HEALTHCHECK is, for a record.
func describe(h *Healthcheck) string {
	if h == nil {
		return "none"
	}
	test, err := json.Marshal(h.Test)
	if err != nil {
		// Unreachable: JSON holds any list of strings.
		panic(err)
	}
	return fmt.Sprintf("%s, interval %s, timeout %s, start period %s, start interval %s, retries %d",
		test, h.Interval, h.Timeout, h.StartPeriod, h.StartInterval, h.Retries)
}

// healthProbe runs the health command in the container, as the engine's
// health check runs it.
func (s *suite) healthProbe(ctx context.Context, _ testing.TB) ([]harness.Record, error) {
	if _, err := s.container(); err != nil {
		return nil, err
	}
	res, err := s.ctr.Exec(ctx, nil, s.cfg.HealthCmd...)
	if err != nil {
		return nil, err
	}
	probe := s.cfg.HealthCmd[len(s.cfg.HealthCmd)-1]
	out := strings.TrimSpace(string(res.Stdout) + string(res.Stderr))
	return []harness.Record{
		equal(probe+" exits 0", "0", strconv.Itoa(res.Code)),
		equal(probe+" prints nothing", "", out),
	}, nil
}

// engineHealthy has the engine's own health machinery judge the
// container: Docker runs the image's HEALTHCHECK, Podman the --health-cmd
// it was given. A shell-form command needs /bin/sh, which no divbast
// image has, so only the exec form can pass.
func (s *suite) engineHealthy(ctx context.Context, _ testing.TB) ([]harness.Record, error) {
	if _, err := s.container(); err != nil {
		return nil, err
	}
	// Docker runs the image's own, so its own start period bounds the wait.
	startPeriod := s.cfg.Healthcheck.StartPeriod
	if s.image.Healthcheck != nil {
		startPeriod = s.image.Healthcheck.StartPeriod
	}
	what := fmt.Sprintf("%s reports it healthy within the %d s start period", s.engine.Name(), int(startPeriod/time.Second))
	want := "healthy"
	if s.engine.Name() == "podman" {
		what, want = "podman healthcheck run", "0"
	}
	found := want
	if err := s.ctr.EngineHealthy(ctx, startPeriod); err != nil {
		found = err.Error()
	}
	return []harness.Record{equal(what, want, found)}, nil
}

// healthPortOnly checks the health port serves /healthz and nothing else,
// and the app port does not serve /healthz. A path that gets no answer is
// a failing record of its own.
func (s *suite) healthPortOnly(ctx context.Context, _ testing.TB) ([]harness.Record, error) {
	p, err := s.container()
	if err != nil {
		return nil, err
	}
	type target struct {
		port int
		path string
	}
	targets := make([]target, 0, len(s.cfg.HealthOnly404)+1)
	for _, path := range s.cfg.HealthOnly404 {
		targets = append(targets, target{s.cfg.HealthPort, path})
	}
	targets = append(targets, target{s.cfg.AppPort, "/healthz"})

	records := make([]harness.Record, 0, len(targets))
	for _, tg := range targets {
		var found string
		resp, err := p.HTTP(ctx, http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d%s", tg.port, tg.path), nil, "")
		if err != nil {
			found = "no answer: " + err.Error()
		} else {
			found = strconv.Itoa(resp.Status)
		}
		records = append(records, equal(fmt.Sprintf("GET :%d%s", tg.port, tg.path), "404", found))
	}
	return records, nil
}

// The records no-volume makes.
const (
	volumeRecord     = "the image declares no VOLUME"
	mountsRecordWhat = "the engine mounts the tmpfs at /tmp and Config.Mounts, and nothing else (Mounts, HostConfig.Tmpfs)"
)

// noVolume checks the image declares no volume, which the engine would
// mount writable whatever the run asked, and that the container under the
// contract has no mount but the tmpfs the contract grants and the ones the
// app's Config gave it.
func (s *suite) noVolume(ctx context.Context, _ testing.TB) ([]harness.Record, error) {
	if s.imageErr != nil {
		return nil, s.imageErr
	}
	declared := equal(volumeRecord, "none", listOrNone(slices.Sorted(maps.Keys(s.image.Volumes))))
	if _, err := s.container(); err != nil {
		return []harness.Record{declared}, err
	}
	ins, err := s.ctr.Inspect(ctx)
	if err != nil {
		return []harness.Record{declared}, err
	}
	return []harness.Record{declared, mountsRecord(s.mounts, &ins)}, nil
}

// mountsRecord checks the mounts ins reports are the contract's tmpfs at
// /tmp and given, the mounts the app's Config gave the container, each
// read-only if it was given so, and nothing else.
func mountsRecord(given []harness.Mount, ins *harness.Inspect) harness.Record {
	want := make([]string, 0, 1+len(given))
	want = append(want, "tmpfs /tmp")
	for _, m := range given {
		kind := "bind"
		if m.Volume {
			kind = "volume"
		}
		want = append(want, mountName(kind, m.Target, !m.ReadOnly))
	}
	found := make([]string, 0, len(ins.HostConfig.Tmpfs)+len(ins.Mounts))
	for dest := range ins.HostConfig.Tmpfs {
		found = append(found, mountName("tmpfs", dest, true))
	}
	for _, m := range ins.Mounts {
		found = append(found, mountName(m.Type, m.Destination, m.RW))
	}
	slices.Sort(want)
	slices.Sort(found)
	foundText := "none"
	if len(found) > 0 {
		foundText = strings.Join(slices.Compact(found), ", ")
	}
	return equal(mountsRecordWhat, strings.Join(want, ", "), foundText)
}

// mountName names a mount for mountsRecord: its kind and where it is in
// the container, and whether the container may not write to it.
func mountName(kind, dest string, rw bool) string {
	if rw {
		return kind + " " + dest
	}
	return kind + " " + dest + " (read-only)"
}

// hostConfig checks how the engine ran the container, which no probe
// inside it can see: a raw flag a test passed could have loosened any of
// it.
func (s *suite) hostConfig(ctx context.Context, _ testing.TB) ([]harness.Record, error) {
	if _, err := s.container(); err != nil {
		return nil, err
	}
	ins, err := s.ctr.Inspect(ctx)
	if err != nil {
		return nil, err
	}
	return hostConfigRecords(ins.HostConfigJSON)
}

// hostConfigRecords checks raw, the HostConfig the engine printed, is the
// contract's: no capability added, not privileged, a read-only root,
// seccomp, AppArmor and SELinux left as the engine confines by default, no
// init in front of the server, and a network namespace of the container's
// own.
//
// A field left out would read as its zero value, which for all but
// ReadonlyRootfs is the value the contract wants, so each record but
// Init's fails when its field is not there at all. Docker and Podman both
// print every one of them, except Docker's Init, which it leaves out
// unless --init was given.
func hostConfigRecords(raw json.RawMessage) ([]harness.Record, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, fmt.Errorf("the engine's HostConfig: %w", err)
	}
	if fields == nil {
		return nil, fmt.Errorf("the engine printed no HostConfig, but %q", raw)
	}
	var h harness.HostConfig
	if err := json.Unmarshal(raw, &h); err != nil {
		return nil, fmt.Errorf("the engine's HostConfig: %w", err)
	}
	records := hostConfigValues(&h)
	for i, field := range hostConfigFields {
		if _, ok := fields[field]; field != "" && !ok {
			records[i].OK = false
			records[i].Found = "absent: the engine printed no HostConfig." + field
		}
	}
	return records, nil
}

// hostConfigFields names the field each of hostConfigValues' records
// reads, in order, and must find printed: all but Init's.
var hostConfigFields = []string{"CapAdd", "Privileged", "ReadonlyRootfs", "SecurityOpt", "", "NetworkMode"}

// hostConfigValues checks the values in h, as hostConfigRecords says.
func hostConfigValues(h *harness.HostConfig) []harness.Record {
	withInit := "unset"
	if h.Init != nil {
		withInit = strconv.FormatBool(*h.Init)
	}
	loosening := slices.DeleteFunc(slices.Clone(h.SecurityOpt), func(opt string) bool { return !loosens(opt) })
	return []harness.Record{
		equal("the engine adds no capability (HostConfig.CapAdd)", "none", listOrNone(h.CapAdd)),
		equal("the container is not privileged (HostConfig.Privileged)", "false", strconv.FormatBool(h.Privileged)),
		equal("the engine mounts the root filesystem read-only (HostConfig.ReadonlyRootfs)", "true", strconv.FormatBool(h.ReadonlyRootfs)),
		{
			OK:       len(loosening) == 0,
			What:     "no security option turns off seccomp, AppArmor or SELinux confinement (HostConfig.SecurityOpt)",
			Expected: "no seccomp or apparmor option, and no label=disable",
			Found:    listOrNone(h.SecurityOpt),
		},
		{
			OK:       h.Init == nil || !*h.Init,
			What:     "the engine puts no init before the entrypoint (HostConfig.Init)",
			Expected: "unset or false",
			Found:    withInit,
		},
		{
			OK:       !sharesNetwork(h.NetworkMode),
			What:     "the container shares no other network namespace (HostConfig.NetworkMode)",
			Expected: "a network of its own: not host, container:<id> or ns:<path>",
			Found:    h.NetworkMode,
		},
	}
}

// loosens reports whether a --security-opt value, as either engine
// records it, changes how seccomp or AppArmor confine the container, or
// turns SELinux labelling off. A profile of one's own counts: nothing
// here can tell whether it confines as tightly as the engine's default.
// Docker takes a colon between key and value as well as =.
func loosens(opt string) bool {
	key, value := opt, ""
	if i := strings.IndexAny(opt, "=:"); i >= 0 {
		key, value = opt[:i], opt[i+1:]
	}
	switch strings.ToLower(key) {
	case "seccomp", "apparmor":
		return true
	case "label":
		return strings.EqualFold(value, "disable")
	default:
		return false
	}
}

// sharesNetwork reports whether a NetworkMode, as either engine reports
// it, is a network namespace other than one of the container's own: the
// host's, another container's, or on Podman one joined by its path.
func sharesNetwork(mode string) bool {
	return mode == "host" || strings.HasPrefix(mode, "container:") || strings.HasPrefix(mode, "ns:")
}

// equal is a record of what, ok when found is want.
func equal(what, want, found string) harness.Record {
	return harness.Record{OK: found == want, What: what, Expected: want, Found: found}
}

// listOrNone returns list joined by spaces, or "none" when it is empty.
func listOrNone(list []string) string {
	if len(list) == 0 {
		return "none"
	}
	return strings.Join(list, " ")
}
