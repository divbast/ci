// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

// Package harness is divbast's acceptance harness. It drives containers
// through the docker or podman CLI, with the same flags a user would type,
// so a check runs under exactly the confinement an image's contract claims
// and never a looser one an SDK might set up instead. It also brings the
// probe those checks run inside a container: a static Go binary, built
// from the ci module the tests require, for the image's architecture, and
// mounted read-only from a volume, so it needs nothing in the image at
// all. A PHP app's own subcommands run under the app's own PHP instead.
//
// Every container, image, network and volume it makes carries the label
// divbast.harness=<module>, where <module> is the path of the main module
// of the binary running it, and is removed when the test that made it
// ends. An app's acceptance suite is a test binary of the app's own
// module, so each repository's suite has a label of its own, and
// [Engine.Sweep] removes whatever a run of it that died left behind, and
// nothing another repository's suite on the same host made. A second
// label, divbast.harness.run, names the run that made it: the host and
// the process, so a Sweep leaves alone what another run of the same
// suite that is still going made.
package harness

import (
	"bytes"
	"cmp"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"runtime/debug"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/divbast/ci/internal/execx"
)

// Label is the label the harness gave everything it made, whichever suite
// ran it, before it labelled by module.
//
// Deprecated: nothing the harness makes carries Label, and Sweep does not
// remove by it. [Engine.Label] returns the label it gives instead.
const Label = "divbast.harness=1"

// labelKey is the key of the label the harness gives everything it makes.
const labelKey = "divbast.harness"

// moduleLabel is the label this binary gives everything it makes,
// worked out once.
var moduleLabel = sync.OnceValue(func() string { return labelFor(debug.ReadBuildInfo()) })

// labelFor returns the label for a binary whose build info is bi, which ok
// says it records: labelKey, and the main module's path as its value. A
// binary that records no main module, as a test of files named on go
// test's command line does not, gets a unique value of its own instead, so
// its Sweep can only ever remove what it made itself.
func labelFor(bi *debug.BuildInfo, ok bool) string {
	if ok && bi.Main.Path != "" {
		return labelKey + "=" + bi.Main.Path
	}
	return labelKey + "=" + uniqueName()
}

// cleanupTimeout bounds each removal a test's cleanup runs. The test's own
// context is done by then.
const cleanupTimeout = 2 * time.Minute

// runner runs what the harness runs: the engine's CLI, fed a stdin when
// it reads one, and the zstd command, whose output a layer's reader reads
// as it writes it.
type runner interface {
	execx.StdinRunner
	execx.StreamRunner
}

// Engine is the container engine's CLI: docker or podman.
type Engine struct {
	name string
	run  runner
	// own is whose e's things are. Every engine EngineFromEnv returns for
	// the same engine shares one. It is a pointer, as the three below
	// are, so that an Engine stays small enough to pass by value.
	own *owner
	// saves holds what its saves of images read. Every engine
	// EngineFromEnv returns shares one.
	saves *saveCache
	// store keeps an image's removal from overlapping a build, on
	// Podman. Every engine EngineFromEnv returns shares one, with every
	// other process of the user's on the host.
	store *storeLock
	// probes holds the probe volumes it made. Every engine EngineFromEnv
	// returns shares one.
	probes *probeRegistry
}

// owner is whose an engine's things are: the labels they carry, and the
// lock its sweeps of them take.
type owner struct {
	// label is the module's label, except in the tests of Sweep, which
	// must not remove what tests running beside them made.
	label string
	// run is the run its run label names: this process's, except in the
	// tests of Sweep, which make the runs a Sweep tells apart.
	run runID
	// sweeps keeps two sweeps of its engine from running at once: with
	// every other process of the user's that shares its lock directory,
	// for an engine EngineFromEnv returns.
	sweeps *sweepLock
}

// sharedOwners is the owner of every engine EngineFromEnv returns, by
// the engine's name.
var sharedOwners = map[string]func() *owner{
	"docker": sync.OnceValue(func() *owner {
		return &owner{label: moduleLabel(), run: processRun(), sweeps: sharedSweeps["docker"]()}
	}),
	"podman": sync.OnceValue(func() *owner {
		return &owner{label: moduleLabel(), run: processRun(), sweeps: sharedSweeps["podman"]()}
	}),
}

// EngineFromEnv returns the engine $ENGINE names: docker, the default when
// it is unset or empty, or podman. Anything else is an error.
func EngineFromEnv() (Engine, error) {
	switch name := cmp.Or(os.Getenv("ENGINE"), "docker"); name {
	case "docker", "podman":
		e := newEngine(name, execx.OS{})
		e.saves = sharedSaves
		e.store = sharedStore()
		e.probes = sharedProbes
		e.own = sharedOwners[name]()
		return e, nil
	default:
		return Engine{}, fmt.Errorf("ENGINE is %q: it must be docker or podman", name)
	}
}

func newEngine(name string, run runner) Engine {
	return Engine{
		name: name, run: run, own: &owner{label: moduleLabel(), run: processRun(), sweeps: newSweepLock("")},
		saves: newSaveCache(), store: newStoreLock(""), probes: newProbeRegistry(),
	}
}

// Name returns the engine's command: docker or podman.
func (e Engine) Name() string { return e.name }

// Label returns the label, as key=value, that everything e makes carries,
// and that [Engine.Sweep] removes by: divbast.harness, and the path of the
// running binary's main module as its value.
func (e Engine) Label() string {
	if e.own == nil {
		return ""
	}
	return e.own.label
}

// labels returns the flags that give what e makes its labels: the
// module's, and its run's. An Engine made by no constructor has neither,
// and labels nothing.
func (e Engine) labels() []string {
	if e.own == nil {
		return nil
	}
	return []string{"--label", e.own.label, "--label", e.own.run.label()}
}

// sweepKinds is what Sweep removes, in order: containers first, since an
// image, network or volume one still uses cannot go. Each lists the IDs,
// or names, of what carries a label, and inspects them, printing each
// one's ID, or name, and its labels as JSON.
var sweepKinds = []struct{ list, inspect, remove []string }{
	{
		list:    []string{"ps", "-a", "-q", "--no-trunc"},
		inspect: []string{"container", "inspect", "--format", "{{.Id}} {{json .Config.Labels}}"},
		remove:  []string{"rm", "-f", "-v"},
	},
	{
		list:    []string{"image", "ls", "-q", "--no-trunc"},
		inspect: []string{"image", "inspect", "--format", "{{.Id}} {{json .Config.Labels}}"},
		remove:  []string{"image", "rm", "-f"},
	},
	{
		list:    []string{"network", "ls", "--format", "{{.Name}}"},
		inspect: []string{"network", "inspect", "--format", "{{.Name}} {{json .Labels}}"},
		remove:  []string{"network", "rm"},
	},
	{
		list:    []string{"volume", "ls", "-q"},
		inspect: []string{"volume", "inspect", "--format", "{{.Name}} {{json .Labels}}"},
		remove:  []string{"volume", "rm"},
	},
}

// Sweep removes every container, image, network and volume that carries
// e's label and that a run which has ended made: what carries no run
// label, as what an older harness made, what e's own run made, and what a
// run made whose process on this host is gone. That label is the
// module's, so whatever another module's suite made on the same host
// stays, and so does what another run of this module's that is still
// going made: Sweep can run while other runs of the suite do, as two runs
// of it on one host at once, each sweeping as it starts.
//
// A run is known by its host's name and its process ID, and where that
// cannot tell, it keeps what the run made: what a run on another host
// made stays until a sweep there finds its process gone. Where each
// container run gets a fresh host name, what such a run made stays for
// good, since no later sweep shares its host name. A process ID that
// another process has taken since, after a reboot say, keeps what the
// run made until that process ends too. The one case that leans the
// other way is a host name that processes in different PID namespaces
// share: a run's process in one of them looks gone from the other, and a
// sweep there removes what it made.
//
// Two sweeps of one engine run one after the other, within a process and
// across the processes that share the directory of the harness's lock
// files, so that both never set out to remove the same thing: Sweep waits
// for one that is running, until ctx is done. On Podman, its removal of
// images also waits for every build running to end, as [Engine.Build]'s
// cleanup does. Something that is gone by the time Sweep removes it, which
// a sweep under an older pin may have removed, is no failure. Every
// failure is returned, joined, and none stops the rest.
func (e Engine) Sweep(ctx context.Context) error {
	release, err := e.own.sweeps.hold(ctx)
	if err != nil {
		return fmt.Errorf("%s: waiting for another sweep to end: %w", e.name, err)
	}
	defer release()
	var errs []error
	for _, k := range sweepKinds {
		if err := e.sweep(ctx, k.list, k.inspect, k.remove); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// sweep is [Engine.Sweep] for one kind of thing: what list lists under e's
// label, inspect reads the run labels of, and remove removes.
func (e Engine) sweep(ctx context.Context, list, inspect, remove []string) error {
	filter := []string{"--filter", "label=" + e.own.label}
	out, err := e.output(ctx, slices.Concat(list, filter)...)
	if err != nil {
		return err
	}
	// An image is listed once for each of its tags.
	ids := slices.Compact(slices.Sorted(slices.Values(strings.Fields(string(out)))))
	if len(ids) == 0 {
		return nil
	}
	runs, err := e.runLabels(ctx, inspect, ids)
	if err != nil {
		return err
	}
	ended := slices.DeleteFunc(slices.Clone(ids), func(id string) bool {
		value, ok := runs[bareID(id)]
		// Not ok: removed since it was listed
		return !ok || !e.ended(value)
	})
	if len(ended) == 0 {
		return nil
	}
	return e.removeAll(ctx, remove, ended, slices.Concat(list, filter))
}

// bareID is id without the sha256: Podman's image inspect leaves off, so
// that what a list prints and what an inspect prints compare.
func bareID(id string) string {
	return strings.TrimPrefix(id, "sha256:")
}

// runLabels returns the value of the run label of each of ids, as inspect
// prints them, by its bare ID: "" for one that carries none. One that is
// gone by the time it runs is left out, and the engine's refusal of it is
// no failure.
func (e Engine) runLabels(ctx context.Context, inspect, ids []string) (map[string]string, error) {
	argv := slices.Concat(inspect, ids)
	res, err := e.run.RunStdin(ctx, nil, e.name, argv...)
	if err != nil {
		return nil, err
	}
	if res.Code != 0 && !allGone(res.Stderr) {
		return nil, fmt.Errorf("%s %s: exit status %d: %s", e.name, strings.Join(argv, " "), res.Code, bytes.TrimSpace(res.Stderr))
	}
	runs := make(map[string]string, len(ids))
	for line := range strings.Lines(string(res.Stdout)) {
		// Docker prints an empty line for one that is gone
		if line = strings.TrimSpace(line); line == "" {
			continue
		}
		id, labels, ok := strings.Cut(line, " ")
		if !ok {
			return nil, fmt.Errorf("%s %s printed %q, which is no ID and labels", e.name, strings.Join(inspect, " "), line)
		}
		var got map[string]string
		if err := json.Unmarshal([]byte(labels), &got); err != nil {
			return nil, fmt.Errorf("%s %s printed labels that are not JSON for %s: %w", e.name, strings.Join(inspect, " "), id, err)
		}
		runs[bareID(id)] = got[runKey]
	}
	return runs, nil
}

// allGone reports whether every line of stderr says that what it names
// is not there, in either engine's words.
func allGone(stderr []byte) bool {
	said := false
	for line := range bytes.Lines(stderr) {
		if line = bytes.TrimSpace(line); len(line) == 0 {
			continue
		}
		if !gone(line) {
			return false
		}
		said = true
	}
	return said
}

// removeAll runs the engine's remove command for ids, once no build holds
// the store when what it removes is images. The engine refuses to remove
// a network or a volume that is gone, which something else, such as a
// sweep under an older pin, may have removed since it was listed. So when
// the command fails, list lists again what is left, and only one of ids
// still there makes the failure Sweep's.
func (e Engine) removeAll(ctx context.Context, remove, ids, list []string) error {
	if remove[0] == "image" {
		release, err := e.hold(ctx, true)
		if err != nil {
			return fmt.Errorf("%s %s: waiting for the builds beside it to end: %w", e.name, strings.Join(remove, " "), err)
		}
		defer release()
	}
	_, err := e.output(ctx, slices.Concat(remove, ids)...)
	if err == nil {
		return nil
	}
	out, lerr := e.output(ctx, list...)
	if lerr != nil {
		return errors.Join(err, lerr)
	}
	left := strings.Fields(string(out))
	if slices.ContainsFunc(ids, func(id string) bool { return slices.Contains(left, id) }) {
		return err
	}
	return nil
}

// output runs the engine and returns what it printed. A command that exits
// non-zero is an error naming it, with its exit status and stderr.
func (e Engine) output(ctx context.Context, args ...string) ([]byte, error) {
	res, err := e.run.RunStdin(ctx, nil, e.name, args...)
	if err != nil {
		return nil, err
	}
	if res.Code != 0 {
		return nil, fmt.Errorf("%s %s: exit status %d: %s", e.name, strings.Join(args, " "), res.Code, bytes.TrimSpace(res.Stderr))
	}
	return res.Stdout, nil
}

// cleanupContext returns a context for a cleanup to remove something in.
// A test's context is done before its cleanups run, so this keeps ctx's
// values and drops its cancellation, then bounds the removal on its own.
func cleanupContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), cleanupTimeout)
}

// remove runs the engine with args, which remove something tb made, for a
// cleanup. Something already gone is no failure; anything else that stops
// the removal fails the test.
func (e Engine) remove(ctx context.Context, tb testing.TB, args ...string) {
	tb.Helper()
	res, err := e.run.RunStdin(ctx, nil, e.name, args...)
	switch {
	case err != nil:
		tb.Errorf("cleanup: %v", err)
	case res.Code != 0 && !gone(res.Stderr):
		tb.Errorf("cleanup: %s %s: exit status %d: %s", e.name, strings.Join(args, " "), res.Code, bytes.TrimSpace(res.Stderr))
	}
}

// removeOnCleanup has tb's cleanup remove something it made, with args.
func (e Engine) removeOnCleanup(ctx context.Context, tb testing.TB, args ...string) {
	tb.Helper()
	tb.Cleanup(func() {
		rmCtx, cancel := cleanupContext(ctx)
		defer cancel()
		e.remove(rmCtx, tb, args...)
	})
}

// gone reports whether an engine's error says what it was asked to remove
// does not exist, in the words either engine uses.
func gone(stderr []byte) bool {
	s := bytes.ToLower(stderr)
	return bytes.Contains(s, []byte("no such container")) ||
		bytes.Contains(s, []byte("no such volume")) ||
		bytes.Contains(s, []byte("no such image")) ||
		bytes.Contains(s, []byte("image not known")) ||
		bytes.Contains(s, []byte("not found"))
}

// uniqueName returns a name no other run will have chosen, for a container,
// network or volume the caller left unnamed.
func uniqueName() string {
	return "divbast-" + strings.ToLower(rand.Text()[:12])
}
