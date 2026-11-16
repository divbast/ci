// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

package harness

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
)

// coreProbePackage is the core probe's main package, built from the ci
// module the module under test requires: in a caller, the one its go.mod
// replaces with ./.ci, so the probe is always the pinned ci commit's, and
// nothing is fetched.
const coreProbePackage = "github.com/divbast/ci/harness/probe/core"

// probeRegistry holds the probe volumes this process made, one for each
// engine, architecture and app probe, and each image's architecture, as
// read once. Every engine EngineFromEnv returns shares one.
type probeRegistry struct {
	mu      sync.Mutex
	arches  map[string]string
	volumes map[probeKey]*probeVolume
}

// probeKey is what tells one probe volume from another.
type probeKey struct{ engine, arch, app string }

// probeVolume is one probe volume, made once: done closes when it is, or
// when making it failed, as err says.
type probeVolume struct {
	done chan struct{}
	name string
	err  error
}

func newProbeRegistry() *probeRegistry {
	return &probeRegistry{arches: make(map[string]string), volumes: make(map[probeKey]*probeVolume)}
}

// sharedProbes is the registry every engine EngineFromEnv returns shares.
var sharedProbes = newProbeRegistry()

// probeArch returns image's architecture, as its configuration names it.
func (e Engine) probeArch(ctx context.Context, tb testing.TB, image string) (string, error) {
	tb.Helper()
	e.probes.mu.Lock()
	arch, ok := e.probes.arches[image]
	e.probes.mu.Unlock()
	if ok {
		return arch, nil
	}
	cfg, err := e.ImageConfig(ctx, tb, image)
	if err != nil {
		return "", fmt.Errorf("the architecture of %s, to build the probe for: %w", image, err)
	}
	if cfg.Architecture == "" {
		return "", fmt.Errorf("%s names no architecture, to build the probe for", image)
	}
	e.probes.mu.Lock()
	e.probes.arches[image] = cfg.Architecture
	e.probes.mu.Unlock()
	return cfg.Architecture, nil
}

// probeVolume returns the probe volume for arch, with the app probe app
// beside the core one when it is not empty, making it on first use: the
// first caller makes it, and every other waits for that and gets the
// same, volume or failure.
//
// The volume carries e's label and outlives the test that made it, since
// every later test of this process mounts it: [Engine.RemoveProbeVolumes]
// removes it, or else the next run's [Engine.Sweep].
//
// A first caller whose context ended while it made the volume fails on
// its own: the entry is dropped, so the next caller, or one waiting with
// a context still live, makes it afresh.
func (e Engine) probeVolume(ctx context.Context, tb testing.TB, arch, app string) (string, error) {
	tb.Helper()
	key := probeKey{engine: e.name, arch: arch, app: app}
	for {
		e.probes.mu.Lock()
		v, ok := e.probes.volumes[key]
		if !ok {
			v = &probeVolume{done: make(chan struct{})}
			e.probes.volumes[key] = v
		}
		e.probes.mu.Unlock()
		if !ok {
			v.name, v.err = e.makeProbeVolume(ctx, tb, arch, app)
			if cancelled(v.err) {
				e.probes.mu.Lock()
				delete(e.probes.volumes, key)
				e.probes.mu.Unlock()
			}
			close(v.done)
			return v.name, v.err
		}
		select {
		case <-v.done:
		case <-ctx.Done():
			return "", ctx.Err()
		}
		if !cancelled(v.err) || ctx.Err() != nil {
			return v.name, v.err
		}
	}
}

// cancelled reports whether err is a context's ending, which says nothing
// of the probe volume itself.
func cancelled(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

// makeProbeVolume builds the probes for arch, static, into an image
// holding nothing else, and fills a new volume from it, by the engine's
// copy of an image's files into an empty volume on first mount. The fill
// runs the core probe itself, from the volume, under the contract, so a
// volume it filled is one a confined container can run the probe from.
func (e Engine) makeProbeVolume(ctx context.Context, tb testing.TB, arch, app string) (string, error) {
	tb.Helper()
	dir, err := os.MkdirTemp("", "divbast-probe-")
	if err != nil {
		return "", err
	}
	defer func() { _ = os.RemoveAll(dir) }()
	image, err := e.probeImage(ctx, tb, dir, arch, app)
	if err != nil {
		return "", fmt.Errorf("building the probe image: %w", err)
	}

	name := "divbast-probe-" + strings.TrimPrefix(uniqueName(), "divbast-")
	if _, err = e.output(ctx, "volume", "create", "--label", e.label, name); err != nil {
		return "", err
	}
	// From here the volume exists: a failure returns its name too, so
	// RemoveProbeVolumes removes it with the rest
	res, err := e.Run(ctx, tb, &RunSpec{
		Image:      image,
		Network:    "none",
		Confine:    Contract("1m"),
		Mounts:     []Mount{{Source: name, Target: ProbeMount, Volume: true}},
		Entrypoint: []string{CoreProbePath},
		Args:       []string{"is-file", CoreProbePath},
	})
	if err != nil {
		return name, err
	}
	if res.Code != 0 || strings.TrimSpace(string(res.Stdout)) != present {
		return name, fmt.Errorf("the probe volume %s: %s could not run the probe from it, so the probe image's files "+
			"were not copied into it on first mount, or cannot run there: exit status %d: %s", name, e.name, res.Code, combined(res))
	}
	return name, nil
}

// probeImage builds the core probe, and app when it is not empty, into
// dir, and an image from scratch holding them at CoreProbePath and
// AppProbePath, which it returns.
func (e Engine) probeImage(ctx context.Context, tb testing.TB, dir, arch, app string) (string, error) {
	tb.Helper()
	root, err := e.moduleRoot(ctx)
	if err != nil {
		return "", err
	}
	builds := []struct{ out, pkg, at string }{{"core", coreProbePackage, CoreProbePath}}
	if app != "" {
		builds = append(builds, struct{ out, pkg, at string }{"app", app, AppProbePath})
	}
	var containerfile strings.Builder
	containerfile.WriteString("FROM scratch\n")
	for _, b := range builds {
		err = e.buildProbe(ctx, root, arch, filepath.Join(dir, b.out), b.pkg)
		if err != nil {
			return "", err
		}
		// go build's output keeps the host's umask, which may leave it
		// 0700, root's in the image, and no one else's to run
		containerfile.WriteString("COPY --chmod=0555 " + b.out + " " + b.at + "\n")
	}
	err = os.WriteFile(filepath.Join(dir, "Containerfile"), []byte(containerfile.String()), 0o600)
	if err != nil {
		return "", err
	}
	return e.Build(ctx, tb, filepath.Join(dir, "Containerfile"), nil)
}

// moduleRoot returns the directory of the main module the tests run in,
// whose go.mod names the ci module the probe is built from.
func (e Engine) moduleRoot(ctx context.Context) (string, error) {
	res, err := e.run.RunStdin(ctx, nil, "go", "env", "GOMOD")
	if err != nil {
		return "", fmt.Errorf("finding the module to build the probe in: %w", err)
	}
	gomod := strings.TrimSpace(string(res.Stdout))
	if res.Code != 0 || gomod == "" || gomod == os.DevNull {
		return "", fmt.Errorf("the probe is built in the module under test, and go env GOMOD names none: exit status %d: %s",
			res.Code, combined(res))
	}
	return filepath.Dir(gomod), nil
}

// buildProbe builds pkg, in the module at root, static, for linux on
// arch, to out.
func (e Engine) buildProbe(ctx context.Context, root, arch, out, pkg string) error {
	argv := []string{"CGO_ENABLED=0", "GOOS=linux", "GOARCH=" + arch, "go", "-C", root, "build", "-trimpath", "-o", out, pkg}
	res, err := e.run.RunStdin(ctx, nil, "env", argv...)
	if err != nil {
		return fmt.Errorf("building the probe %s: %w", pkg, err)
	}
	if res.Code != 0 {
		return fmt.Errorf("building the probe %s for linux/%s: exit status %d: %s", pkg, arch, res.Code, bytes.TrimSpace(res.Stderr))
	}
	return nil
}

// RemoveProbeVolumes removes the probe volumes this process made through
// e, for a suite's TestMain to call once m.Run has returned: no test is
// left to mount them. Each is made again if a test asks for it after.
// A suite that never calls it leaves them to the next run's
// [Engine.Sweep].
func (e Engine) RemoveProbeVolumes(ctx context.Context) error {
	e.probes.mu.Lock()
	defer e.probes.mu.Unlock()
	var names []string
	for key, v := range e.probes.volumes {
		if key.engine != e.name {
			continue
		}
		select {
		case <-v.done:
		default:
			// Still being made: whoever asked for it will use it.
			continue
		}
		if v.name != "" {
			names = append(names, v.name)
		}
		delete(e.probes.volumes, key)
	}
	if len(names) == 0 {
		return nil
	}
	slices.Sort(names)
	_, err := e.output(ctx, append([]string{"volume", "rm"}, names...)...)
	return err
}
