// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

package contract

import (
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/divbast/ci/harness"
	"github.com/divbast/ci/internal/testfixture"
)

// needsContainer is every check that runs in the container under the
// contract, rather than reading the image or running a container of its
// own.
var needsContainer = map[string]bool{
	checkRuntimeUser: true, checkCaps: true, checkReadOnly: true, checkNoVolume: true, checkPID1: true, checkNoShell: true,
	checkListeners: true, checkNoEgress: true, checkHealthProbe: true, checkEngineHealthy: true, checkHealthPortOnly: true,
	checkHostConfig: true,
}

// failure is a record a mutant must make FAIL: the check that makes it,
// its name, and words its finding must hold, so a check failing for some
// other reason does not count.
type failure struct {
	check, record string
	found         []string
}

// mutant is one way of breaking the contract.
type mutant struct {
	name string
	// dir is the directory under testdata/mutants its image is built from,
	// FROM the fixture, which it takes as the build argument FIXTURE.
	// Empty runs the fixture itself.
	dir string
	// loosen holds raw run flags for the container under the contract.
	loosen []string
	// fails is every record that must FAIL. Every other record, of these
	// checks or any other, must be ok.
	fails []failure
	// unstartable is a mutant whose server cannot start under the
	// contract at all, so every check that needs the container fails
	// with it, for that one reason, asserting nothing.
	unstartable bool
}

// TestContractMutants breaks the contract one way at a time, and exactly
// the records that way breaks must fail: a mutant that fails other checks
// as well proves nothing about any one of them.
func TestContractMutants(t *testing.T) {
	t.Parallel()
	e := integration(t)

	for _, m := range []mutant{
		{
			name: "root-user", dir: "root-user",
			fails: []failure{{checkDefaultUser, "the image runs as uid/gid 65532 by default", []string{"0:0"}}},
		},
		{
			name: "shell", dir: "shell",
			fails: []failure{{checkNoShell, "/bin/sh is absent from the image", []string{"present"}}},
		},
		{
			// A shell 65532 cannot look up is not proven absent. The
			// directory hides bash and dash alike, which are not there.
			name: "shell-unsearchable", dir: "shell-unsearchable",
			fails: []failure{
				{checkNoShell, "/bin/sh is absent from the image", []string{"Permission denied"}},
				{checkNoShell, "/bin/bash is absent from the image", []string{"Permission denied"}},
				{checkNoShell, "/bin/dash is absent from the image", []string{"Permission denied"}},
			},
		},
		{
			// The kernel refuses to exec a binary carrying a file capability
			// under --cap-drop ALL, so neither the check's own run nor the
			// server starts. The check must fail on that refusal, in the
			// runtime's own words, and not on a pull or a bad flag. The scan
			// of the layers finds the capability without running anything.
			name: "filecap", dir: "filecap",
			fails: []failure{
				{checkFileCapability, fileCapabilityRecord, []string{"operation not permitted", "/usr/local/bin/frankenphp"}},
				{checkNoFileCapabilityXattr, xattrRecord, []string{"/usr/local/bin/frankenphp"}},
			},
			unstartable: true,
		},
		{
			name: "healthcheck", dir: "healthcheck",
			fails: []failure{{checkHealthcheckConfig, healthcheckRecordWhat, []string{"interval 31s"}}},
		},
		{
			name: "listener", dir: "listener",
			fails: []failure{{checkListeners, "TCP ports a process in the container listens on", []string{"9090"}}},
		},
		{
			// Not an image: a flag that loosens the run, which the probe
			// inside cannot see
			name: "seccomp-unconfined", loosen: []string{"--security-opt", "seccomp=unconfined"},
			fails: []failure{{
				checkHostConfig,
				"no security option turns off seccomp, AppArmor or SELinux confinement (HostConfig.SecurityOpt)",
				[]string{"seccomp=unconfined"},
			}},
		},
	} {
		t.Run(m.name, func(t *testing.T) {
			t.Parallel()
			runMutant(t, e, testfixture.LibreSpeed, libreSpeed, &m)
		})
	}
}

// runMutant builds m from fixture, checks it under the contract config
// returns for it, and fails t unless exactly the records m names fail.
func runMutant(t *testing.T, e harness.Engine, fixture string, config func(image string) Config, m *mutant) {
	t.Helper()
	ctx := t.Context()

	image := fixture
	if m.dir != "" {
		var err error
		image, err = e.Build(ctx, t, filepath.Join("testdata", "mutants", m.dir, "Containerfile"),
			map[string]string{"FIXTURE": fixture})
		if err != nil {
			t.Fatal(err)
		}
	}
	cfg := config(image)
	results := check(ctx, t, &cfg, m.loosen)
	if got := checkNames(results); !slices.Equal(got, allChecks) {
		t.Fatalf("check() ran %q, want %q", got, allChecks)
	}

	var shared string // why the container did not come up
	for i := range results {
		r := &results[i]
		for _, rec := range r.Records {
			t.Logf("%s: ok=%t %s (expected %q, found %q)", r.Check, rec.OK, rec.What, rec.Expected, rec.Found)
		}
		if !r.OK {
			t.Logf("%s failed: %s", r.Check, r.Detail)
		}
		if c := crashed(r.Records); len(c) > 0 {
			t.Errorf("%s: a probe crashed rather than checked: %+v", r.Check, c)
		}
		fails := slices.DeleteFunc(slices.Clone(m.fails), func(f failure) bool { return f.check != r.Check })
		switch {
		case len(fails) > 0:
			assertFails(t, r, fails)
		case m.unstartable && needsContainer[r.Check]:
			if shared == "" {
				shared = r.Detail
			}
			assertBlocked(t, r, shared)
		case !r.OK:
			t.Errorf("%s failed as well, so this mutant proves nothing about the records it names alone: %s", r.Check, r.Detail)
		}
	}
	for _, f := range m.fails {
		if !slices.Contains(allChecks, f.check) {
			t.Errorf("no check %s ran, to fail %q", f.check, f.record)
		}
	}
}

// assertFails fails t unless r failed on each of fails, each finding
// holding the words its failure names, with every other record of r ok.
func assertFails(t *testing.T, r *Result, fails []failure) {
	t.Helper()
	if r.OK {
		t.Errorf("%s passed, want it to fail: %s", r.Check, r.Detail)
	}
	for _, f := range fails {
		i := slices.IndexFunc(r.Records, func(rec harness.Record) bool { return rec.What == f.record })
		if i < 0 {
			t.Errorf("%s made no record %q: %s", r.Check, f.record, r.Detail)
			continue
		}
		rec := r.Records[i]
		if rec.OK {
			t.Errorf("%s: %q is ok, want it to FAIL: found %q", r.Check, f.record, rec.Found)
		}
		for _, word := range f.found {
			if !strings.Contains(strings.ToLower(rec.Found), strings.ToLower(word)) {
				t.Errorf("%s: %q found %q, which does not say %q", r.Check, f.record, rec.Found, word)
			}
		}
	}
	for _, rec := range r.Records {
		named := slices.ContainsFunc(fails, func(f failure) bool { return f.record == rec.What })
		if !named && !rec.OK {
			t.Errorf("%s: %q failed too, want only the records named to: found %q", r.Check, rec.What, rec.Found)
		}
	}
}

// assertBlocked fails t unless r failed only because the container under
// the contract never came up, for the reason shared, asserting nothing
// false of its own.
func assertBlocked(t *testing.T, r *Result, shared string) {
	t.Helper()
	for _, rec := range r.Records {
		if !rec.OK {
			t.Errorf("%s: %q failed on its own, want it blocked by the container alone: found %q", r.Check, rec.What, rec.Found)
		}
	}
	if r.OK || r.Detail != shared || !strings.Contains(r.Detail, "did not come up") {
		t.Errorf("%s: OK = %t, Detail %q; want it blocked by the container that did not come up: %q", r.Check, r.OK, r.Detail, shared)
	}
}
