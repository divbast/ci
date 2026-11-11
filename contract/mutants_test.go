// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

package contract

import (
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/divbast/ci/internal/testfixture"
)

// needsContainer is every check that runs in the container under the
// contract, rather than reading the image or running a container of its
// own.
var needsContainer = map[string]bool{
	checkCaps: true, checkReadOnly: true, checkPID1: true, checkNoShell: true, checkListeners: true,
	checkNoEgress: true, checkHealthProbe: true, checkEngineHealthy: true, checkHealthPortOnly: true,
	checkHostConfig: true,
}

// TestContractMutants breaks the contract one way at a time, and exactly
// the check for that one way must fail: a mutant that fails several
// checks proves nothing about any one of them. Each case names the check,
// the record in it that must FAIL, and words its finding must hold, so a
// check failing for some other reason does not count.
func TestContractMutants(t *testing.T) {
	t.Parallel()
	e := integration(t)

	tests := []struct {
		name string
		// mutant is the directory under testdata/mutants its image is built
		// from, FROM the LibreSpeed fixture. Empty runs the fixture itself.
		mutant string
		// loosen holds raw run flags for the container under the contract.
		loosen []string
		check  string   // the one check that must fail
		record string   // the record in it that must FAIL
		found  []string // what that record's finding must hold
		// unstartable is a mutant whose server cannot start under the
		// contract at all, so every check that needs the container fails
		// with it, for that one reason, asserting nothing.
		unstartable bool
	}{
		{
			name: "root-user", mutant: "root-user",
			check: checkDefaultUser, record: "the image runs as uid/gid 65532 by default", found: []string{"0:0"},
		},
		{
			name: "shell", mutant: "shell",
			check: checkNoShell, record: "/bin/sh is absent from the image", found: []string{"present"},
		},
		{
			// The kernel refuses to exec a binary carrying a file capability
			// under --cap-drop ALL, so neither the check's own run nor the
			// server starts. The check must fail on that refusal, in the
			// runtime's own words, and not on a pull or a bad flag.
			name: "filecap", mutant: "filecap",
			check:       checkFileCapability,
			record:      "/usr/local/bin/frankenphp runs under --cap-drop ALL, so it carries no file capability",
			found:       []string{"operation not permitted", "/usr/local/bin/frankenphp"},
			unstartable: true,
		},
		{
			name: "healthcheck", mutant: "healthcheck",
			check:  checkHealthcheckConfig,
			record: "the image's HEALTHCHECK: the probe in exec form, with no shell, at Baikal's timings",
			found:  []string{"interval 31s"},
		},
		{
			name: "listener", mutant: "listener",
			check: checkListeners, record: "TCP ports a process in the container listens on", found: []string{"9090"},
		},
		{
			// Not an image: a flag that loosens the run, which the probe
			// inside cannot see
			name: "seccomp-unconfined", loosen: []string{"--security-opt", "seccomp=unconfined"},
			check:  checkHostConfig,
			record: "no security option turns off seccomp, AppArmor or SELinux confinement (HostConfig.SecurityOpt)",
			found:  []string{"seccomp=unconfined"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()

			image := testfixture.LibreSpeed
			if tt.mutant != "" {
				var err error
				image, err = e.Build(ctx, t, filepath.Join("testdata", "mutants", tt.mutant, "Containerfile"),
					map[string]string{"FIXTURE": testfixture.LibreSpeed})
				if err != nil {
					t.Fatal(err)
				}
			}
			cfg := libreSpeed(image)
			results := check(ctx, t, &cfg, tt.loosen)
			if got := checkNames(results); !slices.Equal(got, allChecks) {
				t.Fatalf("check() ran %q, want %q", got, allChecks)
			}

			var shared string // why the container did not come up
			for _, r := range results {
				for _, rec := range r.Records {
					t.Logf("%s: ok=%t %s (expected %q, found %q)", r.Check, rec.OK, rec.What, rec.Expected, rec.Found)
				}
				if !r.OK {
					t.Logf("%s failed: %s", r.Check, r.Detail)
				}
				if c := crashed(r.Records); len(c) > 0 {
					t.Errorf("%s: a probe crashed rather than checked: %+v", r.Check, c)
				}
				switch {
				case r.Check == tt.check:
					assertFails(t, r, tt.record, tt.found)
				case tt.unstartable && needsContainer[r.Check]:
					if shared == "" {
						shared = r.Detail
					}
					assertBlocked(t, r, shared)
				case !r.OK:
					t.Errorf("%s failed as well, so this mutant proves nothing about %s alone: %s", r.Check, tt.check, r.Detail)
				}
			}
		})
	}
}

// assertFails fails t unless r failed on record, whose finding holds each
// of found, with every other record of r ok.
func assertFails(t *testing.T, r Result, record string, found []string) {
	t.Helper()
	if r.OK {
		t.Errorf("%s passed, want it to fail: %s", r.Check, r.Detail)
	}
	seen := false
	for _, rec := range r.Records {
		if rec.What != record {
			if !rec.OK {
				t.Errorf("%s: %q failed too, want only %q to: found %q", r.Check, rec.What, record, rec.Found)
			}
			continue
		}
		seen = true
		if rec.OK {
			t.Errorf("%s: %q is ok, want it to FAIL: found %q", r.Check, record, rec.Found)
		}
		for _, f := range found {
			if !strings.Contains(strings.ToLower(rec.Found), strings.ToLower(f)) {
				t.Errorf("%s: %q found %q, which does not say %q", r.Check, record, rec.Found, f)
			}
		}
	}
	if !seen {
		t.Errorf("%s made no record %q: %s", r.Check, record, r.Detail)
	}
}

// assertBlocked fails t unless r failed only because the container under
// the contract never came up, for the reason shared, asserting nothing
// false of its own.
func assertBlocked(t *testing.T, r Result, shared string) {
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
