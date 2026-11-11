// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

package pin_test

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/divbast/ci/internal/pin"
)

const (
	sha1 = "3d3c42e5aac5ba805825da76410c181273ba90b1"
	sha2 = "0f6bb7320c4b4a9e3a1d5c3b2a1f0e9d8c7b6a59"
)

// caller is a workflow calling ci's lint.yml at ref, as callers write it.
func caller(ref string) string {
	return `name: build
on: pull_request
permissions: {}
jobs:
  lint:
    uses: divbast/ci/.github/workflows/lint.yml@` + ref + ` # v1.0.0
`
}

// fixture returns a root over a new directory holding files, closed when
// the test ends.
func fixture(t *testing.T, files map[string]string) *os.Root {
	t.Helper()
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := root.Close(); err != nil {
			t.Error(err)
		}
	})
	for name, body := range files {
		if err := root.WriteFile(name, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestFromWorkflows(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		files   map[string]string
		want    string
		wantErr error
		// wantMsg, when set, is the whole error message.
		wantMsg string
	}{
		{
			name: "single",
			files: map[string]string{
				"build.yml": caller(sha1),
				"stall.yml": caller(sha1),
			},
			want: sha1,
		},
		{
			name: "mixed",
			files: map[string]string{
				"build.yml":    caller(sha1),
				"renovate.yml": caller(sha2),
				"stall.yml":    caller(sha1),
			},
			wantErr: pin.ErrMixedPins,
			wantMsg: "workflows pin more than one divbast/ci commit: " +
				sha2 + " in renovate.yml; " + sha1 + " in build.yml, stall.yml",
		},
		{
			name: "none",
			files: map[string]string{
				"build.yml": "jobs:\n  lint:\n    steps:\n      - uses: actions/checkout@" + sha1 + " # v7.0.1\n",
			},
			wantErr: pin.ErrNoPin,
		},
		{
			name: "ignores-other-owners-and-local",
			files: map[string]string{
				"build.yml": "jobs:\n  a:\n    uses: divbast/other/.github/workflows/lint.yml@" + sha1 + "\n" +
					"  b:\n    uses: divbast/cix/.github/workflows/lint.yml@" + sha1 + "\n",
				"local.yml": "jobs:\n  c:\n    uses: ./.github/workflows/x.yml\n",
			},
			wantErr: pin.ErrNoPin,
		},
		{
			name: "ignores-comments-and-other-files",
			files: map[string]string{
				"build.yml": caller(sha1),
				"old.yml":   "jobs:\n  lint:\n    # uses: divbast/ci/.github/workflows/lint.yml@" + sha2 + "\n    uses: ./x.yml\n",
				"notes.md":  "uses: divbast/ci/.github/workflows/lint.yml@" + sha2 + "\n",
			},
			want: sha1,
		},
		{
			name: "yaml-extension-and-quotes",
			files: map[string]string{
				"build.yml":     caller(sha1),
				"stall.yaml":    "jobs:\n  s:\n    uses: \"divbast/ci/.github/workflows/stall.yml@" + sha2 + "\"\n",
				"steps.yml":     "jobs:\n  s:\n    steps:\n      - uses: 'divbast/ci/actions/x@" + sha1 + "'\n",
				"unrelated.yml": "on: push\n",
			},
			wantErr: pin.ErrMixedPins,
			wantMsg: "workflows pin more than one divbast/ci commit: " +
				sha2 + " in stall.yaml; " + sha1 + " in build.yml, steps.yml",
		},
		{
			name: "branch-ref",
			files: map[string]string{
				"build.yml": caller("main"),
			},
			wantErr: pin.ErrNoPin,
			wantMsg: `no workflow pins divbast/ci to a commit: it is called at "main" in build.yml`,
		},
		{
			name: "sha-and-branch",
			files: map[string]string{
				"build.yml": caller(sha1),
				"stall.yml": caller("main"),
			},
			wantErr: pin.ErrMixedPins,
			wantMsg: "workflows pin more than one divbast/ci commit: " +
				sha1 + " in build.yml; main in stall.yml",
		},
		{
			name: "short-sha",
			files: map[string]string{
				"build.yml": caller(sha1[:12]),
			},
			wantErr: pin.ErrNoPin,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := pin.FromWorkflows(fixture(t, tt.files))
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("FromWorkflows() error = %v, want %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("FromWorkflows() = %q, want %q", got, tt.want)
			}
			if tt.wantMsg != "" && err.Error() != tt.wantMsg {
				t.Errorf("FromWorkflows() error message:\n got %s\nwant %s", err, tt.wantMsg)
			}
		})
	}
}

func TestFromWorkflowsUnreadable(t *testing.T) {
	t.Parallel()

	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err = root.Close(); err != nil {
		t.Fatal(err)
	}

	_, err = pin.FromWorkflows(root)
	if err == nil || errors.Is(err, pin.ErrNoPin) || errors.Is(err, pin.ErrMixedPins) {
		t.Fatalf("FromWorkflows(closed root) error = %v, want a read error", err)
	}
	if !strings.Contains(err.Error(), "read") {
		t.Errorf("FromWorkflows(closed root) error = %q, want it to say it could not read", err)
	}
}
