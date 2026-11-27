// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

package testfixture

import (
	"bytes"
	"strings"
	"testing"
	"testing/synctest"

	"github.com/divbast/ci/internal/execx"
)

// TestPull leaves a fixture that is here as it is, and pulls one that is
// not, again through Fetch while the registry answers with a server
// error. A fixture that cannot be pulled is an error naming its pull,
// and the others are pulled all the same.
func TestPull(t *testing.T) {
	t.Parallel()

	inspect := func(engine, image string, here bool) execx.Call {
		c := execx.Call{Argv: []string{engine, "image", "inspect", "--format", "{{.Id}}", image}}
		if here {
			c.Result.Stdout = []byte("sha256:123d515e67002d5affbbbce43920d2b0ebe30e3da40e74c3a814e7bb457c9a8d\n")
		} else {
			c.Result = execx.Result{Code: 125, Stderr: []byte("Error: " + image + ": image not known\n")}
		}
		return c
	}
	pull := func(engine, image string, code int, stderr string) execx.Call {
		return execx.Call{Argv: []string{engine, "pull", "-q", image}, Result: execx.Result{Code: code, Stderr: []byte(stderr)}}
	}
	unknown := "Error: initializing source docker://" + Baikal + ": reading manifest in ghcr.io/divbast/baikal: manifest unknown\n"

	for _, tt := range []struct {
		name, engine string
		images       []string
		calls        []execx.Call
		wantErr      string
		wantAgain    int
	}{
		{name: "here", engine: "podman", images: []string{LibreSpeed}, calls: []execx.Call{inspect("podman", LibreSpeed, true)}},
		{
			name: "pulled", engine: "docker", images: []string{LibreSpeed},
			calls: []execx.Call{inspect("docker", LibreSpeed, false), pull("docker", LibreSpeed, 0, "")},
		},
		{
			name: "pulled-after-a-500", engine: "podman", images: []string{LibreSpeed},
			calls: []execx.Call{
				inspect("podman", LibreSpeed, false), pull("podman", LibreSpeed, 125, podman500), pull("podman", LibreSpeed, 0, ""),
			},
			wantAgain: 1,
		},
		{
			name: "one-of-two-refused", engine: "podman", images: []string{Baikal, LibreSpeed},
			calls: []execx.Call{
				inspect("podman", Baikal, false), pull("podman", Baikal, 125, unknown),
				inspect("podman", LibreSpeed, false), pull("podman", LibreSpeed, 0, ""),
			},
			wantErr: "podman pull " + Baikal + ", attempt 1 of 3: exit status 125: Error: initializing source",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			synctest.Test(t, func(t *testing.T) {
				var log bytes.Buffer
				err := Pull(t.Context(), execx.NewFake(t, tt.calls...), &log, tt.engine, tt.images...)
				if again := strings.Count(log.String(), "so fetching again"); again != tt.wantAgain {
					t.Errorf("Pull() logged %d pulls again, want %d: %q", again, tt.wantAgain, log.String())
				}
				if tt.wantErr == "" {
					if err != nil {
						t.Fatalf("Pull() error = %v", err)
					}
					return
				}
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("Pull() error = %v, want one holding %q", err, tt.wantErr)
				}
			})
		})
	}
}
