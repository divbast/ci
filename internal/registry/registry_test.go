// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

package registry_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/divbast/ci/internal/execx"
	"github.com/divbast/ci/internal/ghapi"
	"github.com/divbast/ci/internal/registry"
)

const (
	latest    = "ghcr.io/divbast/librespeed:latest"
	noTag     = "ghcr.io/divbast/librespeed:no-such-tag"
	noPackage = "ghcr.io/divbast/no-such-package:latest"
	revision  = "24e63e21ef880cd22c26964ee987fa593f5e92fc"

	librespeedAPI = "orgs/divbast/packages/container/librespeed"
	noPackageAPI  = "orgs/divbast/packages/container/no-such-package"
)

// stderr returns skopeo's stderr from one of the recordings in testdata,
// all made by skopeo 1.24.1 with an empty DOCKER_CONFIG and
// REGISTRY_AUTH_FILE, as skopeo inspect --raw --no-creds docker://REF:
//
//	skopeo-no-such-package.txt  ghcr.io/divbast/no-such-package:latest
//	skopeo-no-such-tag.txt      ghcr.io/divbast/librespeed:no-such-tag
//	skopeo-timeout.txt          ghcr.io/divbast/librespeed:latest, under
//	                            skopeo --command-timeout 1ms
//	skopeo-denied.txt           docker.io/divbast/no-such-repo-t4:latest
//	skopeo-unauthorized.txt     quay.io/divbast/no-such-repo-t4:latest
//	skopeo-name-unknown.txt     public.ecr.aws/divbast/no-such-repo-t4:latest
//	skopeo-token-503.txt        a local stub registry that answers the
//	                            token request 503
//	skopeo-manifest-503.txt     one that answers the manifest 503
//	skopeo-manifest-429.txt     one that answers the manifest 429
//
// ghcr.io never says denied, unauthorized or name unknown to an anonymous
// client: a missing or private package gets a 403 on the token request.
// Those three come from registries that do, and are replayed here as if
// ghcr.io had said them, since nothing stops it doing so. Nor can ghcr.io
// be made to fail on demand, hence the stub.
func stderr(t *testing.T, name string) []byte {
	t.Helper()
	return readTestdata(t, name)
}

// readTestdata returns the file name in testdata.
func readTestdata(t *testing.T, name string) []byte {
	t.Helper()
	root, err := os.OpenRoot("testdata")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	data, err := root.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// failed is skopeo exiting code with the recorded stderr in name.
func failed(t *testing.T, name string, code int) execx.Result {
	t.Helper()
	return execx.Result{Stderr: stderr(t, name), Code: code}
}

// index is skopeo printing an image index with these annotations.
func index(annotations string) execx.Result {
	return execx.Result{Stdout: []byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[],` +
		`"annotations":` + annotations + `}`)}
}

// pkg is gh api -i answering 200 with a package of this visibility, shaped
// like GitHub's documented response for "Get a package for an
// organization".
func pkg(visibility string) execx.Result {
	return execx.Result{Stdout: []byte("HTTP/2.0 200 OK\n" +
		"Content-Type: application/json; charset=utf-8\r\n\r\n" +
		`{"id":1,"name":"librespeed","package_type":"container","visibility":"` + visibility + `"}`)}
}

// status is gh api -i answering a non-2xx status, which gh exits 1 on.
func status(code int, text string) execx.Result {
	return execx.Result{
		Stdout: fmt.Appendf(nil, "HTTP/2.0 %d %s\nContent-Type: application/json; charset=utf-8\r\n\r\n"+
			`{"message":%q,"status":"%d"}`, code, text, text, code),
		Stderr: fmt.Appendf(nil, "gh: %s (HTTP %d)\n", text, code),
		Code:   1,
	}
}

func skopeoArgv(image string) []string {
	return []string{"skopeo", "inspect", "--raw", "--no-creds", "docker://" + image}
}

func TestRevision(t *testing.T) {
	t.Parallel()

	published := readTestdata(t, "skopeo-librespeed-latest.json")
	tokenRefused := failed(t, "skopeo-no-such-package.txt", 1)

	tests := []struct {
		name      string
		image     string
		skopeo    execx.Result
		skopeoErr error
		// api is the package endpoint gh is asked for, and gh its answer.
		// An empty api means gh must not be asked at all.
		api string
		gh  execx.Result

		wantRev   string
		wantState registry.State
		// wantErr lists what the error must contain; nil means no error.
		wantErr []string
		// notErr lists what the error must not contain.
		notErr      []string
		wantPrivate bool
	}{
		{
			// Recorded: skopeo inspect --raw --no-creds docker://ghcr.io/divbast/librespeed:latest
			name:      "published",
			image:     latest,
			skopeo:    execx.Result{Stdout: published},
			wantRev:   revision,
			wantState: registry.Published,
		},
		{
			name:    "no-annotation",
			image:   latest,
			skopeo:  index(`{"org.opencontainers.image.version":"6.3.1"}`),
			wantErr: []string{latest + " carries no revision annotation, only ''"},
		},
		{
			name:    "short-annotation",
			image:   latest,
			skopeo:  index(`{"org.opencontainers.image.revision":"24e63e2"}`),
			wantErr: []string{latest + " carries no revision annotation, only '24e63e2'"},
		},
		{
			name:    "uppercase-annotation",
			image:   latest,
			skopeo:  index(`{"org.opencontainers.image.revision":"` + strings.ToUpper(revision) + `"}`),
			wantErr: []string{"carries no revision annotation"},
		},
		{
			name:    "not-json",
			image:   latest,
			skopeo:  execx.Result{Stdout: []byte("<html>")},
			wantErr: []string{"could not read " + latest},
		},
		{
			name:      "absent-package",
			image:     noPackage,
			skopeo:    tokenRefused,
			api:       noPackageAPI,
			gh:        status(404, "Package not found."),
			wantState: registry.Absent,
		},
		{
			// skopeo exits 2 when the registry says the manifest is unknown.
			name:      "missing-tag-public",
			image:     noTag,
			skopeo:    failed(t, "skopeo-no-such-tag.txt", 2),
			api:       librespeedAPI,
			gh:        pkg("public"),
			wantState: registry.Absent,
		},
		{
			// ghcr.io refuses a private package's token request exactly as
			// it refuses a missing one's.
			name:        "token-refused-private",
			image:       noPackage,
			skopeo:      tokenRefused,
			api:         noPackageAPI,
			gh:          pkg("private"),
			wantErr:     []string{"package is private", "private"},
			wantPrivate: true,
		},
		{
			name:        "denied-private",
			image:       latest,
			skopeo:      failed(t, "skopeo-denied.txt", 1),
			api:         librespeedAPI,
			gh:          pkg("private"),
			wantErr:     []string{"package is private"},
			wantPrivate: true,
		},
		{
			name:        "unauthorized-internal",
			image:       latest,
			skopeo:      failed(t, "skopeo-unauthorized.txt", 1),
			api:         librespeedAPI,
			gh:          pkg("internal"),
			wantErr:     []string{"package is private", "internal"},
			wantPrivate: true,
		},
		{
			name:    "denied-public",
			image:   latest,
			skopeo:  failed(t, "skopeo-denied.txt", 1),
			api:     librespeedAPI,
			gh:      pkg("public"),
			wantErr: []string{"public", "requested access to the resource is denied"},
		},
		{
			name:    "unauthorized-public",
			image:   latest,
			skopeo:  failed(t, "skopeo-unauthorized.txt", 1),
			api:     librespeedAPI,
			gh:      pkg("public"),
			wantErr: []string{"public", "unauthorized"},
		},
		{
			name:    "token-refused-public",
			image:   noPackage,
			skopeo:  tokenRefused,
			api:     noPackageAPI,
			gh:      pkg("public"),
			wantErr: []string{"public", "403 Forbidden"},
		},
		{
			name:      "name-unknown-absent",
			image:     latest,
			skopeo:    failed(t, "skopeo-name-unknown.txt", 1),
			api:       librespeedAPI,
			gh:        status(404, "Package not found."),
			wantState: registry.Absent,
		},
		{
			// Only a missing tag on a public package is absent: a public
			// package the registry says has no repository is a contradiction.
			name:    "name-unknown-public",
			image:   latest,
			skopeo:  failed(t, "skopeo-name-unknown.txt", 1),
			api:     librespeedAPI,
			gh:      pkg("public"),
			wantErr: []string{"public", "name unknown"},
		},
		{
			// Recorded: gh api -i orgs/divbast/packages/container/librespeed
			name:    "api-403",
			image:   noTag,
			skopeo:  failed(t, "skopeo-no-such-tag.txt", 2),
			api:     librespeedAPI,
			gh:      status(403, "You need at least read:packages scope to get a package."),
			wantErr: []string{"HTTP 403", "You need at least read:packages scope to get a package."},
		},
		{
			// A 403 is not always a missing scope: GitHub says which it is.
			name:    "api-403-rate-limit",
			image:   noTag,
			skopeo:  failed(t, "skopeo-no-such-tag.txt", 2),
			api:     librespeedAPI,
			gh:      status(403, "API rate limit exceeded for installation ID 1."),
			wantErr: []string{"HTTP 403", "API rate limit exceeded for installation ID 1."},
			notErr:  []string{"needs packages: read"},
		},
		{
			// Only GitHub's "Package not found." is a package that does not
			// exist. Any other 404, a path that names nothing, is not.
			name:    "api-404-generic",
			image:   noPackage,
			skopeo:  tokenRefused,
			api:     noPackageAPI,
			gh:      status(404, "Not Found"),
			wantErr: []string{"HTTP 404", `"Not Found"`},
		},
		{
			// GitHub giving a package no visibility says nothing of whether
			// it is private.
			name:    "visibility-empty",
			image:   noPackage,
			skopeo:  tokenRefused,
			api:     noPackageAPI,
			gh:      pkg(""),
			wantErr: []string{"no visibility"},
		},
		{
			name:    "api-5xx",
			image:   noPackage,
			skopeo:  tokenRefused,
			api:     noPackageAPI,
			gh:      status(502, "Bad Gateway"),
			wantErr: []string{"502"},
		},
		{
			name:   "api-unreachable",
			image:  noPackage,
			skopeo: tokenRefused,
			api:    noPackageAPI,
			gh: execx.Result{
				Stderr: []byte("error connecting to api.github.com\ncheck your internet connection or https://githubstatus.com\n"),
				Code:   1,
			},
			wantErr: []string{"error connecting to api.github.com"},
		},
		{
			name:    "timeout",
			image:   latest,
			skopeo:  failed(t, "skopeo-timeout.txt", 1),
			wantErr: []string{"could not read " + latest, "context deadline exceeded"},
		},
		{
			name:    "5xx",
			image:   latest,
			skopeo:  failed(t, "skopeo-manifest-503.txt", 1),
			wantErr: []string{"could not read " + latest, "503 Service Unavailable"},
		},
		{
			// The token request failing for any reason but a 403 is an
			// outage, not a refusal.
			name:    "token-5xx",
			image:   latest,
			skopeo:  failed(t, "skopeo-token-503.txt", 1),
			wantErr: []string{"could not read " + latest, "Requesting bearer token", "503"},
		},
		{
			name:    "rate-limited",
			image:   latest,
			skopeo:  failed(t, "skopeo-manifest-429.txt", 1),
			wantErr: []string{"could not read " + latest, "toomanyrequests"},
		},
		{
			name:      "skopeo-missing",
			image:     latest,
			skopeoErr: exec.ErrNotFound,
			wantErr:   []string{"could not read " + latest},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			calls := []execx.Call{{Argv: skopeoArgv(tt.image), Result: tt.skopeo, Err: tt.skopeoErr}}
			if tt.api != "" {
				calls = append(calls, execx.Call{Argv: []string{"gh", "api", "-i", tt.api}, Result: tt.gh})
			}
			run := execx.NewFake(t, calls...)
			l := registry.Lookup{Run: run, GH: ghapi.Client{Run: run}}

			rev, state, err := l.Revision(t.Context(), tt.image)
			if tt.wantErr == nil {
				if err != nil {
					t.Fatalf("Revision(%q) error = %v, want nil", tt.image, err)
				}
				if rev != tt.wantRev || state != tt.wantState {
					t.Errorf("Revision(%q) = %q, %v; want %q, %v", tt.image, rev, state, tt.wantRev, tt.wantState)
				}
				return
			}

			if err == nil {
				t.Fatalf("Revision(%q) = %q, %v, nil; want an error containing %q", tt.image, rev, state, tt.wantErr)
			}
			// An error is never an answer: above all, never Absent.
			if state == registry.Absent || state == registry.Published || rev != "" {
				t.Errorf("Revision(%q) = %q, %v with error %v; want no revision and no state", tt.image, rev, state, err)
			}
			for _, want := range tt.wantErr {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("Revision(%q) error = %q, want it to contain %q", tt.image, err, want)
				}
			}
			for _, not := range tt.notErr {
				if strings.Contains(err.Error(), not) {
					t.Errorf("Revision(%q) error = %q, want it not to contain %q", tt.image, err, not)
				}
			}
			if got := errors.Is(err, registry.ErrPrivate); got != tt.wantPrivate {
				t.Errorf("Revision(%q) error = %v; errors.Is(err, ErrPrivate) = %t, want %t", tt.image, err, got, tt.wantPrivate)
			}
			if tt.skopeoErr != nil && !errors.Is(err, tt.skopeoErr) {
				t.Errorf("Revision(%q) error = %v, want it to wrap %v", tt.image, err, tt.skopeoErr)
			}
		})
	}
}

// TestPresence checks Presence, which decides absent and private as
// Revision does but asks nothing of the image's annotations, and a
// RegistryOnly Lookup, which never asks GitHub: a refusal is ErrRefused
// there, never an answer, and a registry that fails to answer is still a
// plain error.
func TestPresence(t *testing.T) {
	t.Parallel()

	tokenRefused := failed(t, "skopeo-no-such-package.txt", 1)
	tests := []struct {
		name         string
		registryOnly bool
		skopeo       execx.Result
		skopeoErr    error
		// gh is GitHub's answer about the package, nil when it must not be
		// asked.
		gh        *execx.Result
		wantState registry.State
		wantErr   []string
		// notErr lists what the error must not contain: Presence's callers,
		// the scan among them, ask nothing about a commit.
		notErr      []string
		wantPrivate bool
		wantRefused bool
	}{
		{name: "published", skopeo: execx.Result{Stdout: readTestdata(t, "skopeo-librespeed-latest.json")}, wantState: registry.Published},
		{name: "published-without-a-revision", skopeo: index(`{"org.opencontainers.image.version":"6.3.1"}`), wantState: registry.Published},
		{name: "absent", skopeo: tokenRefused, gh: new(status(404, "Package not found.")), wantState: registry.Absent},
		{name: "missing-tag-public", skopeo: failed(t, "skopeo-no-such-tag.txt", 2), gh: new(pkg("public")), wantState: registry.Absent},
		{name: "private", skopeo: tokenRefused, gh: new(pkg("private")), wantErr: []string{"package is private"}, wantPrivate: true},
		{
			name: "refused-though-public", skopeo: tokenRefused, gh: new(pkg("public")),
			wantErr: []string{"public", "403 Forbidden"}, notErr: []string{"commit"},
		},
		{name: "api-5xx", skopeo: tokenRefused, gh: new(status(502, "Bad Gateway")), wantErr: []string{"502"}},
		{
			name: "unreachable", skopeo: failed(t, "skopeo-manifest-503.txt", 1),
			wantErr: []string{"could not read " + latest, "503"}, notErr: []string{"commit"},
		},
		{
			name: "registry-only-published", registryOnly: true,
			skopeo: execx.Result{Stdout: readTestdata(t, "skopeo-librespeed-latest.json")}, wantState: registry.Published,
		},
		{
			name: "registry-only-refused", registryOnly: true, skopeo: tokenRefused,
			wantErr: []string{"ghcr.io refused to show " + latest, "403 Forbidden"}, wantRefused: true,
		},
		{
			name: "registry-only-missing-tag", registryOnly: true, skopeo: failed(t, "skopeo-no-such-tag.txt", 2),
			wantErr: []string{"manifest unknown"}, wantRefused: true,
		},
		{
			name: "registry-only-unreachable", registryOnly: true, skopeo: failed(t, "skopeo-manifest-503.txt", 1),
			wantErr: []string{"could not read " + latest, "503"}, notErr: []string{"commit"},
		},
		{
			// A local scan on a host without skopeo
			name: "registry-only-skopeo-missing", registryOnly: true, skopeoErr: exec.ErrNotFound,
			wantErr: []string{"could not read " + latest, "executable file not found"}, notErr: []string{"commit"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			calls := []execx.Call{{Argv: skopeoArgv(latest), Result: tt.skopeo, Err: tt.skopeoErr}}
			if tt.gh != nil {
				calls = append(calls, execx.Call{Argv: []string{"gh", "api", "-i", librespeedAPI}, Result: *tt.gh})
			}
			run := execx.NewFake(t, calls...)
			l := registry.Lookup{Run: run, GH: ghapi.Client{Run: run}, RegistryOnly: tt.registryOnly}

			state, err := l.Presence(t.Context(), latest)
			if tt.wantErr == nil {
				if err != nil || state != tt.wantState {
					t.Errorf("Presence() = %v, %v; want %v", state, err, tt.wantState)
				}
				return
			}
			if err == nil {
				t.Fatalf("Presence() = %v, nil; want an error containing %q", state, tt.wantErr)
			}
			// An error is never an answer
			if state != 0 {
				t.Errorf("Presence() = %v with error %v; want no state", state, err)
			}
			for _, want := range tt.wantErr {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("Presence() error = %q, want it to contain %q", err, want)
				}
			}
			for _, not := range tt.notErr {
				if strings.Contains(err.Error(), not) {
					t.Errorf("Presence() error = %q, want it not to contain %q", err, not)
				}
			}
			if tt.skopeoErr != nil && !errors.Is(err, tt.skopeoErr) {
				t.Errorf("Presence() error = %v, want it to wrap %v", err, tt.skopeoErr)
			}
			if got := errors.Is(err, registry.ErrPrivate); got != tt.wantPrivate {
				t.Errorf("errors.Is(%v, ErrPrivate) = %t, want %t", err, got, tt.wantPrivate)
			}
			if got := errors.Is(err, registry.ErrRefused); got != tt.wantRefused {
				t.Errorf("errors.Is(%v, ErrRefused) = %t, want %t", err, got, tt.wantRefused)
			}
		})
	}
}

// TestRevisionRegistryOnly checks that Revision, too, takes no refusal to
// GitHub when the Lookup is RegistryOnly.
func TestRevisionRegistryOnly(t *testing.T) {
	t.Parallel()

	run := execx.NewFake(t, execx.Call{Argv: skopeoArgv(noPackage), Result: failed(t, "skopeo-no-such-package.txt", 1)})
	l := registry.Lookup{Run: run, GH: ghapi.Client{Run: run}, RegistryOnly: true}
	rev, state, err := l.Revision(t.Context(), noPackage)
	if !errors.Is(err, registry.ErrRefused) || rev != "" || state != 0 {
		t.Errorf("Revision() = %q, %v, %v; want an error wrapping ErrRefused", rev, state, err)
	}
}

// TestRevisionPackage checks which package the GitHub API is asked about.
// A refused token request sends every image there, and a 404 makes it
// Absent.
func TestRevisionPackage(t *testing.T) {
	t.Parallel()

	tests := []struct {
		image string
		api   string
	}{
		{image: "ghcr.io/divbast/librespeed", api: librespeedAPI},
		{image: "ghcr.io/divbast/librespeed:latest", api: librespeedAPI},
		{image: "ghcr.io/divbast/librespeed@sha256:d9ea226a05957bd70876b6b3eb81ca454fefc4365902f061dba82515efb12909", api: librespeedAPI},
		{image: "ghcr.io/divbast/librespeed:latest@sha256:d9ea226a05957bd70876b6b3eb81ca454fefc4365902f061dba82515efb12909", api: librespeedAPI},
		{image: "ghcr.io/divbast/frankenphp:librespeed-amd64", api: "orgs/divbast/packages/container/frankenphp"},
		{image: "ghcr.io/divbast/a/b:latest", api: "orgs/divbast/packages/container/a%2Fb"},
	}

	for _, tt := range tests {
		t.Run(tt.image, func(t *testing.T) {
			t.Parallel()

			run := execx.NewFake(t,
				execx.Call{Argv: skopeoArgv(tt.image), Result: failed(t, "skopeo-no-such-package.txt", 1)},
				execx.Call{Argv: []string{"gh", "api", "-i", tt.api}, Result: status(404, "Package not found.")},
			)
			l := registry.Lookup{Run: run, GH: ghapi.Client{Run: run}}
			rev, state, err := l.Revision(t.Context(), tt.image)
			if err != nil || rev != "" || state != registry.Absent {
				t.Errorf("Revision(%q) = %q, %v, %v; want Absent", tt.image, rev, state, err)
			}
		})
	}
}

// TestRevisionRejects checks that only a ghcr.io reference is read: the
// API that tells absent from private only knows about GitHub's packages.
func TestRevisionRejects(t *testing.T) {
	t.Parallel()

	for _, image := range []string{
		"docker.io/library/alpine:latest",
		"docker://ghcr.io/divbast/librespeed:latest",
		"ghcr.io.example.com/divbast/librespeed:latest",
		"ghcr.io/divbast",
		"ghcr.io/divbast/",
		"ghcr.io//librespeed:latest",
		"",
	} {
		t.Run(image, func(t *testing.T) {
			t.Parallel()

			// No calls scripted: nothing may run for a reference refused.
			run := execx.NewFake(t)
			l := registry.Lookup{Run: run, GH: ghapi.Client{Run: run}}
			rev, state, err := l.Revision(t.Context(), image)
			if err == nil {
				t.Fatalf("Revision(%q) = %q, %v, nil; want an error", image, rev, state)
			}
			if !strings.Contains(err.Error(), "ghcr.io") {
				t.Errorf("Revision(%q) error = %q, want it to say only ghcr.io is read", image, err)
			}
			if state == registry.Absent {
				t.Errorf("Revision(%q) state = Absent with an error", image)
			}
		})
	}
}

func TestStateString(t *testing.T) {
	t.Parallel()

	for state, want := range map[registry.State]string{
		registry.Absent:    "absent",
		registry.Published: "published",
		registry.State(0):  "State(0)",
	} {
		if got := state.String(); got != want {
			t.Errorf("State(%d).String() = %q, want %q", int(state), got, want)
		}
	}
}

// runFunc is a Runner that answers with a function.
type runFunc func(ctx context.Context, name string, args ...string) (execx.Result, error)

func (f runFunc) Run(ctx context.Context, name string, args ...string) (execx.Result, error) {
	return f(ctx, name, args...)
}

// hangs returns a Runner on which the command name runs until its context
// ends, as one that hangs would, and fails as execx.OS then does. Any
// other command is refused a token, as ghcr.io refuses a missing package.
func hangs(t *testing.T, name string) execx.Runner {
	t.Helper()
	refused := failed(t, "skopeo-no-such-package.txt", 1)
	return runFunc(func(ctx context.Context, cmd string, _ ...string) (execx.Result, error) {
		if cmd != name {
			return refused, nil
		}
		<-ctx.Done()
		return execx.Result{}, fmt.Errorf("run %s: %w", cmd, ctx.Err())
	})
}

// TestRevisionTimeout checks that a skopeo or a gh that hangs is given up
// on after a minute each, or after the timeout the Lookup or its Client
// sets, and is an error rather than an answer, one that names the call and
// its limit. A deadline of the caller's that comes first is the caller's
// to report: the error then says nothing of the Lookup giving up (backlog
// CI-6; ghapi's own tests hold its Client to the same). The bubble's clock
// moves only when everything in it waits, so no test waits a minute.
func TestRevisionTimeout(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		hung string
		// skopeo and gh are the Lookup's and its Client's timeouts.
		skopeo, gh time.Duration
		// caller is a deadline the caller's context sets; zero for none.
		caller time.Duration
		want   time.Duration
		// wantErr is what the error must say: the call and its limit.
		// Empty means it must not say the call gave up.
		wantErr string
	}{
		{
			name: "skopeo", hung: "skopeo", want: time.Minute,
			wantErr: "skopeo inspect docker://" + noPackage + " gave up after 1m0s: ",
		},
		{
			name: "skopeo-set", hung: "skopeo", skopeo: 2 * time.Second, gh: 5 * time.Second, want: 2 * time.Second,
			wantErr: "skopeo inspect docker://" + noPackage + " gave up after 2s: ",
		},
		{
			name: "gh", hung: "gh", want: time.Minute,
			wantErr: "gh api " + noPackageAPI + " gave up after 1m0s: ",
		},
		{
			name: "gh-set", hung: "gh", skopeo: 2 * time.Second, gh: 5 * time.Second, want: 5 * time.Second,
			wantErr: "gh api " + noPackageAPI + " gave up after 5s: ",
		},
		{name: "skopeo-caller-first", hung: "skopeo", caller: 3 * time.Second, want: 3 * time.Second},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			synctest.Test(t, func(t *testing.T) {
				ctx := t.Context()
				if tt.caller != 0 {
					var cancel context.CancelFunc
					ctx, cancel = context.WithTimeout(ctx, tt.caller)
					defer cancel()
				}
				start := time.Now()
				run := hangs(t, tt.hung)
				l := registry.Lookup{Run: run, GH: ghapi.Client{Run: run, Timeout: tt.gh}, Timeout: tt.skopeo}
				rev, state, err := l.Revision(ctx, noPackage)
				if !errors.Is(err, context.DeadlineExceeded) {
					t.Fatalf("Revision() = %q, %v, %v; want an error wrapping %v", rev, state, err, context.DeadlineExceeded)
				}
				if state != 0 || rev != "" {
					t.Errorf("Revision() = %q, %v with error %v; want no revision and no state", rev, state, err)
				}
				if waited := time.Since(start); waited != tt.want {
					t.Errorf("Revision() gave up after %v, want %v", waited, tt.want)
				}
				switch said := err.Error(); {
				case tt.wantErr == "" && strings.Contains(said, "gave up"):
					t.Errorf("Revision() error = %q, want it not to say the call gave up on a deadline of the caller's", err)
				case !strings.Contains(said, tt.wantErr):
					t.Errorf("Revision() error = %q, want it to contain %q", err, tt.wantErr)
				}
			})
		})
	}
}

// The librespeed index the recording holds, by the sha256 of its bytes,
// which is its digest: skopeo inspect --raw prints them as served.
const pinnedLatest = "ghcr.io/divbast/librespeed@sha256:d9ea226a05957bd70876b6b3eb81ca454fefc4365902f061dba82515efb12909"

// TestPin checks that Pin answers as Presence does, and that a published
// image's answer names its repository at the digest of what the registry
// served, whatever tag or digest the reference carried.
func TestPin(t *testing.T) {
	t.Parallel()

	served := execx.Result{Stdout: readTestdata(t, "skopeo-librespeed-latest.json")}
	tests := []struct {
		name      string
		image     string
		skopeo    execx.Result
		gh        *execx.Result
		want      string
		wantState registry.State
		wantErr   string
	}{
		{name: "tag", image: latest, skopeo: served, want: pinnedLatest, wantState: registry.Published},
		{name: "digest", image: pinnedLatest, skopeo: served, want: pinnedLatest, wantState: registry.Published},
		{name: "tag-and-digest", image: "ghcr.io/divbast/librespeed:latest@sha256:00", skopeo: served, want: pinnedLatest, wantState: registry.Published},
		{
			name: "nested-name", image: "ghcr.io/divbast/a/b:latest", skopeo: served,
			want: "ghcr.io/divbast/a/b@sha256:d9ea226a05957bd70876b6b3eb81ca454fefc4365902f061dba82515efb12909", wantState: registry.Published,
		},
		{
			name: "absent", image: latest, skopeo: failed(t, "skopeo-no-such-package.txt", 1), gh: new(status(404, "Package not found.")),
			wantState: registry.Absent,
		},
		{
			name: "private", image: latest, skopeo: failed(t, "skopeo-no-such-package.txt", 1), gh: new(pkg("private")),
			wantErr: "package is private",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			calls := []execx.Call{{Argv: skopeoArgv(tt.image), Result: tt.skopeo}}
			if tt.gh != nil {
				calls = append(calls, execx.Call{Argv: []string{"gh", "api", "-i", librespeedAPI}, Result: *tt.gh})
			}
			run := execx.NewFake(t, calls...)
			l := registry.Lookup{Run: run, GH: ghapi.Client{Run: run}}
			got, state, err := l.Pin(t.Context(), tt.image)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) || got != "" || state != 0 {
					t.Errorf("Pin() = %q, %v, %v; want an error containing %q", got, state, err, tt.wantErr)
				}
				return
			}
			if err != nil || got != tt.want || state != tt.wantState {
				t.Errorf("Pin() = %q, %v, %v; want %q, %v", got, state, err, tt.want, tt.wantState)
			}
		})
	}
}

// copyArgv is skopeo copying ref's linux/arch image into the layout dir,
// as an anonymous client.
func copyArgv(ref, arch, dir string) []string {
	return []string{"skopeo", "copy", "--quiet", "--src-no-creds", "--override-os", "linux", "--override-arch", arch, "docker://" + ref, "oci:" + dir}
}

func TestCopy(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	tests := []struct {
		name    string
		ref     string
		dir     string
		skopeo  *execx.Result
		err     error
		wantErr []string
	}{
		{name: "copied", ref: pinnedLatest, dir: dir, skopeo: &execx.Result{}},
		{
			name: "fails", ref: pinnedLatest, dir: dir, skopeo: new(failed(t, "skopeo-manifest-503.txt", 1)),
			wantErr: []string{"could not copy " + pinnedLatest, "503"},
		},
		{name: "skopeo-missing", ref: pinnedLatest, dir: dir, err: exec.ErrNotFound, wantErr: []string{"could not copy", "executable file not found"}},
		// A tag can move between two reads: only a digest names one image
		{name: "unpinned", ref: latest, dir: dir, wantErr: []string{latest, "no digest"}},
		// oci:'s reference ends a path at its first colon
		{name: "colon-in-dir", ref: pinnedLatest, dir: dir + "/a:b", wantErr: []string{"a:b", "colon"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var calls []execx.Call
			if tt.skopeo != nil || tt.err != nil {
				res := execx.Result{}
				if tt.skopeo != nil {
					res = *tt.skopeo
				}
				calls = append(calls, execx.Call{Argv: copyArgv(tt.ref, "arm64", tt.dir), Result: res, Err: tt.err})
			}
			run := execx.NewFake(t, calls...)
			err := registry.Lookup{Run: run}.Copy(t.Context(), tt.ref, "arm64", tt.dir)
			if len(tt.wantErr) == 0 {
				if err != nil {
					t.Errorf("Copy() error = %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("Copy() error = nil, want one containing %q", tt.wantErr)
			}
			for _, want := range tt.wantErr {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("Copy() error = %q, want it to contain %q", err, want)
				}
			}
			if tt.err != nil && !errors.Is(err, tt.err) {
				t.Errorf("Copy() error = %v, want it to wrap %v", err, tt.err)
			}
		})
	}
}

// TestCopyTimeout checks that a skopeo copy that hangs is given up on
// after five minutes, naming the copy and its limit, unless the caller's
// deadline comes first.
func TestCopyTimeout(t *testing.T) {
	t.Parallel()
	for _, caller := range []time.Duration{0, 3 * time.Second} {
		t.Run(caller.String(), func(t *testing.T) {
			t.Parallel()
			synctest.Test(t, func(t *testing.T) {
				ctx := t.Context()
				want := 5 * time.Minute
				if caller != 0 {
					var cancel context.CancelFunc
					ctx, cancel = context.WithTimeout(ctx, caller)
					defer cancel()
					want = caller
				}
				start := time.Now()
				err := registry.Lookup{Run: hangs(t, "skopeo")}.Copy(ctx, pinnedLatest, "arm64", t.TempDir())
				if !errors.Is(err, context.DeadlineExceeded) {
					t.Fatalf("Copy() error = %v, want one wrapping %v", err, context.DeadlineExceeded)
				}
				if waited := time.Since(start); waited != want {
					t.Errorf("Copy() gave up after %v, want %v", waited, want)
				}
				if gaveUp := strings.Contains(err.Error(), "gave up after 5m0s"); gaveUp != (caller == 0) {
					t.Errorf("Copy() error = %q; it says the copy gave up: %t, want %t", err, gaveUp, caller == 0)
				}
			})
		})
	}
}
