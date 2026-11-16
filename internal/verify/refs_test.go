// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

package verify_test

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/divbast/ci/internal/verify"
)

const (
	digest = "sha256:d9ea226a05957bd70876b6b3eb81ca454fefc4365902f061dba82515efb12909"
	other  = "sha256:4dcdd53971ba1f373c3eb90e393dd3944687938c5c03494ab684921594905fc7"
	pinned = "ghcr.io/divbast/frankenphp:librespeed@" + digest
	// runtime is the distroless base app's ARG names.
	runtime = "gcr.io/distroless/cc-debian13:nonroot@" + other
	fetch   = "debian:13-slim@" + other
)

// app is an app's Containerfile around lines, which stand where its
// runtime stage takes the binary: the runtime image an ARG names, and a
// fetch stage the runtime copies from.
func app(lines ...string) string {
	return `# An app's Containerfile
ARG RUNTIME_IMAGE=` + runtime + `

FROM ` + fetch + ` AS fetch
RUN mkdir -p /out/app

FROM ${RUNTIME_IMAGE}
` + strings.Join(lines, "\n") + `
COPY --from=fetch --chown=root:root /out/app /var/www/app
USER 65532:65532
`
}

// names returns each ref as its Containerfile names it, and its line.
func names(refs []verify.Ref) []string {
	out := make([]string, len(refs))
	for i, r := range refs {
		out[i] = fmt.Sprintf("%s line %02d", r, r.Line)
	}
	return out
}

func TestRefs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		containerfile string
		want          []string // each "<ref> line <NN>"
		wantErr       error
		// wantIn lists what the error message must contain.
		wantIn []string
	}{
		{
			name:          "an-app",
			containerfile: app("COPY --from=" + pinned + " /frankenphp /usr/local/bin/frankenphp"),
			want:          []string{fetch + " line 04", runtime + " line 07", pinned + " line 08"},
		},
		{
			name:          "no-frankenphp",
			containerfile: app("COPY --from=fetch /out/frankenphp /usr/local/bin/frankenphp"),
			want:          []string{fetch + " line 04", runtime + " line 07"},
		},
		{
			name:          "tag-only",
			containerfile: app("COPY --from=ghcr.io/divbast/frankenphp:librespeed /frankenphp /usr/local/bin/frankenphp"),
			wantErr:       verify.ErrUnpinned,
			wantIn:        []string{"line 8", "ghcr.io/divbast/frankenphp:librespeed"},
		},
		{
			name: "arg",
			containerfile: app(
				"ARG FP="+pinned,
				"COPY --from=${FP} /frankenphp /usr/local/bin/frankenphp",
			),
			wantErr: verify.ErrNotLiteral,
			wantIn:  []string{"line 9", "${FP}"},
		},
		{
			name:          "arg-without-braces",
			containerfile: app("COPY --from=$FP /frankenphp /usr/local/bin/frankenphp"),
			wantErr:       verify.ErrNotLiteral,
		},
		{
			name: "other-registries",
			containerfile: app(
				"COPY --from=docker.io/divbast/frankenphp:librespeed@"+other+" /frankenphp /opt/a",
				"COPY --from=ghcr.io/dunglas/frankenphp:latest@"+other+" /frankenphp /opt/b",
				"COPY --from="+pinned+" /frankenphp /usr/local/bin/frankenphp",
			),
			want: []string{
				fetch + " line 04", runtime + " line 07", "docker.io/divbast/frankenphp:librespeed@" + other + " line 08",
				"ghcr.io/dunglas/frankenphp:latest@" + other + " line 09", pinned + " line 10",
			},
		},
		{
			name: "comment-ignored",
			containerfile: app(
				"# COPY --from=ghcr.io/divbast/frankenphp:librespeed@"+other+" /frankenphp /usr/local/bin/frankenphp",
				"   # was ghcr.io/divbast/frankenphp:librespeed",
				"COPY --from="+pinned+" /frankenphp /usr/local/bin/frankenphp",
			),
			want: []string{fetch + " line 04", runtime + " line 07", pinned + " line 10"},
		},
		{
			name:          "flags-before-from",
			containerfile: app("COPY --chmod=0755 --link --from=" + pinned + " /frankenphp /usr/local/bin/frankenphp"),
			want:          []string{fetch + " line 04", runtime + " line 07", pinned + " line 08"},
		},
		{
			name: "continued-lines",
			containerfile: app(
				`COPY --chmod=0755 \`,
				`    # a comment inside an instruction is dropped, as BuildKit drops it`,
				`    --from=`+pinned+` \`,
				`    /frankenphp /usr/local/bin/frankenphp`,
			),
			want: []string{fetch + " line 04", runtime + " line 07", pinned + " line 08"},
		},
		{
			name:          "lower-case-instruction",
			containerfile: app("copy --from=" + pinned + " /frankenphp /usr/local/bin/frankenphp"),
			want:          []string{fetch + " line 04", runtime + " line 07", pinned + " line 08"},
		},
		// A stage built from a build argument with no default could be any
		// image at all.
		{
			name: "stage-from-an-unresolved-build-argument",
			containerfile: app(
				"FROM ${BASE} AS base",
				"FROM ${RUNTIME_IMAGE}",
				"COPY --from=base /tool /usr/local/bin/tool",
			),
			wantErr: verify.ErrNotLiteral,
			wantIn:  []string{"line 8", "${BASE}"},
		},
		{
			// An ARG a stage declares is no default a FROM can use
			name: "an-arg-in-a-stage",
			containerfile: app(
				"ARG BASE="+fetch,
				"FROM ${BASE}",
			),
			wantErr: verify.ErrNotLiteral,
			wantIn:  []string{"line 9", "${BASE}"},
		},
		{
			// A COPY --from= of a stage built from one is refused too, as
			// before
			name: "copy-from-a-stage-on-an-unresolved-build-argument",
			containerfile: app(
				"FROM $BASE",
				"FROM ${RUNTIME_IMAGE}",
				"COPY --from=2 /tool /usr/local/bin/tool",
			),
			wantErr: verify.ErrNotLiteral,
			wantIn:  []string{"$BASE"},
		},
		{
			name:          "digest-only",
			containerfile: app("COPY --from=ghcr.io/divbast/frankenphp@" + digest + " /frankenphp /usr/local/bin/frankenphp"),
			wantErr:       verify.ErrUnpinned,
		},
		{
			name:          "short-digest",
			containerfile: app("COPY --from=ghcr.io/divbast/frankenphp:librespeed@sha256:d9ea226a /frankenphp /usr/local/bin/frankenphp"),
			wantErr:       verify.ErrUnpinned,
		},
		{
			// A FROM may take a table image, which is then verified as the
			// image it is
			name: "frankenphp-by-from",
			containerfile: app(
				"FROM "+pinned+" AS fp",
				"FROM ${RUNTIME_IMAGE}",
				"COPY --from=fp /frankenphp /usr/local/bin/frankenphp",
			),
			want: []string{fetch + " line 04", runtime + " line 07", pinned + " line 08", runtime + " line 09"},
		},
		{
			// Named anywhere else, a table image is a way in for a binary no
			// check sees
			name:          "frankenphp-in-a-run",
			containerfile: app("RUN --mount=type=bind,from=" + pinned + ",target=/fp cp /fp/frankenphp /usr/local/bin/"),
			wantErr:       verify.ErrStray,
			wantIn:        []string{"line 8"},
		},
		{
			name:          "distroless-in-a-label",
			containerfile: app(`LABEL org.opencontainers.image.base.name="gcr.io/distroless/cc-debian13:nonroot"`),
			wantErr:       verify.ErrStray,
			wantIn:        []string{"line 8"},
		},
		{
			// An ARG that names a table image and that no FROM uses
			name:          "distroless-in-an-unused-arg",
			containerfile: "ARG OTHER=gcr.io/distroless/static-debian13:nonroot@" + other + "\nFROM " + fetch + "\n",
			wantErr:       verify.ErrStray,
			wantIn:        []string{"line 1"},
		},
		{
			name:          "empty",
			containerfile: "# nothing\n",
			wantErr:       verify.ErrNoFrom,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := verify.Refs(strings.NewReader(tt.containerfile))
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("Refs() = %q, %v; want error %v", names(got), err, tt.wantErr)
			}
			for _, s := range tt.wantIn {
				if !strings.Contains(err.Error(), s) {
					t.Errorf("Refs() error = %q, want it to contain %q", err, s)
				}
			}
			if tt.wantErr == nil && !slices.Equal(names(got), tt.want) {
				t.Errorf("Refs() = %q, want %q", names(got), tt.want)
			}
		})
	}
}

func TestRefsUnpinned(t *testing.T) {
	t.Parallel()

	_, err := verify.Refs(strings.NewReader("FROM golang:1.27.4-trixie@" + other + " AS build\nFROM debian:13-slim\n"))
	if !errors.Is(err, verify.ErrUnpinned) || !strings.Contains(err.Error(), "line 2") || !strings.Contains(err.Error(), "debian:13-slim") {
		t.Fatalf("Refs() error = %v, want ErrUnpinned naming line 2 and debian:13-slim", err)
	}
}

// TestRefsShapes reads every shape of FROM and COPY --from= a
// Containerfile may take that names no image, or names one pinned, and
// none of them is refused.
func TestRefsShapes(t *testing.T) {
	t.Parallel()

	golang := "golang:1.27.4-trixie@" + other
	static := "gcr.io/distroless/static-debian13:nonroot@" + digest
	containerfile := strings.Join([]string{
		"FROM scratch AS probe",
		"COPY core /divbast/probe/core",
		"FROM --platform=$BUILDPLATFORM " + golang + " as golang",
		"FROM golang AS build",
		"COPY --from=0 /divbast/probe/core /core",
		"FROM \\",
		"    " + static,
		"COPY --from=build /out/app /usr/local/bin/app",
		"COPY --from=golang /usr/local/go/LICENSE /licenses/go",
		"COPY --from=probe /divbast/probe/core /x",
	}, "\n")
	got, err := verify.Refs(strings.NewReader(containerfile))
	if err != nil {
		t.Fatalf("Refs() error = %v", err)
	}
	if want := []string{golang + " line 03", static + " line 06"}; !slices.Equal(names(got), want) {
		t.Errorf("Refs() = %q, want %q", names(got), want)
	}
}

// TestRefsBypasses reads every way, found in review, that a Containerfile
// could name an image BuildKit pulls but the verifier read as something
// else: a variable left after expansion, a registry written with its port
// or in capitals, an unpinned frontend, a stage inside a heredoc, and a
// mount's from= in capitals.
func TestRefsBypasses(t *testing.T) {
	t.Parallel()

	static := "gcr.io/distroless/static-debian13:nonroot@" + digest
	tests := []struct {
		name          string
		containerfile string
		want          []string // when it reads
		wantErr       error
		wantIn        []string
	}{
		{
			name:          "a-default-inside-a-variable",
			containerfile: "ARG A\nFROM ${A:-ghcr.io/divbast}/frankenphp:librespeed@" + digest + "\n",
			wantErr:       verify.ErrNotLiteral,
			wantIn:        []string{"line 2"},
		},
		{
			name:          "an-arg-built-from-an-arg",
			containerfile: "ARG REG=ghcr.io/divbast\nARG IMG=${REG}/frankenphp:librespeed@" + digest + "\nFROM ${IMG}\n",
			wantErr:       verify.ErrNotLiteral,
			wantIn:        []string{"line 3"},
		},
		{
			name:          "a-registry-port",
			containerfile: "FROM ghcr.io:443/divbast/frankenphp:librespeed@" + digest + "\n",
			want:          []string{pinned + " line 01"},
		},
		{
			name:          "a-registry-in-capitals",
			containerfile: "FROM scratch\nCOPY --from=GCR.IO:443/distroless/static-debian13:nonroot@" + digest + " /a /b\n",
			want:          []string{static + " line 02"},
		},
		{
			name:          "an-unpinned-frontend",
			containerfile: "# syntax=docker/dockerfile:1\nFROM scratch\n",
			wantErr:       verify.ErrUnpinned,
			wantIn:        []string{"line 1", "docker/dockerfile:1"},
		},
		{
			name:          "a-pinned-frontend",
			containerfile: "# syntax = docker/dockerfile:1.12@" + other + "\nFROM scratch\n",
			want:          []string{"docker/dockerfile:1.12@" + other + " line 01"},
		},
		{
			name:          "a-directive-after-the-first-instruction-is-a-comment",
			containerfile: "FROM scratch\n# syntax=docker/dockerfile:1\n",
		},
		{
			name:          "another-escape",
			containerfile: "# escape=`\nFROM scratch\n",
			wantErr:       verify.ErrNotLiteral,
			wantIn:        []string{"escape"},
		},
		{
			name:          "a-stage-inside-a-heredoc",
			containerfile: "FROM " + fetch + "\nRUN <<EOF\nFROM scratch AS alpine\nEOF\nCOPY --from=alpine /x /y\n",
			wantErr:       verify.ErrUnpinned,
			wantIn:        []string{"line 5", "alpine"},
		},
		{
			name:          "a-heredoc-with-tabs-stripped-and-quoted",
			containerfile: "FROM " + fetch + "\nRUN <<-\"END\"\n\tFROM scratch AS x\n\tEND\nCOPY --from=x /x /y\n",
			wantErr:       verify.ErrUnpinned,
			wantIn:        []string{"line 5"},
		},
		{
			// A marker in quotes is no heredoc, so the next line is read
			name:          "a-heredoc-marker-in-quotes",
			containerfile: "FROM " + fetch + "\nRUN echo \"a <<END\" 'b <<END'\nFROM alpine\n",
			wantErr:       verify.ErrUnpinned,
			wantIn:        []string{"line 3", "alpine"},
		},
		{
			name:          "a-heredoc-that-never-ends",
			containerfile: "FROM " + fetch + "\nRUN <<EOF\necho\n",
			wantErr:       verify.ErrNotLiteral,
			wantIn:        []string{"EOF"},
		},
		{
			name:          "a-mounts-from-in-capitals",
			containerfile: "FROM scratch\nRUN --mount=type=bind,FROM=alpine,target=/a true\n",
			wantErr:       verify.ErrUnpinned,
			wantIn:        []string{"line 2", "alpine"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := verify.Refs(strings.NewReader(tt.containerfile))
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("Refs() = %q, %v; want error %v", names(got), err, tt.wantErr)
			}
			for _, s := range tt.wantIn {
				if !strings.Contains(err.Error(), s) {
					t.Errorf("Refs() error = %q, want it to contain %q", err, s)
				}
			}
			if tt.wantErr == nil && !slices.Equal(names(got), tt.want) {
				t.Errorf("Refs() = %q, want %q", names(got), tt.want)
			}
		})
	}
}

func TestRefsUnreadable(t *testing.T) {
	t.Parallel()

	failure := errors.New("disk on fire")
	if _, err := verify.Refs(iotest.ErrReader(failure)); !errors.Is(err, failure) {
		t.Fatalf("Refs() error = %v, want it to wrap %v", err, failure)
	}
}

func TestRefString(t *testing.T) {
	t.Parallel()

	r := verify.Ref{Name: "ghcr.io/divbast/frankenphp", Tag: "librespeed", Digest: digest, Line: 3}
	if got := r.String(); got != pinned {
		t.Errorf("String() = %q, want %q", got, pinned)
	}
}
