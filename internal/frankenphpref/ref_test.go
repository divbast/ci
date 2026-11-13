// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

package frankenphpref_test

import (
	"errors"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/divbast/ci/internal/frankenphpref"
)

const (
	digest = "sha256:d9ea226a05957bd70876b6b3eb81ca454fefc4365902f061dba82515efb12909"
	other  = "sha256:4dcdd53971ba1f373c3eb90e393dd3944687938c5c03494ab684921594905fc7"
	pinned = "ghcr.io/divbast/frankenphp:librespeed@" + digest
)

// app is an app's Containerfile around lines, which stand where its
// runtime stage takes the binary.
func app(lines ...string) string {
	return `# syntax=docker/dockerfile:1
ARG RUNTIME_IMAGE=gcr.io/distroless/cc-debian13:nonroot@` + other + `

FROM debian:13-slim@` + other + ` AS fetch
RUN mkdir -p /out/app

FROM ${RUNTIME_IMAGE}
` + strings.Join(lines, "\n") + `
COPY --from=fetch --chown=root:root /out/app /var/www/app
USER 65532:65532
`
}

func TestFind(t *testing.T) {
	t.Parallel()

	want := frankenphpref.Ref{Tag: "librespeed", Digest: digest}

	tests := []struct {
		name          string
		containerfile string
		want          frankenphpref.Ref
		wantErr       error
		// wantIn lists what the error message must contain.
		wantIn []string
	}{
		{
			name:          "single",
			containerfile: app("COPY --from=" + pinned + " /frankenphp /usr/local/bin/frankenphp"),
			want:          want,
		},
		{
			name:          "none",
			containerfile: app("COPY --from=fetch /out/frankenphp /usr/local/bin/frankenphp"),
			wantErr:       frankenphpref.ErrNoRef,
		},
		{
			name: "two",
			containerfile: app(
				"COPY --from="+pinned+" /frankenphp /usr/local/bin/frankenphp",
				"COPY --from=ghcr.io/divbast/frankenphp:baikal@"+other+" /frankenphp /usr/local/bin/php",
			),
			wantErr: frankenphpref.ErrManyRefs,
			wantIn:  []string{"line 8", "line 9"},
		},
		{
			name:          "tag-only",
			containerfile: app("COPY --from=ghcr.io/divbast/frankenphp:librespeed /frankenphp /usr/local/bin/frankenphp"),
			wantErr:       frankenphpref.ErrUnpinned,
			wantIn:        []string{"line 8", "ghcr.io/divbast/frankenphp:librespeed"},
		},
		{
			name: "arg",
			containerfile: app(
				"ARG FP="+pinned,
				"COPY --from=${FP} /frankenphp /usr/local/bin/frankenphp",
			),
			wantErr: frankenphpref.ErrNotLiteral,
			wantIn:  []string{"line 9", "${FP}"},
		},
		{
			name: "other-registry-ignored",
			containerfile: app(
				"COPY --from=docker.io/divbast/frankenphp:librespeed@"+other+" /frankenphp /opt/a",
				"COPY --from=ghcr.io/dunglas/frankenphp:latest /frankenphp /opt/b",
				"COPY --from="+pinned+" /frankenphp /usr/local/bin/frankenphp",
			),
			want: want,
		},
		{
			name: "comment-ignored",
			containerfile: app(
				"# COPY --from=ghcr.io/divbast/frankenphp:librespeed@"+other+" /frankenphp /usr/local/bin/frankenphp",
				"   # was ghcr.io/divbast/frankenphp:librespeed",
				"COPY --from="+pinned+" /frankenphp /usr/local/bin/frankenphp",
			),
			want: want,
		},
		// Ruling R3: --from= counts wherever it stands among the flags.
		{
			name:          "flags-before-from",
			containerfile: app("COPY --chmod=0755 --link --from=" + pinned + " /frankenphp /usr/local/bin/frankenphp"),
			want:          want,
		},
		{
			name:          "flags-after-from",
			containerfile: app("COPY --from=" + pinned + " --chmod=0755 /frankenphp /usr/local/bin/frankenphp"),
			want:          want,
		},
		{
			name: "continued-lines",
			containerfile: app(
				`COPY --chmod=0755 \`,
				`    # a comment inside an instruction is dropped, as BuildKit drops it`,
				`    --from=`+pinned+` \`,
				`    /frankenphp /usr/local/bin/frankenphp`,
			),
			want: want,
		},
		{
			name:          "lower-case-instruction",
			containerfile: app("copy --from=" + pinned + " /frankenphp /usr/local/bin/frankenphp"),
			want:          want,
		},
		{
			name:          "arg-without-braces",
			containerfile: app("COPY --from=$FP /frankenphp /usr/local/bin/frankenphp"),
			wantErr:       frankenphpref.ErrNotLiteral,
		},
		// CI-49: a stage built from an unresolved build argument, which a
		// COPY --from= names, is refused as the argument itself is: by
		// name, by number and through a stage built on it.
		{
			name: "stage-from-an-unresolved-build-argument",
			containerfile: app(
				"COPY --from="+pinned+" /frankenphp /usr/local/bin/frankenphp",
				"FROM ${BASE} AS base",
				"FROM ${RUNTIME_IMAGE}",
				"COPY --from=base /tool /usr/local/bin/tool",
			),
			wantErr: frankenphpref.ErrNotLiteral,
			wantIn:  []string{"line 11", "--from=base", "line 9", "${BASE}"},
		},
		{
			name: "stage-by-number-from-an-unresolved-build-argument",
			containerfile: app(
				"COPY --from="+pinned+" /frankenphp /usr/local/bin/frankenphp",
				"FROM $BASE",
				"FROM ${RUNTIME_IMAGE}",
				"COPY --from=2 /tool /usr/local/bin/tool",
			),
			wantErr: frankenphpref.ErrNotLiteral,
			wantIn:  []string{"--from=2", "$BASE"},
		},
		{
			name: "stage-on-a-stage-from-an-unresolved-build-argument",
			containerfile: app(
				"COPY --from="+pinned+" /frankenphp /usr/local/bin/frankenphp",
				"FROM ${BASE} AS Base",
				"FROM base AS tools",
				"FROM ${RUNTIME_IMAGE}",
				"COPY --from=tools /tool /usr/local/bin/tool",
			),
			wantErr: frankenphpref.ErrNotLiteral,
			wantIn:  []string{"--from=tools", "${BASE}"},
		},
		// A build argument in a FROM's flag, not its image, is no image
		// built from one, and a stage no COPY --from= names is not read.
		{
			name: "stage-with-a-platform-argument",
			containerfile: app(
				"COPY --from="+pinned+" /frankenphp /usr/local/bin/frankenphp",
				"FROM --platform=${BUILDPLATFORM} debian:13-slim@"+other+" AS tools",
				"FROM ${RUNTIME_IMAGE}",
				"COPY --from=tools /tool /usr/local/bin/tool",
				"COPY --from=2 /other /usr/local/bin/other",
			),
			want: want,
		},
		{
			name:          "digest-only",
			containerfile: app("COPY --from=ghcr.io/divbast/frankenphp@" + digest + " /frankenphp /usr/local/bin/frankenphp"),
			wantErr:       frankenphpref.ErrUnpinned,
		},
		{
			name:          "short-digest",
			containerfile: app("COPY --from=ghcr.io/divbast/frankenphp:librespeed@sha256:d9ea226a /frankenphp /usr/local/bin/frankenphp"),
			wantErr:       frankenphpref.ErrUnpinned,
		},
		// The image named anywhere else is a second way in for a binary
		// the check never saw, so it counts.
		{
			name: "named-by-from-only",
			containerfile: app(
				"FROM "+pinned+" AS fp",
				"COPY --from=fp /frankenphp /usr/local/bin/frankenphp",
			),
			wantErr: frankenphpref.ErrNoRef,
			wantIn:  []string{"line 8"},
		},
		{
			name: "named-by-from-too",
			containerfile: app(
				"FROM ghcr.io/divbast/frankenphp:pr@"+other+" AS fp",
				"COPY --from="+pinned+" /frankenphp /usr/local/bin/frankenphp",
				"COPY --from=fp /frankenphp /usr/local/bin/php",
			),
			wantErr: frankenphpref.ErrManyRefs,
		},
		{
			name:          "look-alike-repository",
			containerfile: app("COPY --from=ghcr.io/divbast/frankenphp-dev:librespeed@" + digest + " /frankenphp /usr/local/bin/frankenphp"),
			wantErr:       frankenphpref.ErrNoRef,
		},
		{
			name:          "empty",
			containerfile: "",
			wantErr:       frankenphpref.ErrNoRef,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := frankenphpref.Find(strings.NewReader(tt.containerfile))
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("Find() error = %v, want %v", err, tt.wantErr)
			}
			for _, s := range tt.wantIn {
				if !strings.Contains(err.Error(), s) {
					t.Errorf("Find() error = %q, want it to contain %q", err, s)
				}
			}
			if got != tt.want {
				t.Errorf("Find() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestFindUnreadable(t *testing.T) {
	t.Parallel()

	failure := errors.New("disk on fire")
	_, err := frankenphpref.Find(iotest.ErrReader(failure))
	if !errors.Is(err, failure) {
		t.Fatalf("Find() error = %v, want it to wrap %v", err, failure)
	}
}

func TestRefString(t *testing.T) {
	t.Parallel()

	ref := frankenphpref.Ref{Tag: "librespeed", Digest: digest}
	if got := ref.String(); got != pinned {
		t.Errorf("String() = %q, want %q", got, pinned)
	}
	if got, want := ref.Image(), "ghcr.io/divbast/frankenphp@"+digest; got != want {
		t.Errorf("Image() = %q, want %q", got, want)
	}
}
