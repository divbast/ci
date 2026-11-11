// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

package frankenphpref

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strconv"

	"github.com/divbast/ci/internal/execx"
)

// MinGH is the oldest gh whose attestation verify [Verify] trusts. 2.102.0
// fixed two ways the wrong attestation could pass: --signer-workflow was
// matched against only the start of the signer's identity, and
// --source-ref without regard to case.
const MinGH = "2.102.0"

// What an attestation must say for [Verify] to pass: that divbast/frankenphp's
// build workflow, run from its main branch, built and signed the binary.
const (
	// SourceRepository is the repository the binary must be built from.
	SourceRepository = "divbast/frankenphp"
	// SignerWorkflow is the workflow, at the ref it ran from, that must
	// have signed the attestation.
	SignerWorkflow = "divbast/frankenphp/.github/workflows/build.yml@refs/heads/main"
	// SourceRef is the ref the binary must be built from.
	SourceRef = "refs/heads/main"
)

var (
	// ErrOldGH means gh is older than [MinGH].
	ErrOldGH = errors.New("gh is older than " + MinGH)
	// ErrNotVerified means gh did not verify the attestation: there is
	// none from divbast/frankenphp's main build, or gh could not tell.
	ErrNotVerified = errors.New("gh did not verify that divbast/frankenphp's main build attested the binary")
)

var (
	// ghVersion is the version on the first line `gh --version` prints,
	// such as "gh version 2.103.3 (2026-10-21)".
	ghVersion = regexp.MustCompile(`^gh version (\S+)`)
	semver    = regexp.MustCompile(`^(\d+)\.(\d+)\.(\d+)`)
	minGH     = mustVersion(MinGH)
)

// Verify asks gh whether divbast/frankenphp's build workflow, run from its
// main branch, attested ref's digest, and returns nil only when gh says it
// did. It first checks that gh is [MinGH] or newer. Whatever gh reports,
// on its stderr and then its stdout, goes to log.
//
// gh reads the attestation through the GitHub API, which needs a token
// that can read attestations, and the image's digest from the registry,
// with any login Docker's configuration holds. The error wraps [ErrOldGH]
// or [ErrNotVerified] where one applies.
func Verify(ctx context.Context, r execx.Runner, ref Ref, log io.Writer) error {
	if err := checkGH(ctx, r); err != nil {
		return err
	}
	res, err := r.Run(ctx, "gh", "attestation", "verify", "oci://"+ref.Image(),
		"--repo", SourceRepository,
		"--signer-workflow", SignerWorkflow,
		"--source-ref", SourceRef)
	if err != nil {
		return fmt.Errorf("gh attestation verify: %w", err)
	}
	if _, err = log.Write(res.Stderr); err == nil {
		_, err = log.Write(res.Stdout)
	}
	if err != nil {
		return fmt.Errorf("write gh's report: %w", err)
	}
	if res.Code != 0 {
		return fmt.Errorf("%w: gh attestation verify exited %d", ErrNotVerified, res.Code)
	}
	return nil
}

// checkGH fails unless gh is MinGH or newer.
func checkGH(ctx context.Context, r execx.Runner) error {
	res, err := r.Run(ctx, "gh", "--version")
	if err != nil {
		return fmt.Errorf("gh --version: %w", err)
	}
	if res.Code != 0 {
		return fmt.Errorf("gh --version exited %d: %s", res.Code, bytes.TrimSpace(res.Stderr))
	}
	first, _, _ := bytes.Cut(res.Stdout, []byte("\n"))
	m := ghVersion.FindSubmatch(first)
	if m == nil {
		return fmt.Errorf("gh --version printed no version: %q", first)
	}
	have, ok := version(string(m[1]))
	if !ok {
		return fmt.Errorf("gh --version printed no version of the form X.Y.Z: %q", first)
	}
	if slices.Compare(have, minGH) < 0 {
		return fmt.Errorf("%w: it is %s", ErrOldGH, m[1])
	}
	return nil
}

// version reads the major, minor and patch numbers at the start of s.
func version(s string) ([]int, bool) {
	m := semver.FindStringSubmatch(s)
	if m == nil {
		return nil, false
	}
	v := make([]int, 0, 3)
	for _, part := range m[1:] {
		n, err := strconv.Atoi(part)
		if err != nil {
			return nil, false
		}
		v = append(v, n)
	}
	return v, true
}

func mustVersion(s string) []int {
	v, ok := version(s)
	if !ok {
		panic("frankenphpref: not a version: " + s)
	}
	return v
}
