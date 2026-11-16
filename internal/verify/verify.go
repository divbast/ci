// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

package verify

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/divbast/ci/internal/execx"
)

// Rule is how one publisher's images are verified.
type Rule struct {
	// Prefix is the image's repository, matched whole, or, ending in a
	// slash, every repository under it.
	Prefix string
	// Once is whether a Containerfile may name such an image only once.
	Once bool
	// Check verifies r, writing what the tool reports to log.
	Check func(ctx context.Context, gh, cosign execx.Runner, r Ref, log io.Writer) error
}

// under reports whether the rule's Prefix names every repository under it.
func (rule Rule) under() bool { return strings.HasSuffix(rule.Prefix, "/") }

// matches reports whether name is a repository the rule verifies, without
// regard to case.
func (rule Rule) matches(name string) bool {
	name, prefix := strings.ToLower(name), strings.ToLower(rule.Prefix)
	if rule.under() {
		return strings.HasPrefix(name, prefix) && len(name) > len(prefix)
	}
	return name == prefix
}

// Table is every image a Containerfile may build from that is verified,
// and how: divbast's own FrankenPHP by GitHub's attestation of the main
// build that made it, and Google's distroless images by their keyless
// cosign signature. A divbast image the table does not name is refused,
// and any other image passes once it is pinned.
var Table = []Rule{
	{Prefix: FrankenPHP, Once: true, Check: attested},
	{Prefix: Distroless, Check: signed},
}

// The images [Table] names, and the registry divbast publishes under.
const (
	FrankenPHP = "ghcr.io/divbast/frankenphp"
	Distroless = "gcr.io/distroless/"
	divbast    = "ghcr.io/divbast/"
)

// What an attestation must say for a FrankenPHP binary to pass: that
// divbast/frankenphp's build workflow, run from its main branch, built
// and signed it.
const (
	// SourceRepository is the repository the binary must be built from.
	SourceRepository = "divbast/frankenphp"
	// SignerWorkflow is the workflow, at the ref it ran from, that must
	// have signed the attestation.
	SignerWorkflow = "divbast/frankenphp/.github/workflows/build.yml@refs/heads/main"
	// SourceRef is the ref the binary must be built from.
	SourceRef = "refs/heads/main"
)

// What a distroless image's signature must say: that the distroless
// project's own keyless signing, as Google's account, made it.
const (
	DistrolessIdentity = "keyless@distroless.iam.gserviceaccount.com"
	DistrolessIssuer   = "https://accounts.google.com"
)

// MinGH is the oldest gh whose attestation verify is trusted. 2.102.0
// fixed two ways the wrong attestation could pass: --signer-workflow was
// matched against only the start of the signer's identity, and
// --source-ref without regard to case.
const MinGH = "2.102.0"

var (
	// ErrUnlisted means a divbast image that [Table] names no way to
	// verify.
	ErrUnlisted = errors.New("a divbast image is not in the table of verified images")
	// ErrManyRefs means an image a [Rule] allows once is named more than
	// once, and only one name could be the one verified.
	ErrManyRefs = errors.New("an image the table allows once is named more than once")
	// ErrOldGH means gh is older than [MinGH].
	ErrOldGH = errors.New("gh is older than " + MinGH)
	// ErrNotVerified means the tool did not verify the image as its
	// publisher's, or could not tell.
	ErrNotVerified = errors.New("not verified")
)

// Listed reports whether [Table] verifies r.
func Listed(r Ref) bool {
	_, ok := ruleFor(r.Name)
	return ok
}

// ruleFor returns the Rule that verifies the repository name.
func ruleFor(name string) (Rule, bool) {
	for _, rule := range Table {
		if rule.matches(name) {
			return rule, true
		}
	}
	return Rule{}, false
}

// Verify verifies every one of refs that [Table] names, once each, and
// returns nil only when each passes. It refuses a divbast image the table
// does not name, and an image a Rule allows once that refs name more than
// once. gh runs gh, and cosign runs cosign; whatever each reports, on its
// stderr and then its stdout, goes to log.
//
// The error wraps [ErrUnlisted], [ErrManyRefs], [ErrOldGH] or
// [ErrNotVerified] where one applies.
func Verify(ctx context.Context, gh, cosign execx.Runner, refs []Ref, log io.Writer) error {
	for _, r := range refs {
		if !Listed(r) && strings.HasPrefix(strings.ToLower(r.Name), divbast) {
			return fmt.Errorf("%w: line %d has %s, and no way to verify it is known", ErrUnlisted, r.Line, r)
		}
	}
	for _, rule := range Table {
		if !rule.Once {
			continue
		}
		var lines []string
		for _, r := range refs {
			if rule.matches(r.Name) {
				lines = append(lines, strconv.Itoa(r.Line))
			}
		}
		if len(lines) > 1 {
			return fmt.Errorf("%w: %s, on line %s", ErrManyRefs, rule.Prefix, strings.Join(lines, ", line "))
		}
	}
	var done []string
	for _, r := range refs {
		rule, ok := ruleFor(r.Name)
		if !ok || slices.Contains(done, r.String()) {
			continue
		}
		if err := rule.Check(ctx, gh, cosign, r, log); err != nil {
			return fmt.Errorf("%s: %w", r, err)
		}
		done = append(done, r.String())
	}
	return nil
}

// attested asks gh whether divbast/frankenphp's build workflow, run from
// its main branch, attested r's digest. gh reads the attestation through
// the GitHub API, which needs a token that can read attestations.
func attested(ctx context.Context, gh, _ execx.Runner, r Ref, log io.Writer) error {
	if err := checkGH(ctx, gh); err != nil {
		return err
	}
	return report(ctx, gh, log, "gh did not verify that divbast/frankenphp's main build attested it",
		"gh", "attestation", "verify", "oci://"+r.Image(),
		"--repo", SourceRepository,
		"--signer-workflow", SignerWorkflow,
		"--source-ref", SourceRef)
}

// signed asks cosign whether the distroless project's keyless signing
// signed r's digest. Any status but 0 is a refusal: cosign exits 10 for an
// image with no signature and 12 for one signed by someone else.
func signed(ctx context.Context, _, cosign execx.Runner, r Ref, log io.Writer) error {
	return report(ctx, cosign, log, "cosign did not verify that the distroless project signed it",
		"cosign", "verify", r.Image(),
		"--certificate-identity", DistrolessIdentity,
		"--certificate-oidc-issuer", DistrolessIssuer)
}

// report runs a verification through runner, writes what it reported to
// log, and returns an error wrapping [ErrNotVerified], saying refusal,
// unless it exited 0.
func report(ctx context.Context, runner execx.Runner, log io.Writer, refusal, name string, args ...string) error {
	res, err := runner.Run(ctx, name, args...)
	if err != nil {
		return fmt.Errorf("%s %s: %w", name, args[0], err)
	}
	if _, err = log.Write(res.Stderr); err == nil {
		_, err = log.Write(res.Stdout)
	}
	if err != nil {
		return fmt.Errorf("write %s's report: %w", name, err)
	}
	if res.Code != 0 {
		return fmt.Errorf("%w: %s: %s %s exited %d", ErrNotVerified, refusal, name, args[0], res.Code)
	}
	return nil
}

var (
	// ghVersion is the version on the first line `gh --version` prints,
	// such as "gh version 2.103.3 (2026-10-21)".
	ghVersion = regexp.MustCompile(`^gh version (\S+)`)
	semver    = regexp.MustCompile(`^(\d+)\.(\d+)\.(\d+)`)
	minGH     = mustVersion(MinGH)
)

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
		panic("verify: not a version: " + s)
	}
	return v
}
