// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

// Package workflows_test reads ci's workflows as text, so that no job
// holding a write scope runs install code from the caller's toolchain that
// it does not need. Every job whose permissions, its own or else its
// workflow's, grant a write scope, and every job that mints a GitHub App
// token in a step, whose scopes its permissions do not bound, must give
// each jdx/mise-action step install_args that name a tool, set
// MISE_AUTO_INSTALL to false in the job's env if it has such a step, and
// set it to nothing else in any step. A permissions value the test cannot
// read fails as well.
package workflows_test

import (
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/divbast/ci/internal/execx"
)

// mustGuard are jobs the derived set must hold, so that a parser
// regression cannot empty it unnoticed: the two whose permissions hold a
// write scope today, and the two that mint a GitHub App token in a step.
var mustGuard = []string{"app-check.yml/scan", "app-publish.yml/publish", "renovate.yml/renovate", "self-ci.yml/release"}

// TestWriteScopedJobsInstallOnlyWhatTheyName runs check over every
// workflow in .github/workflows, and fails on each problem it finds, or
// when the jobs it guards do not include mustGuard.
func TestWriteScopedJobsInstallOnlyWhatTheyName(t *testing.T) {
	t.Parallel()
	guarded, found := check(readWorkflows(t))
	for _, want := range mustGuard {
		if !slices.Contains(guarded, want) {
			t.Errorf("guards %q, which does not include %s", guarded, want)
		}
	}
	for _, p := range found {
		t.Error(p)
	}
}

// TestCheck makes one change each to ci's own workflows, and sees check
// guard the job the change gives a write scope and fail on it, or leave
// alone a job the change does not.
func TestCheck(t *testing.T) {
	t.Parallel()
	const bare = "    steps:\n      - uses: jdx/mise-action@b44d12e7d0d8ee7461bb893e1b1993500433185b # v5.2.7\n"
	const scope = "      attestations: read # verify the FrankenPHP binary's attestation\n"
	const mint = "      - uses: actions/create-github-app-token@64ab729a6294000f5aa4a4bc0b73d1f32bc45510 # v3.3.0\n"
	tests := []struct {
		name    string
		change  func(workflows map[string]string)
		job     string // file/job
		guarded bool
		want    string // what one problem must say, when not empty
	}{
		{
			name: "a new write-scoped job without install_args",
			change: func(w map[string]string) {
				w["app-check.yml"] += "\n  sign:\n    runs-on: ubuntu-26.04\n    permissions:\n      contents: read\n      id-token: write # sign\n" + bare
			},
			job:     "app-check.yml/sign",
			guarded: true,
		},
		{
			name: "build gains packages: write",
			change: func(w map[string]string) {
				w["app-check.yml"] = strings.Replace(w["app-check.yml"], scope, scope+"      packages: write\n", 1)
			},
			job:     "app-check.yml/build",
			guarded: true,
		},
		{
			name: "a write-scoped job in a new workflow",
			change: func(w map[string]string) {
				w["release.yml"] = "permissions: {}\n\njobs:\n  tag:\n    runs-on: ubuntu-26.04\n    permissions:\n      contents: write\n" + bare
			},
			job:     "release.yml/tag",
			guarded: true,
		},
		{
			name: "write-all on the job",
			change: func(w map[string]string) {
				w["release.yml"] = "permissions: {}\n\njobs:\n  tag:\n    runs-on: ubuntu-26.04\n    permissions: write-all\n" + bare
			},
			job:     "release.yml/tag",
			guarded: true,
		},
		{
			name: "write scopes from the workflow, to a job with none of its own",
			change: func(w map[string]string) {
				w["release.yml"] = "permissions:\n  contents: write\n\njobs:\n  tag:\n    runs-on: ubuntu-26.04\n" + bare
			},
			job:     "release.yml/tag",
			guarded: true,
		},
		{
			name: "the job's own read scopes over the workflow's write",
			change: func(w map[string]string) {
				w["release.yml"] = "permissions:\n  contents: write\n\njobs:\n  tag:\n    runs-on: ubuntu-26.04\n    permissions:\n      contents: read\n" + bare
			},
			job: "release.yml/tag",
		},
		{
			name: "flow-style write on the job",
			change: func(w map[string]string) {
				w["release.yml"] = "permissions: {}\n\njobs:\n  tag:\n    runs-on: ubuntu-26.04\n    permissions: { contents: write }\n" + bare
			},
			job:     "release.yml/tag",
			guarded: true,
		},
		{
			name: "flow-style write from the workflow",
			change: func(w map[string]string) {
				w["release.yml"] = "permissions: { contents: read, packages: write }\n\njobs:\n  tag:\n    runs-on: ubuntu-26.04\n" + bare
			},
			job:     "release.yml/tag",
			guarded: true,
		},
		{
			name: "flow-style read on the job",
			change: func(w map[string]string) {
				w["release.yml"] = "permissions: {}\n\njobs:\n  tag:\n    runs-on: ubuntu-26.04\n    permissions: { contents: read }\n" + bare
			},
			job: "release.yml/tag",
		},
		{
			name: "an empty flow map on the job",
			change: func(w map[string]string) {
				w["release.yml"] = "permissions: { contents: write }\n\njobs:\n  tag:\n    runs-on: ubuntu-26.04\n    permissions: {}\n" + bare
			},
			job: "release.yml/tag",
		},
		{
			name: "a permissions value it cannot read",
			change: func(w map[string]string) {
				w["release.yml"] = "permissions: {}\n\njobs:\n  tag:\n    runs-on: ubuntu-26.04\n    permissions: ${{ inputs.permissions }}\n" + bare
			},
			job:     "release.yml/tag",
			guarded: true,
			want:    "line 6: permissions: ${{ inputs.permissions }} is none of {}, read-all, write-all or a { } map; write it in block style",
		},
		{
			name: "a workflow permissions value it cannot read",
			change: func(w map[string]string) {
				w["release.yml"] = "permissions: write\n\njobs:\n  tag:\n    runs-on: ubuntu-26.04\n" + bare
			},
			job:     "release.yml/tag",
			guarded: true,
			want:    "release.yml: line 1: permissions: write is none of {}, read-all, write-all or a { } map",
		},
		{
			name: "read-all, and an App token with write minted in a step",
			change: func(w map[string]string) {
				w["release.yml"] = "permissions: {}\n\njobs:\n  tag:\n    runs-on: ubuntu-26.04\n    permissions: read-all\n" + bare + mint +
					"        with:\n          permission-contents: write\n"
			},
			job:     "release.yml/tag",
			guarded: true,
		},
		{
			name: "no permissions at all, and an App token minted in a step",
			change: func(w map[string]string) {
				w["release.yml"] = "permissions: {}\n\njobs:\n  tag:\n    runs-on: ubuntu-26.04\n    permissions: {}\n" + bare +
					"      - id: token\n" + strings.Replace(mint, "- uses:", "  uses:", 1)
			},
			job:     "release.yml/tag",
			guarded: true,
		},
		{
			name: "renovate gains a mise step",
			change: func(w map[string]string) {
				w["renovate.yml"] = strings.Replace(w["renovate.yml"], "    steps:\n", bare, 1)
			},
			job:     "renovate.yml/renovate",
			guarded: true,
		},
	}
	base := readWorkflows(t)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			workflows := maps.Clone(base)
			before := maps.Clone(workflows)
			tt.change(workflows)
			if maps.Equal(workflows, before) {
				t.Fatal("the change changed nothing")
			}
			guarded, found := check(workflows)
			file, job, _ := strings.Cut(tt.job, "/")
			fails := slices.ContainsFunc(found, func(p string) bool {
				return strings.HasPrefix(p, file+": job "+job+": ")
			})
			if got := slices.Contains(guarded, tt.job); got != tt.guarded || fails != tt.guarded {
				t.Errorf("check guards %s: %t, and fails on it: %t; want %t for both\nguarded: %q\nfound: %q",
					tt.job, got, fails, tt.guarded, guarded, found)
			}
			if tt.want != "" && !slices.ContainsFunc(found, func(p string) bool { return strings.Contains(p, tt.want) }) {
				t.Errorf("no problem says %q\nfound: %q", tt.want, found)
			}
		})
	}
}

// TestProblems sees each way a job can fail the guard caught, and a job
// that passes it left alone.
func TestProblems(t *testing.T) {
	t.Parallel()
	const head = "jobs:\n  j:\n    runs-on: ubuntu-26.04\n"
	const off = "    env:\n      MISE_AUTO_INSTALL: \"false\"\n"
	const mise = "      - uses: jdx/mise-action@b44d12e7d0d8ee7461bb893e1b1993500433185b # v5.2.7\n"
	tests := []struct {
		name, workflow string
		want           []string
	}{
		{
			name:     "named tools and no auto-install",
			workflow: head + off + "    steps:\n" + mise + "        with:\n          install_args: core:go\n      - run: go version\n",
		},
		{
			name:     "no mise step",
			workflow: head + "    steps:\n      - run: go version\n",
		},
		{
			name:     "no with",
			workflow: head + off + "    steps:\n" + mise + "      - run: go version\n",
			want:     []string{"line 7 runs jdx/mise-action without install_args"},
		},
		{
			name:     "with but no install_args",
			workflow: head + off + "    steps:\n" + mise + "        with:\n          cache: false\n",
			want:     []string{"line 7 runs jdx/mise-action without install_args"},
		},
		{
			name:     "install_args commented out",
			workflow: head + off + "    steps:\n" + mise + "        with:\n          # install_args: core:go\n          cache: false\n",
			want:     []string{"line 7 runs jdx/mise-action without install_args"},
		},
		{
			name:     "empty install_args",
			workflow: head + off + "    steps:\n" + mise + "        with:\n          install_args: \"\"\n",
			want:     []string{"line 7 runs jdx/mise-action without install_args"},
		},
		{
			name:     "comments, in column 0 as well",
			workflow: head + off + "    steps:\n# a note\n" + mise + "        with:\n  # install_args: core:go\n          cache: false\n",
			want:     []string{"line 8 runs jdx/mise-action without install_args"},
		},
		{
			name:     "install_args on the next step",
			workflow: head + off + "    steps:\n" + mise + "      - uses: jdx/mise-action@b44d12e7d0d8ee7461bb893e1b1993500433185b # v5.2.7\n        with:\n          install_args: core:go\n",
			want:     []string{"line 7 runs jdx/mise-action without install_args"},
		},
		{
			name:     "no job env",
			workflow: head + "    steps:\n" + mise + "        with:\n          install_args: core:go\n",
			want:     []string{"sets no MISE_AUTO_INSTALL: \"false\""},
		},
		{
			name:     "auto-install off in one step only",
			workflow: head + "    steps:\n" + mise + "        with:\n          install_args: core:go\n      - run: just scan\n        env:\n          MISE_AUTO_INSTALL: \"false\"\n",
			want:     []string{"sets no MISE_AUTO_INSTALL: \"false\""},
		},
		{
			name:     "install_args of flags alone",
			workflow: head + off + "    steps:\n" + mise + "        with:\n          install_args: --locked\n",
			want:     []string{"line 7 runs jdx/mise-action without install_args"},
		},
		{
			name:     "auto-install back on in a step",
			workflow: head + off + "    steps:\n" + mise + "        with:\n          install_args: core:go\n      - run: just scan\n        env:\n          MISE_AUTO_INSTALL: \"true\"\n",
			want:     []string{"line 12 sets MISE_AUTO_INSTALL"},
		},
		{
			name:     "auto-install on",
			workflow: head + "    env:\n      MISE_AUTO_INSTALL: \"true\"\n    steps:\n" + mise + "        with:\n          install_args: core:go\n",
			want:     []string{"sets no MISE_AUTO_INSTALL: \"false\""},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := problems(jobsOf(linesOf(tt.workflow))["j"])
			if len(got) != len(tt.want) {
				t.Fatalf("problems() = %q, want %d starting %q", got, len(tt.want), tt.want)
			}
			for i, p := range got {
				if !strings.HasPrefix(p, tt.want[i]) {
					t.Errorf("problems()[%d] = %q, want it to start %q", i, p, tt.want[i])
				}
			}
		})
	}
}

// TestRenovateTokenReadsDependabotAlerts checks that renovate.yml's App
// token asks to read Dependabot alerts. Renovate reads a repository's
// alerts to raise its security updates, and given a token that cannot, it
// warns in its log and raises none: nothing would fail to say so. Against
// renovate.yml as it is, then with the permission taken out, which the
// check must refuse.
func TestRenovateTokenReadsDependabotAlerts(t *testing.T) {
	t.Parallel()
	renovate := readWorkflows(t)["renovate.yml"]
	if err := readsDependabotAlerts(renovate); err != nil {
		t.Errorf("renovate.yml: %v", err)
	}
	const perm = "          permission-vulnerability-alerts: read\n"
	for name, mutant := range map[string]string{
		"taken out":     strings.Replace(renovate, perm, "", 1),
		"commented out": strings.Replace(renovate, perm, "          # permission-vulnerability-alerts: read\n", 1),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if mutant == renovate {
				t.Fatal("the change changed nothing")
			}
			if readsDependabotAlerts(mutant) == nil {
				t.Error("passes renovate.yml with permission-vulnerability-alerts " + name)
			}
		})
	}
}

// readsDependabotAlerts returns an error unless the workflow has a step
// that mints a GitHub App token, and each such step asks for
// permission-vulnerability-alerts: read.
func readsDependabotAlerts(workflow string) error {
	minted := false
	for _, job := range jobsOf(linesOf(workflow)) {
		for _, step := range steps(job) {
			if !slices.ContainsFunc(step, mintsAppToken) {
				continue
			}
			minted = true
			if !slices.ContainsFunc(step, func(l line) bool {
				v, ok := strings.CutPrefix(strings.TrimSpace(l.text), "permission-vulnerability-alerts:")
				return ok && unquote(v) == "read"
			}) {
				return fmt.Errorf("line %d mints a token without permission-vulnerability-alerts: read,"+
					" so Renovate cannot read the Dependabot alerts it raises security updates for", step[0].n)
			}
		}
	}
	if !minted {
		return errors.New("no step mints a GitHub App token")
	}
	return nil
}

// mintsAppToken reports whether l is a step's uses: line for
// actions/create-github-app-token.
func mintsAppToken(l line) bool {
	return strings.HasPrefix(strings.TrimPrefix(strings.TrimSpace(l.text), "- "), "uses: actions/create-github-app-token@")
}

// TestStallContentGated checks that stall.yml's content-gated input, off
// unless a caller sets it, reaches divbast-stall as -content-gated in the
// slots job alone: a caller that leaves it unset sees the checks run as
// they always have, and the other checks would refuse the flag. Against
// stall.yml as it is, then with each link from the input to the command
// broken, which the check must refuse.
func TestStallContentGated(t *testing.T) {
	t.Parallel()
	stall := readWorkflows(t)["stall.yml"]
	if err := passesContentGated(t, stall); err != nil {
		t.Errorf("stall.yml: %v", err)
	}
	const (
		input   = "      content-gated:\n"
		boolean = "        type: boolean\n"
		dflt    = "        default: false\n"
		env     = "          CONTENT_GATED: ${{ inputs.content-gated }}\n"
		test    = `[[ "${CHECK}" == slots && "${CONTENT_GATED}" == true ]]`
	)
	for name, mutant := range map[string]string{
		"input taken out":          strings.Replace(stall, input, "      content-gated-not:\n", 1),
		"on by default":            strings.Replace(stall, boolean+dflt, boolean+"        default: true\n", 1),
		"not passed to the step":   strings.Replace(stall, env, "", 1),
		"another input passed":     strings.Replace(stall, env, "          CONTENT_GATED: ${{ inputs.lost-slots }}\n", 1),
		"passed to every check":    strings.Replace(stall, test, `[[ "${CONTENT_GATED}" == true ]]`, 1),
		"passed whatever it says":  strings.Replace(stall, test, `[[ "${CHECK}" == slots ]]`, 1),
		"never given to the check": strings.Replace(stall, " -content-gated\n", "\n", 1),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if mutant == stall {
				t.Fatal("the change changed nothing")
			}
			if passesContentGated(t, mutant) == nil {
				t.Error("passes stall.yml with content-gated " + name)
			}
		})
	}
}

// passesContentGated returns an error unless the workflow declares a
// boolean content-gated input that defaults to false, its stall job's step
// that runs divbast-stall maps the input to CONTENT_GATED, and that step's
// script, run with bash and a stand-in for divbast-stall, passes
// -content-gated to the slots check when CONTENT_GATED is true, and to no
// check otherwise.
func passesContentGated(t *testing.T, workflow string) error {
	t.Helper()
	lines := linesOf(workflow)

	decl := declaration(lines, "content-gated")
	if !slices.Contains(decl, "type: boolean") || !slices.Contains(decl, "default: false") {
		return fmt.Errorf("declares content-gated as %q, not a boolean input that defaults to false", decl)
	}

	var step []line
	for _, st := range steps(jobsOf(lines)["stall"]) {
		if slices.ContainsFunc(st, func(l line) bool { return strings.Contains(l.text, ".ci/bin/divbast-stall") }) {
			step = st
		}
	}
	if step == nil {
		return errors.New("the stall job has no step that runs .ci/bin/divbast-stall")
	}
	if !slices.ContainsFunc(step, func(l line) bool {
		k, v, ok := strings.Cut(strings.TrimSpace(l.text), ":")
		return ok && k == "CONTENT_GATED" && unquote(v) == "${{ inputs.content-gated }}"
	}) {
		return fmt.Errorf("line %d runs divbast-stall with no CONTENT_GATED: ${{ inputs.content-gated }} in its env", step[0].n)
	}

	script, err := runScript(step)
	if err != nil {
		return err
	}
	for _, tt := range []struct{ check, gated, want string }{
		{check: "slots", gated: "true", want: "[slots][-content-gated]"},
		{check: "slots", gated: "false", want: "[slots]"},
		{check: "open", gated: "true", want: "[open]"},
		{check: "stuck", gated: "true", want: "[stuck]"},
		{check: "renovate", gated: "false", want: "[renovate]"},
	} {
		got, err := runStall(t, script, tt.check, tt.gated)
		if err != nil {
			return err
		}
		if got != tt.want {
			return fmt.Errorf("with CHECK=%s and CONTENT_GATED=%s, runs divbast-stall with %s, want %s", tt.check, tt.gated, got, tt.want)
		}
	}
	return nil
}

// declaration returns the lines below a workflow_call input's name, each
// trimmed: its type, default and the rest.
func declaration(lines []line, input string) []string {
	var decl []string
	for i, l := range lines {
		if l.text != "      "+input+":" {
			continue
		}
		for _, d := range lines[i+1:] {
			if indent(d.text) <= 6 {
				break
			}
			decl = append(decl, strings.TrimSpace(d.text))
		}
	}
	return decl
}

// sneak is a step, written run: first, that tags latest through env
// values before the attestation, as review wrote it; sneakOnGate is the
// same on the decision's if:, and sneakNamed the same with a name.
const (
	sneak = "      - run: docker buildx imagetools create \"-t\" \"${D}:${T}\" \"${D}@${S}\"\n" +
		"        env:\n          T: latest\n"
	sneakOnGate = "      - run: docker buildx imagetools create \"-t\" \"${D}:${T}\" \"${D}@${S}\"\n" +
		"        if: steps.decide.outputs.publish == 'true'\n        env:\n          T: latest\n"
	sneakNamed = "      - name: Tag it early\n" +
		"        if: steps.decide.outputs.publish == 'true'\n" +
		"        run: docker buildx imagetools create \"-t\" \"${D}:${T}\" \"${D}@${S}\"\n" +
		"        env:\n          T: latest\n"
)

// The publish job's step names that the mutants below move or change, and
// the if: every step from the first push to the promotion runs on.
const (
	pushName    = "      - name: Push each tested architecture\n"
	stageName   = "      - name: Merge the architectures into one index under a staging tag\n"
	attestStep  = "      - uses: actions/attest@"
	verifyName  = "      - name: Verify the index's attestation\n"
	promoteName = "      - name: Tag the attested index with the version and latest\n"
	movedName   = "      - name: Say that the public tags did not move\n"
	targetName  = "      - name: Choose where to publish\n"
	warnName    = "      - name: Say that this run rehearses\n"
	gateName    = "      - name: Refuse anything but the daily slot or a manual run on main\n"
	checkName   = "      - name: Check both tags are the attested index as users pull them\n"
	gate        = "steps.decide.outputs.publish == 'true'"
)

// TestPublishAttestsBeforePromote checks that app-publish.yml moves no
// public tag until the index is attested and the attestation verified.
// The index is tagged <version>-staging alone, attested, verified as a
// user verifies it, and only then tagged with the version and latest, all
// by the one digest. Every step from the first push to the promotion runs
// on the one decision, and none lets a failure through, so a failed
// attestation leaves the public tags on the last attested index, where a
// re-run decides against them and publishes. Against app-publish.yml as it
// is, then with each of those broken, which the check must refuse.
func TestPublishAttestsBeforePromote(t *testing.T) {
	t.Parallel()
	publish := readWorkflows(t)["app-publish.yml"]
	if err := attestsBeforePromote(publish); err != nil {
		t.Errorf("app-publish.yml: %v", err)
	}
	const (
		staging     = `            -t "${IMAGE}:${VERSION}-staging" \` + "\n"
		version     = "            -t \"${IMAGE}:${VERSION}\"\n"
		latest      = "            -t \"${IMAGE}:latest\"\n"
		digest      = "          DIGEST: ${{ steps.merge.outputs.digest }}\n"
		signer      = " --signer-workflow divbast/ci/.github/workflows/app-publish.yml"
		onGate      = "        if: " + gate + "\n"
		goOn        = "        continue-on-error: true\n"
		from        = `skopeo copy --all "docker://${IMAGE}@$(cat /tmp/digest-amd64)"`
		loop        = `          for tag in "${VERSION}" latest; do ` + from + ` "docker://${IMAGE}:${tag}"; done` + "\n"
		viaVariable = `          tag=latest; ` + from + ` "docker://${IMAGE}:${tag}"` + "\n"
		viaEnv      = "          " + from + ` "docker://${IMAGE}:${PUBLIC}"` + "\n"
	)
	for name, mutant := range map[string]string{
		"the version tagged before attesting":                  strings.Replace(publish, staging, `            -t "${IMAGE}:${VERSION}" \`+"\n", 1),
		"latest tagged before attesting":                       strings.Replace(publish, staging, staging+`            -t "${IMAGE}:latest" \`+"\n", 1),
		"an arch pushed as latest":                             strings.Replace(publish, `"docker://${IMAGE}:${VERSION}-${arch}"`, `"docker://${IMAGE}:latest"`, 1),
		"the version pushed before attesting":                  replaceAfter(publish, pushName, "          done\n", "          done\n          skopeo copy --all \"docker://${IMAGE}@$(cat /tmp/digest-amd64)\" \"docker://${IMAGE}:${VERSION}\"\n"),
		"both tags pushed in a loop":                           replaceAfter(publish, pushName, "          done\n", "          done\n"+loop),
		"latest pushed through a variable":                     replaceAfter(publish, pushName, "          done\n", "          done\n"+viaVariable),
		"latest pushed through the env":                        replaceAfter(replaceAfter(publish, pushName, "          done\n", "          done\n"+viaEnv), pushName, "        env:\n", "        env:\n          PUBLIC: latest\n"),
		"latest pushed unquoted":                               replaceAfter(publish, pushName, "          done\n", "          done\n          skopeo copy --all docker://${IMAGE}@$(cat /tmp/digest-amd64) docker://${IMAGE}:latest\n"),
		"the version pushed unbraced":                          replaceAfter(publish, pushName, "          done\n", "          done\n          "+from+` "docker://${IMAGE}:$VERSION"`+"\n"),
		"latest pushed to ghcr.io by name":                     replaceAfter(publish, pushName, "          done\n", "          done\n          "+from+` "docker://ghcr.io/divbast/librespeed:latest"`+"\n"),
		"a write appended to the decision's read":              strings.Replace(publish, notReferences["decide"][0]+"\n", notReferences["decide"][0]+"; "+from+` "docker://${IMAGE}:latest"`+"\n", 1),
		"another tool's write appended to the decision's read": strings.Replace(publish, notReferences["decide"][0]+"\n", notReferences["decide"][0]+`; crane copy "${IMAGE}@${published}" "${IMAGE}:latest"`+"\n", 1),
		"a run-first step tagging latest early":                strings.Replace(publish, attestStep, sneak+attestStep, 1),
		"a run-first step on the gate tagging early":           strings.Replace(publish, attestStep, sneakOnGate+attestStep, 1),
		"latest staged by a quoted -t":                         strings.Replace(publish, staging, staging+`            "-t" "${IMAGE}:latest" \`+"\n", 1),
		"latest staged by a quoted --tag=":                     strings.Replace(publish, staging, staging+`            "--tag=${IMAGE}:latest" \`+"\n", 1),
		"a tag behind an @ in an expansion":                    replaceAfter(publish, pushName, "          done\n", "          done\n          "+from+` "docker://${IMAGE//@/}:${T}"`+"\n"),
		"a tag behind an @ in a reference":                     replaceAfter(publish, pushName, "          done\n", "          done\n          "+from+` "docker://${IMAGE}@x:latest"`+"\n"),
		"a write appended to the choice of image":              strings.Replace(publish, notReferences["target"][1]+"\n", notReferences["target"][1]+"; "+from+` "docker://${IMAGE}:latest"`+"\n", 1),
		"the decision's read moved past a push":                replaceAfter(publish, verifyName, "        run: |\n", "        run: |\n          published=$(.ci/bin/divbast-published-revision \"${IMAGE}:latest\")\n"),
		"promoted before verifying":                            moveStep(publish, promoteName, verifyName),
		"promoted before attesting":                            moveStep(publish, promoteName, attestStep),
		"verified before attesting":                            moveStep(publish, verifyName, attestStep),
		"attested before staging":                              moveStep(publish, attestStep, stageName),
		"promoted whatever happened":                           replaceAfter(publish, promoteName, onGate, "        if: always() && "+gate+"\n"),
		"verified whatever happened":                           replaceAfter(publish, verifyName, onGate, "        if: ${{ !cancelled() }}\n"),
		"an attestation that may fail":                         replaceAfter(publish, attestStep, onGate, onGate+goOn),
		"a verification that may fail":                         replaceAfter(publish, verifyName, onGate, onGate+goOn),
		"never verified":                                       replaceAfter(publish, verifyName, "gh attestation verify", "gh attestation download"),
		"verified for any signer":                              replaceAfter(publish, verifyName, signer, ""),
		"verified from any ref":                                replaceAfter(publish, verifyName, " --source-ref refs/heads/main", ""),
		"verified for any repository":                          replaceAfter(publish, verifyName, "          REPO: ${{ github.repository }}\n", "          REPO: divbast/oci-image-template\n"),
		"another digest attested":                              strings.Replace(publish, "subject-digest: ${{ steps.merge.outputs.digest }}", "subject-digest: ${{ steps.merge.outputs.amd64 }}", 1),
		"another digest verified":                              replaceAfter(publish, verifyName, digest, "          DIGEST: ${{ steps.merge.outputs.amd64 }}\n"),
		"another digest promoted":                              replaceAfter(publish, promoteName, digest, "          DIGEST: ${{ steps.merge.outputs.amd64 }}\n"),
		"another source promoted":                              strings.Replace(publish, `            "${IMAGE}@${DIGEST}"`+"\n", `            "${IMAGE}@$(cat /tmp/digest-amd64)"`+"\n", 1),
		"latest left out of the promotion":                     strings.Replace(publish, version+latest, version, 1),
		"the version left out of the promotion":                strings.Replace(publish, version+latest, latest, 1),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if mutant == publish {
				t.Fatal("the change changed nothing")
			}
			if attestsBeforePromote(mutant) == nil {
				t.Error("passes app-publish.yml with " + name)
			}
		})
	}
}

var (
	// tagArg is a -t or --tag argument and the reference it names, either
	// quoted or not, given as the next word or after an =.
	tagArg = regexp.MustCompile(`(?:^|[\s(])['"]?(?:-t|--tag)(?:['"]?\s+['"]?|=['"]?)([^"'\s]+)`)
	// publicTag is the version's tag or latest, however the version is
	// written, with the suffix, if any, that makes it the staging tag or
	// an architecture's.
	publicTag = regexp.MustCompile(`:(?:latest|\$\{VERSION\}|\$VERSION|\$\{\{ *steps\.version\.outputs\.version *\}\})(-staging|-\$\{arch\})?`)
)

// imageRef is a reference skopeo reads or writes, or one built on IMAGE
// in any expansion, to the quote or blank that ends it, a $( ) whole.
var imageRef = regexp.MustCompile(`(?:docker://|\$\{IMAGE[^}]*\}|\$IMAGE\b)(?:\$\([^)]*\)|[^"\s])*`)

// unmovedRef is the whole of a reference that leaves the version's tag
// and latest where they are: ${IMAGE} by a digest, sha256: or the
// DIGEST or per-arch digest file the job writes, or tagged
// ${VERSION}-staging or ${VERSION}-${arch}.
var unmovedRef = regexp.MustCompile(`^(?:docker://)?(?:\$\{IMAGE\}|\$IMAGE)` +
	`(?:@(?:sha256:[0-9a-f]{64}|\$\{DIGEST\}|\$\(cat /tmp/digest-(?:amd64|arm64)\))|:\$\{VERSION\}-(?:staging|\$\{arch\}))$`)

// notReferences are the lines before the promotion that may name the image
// otherwise than unmovedRef allows, each matched as the whole line, in the
// step with that id alone: the refusal of the template's image, which
// compares it with that name, the decision's read of the commit latest was
// built from, and the choice of where to publish, which names the image
// but no tag of it.
var notReferences = map[string][]string{
	"template": {`if [ "${IMAGE}" = ghcr.io/divbast/oci-image-template ] && [ "${REHEARSE}" != true ]; then`},
	"decide":   {`published=$(.ci/bin/divbast-published-revision "${IMAGE}:latest")`},
	"target": {
		`echo "image=localhost:5000/${IMAGE#*/}" >> "${GITHUB_OUTPUT}"`,
		`echo "image=${IMAGE}" >> "${GITHUB_OUTPUT}"`,
	},
}

// unmoved reports whether ref, a docker:// reference or one built on
// IMAGE, is one unmovedRef allows. A reference with no tag at all is
// latest's.
func unmoved(ref string) bool {
	return unmovedRef.MatchString(ref)
}

// attestsBeforePromote returns an error unless the publish job has one
// step that tags the index <version>-staging, one that attests it, one
// that verifies the attestation and one that tags latest, after the first
// push and in that order. No line of the job lets a step's failure
// through; every step from the first push to the promotion runs on the
// decision alone; before the promotion, every tag is -staging, every
// docker:// or ${IMAGE} reference is a digest or a -staging or -${arch}
// tag, and no line names the version's tag or latest, but for the lines
// notReferences allows; the promotion tags the version and latest alone;
// and all four steps name the one digest. The verification is a user's: gh attestation verify, for the
// caller's repository, this workflow and main.
func attestsBeforePromote(workflow string) error {
	job := jobsOf(linesOf(workflow))["publish"]
	if i := slices.IndexFunc(job, func(l line) bool {
		return strings.HasPrefix(strings.TrimPrefix(strings.TrimSpace(l.text), "- "), "continue-on-error:")
	}); i >= 0 {
		return fmt.Errorf("line %d lets a failure through", job[i].n)
	}
	st := steps(job)
	tags := func(l line) []string {
		found := tagArg.FindAllStringSubmatch(l.text, -1)
		out := make([]string, 0, len(found))
		for _, m := range found {
			out = append(out, m[1])
		}
		return out
	}
	tagsWith := func(suffix string) func(line) bool {
		return func(l line) bool {
			return slices.ContainsFunc(tags(l), func(t string) bool { return strings.HasSuffix(t, suffix) })
		}
	}
	var at [4]int
	for i, s := range []struct {
		what string
		f    func(line) bool
	}{
		{"tag the index <version>-staging", tagsWith("-staging")},
		{"run actions/attest", isUses("actions/attest")},
		{"run gh attestation verify", contains("gh attestation verify")},
		{"tag latest", tagsWith(":latest")},
	} {
		found := stepsWhere(st, s.f)
		if len(found) != 1 {
			return fmt.Errorf("%d steps %s, want one", len(found), s.what)
		}
		at[i] = found[0]
	}
	stage, attest, verify, promote := at[0], at[1], at[2], at[3]
	pushes := stepsWhere(st, contains("skopeo copy"))
	if len(pushes) == 0 {
		return errors.New("no step pushes with skopeo copy")
	}
	push := pushes[0]
	if push >= stage || stage >= attest || attest >= verify || verify >= promote {
		return fmt.Errorf("steps %d, %d, %d, %d and %d push, stage, attest, verify and promote; want them in that order",
			push+1, stage+1, attest+1, verify+1, promote+1)
	}
	for _, s := range st[push : promote+1] {
		if cond := value(s, "if"); cond != unquote(gate) {
			return fmt.Errorf("line %d runs on %q, not %s alone", s[0].n, cond, gate)
		}
	}

	for _, s := range st[:promote] {
		exempt := notReferences[value(s, "id")]
		for _, l := range s {
			for _, tag := range tags(l) {
				if !strings.HasSuffix(tag, "-staging") {
					return fmt.Errorf("line %d tags %s before the attestation verifies", l.n, tag)
				}
			}
			if slices.Contains(exempt, strings.TrimSpace(l.text)) {
				continue
			}
			for _, ref := range imageRef.FindAllString(l.text, -1) {
				if !unmoved(ref) {
					return fmt.Errorf("line %d names %s before the attestation verifies,"+
						" where only a digest or a -staging or -${arch} tag may stand", l.n, ref)
				}
			}
			for _, m := range publicTag.FindAllStringSubmatch(l.text, -1) {
				if m[1] == "" {
					return fmt.Errorf("line %d names %s before the attestation verifies", l.n, m[0])
				}
			}
		}
	}
	var promoted []string
	for _, l := range st[promote] {
		promoted = append(promoted, tags(l)...)
	}
	if len(promoted) != 2 || !slices.ContainsFunc(promoted, func(t string) bool { return strings.HasSuffix(t, ":${VERSION}") }) ||
		!slices.ContainsFunc(promoted, func(t string) bool { return strings.HasSuffix(t, ":latest") }) {
		return fmt.Errorf("line %d promotes to %q, want the version's tag and latest", st[promote][0].n, promoted)
	}

	id := value(st[stage], "id")
	want := "${{ steps." + id + ".outputs.digest }}"
	if got := value(st[attest], "subject-digest"); id == "" || got != want {
		return fmt.Errorf("line %d attests %q, not the staged index's digest %s", st[attest][0].n, got, want)
	}
	for _, i := range []int{verify, promote} {
		script, err := runScript(st[i])
		if err != nil {
			return err
		}
		if got := value(st[i], "DIGEST"); got != want {
			return fmt.Errorf("line %d sets DIGEST to %q, not %s, the digest attested", st[i][0].n, got, want)
		}
		if !strings.Contains(script, `${IMAGE}@${DIGEST}`) {
			return fmt.Errorf("line %d never names ${IMAGE}@${DIGEST}, the index attested", st[i][0].n)
		}
	}
	script, _ := runScript(st[verify])
	for _, flag := range []string{
		`--repo "${REPO}"`,
		"--signer-workflow divbast/ci/.github/workflows/app-publish.yml",
		"--source-ref refs/heads/main",
	} {
		if !strings.Contains(script, flag) {
			return fmt.Errorf("line %d verifies without %s", st[verify][0].n, flag)
		}
	}
	if got := value(st[verify], "REPO"); got != "${{ github.repository }}" {
		return fmt.Errorf("line %d verifies for %q, not ${{ github.repository }}", st[verify][0].n, got)
	}
	return nil
}

// TestPublishVerifiesWithRetries checks that app-publish.yml's
// verification, run with bash and stand-ins for skopeo, gh and sleep,
// fetches the index by digest and gives gh that file, an empty
// DOCKER_CONFIG and the flags a user gives it, and tries three times, ten
// seconds apart, before it fails. Against app-publish.yml as it is, then
// with each broken, which the check must refuse.
func TestPublishVerifiesWithRetries(t *testing.T) {
	t.Parallel()
	publish := readWorkflows(t)["app-publish.yml"]
	if err := verifiesWithRetries(t, publish); err != nil {
		t.Errorf("app-publish.yml: %v", err)
	}
	const tries = "verify || { sleep 10 && verify; } || { sleep 10 && verify; }"
	for name, mutant := range map[string]string{
		"one try":                       strings.Replace(publish, tries, "verify", 1),
		"four tries":                    strings.Replace(publish, tries, tries+" || { sleep 10 && verify; }", 1),
		"tries a second apart":          strings.Replace(publish, tries, strings.ReplaceAll(tries, "sleep 10", "sleep 1"), 1),
		"the login given to gh":         strings.Replace(publish, `DOCKER_CONFIG="${empty}" gh attestation verify`, "gh attestation verify", 1),
		"the index fetched by a tag":    replaceAfter(publish, verifyName, `"docker://${IMAGE}@${DIGEST}"`, `"docker://${IMAGE}:${DIGEST#sha256:}-staging"`),
		"another file verified":         replaceAfter(publish, verifyName, "gh attestation verify /tmp/index-manifest.json", "gh attestation verify /tmp/index.json"),
		"the third failure let through": strings.Replace(publish, tries, tries+" || true", 1),
		"the fetched bytes let through": replaceAfter(publish, verifyName, "            exit 1\n", ""),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if mutant == publish {
				t.Fatal("the change changed nothing")
			}
			if verifiesWithRetries(t, mutant) == nil {
				t.Error("passes app-publish.yml with " + name)
			}
		})
	}
}

// verifiesWithRetries returns an error unless the publish job's one step
// that runs gh attestation verify, its /tmp moved into a temporary
// directory, fetches the index by digest once, and then calls gh once
// when gh succeeds, three times with ten seconds' sleep between when the
// first two fail, and three times before it fails when all three do.
func verifiesWithRetries(t *testing.T, workflow string) error {
	t.Helper()
	st := publishSteps(workflow)
	found := stepsWhere(st, contains("gh attestation verify"))
	if len(found) != 1 {
		return fmt.Errorf("%d steps run gh attestation verify, want one", len(found))
	}
	script, err := runScript(st[found[0]])
	if err != nil {
		return err
	}
	const (
		image = "ghcr.io/divbast/app"
		index = `{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[]}`
	)
	sum := sha256.Sum256([]byte(index))
	digest := "sha256:" + hex.EncodeToString(sum[:])
	for _, tt := range []struct {
		fails, calls                int
		ok                          bool
		slept, shape, signer, bytes string
	}{
		{fails: 0, calls: 1, ok: true, shape: "array", signer: "signer"},
		{fails: 2, calls: 3, ok: true, slept: "10 10 ", shape: "array", signer: "signer"},
		{fails: 3, calls: 3, slept: "10 10 ", shape: "array"},
		{fails: 0, calls: 1, ok: true, shape: "object", signer: "unknown"},
		{fails: 0, calls: 1, ok: true, shape: "empty", signer: "unknown"},
		{fails: 0, calls: 1, ok: true, shape: "text", signer: "unknown"},
		{fails: 0, calls: 0, shape: "array", bytes: index + " "},
	} {
		dir := t.TempDir()
		bin, login := filepath.Join(dir, "bin"), filepath.Join(dir, "login")
		for _, d := range []string{bin, login} {
			if err := os.Mkdir(d, 0o700); err != nil {
				t.Fatal(err)
			}
		}
		writeFile(t, dir, "login/config.json", "{}\n")
		if tt.bytes == "" {
			tt.bytes = index
		}
		writeFile(t, dir, "fetched", tt.bytes)
		writeFile(t, dir, "bin/skopeo", "#!/usr/bin/env bash\nprintf 'skopeo %s\\n' \"$*\" >> \"${CALLS}\"\ncat \"${FETCHED}\"\n")
		writeFile(t, dir, "bin/gh", "#!/usr/bin/env bash\nprintf 'gh %s\\n' \"$*\" >> \"${CALLS}\"\n"+
			"[ -z \"$(ls -A \"${DOCKER_CONFIG:?}\")\" ] || exit 3\n"+
			"[ \"$(grep -c '^gh ' \"${CALLS}\")\" -gt \"${FAILS}\" ] || exit 1\n"+
			"case \"${SHAPE}\" in\n"+
			"array) echo '[{\"verificationResult\":{\"signature\":{\"certificate\":{\"buildSignerURI\":\"signer\"}}}}]' ;;\n"+
			"object) echo '{\"verificationResult\":{}}' ;;\n"+
			"empty) echo '[]' ;;\n"+
			"*) echo 'not JSON' ;;\nesac\n")
		writeFile(t, dir, "bin/sleep", "#!/usr/bin/env bash\nprintf '%s ' \"$*\" >> \"${SLEPT}\"\n")
		calls, slept := filepath.Join(dir, "calls"), filepath.Join(dir, "slept")
		writeFile(t, dir, "slept", "")
		res := runStep(t, dir, strings.ReplaceAll(script, "/tmp/", dir+"/"),
			"PATH="+bin+":"+os.Getenv("PATH"), "TMPDIR="+dir, "DOCKER_CONFIG="+login,
			"IMAGE="+image, "DIGEST="+digest, "REPO=divbast/app",
			"CALLS="+calls, "SLEPT="+slept, "FAILS="+strconv.Itoa(tt.fails), "SHAPE="+tt.shape,
			"FETCHED="+filepath.Join(dir, "fetched"))
		got, err := os.ReadFile(calls) //nolint:gosec // G304: the test's own temporary directory
		if err != nil {
			return fmt.Errorf("with %d failures, nothing ran: %w", tt.fails, err)
		}
		gh := "gh attestation verify " + dir + "/index-manifest.json --repo divbast/app" +
			" --signer-workflow divbast/ci/.github/workflows/app-publish.yml --source-ref refs/heads/main --format json\n"
		want := "skopeo inspect --raw docker://" + image + "@" + digest + "\n" + strings.Repeat(gh, tt.calls)
		if string(got) != want {
			return fmt.Errorf("with %d failures, runs\n%s\nwant\n%s", tt.fails, got, want)
		}
		if tt.calls > 0 {
			if f, _ := os.ReadFile(filepath.Join(dir, "index-manifest.json")); string(f) != tt.bytes { //nolint:gosec // G304: the test's own temporary directory
				return fmt.Errorf("gh verifies %q, not the bytes fetched", f)
			}
		}
		if s, _ := os.ReadFile(slept); string(s) != tt.slept { //nolint:gosec // G304: the test's own temporary directory
			return fmt.Errorf("with %d failures, sleeps %q, want %q", tt.fails, s, tt.slept)
		}
		if (res.Code == 0) != tt.ok {
			return fmt.Errorf("with %d failures and gh printing %s, the script exits %d: %s", tt.fails, tt.shape, res.Code, res.Stderr)
		}
		if tt.ok && !strings.Contains(string(res.Stdout), "verifies, signed by "+tt.signer+"\n") {
			return fmt.Errorf("with gh printing %s, the script says %q, not that it was signed by %s", tt.shape, res.Stdout, tt.signer)
		}
	}
	return nil
}

// TestPublishPromotesOnlyTheAttestedDigest checks that app-publish.yml's
// promotion, run with bash and a stand-in for docker, dry-runs the same
// imagetools create it runs, and runs it only when the bytes the dry run
// prints, less its newline, hash to the digest attested. Only then, and
// before it runs it, does the step set its moving output, which tells the
// note that follows whether the public tags may have moved. Against
// app-publish.yml as it is, then with each broken, which the check must
// refuse.
func TestPublishPromotesOnlyTheAttestedDigest(t *testing.T) {
	t.Parallel()
	publish := readWorkflows(t)["app-publish.yml"]
	if err := promotesOnlyTheDigest(t, publish); err != nil {
		t.Errorf("app-publish.yml: %v", err)
	}
	const (
		dry    = `          docker buildx imagetools create --dry-run "${args[@]}" > /tmp/promoted.json` + "\n"
		create = `          docker buildx imagetools create "${args[@]}"` + "\n"
		moving = `          echo "moving=true" >> "${GITHUB_OUTPUT}"` + "\n"
	)
	for name, mutant := range map[string]string{
		"no comparison":                  strings.Replace(publish, `if [ "sha256:${would%% *}" != "${DIGEST}" ]; then`, "if false; then", 1),
		"the newline hashed too":         strings.Replace(publish, `head -c "$((size - 1))" /tmp/promoted.json`, "cat /tmp/promoted.json", 1),
		"tags moved before":              strings.Replace(publish, dry, create+dry, 1),
		"a dry run of the source":        strings.Replace(publish, dry, `          docker buildx imagetools create --dry-run "${IMAGE}@${DIGEST}" > /tmp/promoted.json`+"\n", 1),
		"moving never said":              strings.Replace(publish, moving, "", 1),
		"moving said after":              strings.Replace(publish, moving+create, create+moving, 1),
		"moving said before the dry run": strings.Replace(strings.Replace(publish, moving, "", 1), dry, moving+dry, 1),
		"a mismatch let through":         replaceAfter(publish, promoteName, "            exit 1\n", ""),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if mutant == publish {
				t.Fatal("the change changed nothing")
			}
			if promotesOnlyTheDigest(t, mutant) == nil {
				t.Error("passes app-publish.yml with " + name)
			}
		})
	}
}

// promotesOnlyTheDigest returns an error unless the publish job's step
// with id promote, its /tmp moved into a temporary directory, runs docker
// buildx imagetools create --dry-run and then, having set moving=true in
// its outputs, the same command without it, when the dry run prints the
// attested index; and the dry run alone, then fails without setting
// moving, when it prints another or fails itself.
func promotesOnlyTheDigest(t *testing.T, workflow string) error {
	t.Helper()
	st := publishSteps(workflow)
	found := stepsWhere(st, func(l line) bool { return strings.TrimSpace(l.text) == "id: promote" })
	if len(found) != 1 {
		return fmt.Errorf("%d steps have id promote, want one", len(found))
	}
	script, err := runScript(st[found[0]])
	if err != nil {
		return err
	}
	const (
		image = "ghcr.io/divbast/app"
		index = `{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[]}`
	)
	sum := sha256.Sum256([]byte(index))
	digest := "sha256:" + hex.EncodeToString(sum[:])
	args := "-t " + image + ":1.2.3 -t " + image + ":latest " + image + "@" + digest
	dry := "buildx imagetools create --dry-run " + args + "\n"
	for _, tt := range []struct {
		name, would, calls, output string
		dryFails, ok               bool
	}{
		{
			name: "the index attested", would: index, ok: true, output: "moving=true\n",
			calls: dry + "buildx imagetools create " + args + " (moving)\n",
		},
		{name: "another index", would: index + " ", calls: dry},
		{name: "nothing, failing", dryFails: true, calls: dry},
	} {
		dir := t.TempDir()
		if err := os.Mkdir(filepath.Join(dir, "bin"), 0o700); err != nil {
			t.Fatal(err)
		}
		writeFile(t, dir, "would", tt.would)
		writeFile(t, dir, "output", "")
		writeFile(t, dir, "bin/docker", "#!/usr/bin/env bash\n"+
			"case \" $* \" in\n"+
			"*\" --dry-run \"*) printf '%s\\n' \"$*\" >> \"${CALLS}\"; [ -z \"${DRY_FAILS}\" ] || exit 1; cat \"${WOULD}\"; echo ;;\n"+
			"*) if grep -qx moving=true \"${GITHUB_OUTPUT}\"; then printf '%s (moving)\\n' \"$*\"; else printf '%s\\n' \"$*\"; fi >> \"${CALLS}\" ;;\n"+
			"esac\n")
		dryFails := ""
		if tt.dryFails {
			dryFails = "1"
		}
		calls, output := filepath.Join(dir, "calls"), filepath.Join(dir, "output")
		res := runStep(t, dir, strings.ReplaceAll(script, "/tmp/", dir+"/"),
			"PATH="+filepath.Join(dir, "bin")+":"+os.Getenv("PATH"),
			"IMAGE="+image, "VERSION=1.2.3", "DIGEST="+digest, "CALLS="+calls, "WOULD="+filepath.Join(dir, "would"),
			"DRY_FAILS="+dryFails, "GITHUB_OUTPUT="+output)
		got, err := os.ReadFile(calls) //nolint:gosec // G304: the test's own temporary directory
		if err != nil {
			return fmt.Errorf("when the dry run prints %s, docker never runs: %w", tt.name, err)
		}
		if string(got) != tt.calls {
			return fmt.Errorf("when the dry run prints %s, runs\n%s\nwant\n%s", tt.name, got, tt.calls)
		}
		if (res.Code == 0) != tt.ok {
			return fmt.Errorf("when the dry run prints %s, the script exits %d: %s", tt.name, res.Code, res.Stderr)
		}
		if out, _ := os.ReadFile(output); string(out) != tt.output { //nolint:gosec // G304: the test's own temporary directory
			return fmt.Errorf("when the dry run prints %s, the step outputs %q, want %q", tt.name, out, tt.output)
		}
	}
	return nil
}

// TestPublishSaysWhenRerunningPublishes checks that app-publish.yml, when
// a step fails after the decision and before the promotion begins to move
// the tags, its dry run included, says in an error that the version's tag
// and latest did not move, and when re-running the failed job publishes. Against app-publish.yml as it is,
// then with each broken, which the check must refuse.
func TestPublishSaysWhenRerunningPublishes(t *testing.T) {
	t.Parallel()
	publish := readWorkflows(t)["app-publish.yml"]
	if err := saysWhenRerunningPublishes(t, publish); err != nil {
		t.Errorf("app-publish.yml: %v", err)
	}
	const cond = "        if: failure() && " + gate + " && steps.promote.outputs.moving != 'true'\n"
	for name, mutant := range map[string]string{
		"said after a promotion that failed":       strings.Replace(publish, cond, "        if: failure() && "+gate+"\n", 1),
		"said when nothing failed":                 strings.Replace(publish, cond, "        if: "+gate+" && steps.promote.outputs.moving != 'true'\n", 1),
		"said only when the promotion was skipped": strings.Replace(publish, cond, "        if: failure() && "+gate+" && steps.promote.outcome == 'skipped'\n", 1),
		"said before the promotion":                moveStep(publish, movedName, promoteName),
		"no tags named":                            strings.Replace(publish, "::error::the public tags :${VERSION:-<version>} and :latest did not move.", "::error::no public tag moved.", 1),
		"no word on when":                          strings.Replace(publish, `"Re-running the failed job publishes for a day after this run built its images, while their artifacts last," \`+"\n", "", 1),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if mutant == publish {
				t.Fatal("the change changed nothing")
			}
			if saysWhenRerunningPublishes(t, mutant) == nil {
				t.Error("passes app-publish.yml with " + name)
			}
		})
	}
}

// saysWhenRerunningPublishes returns an error unless the publish job's
// one step that says the public tags did not move comes after the
// promotion, runs on a failure once the decision was to publish and the
// promotion had not begun to move the tags, and, run with bash, prints one
// error naming the version's tag and latest and saying a re-run of the
// failed job publishes for a day after the build.
func saysWhenRerunningPublishes(t *testing.T, workflow string) error {
	t.Helper()
	st := publishSteps(workflow)
	found := stepsWhere(st, contains("::error::"))
	promote := stepsWhere(st, func(l line) bool { return strings.TrimSpace(l.text) == "id: promote" })
	if len(found) != 1 || len(promote) != 1 {
		return fmt.Errorf("%d steps print an error and %d have id promote, want one of each", len(found), len(promote))
	}
	s := st[found[0]]
	if found[0] < promote[0] {
		return fmt.Errorf("line %d says the tags did not move before the promotion, which then runs", s[0].n)
	}
	want := unquote("failure() && " + gate + " && steps.promote.outputs.moving != 'true'")
	if cond := value(s, "if"); cond != want {
		return fmt.Errorf("line %d says the tags did not move on %q, not %q", s[0].n, cond, want)
	}
	script, err := runScript(s)
	if err != nil {
		return err
	}
	res := runStep(t, t.TempDir(), script, "VERSION=1.2.3")
	out := string(res.Stdout)
	if res.Code != 0 || strings.Count(out, "\n") != 1 ||
		!strings.HasPrefix(out, "::error::the public tags :1.2.3 and :latest did not move. ") ||
		!strings.Contains(out, "Re-running the failed job publishes for a day after this run built its images") {
		return fmt.Errorf("with VERSION=1.2.3, the script exits %d and prints %q", res.Code, out)
	}
	return nil
}

// update rewrites testdata/app-publish-shell.golden.txt from
// app-publish.yml, for a change to the publish job's shell that is meant:
//
//	go test ./internal/workflows -run TestPublishShellPinned -update
var update = flag.Bool("update", false, "rewrite testdata/app-publish-shell.golden.txt from app-publish.yml")

// shellGolden is where the publish job's pinned shell is kept.
const shellGolden = "app-publish-shell.golden.txt"

// TestPublishShellPinned checks that every run: script app-publish.yml's
// publish job runs from the gate on, but for the steps before the decision
// that publish nothing, is exactly the script testdata keeps: the shell
// that pushes, stages, verifies, promotes and checks is pinned, not
// matched against patterns. The registry's pin is left to Renovate. A
// change to that shell fails here with a diff until the golden file is
// rewritten on purpose with -update. Against app-publish.yml as it is,
// then with each change below, and with each exit 1 in the job taken out,
// which the check must refuse.
func TestPublishShellPinned(t *testing.T) {
	t.Parallel()
	publish := readWorkflows(t)["app-publish.yml"]
	root, err := os.OpenRoot("testdata")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	if *update {
		got, shellErr := publishShell(publish)
		if shellErr != nil {
			t.Fatal(shellErr)
		}
		if err = root.WriteFile(shellGolden, []byte(got), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	golden, err := root.ReadFile(shellGolden)
	if err != nil {
		t.Fatal(err)
	}
	if err := shellPinned(publish, string(golden)); err != nil {
		t.Errorf("app-publish.yml: %v", err)
	}
	const from = `skopeo copy --all "docker://${IMAGE}@$(cat /tmp/digest-amd64)"`
	mutants := map[string]string{
		"a write through a loop variable": replaceAfter(publish, pushName, "          done\n",
			"          done\n          for t in \"${VERSION}\" latest; do "+from+" \"docker://${IMAGE}:${t}\"; done\n"),
		"a write through a variable": replaceAfter(publish, pushName, "          done\n",
			"          done\n          tag=latest; "+from+" \"docker://${IMAGE}:${tag}\"\n"),
		"latest written unquoted": replaceAfter(publish, pushName, "          done\n",
			"          done\n          skopeo copy --all docker://${IMAGE}@$(cat /tmp/digest-amd64) docker://${IMAGE}:latest\n"),
		"the version unbraced": replaceAfter(publish, pushName, "          done\n",
			"          done\n          "+from+" \"docker://${IMAGE}:$VERSION\"\n"),
		"latest written to ghcr.io by name": replaceAfter(publish, pushName, "          done\n",
			"          done\n          "+from+" \"docker://ghcr.io/divbast/librespeed:latest\"\n"),
		"a write appended to the decision's read": strings.Replace(publish, notReferences["decide"][0]+"\n",
			notReferences["decide"][0]+"; "+from+" \"docker://${IMAGE}:latest\"\n", 1),
		"a write appended to the choice of image": strings.Replace(publish, notReferences["target"][1]+"\n",
			notReferences["target"][1]+"; "+from+" \"docker://${IMAGE}:latest\"\n", 1),
		"another version tag staged":                 strings.Replace(publish, `-t "${IMAGE}:${VERSION}-staging"`, `-t "${IMAGE}:${VERSION}-stage"`, 1),
		"the registry's wait changed":                strings.Replace(publish, "--retry 10 --retry-delay 1", "--retry 3 --retry-delay 1", 1),
		"a run-first step tagging latest early":      strings.Replace(publish, attestStep, sneak+attestStep, 1),
		"a run-first step on the gate tagging early": strings.Replace(publish, attestStep, sneakOnGate+attestStep, 1),
		"a named step tagging latest early":          strings.Replace(publish, attestStep, sneakNamed+attestStep, 1),
		"a step that neither runs nor uses":          strings.Replace(publish, attestStep, "      - name: Nothing at all\n        if: steps.decide.outputs.publish == 'true'\n"+attestStep, 1),
		// Ruling R87: what bash reads before a line of the script runs,
		// and how it is started
		"BASH_ENV in a pinned step's env":     replaceAfter(publish, "        id: decide\n", "        env:\n", "        env:\n          BASH_ENV: $(id >&2)\n"),
		"BASH_ENV in the job's env":           strings.Replace(publish, "    env:\n      MISE_AUTO_INSTALL:", "    env:\n      BASH_ENV: $(id >&2)\n      MISE_AUTO_INSTALL:", 1),
		"BASH_ENV in the workflow's env":      strings.Replace(publish, "\nenv:\n", "\nenv:\n  BASH_ENV: $(id >&2)\n", 1),
		"PATH moved in a pinned step's env":   replaceAfter(publish, "        id: decide\n", "        env:\n", "        env:\n          PATH: /tmp/elsewhere:/usr/bin:/bin\n"),
		"a job default shell that runs first": strings.Replace(publish, "    timeout-minutes: 30\n", "    timeout-minutes: 30\n    defaults:\n      run:\n        shell: sh -c 'id >&2; exec bash -eo pipefail \"$0\"' {0}\n", 1),
		"a workflow default without -e":       strings.Replace(publish, "\ndefaults:\n  run:\n    shell: bash\n", "\ndefaults:\n  run:\n    shell: bash {0}\n", 1),
		"a pinned step's own shell":           replaceAfter(publish, promoteName, "        env:\n", "        shell: bash {0}\n        env:\n"),
	}
	exits := 0
	for i, l := range strings.SplitAfter(publish, "\n") {
		if strings.TrimSpace(l) != "exit 1" {
			continue
		}
		exits++
		lines := strings.SplitAfter(publish, "\n")
		mutants["exit 1 taken out of line "+strconv.Itoa(i+1)] = strings.Join(slices.Delete(lines, i, i+1), "")
	}
	if exits == 0 {
		t.Fatal("app-publish.yml has no exit 1 to take out")
	}
	for name, mutant := range mutants {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if mutant == publish {
				t.Fatal("the change changed nothing")
			}
			if shellPinned(mutant, string(golden)) == nil {
				t.Error("passes app-publish.yml with " + name)
			}
		})
	}
	// What Renovate does to the registry's pin: a new digest for the same
	// version, and a new version with its digest. Each new value is made
	// from the old one, so it differs whatever the workflow pins.
	pin := registryManager.FindStringSubmatch(publish)
	if pin == nil {
		t.Fatal("app-publish.yml pins no registry image Renovate reads")
	}
	version, digest := pin[registryManager.SubexpIndex("currentValue")], pin[registryManager.SubexpIndex("currentDigest")]
	moved := sha256.Sum256([]byte(digest))
	newDigest := "sha256:" + hex.EncodeToString(moved[:])
	for name, bump := range map[string]string{
		"a digest Renovate moves":             "registry:" + version + "@" + newDigest,
		"a version and digest Renovate moves": "registry:" + version + "1@" + newDigest,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			bumped := strings.Replace(publish, "registry:"+version+"@"+digest, bump, 1)
			if bumped == publish {
				t.Fatal("the change changed nothing")
			}
			if registryManager.FindString(bumped) == "" {
				t.Fatalf("Renovate would not read %s", bump)
			}
			if err := shellPinned(bumped, string(golden)); err != nil {
				t.Errorf("refuses app-publish.yml with the registry at %s: %v", bump, err)
			}
		})
	}
	// The one workflow env value Renovate moves, which the golden leaves
	// out, while it keeps every name
	t.Run("a mise release Renovate moves", func(t *testing.T) {
		t.Parallel()
		mise := regexp.MustCompile(`(?m)^ {2}MISE_VERSION: (\S+)$`).FindStringSubmatch(publish)
		if mise == nil {
			t.Fatal("app-publish.yml sets no MISE_VERSION in its env")
		}
		bumped := strings.Replace(publish, "  MISE_VERSION: "+mise[1]+"\n", "  MISE_VERSION: "+mise[1]+"1\n", 1)
		if bumped == publish {
			t.Fatal("the change changed nothing")
		}
		if err := shellPinned(bumped, string(golden)); err != nil {
			t.Errorf("refuses app-publish.yml with MISE_VERSION moved: %v", err)
		}
	})
}

// actionsBash is the shell a step whose shell is bash runs under, by
// GitHub Actions' documentation: bash with -e and pipefail. A step with no
// shell at all, from itself, its job's defaults or its workflow's, runs
// under bash -e {0}, with no pipefail.
const actionsBash = "bash --noprofile --norc -eo pipefail {0}"

// TestPublishShellIsBashWithPipefail (ruling R87) checks that every step
// of app-publish.yml's publish job runs under bash with -e and pipefail,
// which the behaviour tests and the pinned shell assume: its own shell,
// its job's defaults.run.shell or its workflow's, the first that is set,
// is bash or actionsBash written out. Against app-publish.yml as it is,
// then with each broken, which the check must refuse, and with each way
// of writing the same shell, which it must pass.
func TestPublishShellIsBashWithPipefail(t *testing.T) {
	t.Parallel()
	publish := readWorkflows(t)["app-publish.yml"]
	if err := runsBashWithPipefail(publish); err != nil {
		t.Errorf("app-publish.yml: %v", err)
	}
	const (
		workflowDefault = "\ndefaults:\n  run:\n    shell: bash\n"
		jobAt           = "    timeout-minutes: 30\n"
	)
	for name, tt := range map[string]struct {
		mutant string
		pass   bool
	}{
		"no default shell":                        {mutant: strings.Replace(publish, workflowDefault, "\n", 1)},
		"a workflow default without -e":           {mutant: strings.Replace(publish, workflowDefault, "\ndefaults:\n  run:\n    shell: bash {0}\n", 1)},
		"a workflow default of sh":                {mutant: strings.Replace(publish, workflowDefault, "\ndefaults:\n  run:\n    shell: sh\n", 1)},
		"a job default that runs first":           {mutant: strings.Replace(publish, jobAt, jobAt+"    defaults:\n      run:\n        shell: sh -c 'id >&2; exec bash -eo pipefail \"$0\"' {0}\n", 1)},
		"a job default of sh after its directory": {mutant: strings.Replace(publish, jobAt, jobAt+"    defaults:\n      run:\n        working-directory: .\n        shell: sh\n", 1)},
		"a step's own shell without pipefail":     {mutant: replaceAfter(publish, promoteName, "        env:\n", "        shell: bash -e {0}\n        env:\n")},
		"a job default written out":               {mutant: strings.Replace(publish, jobAt, jobAt+"    defaults:\n      run:\n        shell: "+actionsBash+"\n", 1), pass: true},
		"a step's own bash":                       {mutant: replaceAfter(publish, promoteName, "        env:\n", "        shell: bash\n        env:\n"), pass: true},
		"a job default of bash, and none else":    {mutant: strings.Replace(strings.Replace(publish, workflowDefault, "\n", 1), jobAt, jobAt+"    defaults:\n      run:\n        shell: bash\n", 1), pass: true},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if tt.mutant == publish {
				t.Fatal("the change changed nothing")
			}
			if err := runsBashWithPipefail(tt.mutant); (err == nil) != tt.pass {
				t.Errorf("with %s, runsBashWithPipefail() = %v, want it to pass: %t", name, err, tt.pass)
			}
		})
	}
}

// runsBashWithPipefail returns an error naming the first step of the
// publish job whose shell, its own or else its job's or else its
// workflow's defaults.run.shell, is neither bash nor actionsBash, or which
// sets none at all.
func runsBashWithPipefail(workflow string) error {
	lines := linesOf(workflow)
	job := jobsOf(lines)["publish"]
	// The shell: among run:'s keys, in whatever order they come
	shellIn := func(defaults []string) string {
		inRun := false
		for _, l := range defaults {
			switch {
			case indent(l) == 0:
				inRun = l == "run:"
			case inRun && indent(l) == 2:
				if v, ok := strings.CutPrefix(l, "  shell:"); ok {
					return unquote(v)
				}
			}
		}
		return ""
	}
	workflowDefaults, err := mappingOf(lines, 0, "defaults")
	if err != nil {
		return err
	}
	jobDefaults, err := mappingOf(job, 4, "defaults")
	if err != nil {
		return err
	}
	inherited := cmp.Or(shellIn(jobDefaults), shellIn(workflowDefaults), "bash -e {0}")
	for _, s := range steps(job) {
		shell := inherited
		if at := stepKey(s, "shell"); at >= 0 {
			shell = unquote(strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(s[at].text), "- "), "shell:"))
		}
		if shell != "bash" && shell != actionsBash {
			return fmt.Errorf("the step from line %d runs under %q, not bash with -e and pipefail", s[0].n, shell)
		}
	}
	return nil
}

// TestPublishShellReadsEveryForm checks publishShell on a small publish
// job: it reads a script whether run: comes first in its step or not,
// inline or as a block, and stops a block at the step's next key; it
// keeps each step's env and own shell, the job's env and defaults, the
// workflow's defaults and the names alone of the workflow's env; and it
// refuses, rather than skips, a step or a mapping it cannot read in the
// pinned range.
func TestPublishShellReadsEveryForm(t *testing.T) {
	t.Parallel()
	const (
		job   = "jobs:\n  publish:\n"
		steps = "    steps:\n" +
			"      - name: Gate\n        run: |\n          case \"${EVENT}\" in\n            schedule | workflow_dispatch) ;;\n          esac\n" +
			"      - name: Template\n        id: template\n        run: echo template\n" +
			"      - name: Decide\n        id: decide\n        run: echo decide\n"
		none = "== workflow env names ==\n(none)\n== workflow defaults ==\n(none)\n" +
			"== publish job env ==\n(none)\n== publish job defaults ==\n(none)\n"
		gate = "== Gate ==\nrun:\ncase \"${EVENT}\" in\n  schedule | workflow_dispatch) ;;\nesac\n" +
			"== Template ==\nrun:\necho template\n== Decide ==\nrun:\necho decide\n"
	)
	tests := []struct {
		name, workflow, want string
	}{
		{
			name:     "a block written run: first, keys after it",
			workflow: job + steps + "      - run: |\n          echo one\n\n            echo indented\n        name: Block first\n        env:\n          T: latest\n",
			want:     none + gate + "== Block first ==\nenv: T: latest\nrun:\necho one\n\n  echo indented\n",
		},
		{
			name:     "an inline script written run: first",
			workflow: job + steps + "      - run: echo two\n        name: Inline first\n",
			want:     none + gate + "== Inline first ==\nrun:\necho two\n",
		},
		{
			name:     "an action between scripts",
			workflow: job + steps + "      - uses: actions/attest@x\n        with:\n          push-to-registry: true\n      - name: After\n        run: echo after\n",
			want:     none + gate + "== After ==\nrun:\necho after\n",
		},
		{
			name:     "a step's env first and its own shell",
			workflow: job + steps + "      - env:\n          A: one\n          B: two\n        name: Env first\n        shell: bash\n        run: echo env\n",
			want:     none + gate + "== Env first ==\nenv: A: one\nenv: B: two\nshell: bash\nrun:\necho env\n",
		},
		{
			name: "the workflow's and the job's env and defaults",
			workflow: "env:\n  MISE_VERSION: 1\n  OTHER: x\ndefaults:\n  run:\n    shell: bash\n" + job +
				"    env:\n      MISE_AUTO_INSTALL: \"false\"\n    defaults:\n      run:\n        working-directory: app\n" + steps,
			want: "== workflow env names ==\nMISE_VERSION\nOTHER\n== workflow defaults ==\nrun:\n  shell: bash\n" +
				"== publish job env ==\nMISE_AUTO_INSTALL: \"false\"\n== publish job defaults ==\nrun:\n  working-directory: app\n" + gate,
		},
		{name: "a script with no name", workflow: job + steps + "      - run: echo nameless\n"},
		{name: "a step that neither runs nor uses", workflow: job + steps + "      - name: Nothing\n        if: always()\n"},
		{name: "a step that both runs and uses", workflow: job + steps + "      - name: Both\n        uses: actions/attest@x\n        run: echo both\n"},
		{name: "a folded script", workflow: job + steps + "      - name: Folded\n        run: >\n          echo folded\n"},
		{name: "a stripped block", workflow: job + steps + "      - name: Stripped\n        run: |-\n          echo stripped\n"},
		{name: "a step's env on one line", workflow: job + steps + "      - name: Flow\n        env: { BASH_ENV: x }\n        run: echo flow\n"},
		{name: "the job's env on one line", workflow: job + "    env: { BASH_ENV: x }\n" + steps},
		{name: "the workflow's defaults on one line", workflow: "defaults: { run: { shell: sh } }\n" + job + steps},
		{name: "a workflow env that is no NAME: value", workflow: "env:\n  BASH_ENV: |\n    $(id)\n" + job + steps},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := publishShell(tt.workflow)
			switch {
			case tt.want == "" && err == nil:
				t.Errorf("publishShell() = %q, want an error", got)
			case tt.want != "" && err != nil:
				t.Errorf("publishShell() error: %v", err)
			case got != tt.want:
				t.Errorf("publishShell() = %q, want %q", got, tt.want)
			}
		})
	}
}

// shellPinned returns an error, with a diff, unless publishShell of the
// workflow is golden.
func shellPinned(workflow, golden string) error {
	got, err := publishShell(workflow)
	if err != nil {
		return err
	}
	if got != golden {
		return fmt.Errorf("the publish job's shell is not testdata/%s:\n%s"+
			"if the change is meant, review it and rewrite the golden file:"+
			" go test ./internal/workflows -run TestPublishShellPinned -update", shellGolden, lineDiff(golden, got))
	}
	return nil
}

// pinnedRegistry stands in, in the pinned shell, for the registry image's
// version and digest, which Renovate moves.
const pinnedRegistry = "registry:<version>@<digest>"

// publishShell returns what bash runs in the publish job's pinned steps,
// and everything that shapes how it runs (ruling R87): the names of the
// workflow's env, whose one value Renovate moves; the workflow's
// defaults; the publish job's env and defaults; and, under each pinned
// step's name, its env, its own shell if it sets one, and its run: script
// as written, its indent taken off. An env entry such as BASH_ENV, which
// bash expands before the script, or PATH, and a defaults shell, can each
// change what a script does without a line of it changing. The pinned
// steps are the gate, the refusal of the template's image, and every step
// from the decision on. The registry image's version and digest are
// replaced by pinnedRegistry. A step in that range that neither runs a
// script nor uses an action, a script in a step with no name, a block
// scalar other than |, and an env or defaults written on one line are
// errors, never skipped.
func publishShell(workflow string) (string, error) {
	raw := strings.Split(workflow, "\n")
	lines := linesOf(workflow)
	job := jobsOf(lines)["publish"]
	var b strings.Builder
	section := func(title string, body []string) {
		b.WriteString("== " + title + " ==\n")
		if len(body) == 0 {
			b.WriteString("(none)\n")
		}
		for _, l := range body {
			b.WriteString(l + "\n")
		}
	}
	workflowEnv, err := mappingOf(lines, 0, "env")
	if err != nil {
		return "", err
	}
	names := make([]string, 0, len(workflowEnv))
	for _, e := range workflowEnv {
		name, _, ok := strings.Cut(e, ": ")
		if !ok || !envName.MatchString(name) {
			return "", fmt.Errorf("the workflow's env holds %q, not a one-line NAME: value", e)
		}
		names = append(names, name)
	}
	section("workflow env names", names)
	for _, m := range []struct {
		title string
		lines []line
		at    int
		key   string
	}{
		{title: "workflow defaults", lines: lines, at: 0, key: "defaults"},
		{title: "publish job env", lines: job, at: 4, key: "env"},
		{title: "publish job defaults", lines: job, at: 4, key: "defaults"},
	} {
		body, err := mappingOf(m.lines, m.at, m.key)
		if err != nil {
			return "", err
		}
		section(m.title, body)
	}

	st := steps(job)
	decide := stepsWhere(st, func(l line) bool { return strings.TrimSpace(l.text) == "id: decide" })
	gate := stepsWhere(st, contains("schedule | workflow_dispatch)"))
	template := stepsWhere(st, func(l line) bool { return strings.TrimSpace(l.text) == "id: template" })
	if len(decide) != 1 || len(gate) != 1 || len(template) != 1 {
		return "", fmt.Errorf("%d decide steps, %d gate steps and %d steps with id template, want one of each",
			len(decide), len(gate), len(template))
	}
	key := func(l line) string { return strings.TrimPrefix(strings.TrimSpace(l.text), "- ") }
	for i, s := range st {
		if i != gate[0] && i != template[0] && i < decide[0] {
			continue
		}
		at := slices.IndexFunc(s, func(l line) bool { return strings.HasPrefix(key(l), "run:") })
		uses := slices.ContainsFunc(s, func(l line) bool { return strings.HasPrefix(key(l), "uses:") })
		switch {
		case at < 0 && uses:
			continue
		case at < 0 || uses:
			return "", fmt.Errorf("line %d: a step must run a script or use an action, one and not both", s[0].n)
		}
		run := s[at]
		name := value(s, "name")
		if name == "" {
			return "", fmt.Errorf("line %d runs a script in a step with no name", run.n)
		}
		b.WriteString("== " + name + " ==\n")
		env, err := stepMapping(s, "env")
		if err != nil {
			return "", err
		}
		for _, e := range env {
			b.WriteString("env: " + e + "\n")
		}
		if sh := stepKey(s, "shell"); sh >= 0 {
			b.WriteString(key(s[sh]) + "\n")
		}
		b.WriteString("run:\n")
		v := strings.TrimSpace(strings.TrimPrefix(key(run), "run:"))
		if v == "" || strings.HasPrefix(v, ">") || (strings.HasPrefix(v, "|") && v != "|") {
			return "", fmt.Errorf("line %d: run: %s is no script this test reads; write it inline or as a | block", run.n, v)
		}
		if v != "|" {
			b.WriteString(v + "\n")
			continue
		}
		// The block ends at the first line no deeper than the run: key,
		// which sits past the "- " when it is the step's first.
		at = indent(run.text)
		if strings.HasPrefix(strings.TrimSpace(run.text), "- ") {
			at += 2
		}
		var block []string
		for _, r := range raw[run.n:] {
			if strings.TrimSpace(r) != "" && indent(r) <= at {
				break
			}
			block = append(block, r)
		}
		for len(block) > 0 && strings.TrimSpace(block[len(block)-1]) == "" {
			block = block[:len(block)-1]
		}
		first := slices.IndexFunc(block, func(r string) bool { return strings.TrimSpace(r) != "" })
		if first < 0 {
			return "", fmt.Errorf("line %d: an empty run: block", run.n)
		}
		in := indent(block[first])
		for _, r := range block {
			if len(r) >= in {
				r = r[in:]
			}
			b.WriteString(r + "\n")
		}
	}
	return registryPin.ReplaceAllString(b.String(), pinnedRegistry), nil
}

// envName is the name of an environment variable an env: may set.
var envName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// stepMapping is mappingOf for one of a step's own keys, the one on its
// "- " line included.
func stepMapping(step []line, key string) ([]string, error) {
	first := slices.Clone(step)
	first[0].text = strings.Replace(first[0].text, "- ", "  ", 1)
	return mappingOf(first, indent(first[0].text), key)
}

// registryPin is the registry image's version and digest as the shell
// names them.
var registryPin = regexp.MustCompile(`registry:[0-9.]+@sha256:[a-f0-9]{64}`)

// lineDiff returns the lines that differ between want and got, each with
// its number in want or got: "-" for a line only want has, "+" for one only
// got has.
func lineDiff(want, got string) string {
	a, b := strings.Split(want, "\n"), strings.Split(got, "\n")
	// common[i][j] is the length of the longest run of lines a[i:] and b[j:]
	// share, in order.
	common := make([][]int, len(a)+1)
	for i := range common {
		common[i] = make([]int, len(b)+1)
	}
	for i, v := range slices.Backward(a) {
		for j := len(b) - 1; j >= 0; j-- {
			if v == b[j] {
				common[i][j] = common[i+1][j+1] + 1
			} else {
				common[i][j] = max(common[i+1][j], common[i][j+1])
			}
		}
	}
	var out strings.Builder
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		switch {
		case i < len(a) && j < len(b) && a[i] == b[j]:
			i, j = i+1, j+1
		case j < len(b) && (i == len(a) || common[i][j+1] >= common[i+1][j]):
			fmt.Fprintf(&out, "+%d: %s\n", j+1, b[j])
			j++
		default:
			fmt.Fprintf(&out, "-%d: %s\n", i+1, a[i])
			i++
		}
	}
	return out.String()
}

// TestRehearseStillDecides checks that a rehearsal runs app-publish.yml's
// gate and its decision as any publish does. Neither step, nor the job, is
// conditional on rehearse, and the decision reads the image the caller
// names, so a rehearsal runs only from the daily slot or the manual run on
// main, and decides against ghcr.io. Against app-publish.yml as it is, then
// with each broken, which the check must refuse.
func TestRehearseStillDecides(t *testing.T) {
	t.Parallel()
	publish := readWorkflows(t)["app-publish.yml"]
	if err := decidesForReal(publish); err != nil {
		t.Errorf("app-publish.yml: %v", err)
	}
	const (
		decide = "        id: decide\n"
		skip   = "        if: ${{ !inputs.rehearse }}\n"
	)
	for name, mutant := range map[string]string{
		"the decision skipped in a rehearsal": strings.Replace(publish, decide, decide+skip, 1),
		"the decision told of a rehearsal":    replaceAfter(publish, decide, "        env:\n", "        env:\n          REHEARSE: ${{ inputs.rehearse }}\n"),
		"a decision against another image":    replaceAfter(publish, decide, "          IMAGE: ${{ inputs.image }}\n", "          IMAGE: ${{ steps.target.outputs.image }}\n"),
		"the gate skipped in a rehearsal":     strings.Replace(publish, gateName, gateName+skip, 1),
		"the job skipped in a rehearsal":      strings.Replace(publish, "    name: publish\n", "    name: publish\n    if: ${{ !inputs.rehearse }}\n", 1),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if mutant == publish {
				t.Fatal("the change changed nothing")
			}
			if decidesForReal(mutant) == nil {
				t.Error("passes app-publish.yml with " + name)
			}
		})
	}
}

// decidesForReal returns an error if the publish job's own if:, its gate
// step or its decide step mentions rehearse, or the decide step reads
// another image than the caller's.
func decidesForReal(workflow string) error {
	job := jobsOf(linesOf(workflow))["publish"]
	for _, l := range job {
		if indent(l.text) == 4 && strings.HasPrefix(strings.TrimSpace(l.text), "if:") && strings.Contains(l.text, "rehearse") {
			return fmt.Errorf("line %d makes the job conditional on rehearse", l.n)
		}
	}
	st := steps(job)
	gate := stepsWhere(st, contains("schedule | workflow_dispatch)"))
	decide := stepsWhere(st, func(l line) bool { return strings.TrimSpace(l.text) == "id: decide" })
	if len(gate) != 1 || len(decide) != 1 {
		return fmt.Errorf("%d gate steps and %d decide steps, want one of each", len(gate), len(decide))
	}
	for _, i := range []int{gate[0], decide[0]} {
		if j := slices.IndexFunc(st[i], contains("rehearse")); j >= 0 {
			return fmt.Errorf("line %d: the step from line %d mentions rehearse", st[i][j].n, st[i][0].n)
		}
	}
	d := st[decide[0]]
	script, err := runScript(d)
	if err != nil {
		return err
	}
	if got := value(d, "IMAGE"); got != "${{ inputs.image }}" || !strings.Contains(script, `divbast-published-revision "${IMAGE}:latest"`) {
		return fmt.Errorf("line %d decides against %q, not the caller's image", d[0].n, got)
	}
	return nil
}

// TestRehearsePublishesInsideTheJob checks that with rehearse set,
// app-publish.yml writes only to the registry it starts, never to ghcr.io.
// It logs in to ghcr.io only when not rehearsing; every step after the
// decision takes the image it writes from the one step that chooses where
// to publish; and that step, run with bash, chooses
// localhost:5000/<path of image> in a rehearsal and the caller's image
// otherwise. Against app-publish.yml as it is, then with each broken,
// which the check must refuse.
func TestRehearsePublishesInsideTheJob(t *testing.T) {
	t.Parallel()
	publish := readWorkflows(t)["app-publish.yml"]
	if err := publishesInside(t, publish); err != nil {
		t.Errorf("app-publish.yml: %v", err)
	}
	const (
		target = "          IMAGE: ${{ steps.target.outputs.image }}\n"
		input  = "          IMAGE: ${{ inputs.image }}\n"
	)
	for name, mutant := range map[string]string{
		"a ghcr.io login in a rehearsal":      strings.Replace(publish, " && !inputs.rehearse\n        with:\n          registry: ghcr.io\n", "\n        with:\n          registry: ghcr.io\n", 1),
		"a rehearsal to ghcr.io":              strings.Replace(publish, `image=localhost:5000/${IMAGE#*/}`, `image=${IMAGE}`, 1),
		"a rehearsal under the image's host":  strings.Replace(publish, `image=localhost:5000/${IMAGE#*/}`, `image=localhost:5000/${IMAGE}`, 1),
		"a publish to the rehearsal registry": strings.Replace(publish, `if [ "${REHEARSE}" = true ]; then`, `if true; then`, 1),
		"the choice blind to rehearse":        replaceAfter(publish, targetName, "          REHEARSE: ${{ inputs.rehearse }}\n", "          REHEARSE: true\n"),
		"the arches pushed to the input":      replaceAfter(publish, "      - name: Push each tested architecture\n", target, input),
		"the index staged on the input":       replaceAfter(publish, stageName, target, input),
		"the attestation for the input":       strings.Replace(publish, "subject-name: ${{ steps.target.outputs.image }}", "subject-name: ${{ inputs.image }}", 1),
		"the input promoted":                  replaceAfter(publish, promoteName, target, input),
		"the input checked":                   replaceAfter(publish, checkName, target, input),
		"a push to ghcr.io by name":           strings.Replace(publish, `"docker://${IMAGE}:${VERSION}-${arch}"`, `"docker://ghcr.io/divbast/oci-image-template:${VERSION}-${arch}"`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if mutant == publish {
				t.Fatal("the change changed nothing")
			}
			if publishesInside(t, mutant) == nil {
				t.Error("passes app-publish.yml with " + name)
			}
		})
	}
}

// publishesInside returns an error unless the publish job's ghcr.io login
// runs only without rehearse, no line after the decision names ghcr.io but
// that login's registry, no step after the decision but the one with id
// target names inputs.image, every IMAGE or subject-name after it is that
// step's output, and that step's script, run with bash, writes the image
// to publish to as GitHub Actions reads a step's outputs.
func publishesInside(t *testing.T, workflow string) error {
	t.Helper()
	st := publishSteps(workflow)
	login := stepsWhere(st, func(l line) bool { return strings.TrimSpace(l.text) == "registry: ghcr.io" })
	decide := stepsWhere(st, func(l line) bool { return strings.TrimSpace(l.text) == "id: decide" })
	target := stepsWhere(st, func(l line) bool { return strings.TrimSpace(l.text) == "id: target" })
	if len(login) != 1 || len(decide) != 1 || len(target) != 1 {
		return fmt.Errorf("%d ghcr.io logins, %d decide steps and %d target steps, want one of each", len(login), len(decide), len(target))
	}
	if cond := value(st[login[0]], "if"); !strings.Contains(cond, "!inputs.rehearse") {
		return fmt.Errorf("line %d logs in to ghcr.io on %q, in a rehearsal too", st[login[0]][0].n, cond)
	}
	for i := decide[0] + 1; i < len(st); i++ {
		for _, l := range st[i] {
			if strings.Contains(l.text, "ghcr.io") && (i != login[0] || strings.TrimSpace(l.text) != "registry: ghcr.io") {
				return fmt.Errorf("line %d names ghcr.io, which a rehearsal would write to", l.n)
			}
		}
		if i == target[0] {
			continue
		}
		if j := slices.IndexFunc(st[i], contains("inputs.image")); j >= 0 {
			return fmt.Errorf("line %d names inputs.image, which a rehearsal would write to", st[i][j].n)
		}
		for _, key := range []string{"IMAGE", "subject-name"} {
			if got := value(st[i], key); got != "" && got != "${{ steps.target.outputs.image }}" {
				return fmt.Errorf("the step from line %d sets %s to %q, not ${{ steps.target.outputs.image }}", st[i][0].n, key, got)
			}
		}
	}
	s := st[target[0]]
	if got := value(s, "IMAGE"); got != "${{ inputs.image }}" {
		return fmt.Errorf("line %d chooses from %q, not ${{ inputs.image }}", s[0].n, got)
	}
	if got := value(s, "REHEARSE"); got != "${{ inputs.rehearse }}" {
		return fmt.Errorf("line %d chooses on %q, not ${{ inputs.rehearse }}", s[0].n, got)
	}
	script, err := runScript(s)
	if err != nil {
		return err
	}
	for _, tt := range []struct{ image, rehearse, want string }{
		{image: "ghcr.io/divbast/oci-image-template", rehearse: "true", want: "localhost:5000/divbast/oci-image-template"},
		{image: "ghcr.io/divbast/oci-image-template", rehearse: "false", want: "ghcr.io/divbast/oci-image-template"},
		{image: "ghcr.io/divbast/librespeed", rehearse: "false", want: "ghcr.io/divbast/librespeed"},
	} {
		dir := t.TempDir()
		res := runStep(t, dir, script, "IMAGE="+tt.image, "REHEARSE="+tt.rehearse, "GITHUB_OUTPUT="+filepath.Join(dir, "output"))
		if res.Code != 0 {
			return fmt.Errorf("with IMAGE=%s and REHEARSE=%s, the script exits %d: %s", tt.image, tt.rehearse, res.Code, res.Stderr)
		}
		out, err := os.ReadFile(filepath.Join(dir, "output")) //nolint:gosec // G304: the test's own temporary directory
		if err != nil {
			return err
		}
		if got := string(out); got != "image="+tt.want+"\n" {
			return fmt.Errorf("with IMAGE=%s and REHEARSE=%s, the script outputs %q, want image=%s", tt.image, tt.rehearse, got, tt.want)
		}
	}
	return nil
}

// TestRehearseWarnsOutsideTemplate checks that app-publish.yml's rehearse
// input is off unless a caller sets it, and that a rehearsal says, as a
// warning and on the run's summary, that nothing reached ghcr.io. In any
// repository but divbast/oci-image-template, a copy made from it, the line
// also says how to publish: set image and remove rehearse. Against
// app-publish.yml as it is, then with each broken, which the check must
// refuse.
func TestRehearseWarnsOutsideTemplate(t *testing.T) {
	t.Parallel()
	publish := readWorkflows(t)["app-publish.yml"]
	if err := warnsOutsideTemplate(t, publish); err != nil {
		t.Errorf("app-publish.yml: %v", err)
	}
	const input = "      rehearse:\n"
	for name, mutant := range map[string]string{
		"the input taken out":              strings.Replace(publish, input, "      rehearse-not:\n", 1),
		"on by default":                    replaceAfter(publish, input, "        default: false\n", "        default: true\n"),
		"a warning without rehearse":       replaceAfter(publish, warnName, "        if: inputs.rehearse\n", "        if: always()\n"),
		"no warning":                       strings.Replace(publish, `echo "::warning::${line}"`, `echo "${line}"`, 1),
		"no summary":                       strings.Replace(publish, `echo "${line}" >> "${GITHUB_STEP_SUMMARY}"`, `echo "${line}" >&2`, 1),
		"the switch named in the template": strings.Replace(publish, `[ "${REPO}" != divbast/oci-image-template ]`, `[ "${REPO}" != divbast/ci ]`, 1),
		"the switch named nowhere":         strings.Replace(publish, `[ "${REPO}" != divbast/oci-image-template ]`, `false`, 1),
		"the repository not given":         replaceAfter(publish, warnName, "          REPO: ${{ github.repository }}\n", "          REPO: divbast/oci-image-template\n"),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if mutant == publish {
				t.Fatal("the change changed nothing")
			}
			if warnsOutsideTemplate(t, mutant) == nil {
				t.Error("passes app-publish.yml with " + name)
			}
		})
	}
}

// warnsOutsideTemplate returns an error unless the workflow declares a
// boolean rehearse input that defaults to false, and its one step that
// says nothing was published runs on inputs.rehearse alone, takes REPO from
// github.repository and, run with bash, prints the warning and writes the
// summary line, naming the switch outside the template only.
func warnsOutsideTemplate(t *testing.T, workflow string) error {
	t.Helper()
	const said = "rehearsal: nothing was published to ghcr.io"
	lines := linesOf(workflow)
	decl := declaration(lines, "rehearse")
	if !slices.Contains(decl, "type: boolean") || !slices.Contains(decl, "default: false") {
		return fmt.Errorf("declares rehearse as %q, not a boolean input that defaults to false", decl)
	}
	st := publishSteps(workflow)
	found := stepsWhere(st, contains("nothing was published to ghcr.io"))
	if len(found) != 1 {
		return fmt.Errorf("%d steps say nothing was published, want one", len(found))
	}
	s := st[found[0]]
	if cond := value(s, "if"); cond != "inputs.rehearse" {
		return fmt.Errorf("line %d warns on %q, not inputs.rehearse", s[0].n, cond)
	}
	if got := value(s, "REPO"); got != "${{ github.repository }}" {
		return fmt.Errorf("line %d warns for %q, not ${{ github.repository }}", s[0].n, got)
	}
	script, err := runScript(s)
	if err != nil {
		return err
	}
	for _, repo := range []string{"divbast/oci-image-template", "divbast/new-app"} {
		dir := t.TempDir()
		summary := filepath.Join(dir, "summary")
		res := runStep(t, dir, script, "REPO="+repo, "GITHUB_STEP_SUMMARY="+summary)
		if res.Code != 0 {
			return fmt.Errorf("with REPO=%s, the script exits %d: %s", repo, res.Code, res.Stderr)
		}
		wrote, err := os.ReadFile(summary) //nolint:gosec // G304: the test's own temporary directory
		if err != nil {
			return fmt.Errorf("with REPO=%s, the script writes no summary: %w", repo, err)
		}
		line := strings.TrimSuffix(string(wrote), "\n")
		if string(res.Stdout) != "::warning::"+line+"\n" {
			return fmt.Errorf("with REPO=%s, the script prints %q, not the warning ::warning::%s", repo, res.Stdout, line)
		}
		names := strings.Contains(line, "set image") && strings.Contains(line, "remove rehearse")
		switch {
		case !strings.HasPrefix(line, said):
			return fmt.Errorf("with REPO=%s, the summary says %q, not %q", repo, line, said)
		case repo == "divbast/oci-image-template" && line != said:
			return fmt.Errorf("in the template, the summary says %q, not %q alone", line, said)
		case repo != "divbast/oci-image-template" && !names:
			return fmt.Errorf("with REPO=%s, the summary says %q, which does not say to set image and remove rehearse", repo, line)
		}
	}
	return nil
}

// refuseName is the step that refuses the template's image outside a
// rehearsal, and templateFix what its error must tell the caller to do.
const (
	refuseName  = "      - name: Refuse the template's image outside a rehearsal\n"
	templateFix = "set image to your app's own name"
)

// TestPublishRefusesTheTemplatesImage (ruling R88) checks that
// app-publish.yml refuses ghcr.io/divbast/oci-image-template, the
// template's image, unless rehearse is true: an app made from the
// template that drops rehearse but keeps the image would make that
// package from its own repository. The refusal runs on every run, before
// any ghcr.io login or push, takes the image and rehearse from the
// caller's inputs, and, run with bash, fails only on the template's image
// outside a rehearsal, with an error that says what to set. Against
// app-publish.yml as it is, then with each broken, which the check must
// refuse.
func TestPublishRefusesTheTemplatesImage(t *testing.T) {
	t.Parallel()
	publish := readWorkflows(t)["app-publish.yml"]
	if err := refusesTheTemplatesImage(t, publish); err != nil {
		t.Errorf("app-publish.yml: %v", err)
	}
	const check = `if [ "${IMAGE}" = ghcr.io/divbast/oci-image-template ] && [ "${REHEARSE}" != true ]; then`
	for name, mutant := range map[string]string{
		"refused after the login":      moveStep(publish, refuseName, "      # A rehearsal publishes here instead"),
		"refused after a push":         moveStep(publish, refuseName, "      - name: Merge the architectures"),
		"refused only when publishing": strings.Replace(publish, refuseName, refuseName+"        if: steps.decide.outputs.publish == 'true'\n", 1),
		"rehearse taken as true":       replaceAfter(publish, refuseName, "          REHEARSE: ${{ inputs.rehearse }}\n", "          REHEARSE: true\n"),
		"another image checked":        replaceAfter(publish, refuseName, "          IMAGE: ${{ inputs.image }}\n", "          IMAGE: ${{ steps.target.outputs.image }}\n"),
		"refused in a rehearsal too":   strings.Replace(publish, check, `if [ "${IMAGE}" = ghcr.io/divbast/oci-image-template ]; then`, 1),
		"every image refused":          strings.Replace(publish, check, `if [ "${REHEARSE}" != true ]; then`, 1),
		"refused without saying how":   strings.Replace(publish, templateFix, "fix it", 1),
		"no refusal at all":            replaceAfter(publish, refuseName, "            exit 1\n", ""),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if mutant == publish {
				t.Fatal("the change changed nothing")
			}
			if refusesTheTemplatesImage(t, mutant) == nil {
				t.Error("passes app-publish.yml with " + name)
			}
		})
	}
}

// refusesTheTemplatesImage returns an error unless the publish job's one
// step that tells the caller to set its own image has no if:, comes
// before the ghcr.io login and every push, takes IMAGE and REHEARSE from
// the caller's inputs, and, its script run with bash, exits 1 with that
// error for the template's image with rehearse anything but true, and 0
// in silence otherwise.
func refusesTheTemplatesImage(t *testing.T, workflow string) error {
	t.Helper()
	st := publishSteps(workflow)
	found := stepsWhere(st, contains(templateFix))
	login := stepsWhere(st, func(l line) bool { return strings.TrimSpace(l.text) == "registry: ghcr.io" })
	pushes := stepsWhere(st, func(l line) bool {
		return strings.Contains(l.text, "skopeo copy") || strings.Contains(l.text, "imagetools create")
	})
	if len(found) != 1 || len(login) != 1 || len(pushes) == 0 {
		return fmt.Errorf("%d steps refuse the template's image, %d log in to ghcr.io and %d push; want one, one and some",
			len(found), len(login), len(pushes))
	}
	s := st[found[0]]
	if found[0] > login[0] || found[0] > pushes[0] {
		return fmt.Errorf("the step from line %d refuses the template's image after the ghcr.io login or a push", s[0].n)
	}
	if cond := value(s, "if"); cond != "" {
		return fmt.Errorf("the step from line %d refuses only on %q, not on every run", s[0].n, cond)
	}
	for key, want := range map[string]string{"IMAGE": "${{ inputs.image }}", "REHEARSE": "${{ inputs.rehearse }}"} {
		if got := value(s, key); got != want {
			return fmt.Errorf("the step from line %d takes %s from %q, not %s", s[0].n, key, got, want)
		}
	}
	script, err := runScript(s)
	if err != nil {
		return err
	}
	const template = "ghcr.io/divbast/oci-image-template"
	for _, tt := range []struct {
		image, rehearse string
		refused         bool
	}{
		{image: template, rehearse: "false", refused: true},
		{image: template, rehearse: "", refused: true},
		{image: template, rehearse: "true"},
		{image: "ghcr.io/divbast/librespeed", rehearse: "false"},
		{image: "ghcr.io/divbast/librespeed", rehearse: "true"},
	} {
		res := runStep(t, t.TempDir(), script, "IMAGE="+tt.image, "REHEARSE="+tt.rehearse)
		out := string(res.Stdout) + string(res.Stderr)
		switch {
		case tt.refused && (res.Code != 1 || !strings.Contains(out, templateFix)):
			return fmt.Errorf("with IMAGE=%s and REHEARSE=%q, the script exits %d and says %q, want 1 and %q",
				tt.image, tt.rehearse, res.Code, out, templateFix)
		case !tt.refused && (res.Code != 0 || out != ""):
			return fmt.Errorf("with IMAGE=%s and REHEARSE=%q, the script exits %d and says %q, want 0 and nothing",
				tt.image, tt.rehearse, res.Code, out)
		}
	}
	return nil
}

// registryManager is the matchStrings of the regex manager in
// divbast/renovate-config's default.json that moves the rehearsal's
// registry image, as Renovate reads it.
var registryManager = regexp.MustCompile(`# renovate: registry\n[^\n]*docker run [^\n]* (?<depName>registry):(?<currentValue>[0-9.]+)@(?<currentDigest>sha256:[a-f0-9]{64})`)

// registryRun is a line that runs the registry image, pinned or not.
var registryRun = regexp.MustCompile(`docker run .*\sregistry(?:[:@\s]|$)`)

// TestRehearseRegistryPinned checks that app-publish.yml runs the
// rehearsal's registry by version and digest, on a line the org's Renovate
// manager reads, binds it to the loopback alone, and starts it only in a
// rehearsal. Against app-publish.yml as it is, then with each broken, which
// the check must refuse.
func TestRehearseRegistryPinned(t *testing.T) {
	t.Parallel()
	publish := readWorkflows(t)["app-publish.yml"]
	if err := registryPinned(publish); err != nil {
		t.Errorf("app-publish.yml: %v", err)
	}
	const (
		marker   = "          # renovate: registry\n"
		wait     = "curl -fsS --retry 10 --retry-delay 1 --retry-all-errors -u rehearsal:rehearsal -o /dev/null http://127.0.0.1:5000/v2/"
		htpasswd = "cat > \"${RUNNER_TEMP}/rehearsal.htpasswd\" <<'EOF'\n" +
			"          rehearsal:$2y$05$EjEe94vjHWGY2fBH.Ugl6OucgCONUqj7tMeTnrww.QLljzQK06KEW\n          EOF"
	)
	pinned := registryManager.FindString(publish)
	_, digest, _ := strings.Cut(pinned, "@")
	for name, mutant := range map[string]string{
		"no marker":                       strings.Replace(publish, marker, "", 1),
		"the marker a line away":          strings.Replace(publish, marker, marker+"          true\n", 1),
		"a tag alone":                     strings.Replace(publish, "@"+digest, "", 1),
		"a second registry, unpinned":     strings.Replace(publish, marker, "          docker run -d -p 127.0.0.1:5001:5000 registry:3\n"+marker, 1),
		"beyond the loopback":             strings.Replace(publish, "-p 127.0.0.1:5000:5000", "-p 5000:5000", 1),
		"in every publish":                strings.Replace(publish, "        if: steps.decide.outputs.publish == 'true' && inputs.rehearse\n", "        if: steps.decide.outputs.publish == 'true'\n", 1),
		"a wait that gives up on a reset": strings.Replace(publish, " --retry-all-errors", "", 1),
		"a wait without end":              strings.Replace(publish, "curl -fsS --retry 10 ", "curl -fsS --retry 1000 ", 1),
		"no wait":                         strings.Replace(publish, "          "+wait+"\n", "", 1),
		"a registry that asks no login":   strings.Replace(publish, " -e REGISTRY_AUTH=htpasswd", "", 1),
		"no password file mounted":        strings.Replace(publish, ` -v "${RUNNER_TEMP}/rehearsal.htpasswd:/auth/htpasswd:ro"`, "", 1),
		"the password file never written": strings.Replace(publish, "          "+htpasswd+"\n", "", 1),
		"a wait without the login":        strings.Replace(publish, " -u rehearsal:rehearsal", "", 1),
		"no login":                        strings.Replace(publish, "          echo rehearsal | docker login --username rehearsal --password-stdin localhost:5000\n", "", 1),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if mutant == publish {
				t.Fatal("the change changed nothing")
			}
			if registryPinned(mutant) == nil {
				t.Error("passes app-publish.yml with " + name)
			}
		})
	}
}

// registryPinned returns an error unless every line that runs the
// registry image is one registryManager reads, there is one such line,
// it publishes the registry's port on 127.0.0.1 alone, and its step runs
// only on inputs.rehearse.
func registryPinned(workflow string) error {
	runs := 0
	for l := range strings.Lines(workflow) {
		if registryRun.MatchString(l) {
			runs++
		}
	}
	pinned := registryManager.FindAllString(workflow, -1)
	if runs != 1 || len(pinned) != 1 {
		return fmt.Errorf("%d lines run the registry, and Renovate reads %d of them; want one, read", runs, len(pinned))
	}
	if !strings.Contains(pinned[0], " -p 127.0.0.1:5000:5000 ") {
		return fmt.Errorf("%q publishes the registry's port beyond 127.0.0.1:5000", pinned[0])
	}
	st := publishSteps(workflow)
	found := stepsWhere(st, func(l line) bool { return registryRun.MatchString(l.text) })
	if len(found) != 1 {
		return fmt.Errorf("%d steps run the registry, want one", len(found))
	}
	if cond := value(st[found[0]], "if"); !strings.Contains(cond, "inputs.rehearse") || strings.Contains(cond, "!inputs.rehearse") {
		return fmt.Errorf("line %d starts the registry on %q, not in a rehearsal alone", st[found[0]][0].n, cond)
	}
	waits := slices.IndexFunc(st[found[0]], func(l line) bool { return strings.HasPrefix(strings.TrimSpace(l.text), "curl ") })
	if waits < 0 {
		return fmt.Errorf("the step from line %d never waits for the registry with curl", st[found[0]][0].n)
	}
	l := st[found[0]][waits]
	m := boundedRetry.FindStringSubmatch(l.text)
	if !strings.Contains(l.text, " --retry-all-errors") || m == nil {
		return fmt.Errorf("line %d waits for the registry without --retry <n> --retry-delay <s> and --retry-all-errors,"+
			" so a connection the registry resets before it listens fails the rehearsal", l.n)
	}
	if n, _ := strconv.Atoi(m[1]); n < 1 || n > 30 {
		return fmt.Errorf("line %d retries %s times, not between 1 and 30", l.n, m[1])
	}
	// actions/attest pushes only to a registry that answers its first
	// request with a Basic or Bearer challenge, so the registry asks for the
	// login the step writes and then gives Docker.
	mount := htpasswdMount.FindStringSubmatch(pinned[0])
	if !strings.Contains(pinned[0], " -e REGISTRY_AUTH=htpasswd ") || mount == nil ||
		!strings.Contains(pinned[0], " -e REGISTRY_AUTH_HTPASSWD_PATH="+mount[2]+" ") {
		return fmt.Errorf("%q starts a registry that asks no login, which actions/attest cannot push to:"+
			" give it REGISTRY_AUTH=htpasswd and a password file mounted read-only at REGISTRY_AUTH_HTPASSWD_PATH", pinned[0])
	}
	run := slices.IndexFunc(st[found[0]], func(l line) bool { return registryRun.MatchString(l.text) })
	if !slices.ContainsFunc(st[found[0]][:run], func(l line) bool {
		return strings.Contains(l.text, `> "`+mount[1]+`"`)
	}) {
		return fmt.Errorf("the step from line %d mounts %s before it writes it", st[found[0]][0].n, mount[1])
	}
	if !strings.Contains(l.text, " -u ") {
		return fmt.Errorf("line %d waits for the registry without logging in, which a registry that asks one refuses", l.n)
	}
	if !slices.ContainsFunc(st[found[0]], func(l line) bool {
		return strings.Contains(l.text, "docker login ") && strings.HasSuffix(strings.TrimSpace(l.text), " localhost:5000")
	}) {
		return fmt.Errorf("the step from line %d never logs Docker in to localhost:5000", st[found[0]][0].n)
	}
	return nil
}

// htpasswdMount is a read-only bind mount of a password file into the
// registry: its source and its target.
var htpasswdMount = regexp.MustCompile(`-v "([^":]+):([^":]+):ro"`)

// boundedRetry is curl's retry count, given with a delay between tries.
var boundedRetry = regexp.MustCompile(`--retry (\d+) .*--retry-delay \d+`)

// TestPublishChecksAnonymously checks that app-publish.yml's last check,
// run with bash and a stand-in for skopeo, reads both tags as an anonymous
// client does, with --no-creds, unless ANONYMOUS is false, which only a
// rehearsal sets: its registry is the job's own and takes no anonymous
// pulls. Any other value reads anonymously. A tag that is not the digest
// fails it either way. Against app-publish.yml as it is, then with each
// broken, which the check must refuse.
func TestPublishChecksAnonymously(t *testing.T) {
	t.Parallel()
	publish := readWorkflows(t)["app-publish.yml"]
	if err := checksAnonymously(t, publish); err != nil {
		t.Errorf("app-publish.yml: %v", err)
	}
	const env = "          ANONYMOUS: ${{ !inputs.rehearse }}\n"
	for name, mutant := range map[string]string{
		"the login used outside a rehearsal": strings.Replace(publish, env, "          ANONYMOUS: ${{ inputs.rehearse }}\n", 1),
		"never anonymous":                    strings.Replace(publish, env, "          ANONYMOUS: false\n", 1),
		"the login unless told otherwise":    strings.Replace(publish, `if [ "${ANONYMOUS}" = false ]; then`, `if [ "${ANONYMOUS}" != true ]; then`, 1),
		"no --no-creds at all":               strings.Replace(publish, "creds=(--no-creds)", "creds=()", 1),
		"a mismatch let through":             replaceAfter(publish, checkName, "              exit 1\n", ""),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if mutant == publish {
				t.Fatal("the change changed nothing")
			}
			if checksAnonymously(t, mutant) == nil {
				t.Error("passes app-publish.yml with " + name)
			}
		})
	}
}

// checksAnonymously returns an error unless the publish job's step after
// the promotion that runs skopeo inspect takes ANONYMOUS from
// ${{ !inputs.rehearse }} and, its script run with bash, reads each tag
// with --no-creds when ANONYMOUS is true or empty, without it when it is
// false, and fails on a tag whose bytes are not the digest.
func checksAnonymously(t *testing.T, workflow string) error {
	t.Helper()
	st := publishSteps(workflow)
	promote := stepsWhere(st, func(l line) bool { return strings.TrimSpace(l.text) == "id: promote" })
	if len(promote) != 1 {
		return fmt.Errorf("%d steps have id promote, want one", len(promote))
	}
	found := stepsWhere(st[promote[0]+1:], contains("skopeo inspect"))
	if len(found) != 1 {
		return fmt.Errorf("%d steps after the promotion run skopeo inspect, want one", len(found))
	}
	s := st[promote[0]+1+found[0]]
	if got := value(s, "ANONYMOUS"); got != "${{ !inputs.rehearse }}" {
		return fmt.Errorf("line %d checks with ANONYMOUS %q, not ${{ !inputs.rehearse }}", s[0].n, got)
	}
	script, err := runScript(s)
	if err != nil {
		return err
	}
	const (
		image = "ghcr.io/divbast/app"
		index = `{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[]}`
	)
	sum := sha256.Sum256([]byte(index))
	digest := "sha256:" + hex.EncodeToString(sum[:])
	anon := "inspect --raw --no-creds docker://" + image + ":1.2.3\ninspect --raw --no-creds docker://" + image + ":latest\n"
	login := "inspect --raw docker://" + image + ":1.2.3\ninspect --raw docker://" + image + ":latest\n"
	for _, tt := range []struct {
		anonymous, bytes, calls string
		ok                      bool
	}{
		{anonymous: "true", bytes: index, calls: anon, ok: true},
		{anonymous: "", bytes: index, calls: anon, ok: true},
		{anonymous: "false", bytes: index, calls: login, ok: true},
		{anonymous: "true", bytes: index + " ", calls: "inspect --raw --no-creds docker://" + image + ":1.2.3\n"},
		{anonymous: "false", bytes: index + " ", calls: "inspect --raw docker://" + image + ":1.2.3\n"},
	} {
		dir := t.TempDir()
		if err := os.Mkdir(filepath.Join(dir, "bin"), 0o700); err != nil {
			t.Fatal(err)
		}
		writeFile(t, dir, "pulled", tt.bytes)
		writeFile(t, dir, "bin/skopeo", "#!/usr/bin/env bash\nprintf '%s\\n' \"$*\" >> \"${CALLS}\"\ncat \"${PULLED}\"\n")
		calls := filepath.Join(dir, "calls")
		res := runStep(t, dir, script, "PATH="+filepath.Join(dir, "bin")+":"+os.Getenv("PATH"),
			"IMAGE="+image, "VERSION=1.2.3", "DIGEST="+digest, "ANONYMOUS="+tt.anonymous,
			"CALLS="+calls, "PULLED="+filepath.Join(dir, "pulled"))
		got, err := os.ReadFile(calls) //nolint:gosec // G304: the test's own temporary directory
		if err != nil {
			return fmt.Errorf("with ANONYMOUS=%q, skopeo never runs: %w", tt.anonymous, err)
		}
		if string(got) != tt.calls {
			return fmt.Errorf("with ANONYMOUS=%q, runs\n%s\nwant\n%s", tt.anonymous, got, tt.calls)
		}
		if (res.Code == 0) != tt.ok {
			return fmt.Errorf("with ANONYMOUS=%q and the tags pulled as %q, the script exits %d: %s", tt.anonymous, tt.bytes, res.Code, res.Stderr)
		}
	}
	return nil
}

// TestPublishInstallsGoAlone checks that app-publish.yml's job, which can
// push the image and sign its attestation, installs Go alone from the
// caller's mise.toml, as "core:go", with auto-install off: README.md tells
// callers so. Against app-publish.yml as it is, then with each broken,
// which the check must refuse.
func TestPublishInstallsGoAlone(t *testing.T) {
	t.Parallel()
	publish := readWorkflows(t)["app-publish.yml"]
	if err := installsGoAlone(publish); err != nil {
		t.Errorf("app-publish.yml: %v", err)
	}
	for name, mutant := range map[string]string{
		"another tool too": strings.Replace(publish, "install_args: core:go\n", "install_args: core:go aqua:skopeo\n", 1),
		"auto-install on":  strings.Replace(publish, "      MISE_AUTO_INSTALL: \"false\"\n", "      MISE_AUTO_INSTALL: \"true\"\n", 1),
		"no mise step":     strings.Replace(publish, "uses: jdx/mise-action@", "uses: jdx/mise-actions@", 1),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if mutant == publish {
				t.Fatal("the change changed nothing")
			}
			if installsGoAlone(mutant) == nil {
				t.Error("passes app-publish.yml with " + name)
			}
		})
	}
}

// installsGoAlone returns an error unless the publish job has a
// jdx/mise-action step, each such step's install_args is core:go, and the
// job's env sets MISE_AUTO_INSTALL to false.
func installsGoAlone(workflow string) error {
	job := jobsOf(linesOf(workflow))["publish"]
	st := steps(job)
	mise := stepsWhere(st, isUses("jdx/mise-action"))
	if len(mise) == 0 {
		return errors.New("the publish job has no jdx/mise-action step")
	}
	for _, i := range mise {
		if got := value(st[i], "install_args"); got != "core:go" {
			return fmt.Errorf("line %d installs %q, not core:go", st[i][0].n, got)
		}
	}
	if got := unquote(jobEnv(job)["MISE_AUTO_INSTALL"]); got != "false" {
		return fmt.Errorf("the publish job sets MISE_AUTO_INSTALL to %q, not false", got)
	}
	return nil
}

// publishSteps returns the steps of a workflow's publish job.
func publishSteps(workflow string) [][]line {
	return steps(jobsOf(linesOf(workflow))["publish"])
}

// stepsWhere returns the index of each step with a line f is true of.
func stepsWhere(st [][]line, f func(line) bool) []int {
	var out []int
	for i, s := range st {
		if slices.ContainsFunc(s, f) {
			out = append(out, i)
		}
	}
	return out
}

// contains is true of a line that holds s.
func contains(s string) func(line) bool {
	return func(l line) bool { return strings.Contains(l.text, s) }
}

// isUses is true of a step's uses: line for action, at any ref.
func isUses(action string) func(line) bool {
	return func(l line) bool {
		return strings.HasPrefix(strings.TrimPrefix(strings.TrimSpace(l.text), "- "), "uses: "+action+"@")
	}
}

// value returns the value of a step's first key: line, unquoted, or ""
// when it has none.
func value(step []line, key string) string {
	for _, l := range step {
		if v, ok := strings.CutPrefix(strings.TrimPrefix(strings.TrimSpace(l.text), "- "), key+":"); ok {
			return unquote(v)
		}
	}
	return ""
}

// replaceAfter returns s with the first old after the first marker
// replaced by replacement, or s as it is when either is missing.
func replaceAfter(s, marker, old, replacement string) string {
	i := strings.Index(s, marker)
	if i < 0 {
		return s
	}
	head, tail := s[:i+len(marker)], s[i+len(marker):]
	return head + strings.Replace(tail, old, replacement, 1)
}

// moveStep returns workflow with the step that starts with the text what
// moved to just before the one that starts with before, or workflow as it
// is when either is missing. A step runs from its first line to the next
// line at its indent, a step's or a comment's, so the comments above each
// stay where they were.
func moveStep(workflow, what, before string) string {
	i := strings.Index(workflow, what)
	if i < 0 {
		return workflow
	}
	end := len(workflow)
	for _, next := range []string{"\n      - ", "\n      #"} {
		if j := strings.Index(workflow[i+len(what):], next); j >= 0 {
			end = min(end, i+len(what)+j+1)
		}
	}
	step, rest := workflow[i:end], workflow[:i]+workflow[end:]
	k := strings.Index(rest, before)
	if k < 0 {
		return workflow
	}
	return rest[:k] + step + rest[k:]
}

// runScript returns a step's run: script, from a block scalar or a plain
// value. Blank lines and comments are already gone.
func runScript(step []line) (string, error) {
	for i, l := range step {
		v, ok := strings.CutPrefix(strings.TrimPrefix(strings.TrimSpace(l.text), "- "), "run:")
		if !ok {
			continue
		}
		if v = strings.TrimSpace(v); v != "|" {
			return v, nil
		}
		var b strings.Builder
		for _, s := range step[i+1:] {
			if indent(s.text) <= indent(l.text) {
				break
			}
			b.WriteString(strings.TrimSpace(s.text) + "\n")
		}
		return b.String(), nil
	}
	return "", fmt.Errorf("line %d: the step has no run: script", step[0].n)
}

// runStall runs script as runStep does, with a .ci/bin/divbast-stall that
// prints each of its arguments in brackets, and returns what it printed.
func runStall(t *testing.T, script, check, gated string) (string, error) {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".ci", "bin"), 0o700); err != nil {
		t.Fatal(err)
	}
	writeFile(t, dir, ".ci/bin/divbast-stall", "#!/usr/bin/env bash\nprintf '[%s]' \"$@\"\n")
	res := runStep(t, dir, script, "CHECK="+check, "CONTENT_GATED="+gated)
	if res.Code != 0 {
		return "", fmt.Errorf("with CHECK=%s and CONTENT_GATED=%s, the script exits %d: %s", check, gated, res.Code, res.Stderr)
	}
	return string(res.Stdout), nil
}

// runStep runs script as GitHub Actions runs a step whose shell is bash,
// with -e and pipefail (actionsBash), from dir, the workspace, and env on
// top of the test's environment. That is app-publish.yml's every step; a
// step that names no shell runs without pipefail, which only adds
// failures. BASH_ENV is empty, as on a runner, so that no startup file
// moves PATH out from under a stand-in.
func runStep(t *testing.T, dir, script string, env ...string) execx.Result {
	t.Helper()
	writeFile(t, dir, "step.sh", script)
	run := execx.OS{Env: append([]string{"BASH_ENV="}, env...)}
	res, err := run.Run(t.Context(), "bash", "-c", `cd -- "$1" && `+strings.Replace(actionsBash, "{0}", "./step.sh", 1), "bash", dir)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

// writeFile writes an executable file at name inside dir.
func writeFile(t *testing.T, dir, name, body string) {
	t.Helper()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	if err := root.WriteFile(name, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
}

// line is one line of a workflow and its 1-based number in the file.
type line struct {
	n    int
	text string
}

// readWorkflows returns every workflow in .github/workflows, by file name.
func readWorkflows(t *testing.T) map[string]string {
	t.Helper()
	dir := filepath.Join("..", "..", ".github", "workflows")
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	entries, err := fs.ReadDir(root.FS(), ".")
	if err != nil {
		t.Fatal(err)
	}
	workflows := map[string]string{}
	for _, e := range entries {
		if ext := filepath.Ext(e.Name()); ext != ".yml" && ext != ".yaml" {
			continue
		}
		data, err := root.ReadFile(e.Name())
		if err != nil {
			t.Fatal(err)
		}
		workflows[e.Name()] = string(data)
	}
	if len(workflows) == 0 {
		t.Fatalf("no workflows in %s", dir)
	}
	return workflows
}

// check guards every job, in every workflow given by file name, whose
// permissions grant a write scope, as grantsWrite reads them: its own
// permissions key or, when it has none, the workflow's. It guards every
// job with a step that mints a GitHub App token as well, whatever its
// permissions say. A permissions value grantsWrite cannot read is a
// problem, and the job it covers is guarded. check returns the guarded
// jobs, as file/job, and each problem it finds.
func check(workflows map[string]string) (guarded, found []string) {
	for _, file := range slices.Sorted(maps.Keys(workflows)) {
		lines := linesOf(workflows[file])
		jobs := jobsOf(lines)
		_, inherited, err := grantsWrite(lines, 0)
		if err != nil {
			found = append(found, file+": "+err.Error())
			inherited = true
		}
		for _, name := range slices.Sorted(maps.Keys(jobs)) {
			declared, write, err := grantsWrite(jobs[name], 4)
			if err != nil {
				found = append(found, file+": job "+name+": "+err.Error())
				write = true
			}
			if !declared {
				write = inherited
			}
			if !write && !slices.ContainsFunc(jobs[name], mintsAppToken) {
				continue
			}
			guarded = append(guarded, file+"/"+name)
			for _, p := range problems(jobs[name]) {
				found = append(found, file+": job "+name+": "+p)
			}
		}
	}
	return guarded, found
}

// grantsWrite reads the permissions key written at indent among lines:
// whether there is one, and whether it grants write. It does when it is
// write-all, a flow map such as { contents: write } that holds write, or a
// block with any scope on the lines below it set to write. Any other value
// but {} or read-all is an error, so that a form it cannot read fails
// rather than passing for one that grants nothing.
func grantsWrite(lines []line, at int) (declared, write bool, err error) {
	in := false
	for _, l := range lines {
		ind, trimmed := indent(l.text), strings.TrimSpace(l.text)
		switch {
		case ind == at:
			v, ok := strings.CutPrefix(trimmed, "permissions:")
			in, declared = ok, declared || ok
			if !ok {
				break
			}
			switch v = unquote(v); {
			case v == "", v == "{}", v == "read-all":
			case v == "write-all":
				write = true
			case strings.HasPrefix(v, "{") && strings.HasSuffix(v, "}"):
				write = write || strings.Contains(v, "write")
			default:
				err = fmt.Errorf("line %d: permissions: %s is none of {}, read-all, write-all"+
					" or a { } map; write it in block style", l.n, v)
			}
		case in && ind == at+2:
			if _, v, ok := strings.Cut(trimmed, ":"); ok && unquote(v) == "write" {
				write = true
			}
		case ind < at:
			in = false
		}
	}
	return declared, write, err
}

// linesOf returns a workflow's lines, leaving out blank lines and
// comments.
func linesOf(workflow string) []line {
	var lines []line
	n := 0
	for text := range strings.Lines(workflow) {
		n++
		text = strings.TrimRight(text, "\r\n")
		if trimmed := strings.TrimSpace(text); trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		lines = append(lines, line{n: n, text: text})
	}
	return lines
}

// jobsOf returns each job under the workflow's top-level jobs key, by name,
// as its lines. It relies on the two-space indentation every ci workflow
// uses.
func jobsOf(lines []line) map[string][]line {
	jobs := map[string][]line{}
	inJobs, name := false, ""
	for _, l := range lines {
		switch indent(l.text) {
		case 0:
			inJobs, name = l.text == "jobs:", ""
			continue
		case 2:
			if inJobs {
				name = strings.TrimSuffix(strings.TrimSpace(l.text), ":")
				jobs[name] = nil
				continue
			}
		}
		if inJobs && name != "" {
			jobs[name] = append(jobs[name], l)
		}
	}
	return jobs
}

// problems returns what makes a guarded job fail: each jdx/mise-action
// step whose install_args name no tool, each step that sets
// MISE_AUTO_INSTALL to anything but false and, if the job has any mise
// step, a job env without MISE_AUTO_INSTALL set to false.
func problems(job []line) []string {
	var out []string
	runsMise := false
	for _, step := range steps(job) {
		for _, l := range step {
			if v, ok := strings.CutPrefix(strings.TrimSpace(l.text), "MISE_AUTO_INSTALL:"); ok && unquote(v) != "false" {
				out = append(out, "line "+strconv.Itoa(l.n)+" sets MISE_AUTO_INSTALL to "+strings.TrimSpace(v)+
					" in a step, which turns auto-install back on for it")
			}
		}
		if !slices.ContainsFunc(step, func(l line) bool {
			return strings.HasPrefix(strings.TrimPrefix(strings.TrimSpace(l.text), "- "), "uses: jdx/mise-action@")
		}) {
			continue
		}
		runsMise = true
		if !slices.ContainsFunc(step, namesATool) {
			out = append(out, "line "+strconv.Itoa(step[0].n)+" runs jdx/mise-action without install_args that name a tool,"+
				" so it installs every tool in the caller's mise.toml")
		}
	}
	if runsMise && unquote(jobEnv(job)["MISE_AUTO_INSTALL"]) != "false" {
		out = append(out, `sets no MISE_AUTO_INSTALL: "false" in its env,`+
			" under which mise exec, a recipe's shell, installs the rest of the caller's mise.toml")
	}
	return out
}

// namesATool reports whether l is an install_args line with at least one
// word that is not a flag: with only flags, such as --locked, mise install
// installs every tool.
func namesATool(l line) bool {
	v, ok := strings.CutPrefix(strings.TrimSpace(l.text), "install_args:")
	return ok && slices.ContainsFunc(strings.Fields(unquote(v)), func(w string) bool {
		return !strings.HasPrefix(w, "-")
	})
}

// steps splits a job's steps list into its steps, each from its "- " line
// to the line before the next one.
func steps(job []line) [][]line {
	var out [][]line
	in, at := false, -1
	for _, l := range job {
		ind, trimmed := indent(l.text), strings.TrimSpace(l.text)
		if ind <= 4 {
			in = trimmed == "steps:"
			continue
		}
		if !in {
			continue
		}
		if strings.HasPrefix(trimmed, "- ") && (at < 0 || ind == at) {
			at = ind
			out = append(out, nil)
		}
		if len(out) > 0 {
			out[len(out)-1] = append(out[len(out)-1], l)
		}
	}
	return out
}

// jobEnv returns the job-level env: map, values as written.
func jobEnv(job []line) map[string]string {
	env := map[string]string{}
	in := false
	for _, l := range job {
		switch ind := indent(l.text); {
		case ind <= 4:
			in = strings.TrimSpace(l.text) == "env:"
		case in && ind == 6:
			if k, v, ok := strings.Cut(strings.TrimSpace(l.text), ":"); ok {
				env[k] = v
			}
		}
	}
	return env
}

// mappingOf returns the lines under the key called key written at indent
// at among lines, the key's own and its children's indent taken off, or
// nil when there is no such key. A key whose own line holds a value, such
// as a flow mapping, is an error: it is no block this reads.
func mappingOf(lines []line, at int, key string) ([]string, error) {
	for i, l := range lines {
		v, ok := strings.CutPrefix(l.text, strings.Repeat(" ", at)+key+":")
		if !ok || indent(l.text) != at {
			continue
		}
		if v = unquote(v); v != "" {
			return nil, fmt.Errorf("line %d writes %s: as %q, on one line; write it as a block", l.n, key, v)
		}
		var out []string
		for _, next := range lines[i+1:] {
			if indent(next.text) <= at {
				break
			}
			out = append(out, next.text[min(at+2, indent(next.text)):])
		}
		return out, nil
	}
	return nil, nil
}

// stepKey returns the index in step of the line that sets the step's own
// key, the one on its "- " line included, or -1 when it sets none.
func stepKey(step []line, key string) int {
	keys := indent(step[0].text) + 2
	return slices.IndexFunc(step, func(l line) bool {
		text := l.text
		if l == step[0] {
			text = strings.Replace(text, "- ", "  ", 1)
		}
		return indent(text) == keys && strings.HasPrefix(strings.TrimSpace(text), key+":")
	})
}

// unquote returns a plain YAML scalar's value: without a trailing comment,
// surrounding blanks or quotes.
func unquote(v string) string {
	v, _, _ = strings.Cut(v, " #")
	return strings.Trim(strings.TrimSpace(v), `"'`)
}

func indent(s string) int {
	return len(s) - len(strings.TrimLeft(s, " "))
}

// The shapes the org's Renovate preset reads (divbast/renovate-config,
// default.json). A pin written any other way is not kept current.
var (
	buildkitManager = regexp.MustCompile(`image=(?<depName>moby/buildkit):(?<currentValue>v[0-9.]+)@(?<currentDigest>sha256:[a-f0-9]{64})`)
	sbomManager     = regexp.MustCompile(`generator=(?<depName>docker/buildkit-syft-scanner):(?<currentValue>[0-9.]+)@(?<currentDigest>sha256:[a-f0-9]{64})`)
	miseManager     = regexp.MustCompile(`# renovate: datasource=(?<datasource>github-releases) depName=(?<depName>jdx/mise)\n\s*MISE_VERSION: ["']?(?<currentValue>[0-9.]+)["']?`)
	// renovateImage is renovate.yml's image with tag and digest. The
	// github-actions manager reads a digest from renovate-image, and
	// takes all of renovate-version, digest included, as the version.
	renovateImage = regexp.MustCompile(`renovate-image: ghcr\.io/renovatebot/renovate:[0-9.]+@sha256:[a-f0-9]{64}\n`)
)

// TestBuildToolsPinned checks that BuildKit, the SBOM scanner, mise and
// the Renovate image are each pinned in the form Renovate keeps current,
// against ci's workflows as they are, then with each pin undone, which
// the check must refuse.
func TestBuildToolsPinned(t *testing.T) {
	t.Parallel()
	workflows := readWorkflows(t)
	if found := buildToolsPinned(workflows); len(found) > 0 {
		t.Errorf("workflows: %s", strings.Join(found, "\n"))
	}
	mutate := func(file, old, replacement string) map[string]string {
		w := maps.Clone(workflows)
		w[file] = strings.Replace(w[file], old, replacement, 1)
		if w[file] == workflows[file] {
			t.Fatalf("the change to %s changed nothing", file)
		}
		return w
	}
	digest := regexp.MustCompile(`@sha256:[a-f0-9]{64}`)
	bk := buildkitManager.FindString(workflows["app-check.yml"])
	sbom := sbomManager.FindString(workflows["app-check.yml"])
	for name, mutant := range map[string]map[string]string{
		"buildkit without a digest":    mutate("app-check.yml", bk, digest.ReplaceAllString(bk, "")),
		"buildkit left floating":       mutate("app-publish.yml", "driver-opts: ", "ignored: "),
		"sbom generator left floating": mutate("app-check.yml", sbom, "generator=docker/buildkit-syft-scanner:stable-1"),
		"sbom without a digest":        mutate("app-check.yml", sbom, digest.ReplaceAllString(sbom, "")),
		"mise unversioned":             mutate("lint.yml", "version: ${{ env.MISE_VERSION }}", "install_args: core:go"),
		"mise marker removed":          mutate("stall.yml", "# renovate: datasource=github-releases depName=jdx/mise\n", ""),
		"renovate image floating":      mutate("renovate.yml", digest.FindString(workflows["renovate.yml"]), ""),
		"renovate version beside it":   mutate("renovate.yml", "          renovate-image:", "          renovate-version: 44.237.3@sha256:"+strings.Repeat("0", 64)+"\n          renovate-image:"),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if len(buildToolsPinned(mutant)) == 0 {
				t.Error("passes the workflows with " + name)
			}
		})
	}
}

// buildToolsPinned returns each way the workflows leave a build tool
// floating: a setup-buildx-action step without driver-opts that name a
// digest-pinned BuildKit, an SBOM attest without a digest-pinned
// generator, a mise-action step without version: set to env.MISE_VERSION,
// a workflow with such a step and no Renovate-marked MISE_VERSION, and
// renovate.yml without a digest-pinned image, or with a renovate-version.
// It finds one of each, or says so, so that a parser that reads no step
// cannot pass.
func buildToolsPinned(workflows map[string]string) []string {
	var out []string
	var buildx, sboms, mises int
	for _, file := range slices.Sorted(maps.Keys(workflows)) {
		text := workflows[file]
		miseHere := 0
		for name, job := range jobsOf(linesOf(text)) {
			for _, step := range steps(job) {
				at := file + "/" + name + " line " + strconv.Itoa(step[0].n)
				switch {
				case slices.ContainsFunc(step, isUses("docker/setup-buildx-action")):
					buildx++
					if !slices.ContainsFunc(step, func(l line) bool {
						return strings.Contains(l.text, "driver-opts:") && buildkitManager.MatchString(l.text)
					}) {
						out = append(out, at+": setup-buildx-action has no driver-opts: image=moby/buildkit:<tag>@sha256:<digest>")
					}
				case slices.ContainsFunc(step, isUses("jdx/mise-action")):
					mises++
					miseHere++
					if value(step, "version") != "${{ env.MISE_VERSION }}" {
						out = append(out, at+": mise-action does not set version: ${{ env.MISE_VERSION }}")
					}
				}
			}
		}
		for l := range strings.Lines(text) {
			if strings.Contains(l, "type=sbom") && !strings.HasPrefix(strings.TrimSpace(l), "#") {
				sboms++
				if !sbomManager.MatchString(l) {
					out = append(out, file+": the SBOM attest names no digest-pinned generator=docker/buildkit-syft-scanner:<version>@sha256:<digest>: "+strings.TrimSpace(l))
				}
			}
		}
		if miseHere > 0 && len(miseManager.FindAllString(text, -1)) != 1 {
			out = append(out, file+": runs mise-action but has not exactly one '# renovate: datasource=github-releases depName=jdx/mise' MISE_VERSION")
		}
	}
	if buildx == 0 || sboms == 0 || mises == 0 {
		out = append(out, fmt.Sprintf("read %d setup-buildx steps, %d SBOM attests and %d mise steps; want at least one of each", buildx, sboms, mises))
	}
	renovate := workflows["renovate.yml"]
	if !renovateImage.MatchString(renovate) {
		out = append(out, "renovate.yml: no renovate-image: ghcr.io/renovatebot/renovate:<version>@sha256:<digest>")
	}
	if strings.Contains(renovate, "renovate-version:") {
		out = append(out, "renovate.yml: renovate-version beside renovate-image, which the action ignores once the image has a tag")
	}
	return out
}
