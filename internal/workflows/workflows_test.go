// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

// Package workflows_test reads ci's workflows as text, so that no job
// holding a write scope runs install code from the caller's toolchain that
// it does not need. Every job whose permissions, its own or else its
// workflow's, grant a write scope must give each jdx/mise-action step
// install_args that name a tool, set MISE_AUTO_INSTALL to false in the
// job's env if it has such a step, and set it to nothing else in any step.
// A permissions value the test cannot read fails as well.
package workflows_test

import (
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// mustGuard are jobs the derived set must hold, the two that hold write
// scopes today, so that a parser regression cannot empty it unnoticed.
var mustGuard = []string{"app-check.yml/scan", "app-publish.yml/publish"}

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
			name: "read-all, and write only in a step's inputs",
			change: func(w map[string]string) {
				w["release.yml"] = "permissions: {}\n\njobs:\n  tag:\n    runs-on: ubuntu-26.04\n    permissions: read-all\n" + bare +
					"      - uses: actions/create-github-app-token@64ab729a6294000f5aa4a4bc0b73d1f32bc45510 # v3.3.0\n        with:\n          permission-contents: write\n"
			},
			job: "release.yml/tag",
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
// permissions key or, when it has none, the workflow's. A permissions value
// grantsWrite cannot read is a problem, and the job it covers is guarded.
// check returns the guarded jobs, as file/job, and each problem it finds.
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
			if !write {
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

// unquote returns a plain YAML scalar's value: without a trailing comment,
// surrounding blanks or quotes.
func unquote(v string) string {
	v, _, _ = strings.Cut(v, " #")
	return strings.Trim(strings.TrimSpace(v), `"'`)
}

func indent(s string) int {
	return len(s) - len(strings.TrimLeft(s, " "))
}
