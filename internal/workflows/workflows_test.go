// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

// Package workflows_test reads ci's reusable workflows as text, and fails
// on a change that would let a job holding a write scope run install code
// from the caller's toolchain that the job does not need.
package workflows_test

import (
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// guarded names the jobs that hold a write scope and install tools from
// the caller's mise.toml. Every job of app-publish.yml holds packages,
// attestations and id-token write. No jobs means every job in the file.
var guarded = []struct {
	file string
	jobs []string
}{
	{file: "app-publish.yml"},
}

// TestWriteScopedJobsInstallOnlyWhatTheyName fails when a guarded job runs
// jdx/mise-action without install_args, which installs everything in the
// caller's mise.toml, or without MISE_AUTO_INSTALL set to false in the
// job's env, under which a recipe's `mise exec` shell installs the rest.
func TestWriteScopedJobsInstallOnlyWhatTheyName(t *testing.T) {
	t.Parallel()
	for _, g := range guarded {
		t.Run(g.file, func(t *testing.T) {
			t.Parallel()
			data, err := os.ReadFile(filepath.Join("..", "..", ".github", "workflows", g.file))
			if err != nil {
				t.Fatal(err)
			}
			jobs := jobsOf(string(data))
			names := g.jobs
			if len(names) == 0 {
				names = slices.Sorted(maps.Keys(jobs))
			}
			if len(names) == 0 {
				t.Fatalf("%s: found no jobs", g.file)
			}
			for _, name := range names {
				job, ok := jobs[name]
				if !ok {
					t.Errorf("%s: no job %q", g.file, name)
					continue
				}
				for _, p := range problems(job) {
					t.Errorf("%s: job %s: %s", g.file, name, p)
				}
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
			name:     "auto-install on",
			workflow: head + "    env:\n      MISE_AUTO_INSTALL: \"true\"\n    steps:\n" + mise + "        with:\n          install_args: core:go\n",
			want:     []string{"sets no MISE_AUTO_INSTALL: \"false\""},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := problems(jobsOf(tt.workflow)["j"])
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

// jobsOf returns each job under the workflow's top-level jobs key, by name,
// as its lines, leaving out blank lines and comments. It relies on the
// two-space indentation every ci workflow uses.
func jobsOf(workflow string) map[string][]line {
	jobs := map[string][]line{}
	inJobs, name, n := false, "", 0
	for text := range strings.Lines(workflow) {
		n++
		text = strings.TrimRight(text, "\r\n")
		trimmed := strings.TrimSpace(text)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		switch indent(text) {
		case 0:
			inJobs, name = text == "jobs:", ""
			continue
		case 2:
			if inJobs {
				name = strings.TrimSuffix(trimmed, ":")
				jobs[name] = nil
				continue
			}
		}
		if inJobs && name != "" {
			jobs[name] = append(jobs[name], line{n: n, text: text})
		}
	}
	return jobs
}

// problems returns what makes the job fail the guard: each jdx/mise-action
// step without install_args and, if it has any mise step, a job env without
// MISE_AUTO_INSTALL set to false.
func problems(job []line) []string {
	var out []string
	runsMise := false
	for _, step := range steps(job) {
		if !slices.ContainsFunc(step, func(l line) bool {
			return strings.HasPrefix(strings.TrimPrefix(strings.TrimSpace(l.text), "- "), "uses: jdx/mise-action@")
		}) {
			continue
		}
		runsMise = true
		if !slices.ContainsFunc(step, func(l line) bool {
			v, ok := strings.CutPrefix(strings.TrimSpace(l.text), "install_args:")
			return ok && unquote(v) != ""
		}) {
			out = append(out, "line "+strconv.Itoa(step[0].n)+" runs jdx/mise-action without install_args,"+
				" which installs every tool in the caller's mise.toml")
		}
	}
	if runsMise && unquote(jobEnv(job)["MISE_AUTO_INSTALL"]) != "false" {
		out = append(out, `sets no MISE_AUTO_INSTALL: "false" in its env,`+
			" under which mise exec, a recipe's shell, installs the rest of the caller's mise.toml")
	}
	return out
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
