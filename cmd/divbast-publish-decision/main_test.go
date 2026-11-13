// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

package main

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const sha = "24e63e21ef880cd22c26964ee987fa593f5e92fc"

// onMain is a Git in which every commit is on main and has no other
// relatives, which is all these tests need: Decide's own tests walk a DAG.
type onMain struct{}

func (onMain) CommitExists(context.Context, string) (bool, error) { return true, nil }

func (onMain) IsAncestor(_ context.Context, ancestor, descendant string) (bool, error) {
	return ancestor == descendant || descendant == "origin/main", nil
}

func TestRun(t *testing.T) {
	t.Parallel()

	// What the runner already wrote to both files, which must survive.
	const before = "earlier=line\n"

	tests := []struct {
		name string
		args []string
		// actions is whether GITHUB_OUTPUT and GITHUB_STEP_SUMMARY are set.
		actions     bool
		wantCode    int
		wantStdout  string
		wantStderr  []string
		wantOutput  string
		wantSummary string
	}{
		{
			name:        "publish",
			args:        []string{"-event", "schedule", "-built", sha, "-published", ""},
			actions:     true,
			wantStdout:  "publish: nothing is published yet\n",
			wantOutput:  before + "publish=true\n",
			wantSummary: before + "publish: nothing is published yet\n",
		},
		{
			name:        "skip",
			args:        []string{"-event", "push", "-built", sha, "-published", sha},
			actions:     true,
			wantStdout:  "skip: already published\n",
			wantOutput:  before + "publish=false\n",
			wantSummary: before + "skip: already published\n",
		},
		{
			name:        "content-change",
			args:        []string{"-event", "schedule", "-built", sha, "-published", sha, "-content-change", "libaom"},
			actions:     true,
			wantStdout:  "publish: content moved: libaom\n",
			wantOutput:  before + "publish=true\n",
			wantSummary: before + "publish: content moved: libaom\n",
		},
		{
			name:        "refused",
			args:        []string{"-event", "pull_request", "-built", sha, "-published", sha},
			actions:     true,
			wantCode:    1,
			wantStderr:  []string{"only a push to main, the daily slot and a manual run publish, not a pull_request run"},
			wantOutput:  before,
			wantSummary: before + "fail: only a push to main, the daily slot and a manual run publish, not a pull_request run\n",
		},
		{
			name:       "outside-actions",
			args:       []string{"-event", "workflow_dispatch", "-built", sha, "-published", sha},
			wantStdout: "publish: republishing " + sha + " by hand\n",
		},
		{
			name:       "refused-outside-actions",
			args:       []string{"-event", "pull_request", "-built", sha, "-published", sha},
			wantCode:   1,
			wantStderr: []string{"not a pull_request run"},
		},
		{
			// Left out, it would read as nothing published, and publish.
			name:        "published-left-out",
			args:        []string{"-event", "schedule", "-built", sha},
			actions:     true,
			wantCode:    2,
			wantStderr:  []string{"-published is required"},
			wantOutput:  before,
			wantSummary: before + "fail: -published is required\n",
		},
		{
			name:        "unknown-flag-in-actions",
			args:        []string{"-event", "schedule", "-built", sha, "-published", sha, "-nope"},
			actions:     true,
			wantCode:    2,
			wantStderr:  []string{"-nope"},
			wantOutput:  before,
			wantSummary: before + "fail: flag provided but not defined: -nope\n",
		},
		{
			name:        "stray-argument-in-actions",
			args:        []string{"-event", "schedule", "-built", sha, "-published", sha, "extra"},
			actions:     true,
			wantCode:    2,
			wantStderr:  []string{`unexpected argument "extra"`},
			wantOutput:  before,
			wantSummary: before + "fail: unexpected argument \"extra\"\n",
		},
		{
			name:        "built-not-a-sha",
			args:        []string{"-event", "schedule", "-built", "main", "-published", sha},
			actions:     true,
			wantCode:    1,
			wantStderr:  []string{`the built commit "main" is not a full commit SHA`},
			wantOutput:  before,
			wantSummary: before + "fail: the built commit \"main\" is not a full commit SHA\n",
		},
		{
			name:       "event-left-out",
			args:       []string{"-built", sha, "-published", sha},
			wantCode:   2,
			wantStderr: []string{"-event is required"},
		},
		{
			name:       "stray-argument",
			args:       []string{"-event", "schedule", "-built", sha, "-published", sha, "extra"},
			wantCode:   2,
			wantStderr: []string{`unexpected argument "extra"`},
		},
		{
			name:       "unknown-flag",
			args:       []string{"-nope"},
			wantCode:   2,
			wantStderr: []string{"-nope"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()
			output := filepath.Join(dir, "output")
			summary := filepath.Join(dir, "summary")
			env := map[string]string{}
			if tt.actions {
				for _, path := range []string{output, summary} {
					if err := os.WriteFile(path, []byte(before), 0o600); err != nil {
						t.Fatal(err)
					}
				}
				env["GITHUB_OUTPUT"] = output
				env["GITHUB_STEP_SUMMARY"] = summary
			}
			getenv := func(key string) string { return env[key] }

			var stdout, stderr bytes.Buffer
			code := run(t.Context(), tt.args, onMain{}, getenv, &stdout, &stderr)
			if code != tt.wantCode {
				t.Errorf("run(%q) = %d, want %d; stderr: %s", tt.args, code, tt.wantCode, stderr.String())
			}
			if got := stdout.String(); got != tt.wantStdout {
				t.Errorf("stdout = %q, want %q", got, tt.wantStdout)
			}
			for _, want := range tt.wantStderr {
				if !strings.Contains(stderr.String(), want) {
					t.Errorf("stderr = %q, want it to contain %q", stderr.String(), want)
				}
			}

			if !tt.actions {
				// Nothing may be written where GitHub Actions named nothing.
				entries, err := os.ReadDir(dir)
				if err != nil || len(entries) != 0 {
					t.Errorf("wrote %v (%v) with GITHUB_OUTPUT and GITHUB_STEP_SUMMARY unset, want nothing", entries, err)
				}
				return
			}
			root, err := os.OpenRoot(dir)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = root.Close() })
			for file, want := range map[string]string{"output": tt.wantOutput, "summary": tt.wantSummary} {
				got, err := root.ReadFile(file)
				if err != nil && !errors.Is(err, fs.ErrNotExist) {
					t.Fatal(err)
				}
				if string(got) != want {
					t.Errorf("%s = %q, want %q", file, got, want)
				}
			}
		})
	}
}

// A decision that cannot be recorded is not one: the step must fail rather
// than leave the publish step to read an output that was never written,
// and say why on the run's summary, as any failure does.
func TestRunUnwritableOutput(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	summary := filepath.Join(dir, "summary")
	env := map[string]string{
		"GITHUB_OUTPUT":       filepath.Join(dir, "no-such-dir", "output"),
		"GITHUB_STEP_SUMMARY": summary,
	}
	var stdout, stderr bytes.Buffer
	args := []string{"-event", "schedule", "-built", sha, "-published", ""}
	if code := run(t.Context(), args, onMain{}, func(k string) string { return env[k] }, &stdout, &stderr); code != 1 {
		t.Errorf("run() = %d, want 1; stderr: %s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "write the step output") {
		t.Errorf("stderr = %q, want it to say the output could not be written", stderr.String())
	}
	got := readFile(t, summary)
	if !strings.HasPrefix(got, "fail: write the step output: ") || strings.Contains(got, "publish:") {
		t.Errorf("summary = %q, want only the failure to write the step output", got)
	}
}

// failingWriter fails every write, as a closed stdout would.
type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("stdout is closed") }

// A decision that cannot be printed fails the step, and says so on the
// run's summary.
func TestRunUnwritableStdout(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	summary := filepath.Join(dir, "summary")
	output := filepath.Join(dir, "output")
	env := map[string]string{"GITHUB_OUTPUT": output, "GITHUB_STEP_SUMMARY": summary}
	var stderr bytes.Buffer
	args := []string{"-event", "schedule", "-built", sha, "-published", ""}
	if code := run(t.Context(), args, onMain{}, func(k string) string { return env[k] }, failingWriter{}, &stderr); code != 1 {
		t.Errorf("run() = %d, want 1; stderr: %s", code, stderr.String())
	}
	if got, want := readFile(t, summary), "fail: write the decision: stdout is closed\n"; got != want {
		t.Errorf("summary = %q, want %q", got, want)
	}
	if got := readFile(t, output); got != "" {
		t.Errorf("output = %q, want nothing written", got)
	}
}

// readFile returns the file at path, or "" when there is none.
func readFile(t *testing.T, path string) string {
	t.Helper()
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	data, err := root.ReadFile(filepath.Base(path))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		t.Fatal(err)
	}
	return string(data)
}
