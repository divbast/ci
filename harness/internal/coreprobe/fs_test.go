// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

package coreprobe

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
)

// tree makes a root holding files, each a path relative to it, and dirs,
// and returns it. A file whose content starts with "->" is a symlink to
// the rest.
func tree(t *testing.T, files map[string]string, dirs ...string) string {
	t.Helper()
	root := t.TempDir()
	for _, d := range dirs {
		if err := os.MkdirAll(filepath.Join(root, d), 0o750); err != nil {
			t.Fatal(err)
		}
	}
	for name, body := range files {
		p := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if target, ok := strings.CutPrefix(body, "->"); ok {
			if err := os.Symlink(target, p); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// unsearchable makes dir in root searchable by no one but root, until the
// test ends. As root, permissions stop nothing, so the test skips.
func unsearchable(t *testing.T, root, dir string) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("running as root, which permissions do not stop")
	}
	p := filepath.Join(root, dir)
	if err := os.MkdirAll(p, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(p, 0o700) }) //nolint:gosec // G302: a directory, searchable again so the test can remove it
}

func TestAssertNoShell(t *testing.T) {
	t.Parallel()

	absentAll := record(true, "/bin/sh is absent from the image", "absent", "absent") +
		record(true, "/bin/bash is absent from the image", "absent", "absent") +
		record(true, "/bin/dash is absent from the image", "absent", "absent")
	denied := "not looked up (errno 13: Permission denied), so it may be there"
	tests := []struct {
		name     string
		root     func(t *testing.T) string
		wantCode int
		want     string
	}{
		{name: "none", root: func(t *testing.T) string { t.Helper(); return tree(t, nil, "bin") }, want: absentAll},
		{name: "no-bin-at-all", root: func(t *testing.T) string { t.Helper(); return tree(t, nil) }, want: absentAll},
		{
			name:     "a-shell",
			root:     func(t *testing.T) string { t.Helper(); return tree(t, map[string]string{"bin/sh": "#!"}) },
			wantCode: 1,
			want: record(false, "/bin/sh is absent from the image", "absent", "present") +
				record(true, "/bin/bash is absent from the image", "absent", "absent") +
				record(true, "/bin/dash is absent from the image", "absent", "absent"),
		},
		{
			// A dangling link is still a name a shell could be put at
			name:     "a-dangling-link",
			root:     func(t *testing.T) string { t.Helper(); return tree(t, map[string]string{"bin/bash": "->/nowhere"}) },
			wantCode: 1,
			want: record(true, "/bin/sh is absent from the image", "absent", "absent") +
				record(false, "/bin/bash is absent from the image", "absent", "present") +
				record(true, "/bin/dash is absent from the image", "absent", "absent"),
		},
		{
			name: "an-unsearchable-bin",
			root: func(t *testing.T) string {
				t.Helper()
				root := tree(t, nil)
				unsearchable(t, root, "bin")
				return root
			},
			wantCode: 1,
			want: record(false, "/bin/sh is absent from the image", "absent", denied) +
				record(false, "/bin/bash is absent from the image", "absent", denied) +
				record(false, "/bin/dash is absent from the image", "absent", denied),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			code, stdout, _ := probe(t, testEnv(t, fstest.MapFS{}, tt.root(t)), "assert-no-shell")
			if code != tt.wantCode || stdout != tt.want {
				t.Errorf("assert-no-shell = exit %d, stdout %q; want exit %d, stdout %q", code, stdout, tt.wantCode, tt.want)
			}
		})
	}
}

func TestAssertReadOnly(t *testing.T) {
	t.Parallel()

	const what = "writing /.divbast-write-probe fails because / is read-only"
	tests := []struct {
		name string
		root func(t *testing.T) string
		want string
	}{
		{
			name: "a-writable-root",
			root: func(t *testing.T) string { t.Helper(); return tree(t, nil) },
			want: record(false, what, "Read-only file system", "wrote 6 bytes"),
		},
		{
			// A root merely owned by another user answers EACCES, not
			// EROFS: it is not read-only, and fails.
			name: "a-root-owned-by-another",
			root: func(t *testing.T) string {
				t.Helper()
				if os.Geteuid() == 0 {
					t.Skip("running as root, which permissions do not stop")
				}
				root := tree(t, nil)
				if err := os.Chmod(root, 0o500); err != nil { //nolint:gosec // G302: a directory, searchable but not writable, which is the case
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = os.Chmod(root, 0o700) }) //nolint:gosec // G302: a directory, writable again so the test can remove it
				return root
			},
			want: record(false, what, "Read-only file system", "cannot write /.divbast-write-probe: Permission denied"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			root := tt.root(t)
			code, stdout, _ := probe(t, testEnv(t, fstest.MapFS{}, root), "assert-read-only")
			if code != 1 || stdout != tt.want {
				t.Errorf("assert-read-only = exit %d, stdout %q; want exit 1, stdout %q", code, stdout, tt.want)
			}
			if _, err := os.Lstat(filepath.Join(root, ".divbast-write-probe")); !os.IsNotExist(err) {
				t.Errorf("the write probe is still there after the check: %v", err)
			}
		})
	}
}

func TestIsFile(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		root func(t *testing.T) string
		path string
		want string
	}{
		{name: "a-file", root: func(t *testing.T) string { t.Helper(); return tree(t, map[string]string{"etc/passwd": "x"}) }, path: "/etc/passwd", want: "present\n"},
		{name: "a-directory", root: func(t *testing.T) string { t.Helper(); return tree(t, nil, "etc") }, path: "/etc", want: "present\n"},
		{name: "a-dangling-link", root: func(t *testing.T) string { t.Helper(); return tree(t, map[string]string{"x": "->/nowhere"}) }, path: "/x", want: "present\n"},
		{name: "nothing", root: func(t *testing.T) string { t.Helper(); return tree(t, nil) }, path: "/nothing", want: "absent\n"},
		{name: "through-a-file", root: func(t *testing.T) string { t.Helper(); return tree(t, map[string]string{"etc/passwd": "x"}) }, path: "/etc/passwd/x", want: "absent\n"},
		{
			// What may not be looked up may still be there
			name: "under-an-unsearchable-directory",
			root: func(t *testing.T) string {
				t.Helper()
				root := tree(t, nil)
				unsearchable(t, root, "secret")
				return root
			},
			path: "/secret/x",
			want: "present\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			code, stdout, stderr := probe(t, testEnv(t, fstest.MapFS{}, tt.root(t)), "is-file", tt.path)
			if code != 0 || stdout != tt.want {
				t.Errorf("is-file %s = exit %d, stdout %q, stderr %q; want exit 0, stdout %q", tt.path, code, stdout, stderr, tt.want)
			}
		})
	}
}
