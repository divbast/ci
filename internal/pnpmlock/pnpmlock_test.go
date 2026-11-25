// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

package pnpmlock

import (
	"maps"
	"os"
	"slices"
	"strings"
	"testing"
)

// known is every package l holds, as name@version, sorted.
func (l *Lockfile) known() []string {
	return slices.Sorted(maps.Keys(l.kind))
}

// fixture reads testdata/pnpm-lock.yaml, which pnpm 12 wrote: its README
// says how.
func fixture(t *testing.T) []byte {
	t.Helper()
	root, err := os.OpenRoot("testdata")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	data, err := root.ReadFile("pnpm-lock.yaml")
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// split parts a name@version key as Runtime takes it.
func split(t *testing.T, key string) (name, version string) {
	t.Helper()
	i := strings.Index(key[1:], "@") + 1
	if i == 0 {
		t.Fatalf("%q is no name@version", key)
	}
	return key[:i], key[i+1:]
}

// runtimeOf returns the keys of l that Runtime reports as runtime, sorted.
func runtimeOf(t *testing.T, l *Lockfile) []string {
	t.Helper()
	var got []string
	for _, key := range l.known() {
		if l.Runtime(split(t, key)) {
			got = append(got, key)
		}
	}
	return got
}

func TestReadPnpm12(t *testing.T) {
	t.Parallel()
	l, err := Read(fixture(t))
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	// 15 in the boot document, pnpm and its 14 platform binaries, and 12
	// in the project's
	if got := len(l.known()); got != 27 {
		t.Errorf("Read() knows %d packages, want 27: %q", got, l.known())
	}
	// Reached from dependencies, the alias my-minimist, react-dom's peer
	// suffix, optionalDependencies, and loose-envify and minimist from a
	// devDependency too, which a runtime path still wins
	want := []string{
		"is-number@7.0.0", "js-tokens@4.0.0", "loose-envify@1.4.0", "minimist@1.2.5",
		"minimist@1.2.6", "react-dom@18.3.1", "react@18.3.1", "scheduler@0.23.2",
	}
	if got := runtimeOf(t, l); !slices.Equal(got, want) {
		t.Errorf("runtime packages = %q, want %q", got, want)
	}
	for _, key := range []string{
		"lodash@4.17.20", "mkdirp@0.5.5", "debug@2.6.9", "ms@2.0.0",
		"pnpm@12.14.0", "@pnpm/exe.linux-x64@12.14.0", "@pnpm/exe.win32-arm64@12.14.0",
	} {
		if l.Runtime(split(t, key)) {
			t.Errorf("Runtime(%s) = true, want false: only devDependencies or the boot document reach it", key)
		}
	}
}

func TestRuntimeUnknownPackage(t *testing.T) {
	t.Parallel()
	l, err := Read(fixture(t))
	if err != nil {
		t.Fatal(err)
	}
	// A package the lockfile does not name may be anything: runtime, so
	// that only what the lockfile places outside every runtime graph is
	// build-only
	for _, p := range [][2]string{{"left-pad", "1.3.0"}, {"lodash", "4.17.21"}, {"pnpm", "12.21.0"}} {
		if !l.Runtime(p[0], p[1]) {
			t.Errorf("Runtime(%s, %s) = false, want true for a package the lockfile does not name", p[0], p[1])
		}
	}
}

// doc is a project document holding importers and snapshots, as pnpm
// writes one.
func doc(importers, snapshots string) string {
	return "lockfileVersion: '9.0'\n\nsettings:\n  autoInstallPeers: true\n\nimporters:\n\n" + importers +
		"\npackages:\n\n  ignored@1.0.0:\n    resolution: {integrity: sha512-x}\n    engines: {node: '>=18'}\n" +
		"    deprecated: |-\n      a block scalar the reader never reads\n\nsnapshots:\n\n" + snapshots
}

func TestReadForms(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		lockfile    string
		wantRuntime []string
		wantKnown   int
	}{
		{
			name: "one-document",
			lockfile: doc(
				"  .:\n    dependencies:\n      a:\n        specifier: ^1.0.0\n        version: 1.0.0\n"+
					"    devDependencies:\n      d:\n        specifier: 1.0.0\n        version: 1.0.0\n",
				"  a@1.0.0:\n    dependencies:\n      b: 2.0.0\n\n  b@2.0.0: {}\n\n  d@1.0.0:\n    dependencies:\n      e: 1.0.0\n\n  e@1.0.0: {}\n",
			),
			wantRuntime: []string{"a@1.0.0", "b@2.0.0"},
			wantKnown:   4,
		},
		{
			name: "suffixes",
			lockfile: doc(
				"  .:\n    dependencies:\n      plugin:\n        specifier: ^2.0.0\n        version: 2.1.0(patch_hash=58033)(host@5.0.0(color@7.2.0))\n",
				"  host@5.0.0(color@7.2.0):\n    optionalDependencies:\n      color: 7.2.0\n\n  color@7.2.0: {}\n\n"+
					"  plugin@2.1.0(patch_hash=58033)(host@5.0.0(color@7.2.0)):\n    dependencies:\n      host: 5.0.0(color@7.2.0)\n",
			),
			wantRuntime: []string{"color@7.2.0", "host@5.0.0", "plugin@2.1.0"},
			wantKnown:   3,
		},
		{
			// One package in two peer contexts, one a runtime one: runtime,
			// whichever snapshot is read last
			name: "peer-variants",
			lockfile: doc(
				"  .:\n    dependencies:\n      a:\n        specifier: 1.0.0\n        version: 1.0.0(p@1.0.0)\n"+
					"    devDependencies:\n      b:\n        specifier: 1.0.0\n        version: 1.0.0(p@2.0.0)\n",
				"  a@1.0.0(p@1.0.0): {}\n\n  a@1.0.0(p@2.0.0): {}\n\n  b@1.0.0(p@2.0.0):\n    dependencies:\n      a: 1.0.0(p@2.0.0)\n"+
					"  b@1.0.0(p@1.0.0): {}\n\n  z@1.0.0(p@1.0.0): {}\n",
			),
			wantRuntime: []string{"a@1.0.0"},
			wantKnown:   3,
		},
		{
			name: "aliases-links-files-urls",
			lockfile: doc(
				"  .:\n    dependencies:\n      my-utils:\n        specifier: npm:utils@4.17.21\n        version: utils@4.17.21\n"+
					"      scoped:\n        specifier: npm:@scope/real@1.0.0\n        version: '@scope/real@1.0.0'\n"+
					"      lib:\n        specifier: workspace:*\n        version: link:../lib\n"+
					"      local:\n        specifier: file:packages/local\n        version: file:packages/local\n"+
					"      tarball:\n        specifier: https://codeload.github.com/o/r/tar.gz/abc\n        version: https://codeload.github.com/o/r/tar.gz/abc\n"+
					"    dependenciesMeta:\n      local:\n        injected: true\n    publishDirectory: dist\n",
				"  '@scope/real@1.0.0':\n    dependencies:\n      '@scope/dep': 3.0.0\n      other-alias: '@scope/other@1.0.0'\n      self: link:<root>/types\n\n"+
					"  '@scope/dep@3.0.0': {}\n\n  '@scope/other@1.0.0': {}\n\n  local@file:packages/local: {}\n\n"+
					"  tarball@https://codeload.github.com/o/r/tar.gz/abc: {}\n\n  utils@4.17.21: {}\n",
			),
			wantRuntime: []string{
				"@scope/dep@3.0.0", "@scope/other@1.0.0", "@scope/real@1.0.0", "local@file:packages/local",
				"tarball@https://codeload.github.com/o/r/tar.gz/abc", "utils@4.17.21",
			},
			wantKnown: 6,
		},
		{
			name: "workspace-importers",
			lockfile: doc(
				"  .:\n    devDependencies:\n      tool:\n        specifier: 1.0.0\n        version: 1.0.0\n\n"+
					"  packages/app:\n    optionalDependencies:\n      opt:\n        specifier: 1.0.0\n        version: 1.0.0\n\n  packages/empty: {}\n",
				"  opt@1.0.0:\n    optional: true\n    transitivePeerDependencies:\n      - peer\n\n  tool@1.0.0: {}\n",
			),
			wantRuntime: []string{"opt@1.0.0"},
			wantKnown:   2,
		},
		{
			// The boot document's groups are pnpm's own: never runtime, even
			// for a package the project's document also has, under a
			// devDependency
			name: "boot-and-project",
			lockfile: "---\nlockfileVersion: '9.0'\n\nimporters:\n\n  .:\n    configDependencies:\n      plugin:\n        specifier: 1.0.0\n        version: 1.0.0\n" +
				"    packageManagerDependencies:\n      pnpm:\n        specifier: 12.0.0\n        version: 12.0.0\n\n" +
				"packages:\n\n  plugin@1.0.0:\n    resolution: {integrity: sha512-x}\n\n" +
				"snapshots:\n\n  plugin@1.0.0: {}\n\n  pnpm@12.0.0:\n    optionalDependencies:\n      '@pnpm/exe': 12.0.0\n\n  '@pnpm/exe@12.0.0': {}\n\n---\n" +
				doc("  .:\n    devDependencies:\n      pnpm:\n        specifier: 12.0.0\n        version: 12.0.0\n    dependencies:\n      a:\n        specifier: 1.0.0\n        version: 1.0.0\n",
					"  a@1.0.0: {}\n\n  pnpm@12.0.0: {}\n"),
			wantRuntime: []string{"a@1.0.0"},
			wantKnown:   4,
		},
		{
			// A project with no dependencies: pnpm writes its importer, and
			// no snapshots
			name:        "empty-project",
			lockfile:    "lockfileVersion: '9.0'\n\nimporters:\n\n  .: {}\n",
			wantRuntime: nil,
			wantKnown:   0,
		},
		{
			name: "crlf",
			lockfile: strings.ReplaceAll(doc("  .:\n    dependencies:\n      a:\n        specifier: 1.0.0\n        version: 1.0.0\n", "  a@1.0.0: {}\n"),
				"\n", "\r\n"),
			wantRuntime: []string{"a@1.0.0"},
			wantKnown:   1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			l, err := Read([]byte(tt.lockfile))
			if err != nil {
				t.Fatalf("Read() error = %v", err)
			}
			if got := runtimeOf(t, l); !slices.Equal(got, tt.wantRuntime) {
				t.Errorf("runtime packages = %q, want %q", got, tt.wantRuntime)
			}
			if got := len(l.known()); got != tt.wantKnown {
				t.Errorf("Read() knows %d packages, want %d: %q", got, tt.wantKnown, l.known())
			}
		})
	}
}

// TestReadRefuses checks that whatever the reader cannot follow is an
// error, never a guess: a runtime edge it misread would make a runtime
// package build-only, and its findings would never block.
func TestReadRefuses(t *testing.T) {
	t.Parallel()
	dep := "  .:\n    dependencies:\n      a:\n        specifier: 1.0.0\n        version: 1.0.0\n"
	tests := []struct {
		name     string
		lockfile string
		want     string
	}{
		{"empty", "", "no lockfile document"},
		{"only-separators", "---\n\n---\n", "no lockfile document"},
		{"other-format", strings.Replace(doc(dep, "  a@1.0.0: {}\n"), "'9.0'", "'6.0'", 1), "lockfileVersion 6.0"},
		{"no-format", strings.Replace(doc(dep, "  a@1.0.0: {}\n"), "lockfileVersion: '9.0'\n", "", 1), "no lockfileVersion"},
		{"tab", doc("  .:\n    dependencies:\n\ta:\n", ""), "a tab"},
		{"dangling-root", doc(dep, "  b@1.0.0: {}\n"), "a@1.0.0, which no snapshot holds"},
		{"dangling-edge", doc(dep, "  a@1.0.0:\n    dependencies:\n      b: 2.0.0\n"), "b@2.0.0, which no snapshot holds"},
		{"unknown-group", doc("  .:\n    peerDependencies:\n      a:\n        specifier: 1.0.0\n        version: 1.0.0\n", ""), "peerDependencies"},
		{"unknown-snapshot-field", doc(dep, "  a@1.0.0:\n    bundled:\n      b: 1.0.0\n"), "bundled"},
		{"flow-dependencies", doc("  .:\n    dependencies: {a: {specifier: 1.0.0, version: 1.0.0}}\n", "  a@1.0.0: {}\n"), "flow"},
		{"flow-snapshot-edges", doc(dep, "  a@1.0.0:\n    dependencies: {b: 1.0.0}\n"), "flow"},
		{"no-version", doc("  .:\n    dependencies:\n      a:\n        specifier: 1.0.0\n", "  a@1.0.0: {}\n"), "names no version"},
		{"unknown-dependency-field", doc("  .:\n    dependencies:\n      a:\n        version: 1.0.0\n        resolved: x\n", "  a@1.0.0: {}\n"), "resolved"},
		{"block-scalar-version", doc("  .:\n    dependencies:\n      a:\n        version: |\n          1.0.0\n", "  a@1.0.0: {}\n"), "line"},
		{"unterminated-quote", doc("  .:\n    dependencies:\n      'a:\n        version: 1.0.0\n", ""), "quote"},
		{"bad-indent", doc("  .:\n     dependencies:\n", ""), "indented 5"},
		{"unbalanced-key", doc(dep, "  a@1.0.0: {}\n\n  b@1.0.0(c@1.0.0)): {}\n"), "parenthes"},
		{"separator-with-content", "--- !tag\n" + doc(dep, "  a@1.0.0: {}\n"), "---"},
		// pnpm writes importers in every document, so snapshots that no
		// importer could reach mean the reader missed what reaches them
		{"no-importers", "lockfileVersion: '9.0'\n\nsnapshots:\n\n  a@1.0.0: {}\n", "no importers"},
		{"no-importers-no-snapshots", "lockfileVersion: '9.0'\n\nsettings:\n  autoInstallPeers: true\n", "no importers"},
		{"empty-importers", "lockfileVersion: '9.0'\n\nimporters: {}\n\nsnapshots:\n\n  a@1.0.0: {}\n", "importers are empty"},
		{"importers-with-none", "lockfileVersion: '9.0'\n\nimporters:\n\nsnapshots:\n\n  a@1.0.0: {}\n", "importers are empty"},
		{"anchor", doc("  .:\n    dependencies:\n      a:\n        version: &v 1.0.0\n", "  a@1.0.0: {}\n"), "form of YAML"},
		{"alias", doc("  .:\n    dependencies:\n      a:\n        version: *v\n", "  a@1.0.0: {}\n"), "form of YAML"},
		{"nested-under-version", strings.Replace(doc(dep, "  a@1.0.0: {}\n"), "'9.0'\n", "'9.0'\n  extra: 1\n", 1), "lockfileVersion"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			l, err := Read([]byte(tt.lockfile))
			if err == nil {
				t.Fatalf("Read() = %v, nil; want an error containing %q", l.known(), tt.want)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("Read() error = %q, want it to contain %q", err, tt.want)
			}
		})
	}
}
