// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

package ocilayout

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/divbast/ci/internal/execx"
)

// file is one tar entry of a layer: a regular file with body, a symlink
// to link, a hard link to hard, or a directory, for a name ending in /.
type file struct{ name, body, link, hard string }

// layer writes entries as a gzip tar.
func layer(t *testing.T, entries ...file) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		h := &tar.Header{Name: e.name, Mode: 0o644, Size: int64(len(e.body)), Typeflag: tar.TypeReg}
		switch {
		case strings.HasSuffix(e.name, "/"):
			h = &tar.Header{Name: e.name, Mode: 0o755, Typeflag: tar.TypeDir}
		case e.link != "":
			h = &tar.Header{Name: e.name, Mode: 0o777, Linkname: e.link, Typeflag: tar.TypeSymlink}
		case e.hard != "":
			h = &tar.Header{Name: e.name, Mode: 0o644, Linkname: e.hard, Typeflag: tar.TypeLink}
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(e.body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	if _, err := zw.Write(buf.Bytes()); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return gz.Bytes()
}

// write writes a layout at a new directory: one image manifest, naming no
// platform, as skopeo copies one into an oci: layout, with config as its
// config, over layers.
func write(t *testing.T, config string, layers ...[]byte) string {
	t.Helper()
	dir := t.TempDir()
	blobs := filepath.Join(dir, "blobs", "sha256")
	if err := os.MkdirAll(blobs, 0o750); err != nil {
		t.Fatal(err)
	}
	type desc struct {
		MediaType string `json:"mediaType"`
		Digest    string `json:"digest"`
		Size      int    `json:"size"`
	}
	put := func(mediaType string, data []byte) desc {
		sum := sha256.Sum256(data)
		h := hex.EncodeToString(sum[:])
		if err := os.WriteFile(filepath.Join(blobs, h), data, 0o600); err != nil {
			t.Fatal(err)
		}
		return desc{mediaType, "sha256:" + h, len(data)}
	}
	marshal := func(v any) []byte {
		data, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	ls := make([]desc, 0, len(layers))
	for _, l := range layers {
		ls = append(ls, put("application/vnd.oci.image.layer.v1.tar+gzip", l))
	}
	m := put("application/vnd.oci.image.manifest.v1+json", marshal(map[string]any{
		"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
		"config": put("application/vnd.oci.image.config.v1+json", []byte(config)), "layers": ls,
	}))
	if err := os.WriteFile(filepath.Join(dir, "index.json"), marshal(map[string]any{"schemaVersion": 2, "manifests": []desc{m}}), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

const plainConfig = `{"architecture":"arm64","os":"linux"}`

func TestConfigLabels(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		config string
		want   map[string]string
	}{
		{"none", plainConfig, nil},
		{
			"buildkit", `{"architecture":"arm64","os":"linux","config":{"Labels":{"io.github.divbast.scan.lockfiles":"/usr/share/doc/x/pnpm-lock.yaml","org.opencontainers.image.title":"x"}}}`,
			map[string]string{"io.github.divbast.scan.lockfiles": "/usr/share/doc/x/pnpm-lock.yaml", "org.opencontainers.image.title": "x"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			im, err := Open(write(t, tt.config, layer(t, file{name: "etc/hostname", body: "x\n"})), "arm64")
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = im.Close() }()
			cfg, err := im.Config()
			if err != nil {
				t.Fatalf("Config() error = %v", err)
			}
			if cfg.Architecture != "arm64" || !maps.Equal(cfg.Labels, tt.want) {
				t.Errorf("Config() = %+v, want arm64 and labels %v", cfg, tt.want)
			}
		})
	}
}

func TestFiles(t *testing.T) {
	t.Parallel()
	const lock = "usr/share/doc/app/pnpm-lock.yaml"
	keep := func(name string) (int64, bool) { return 64, name == lock || name == "etc/other" }
	tests := []struct {
		name   string
		layers [][]file
		// want is each kept file's body, or "->target" for a symlink.
		want map[string]string
	}{
		{"one-layer", [][]file{{{name: lock, body: "v1"}, {name: "etc/hostname", body: "x"}}}, map[string]string{lock: "v1"}},
		{"later-wins", [][]file{{{name: lock, body: "v1"}}, {{name: "./" + lock, body: "v2"}}}, map[string]string{lock: "v2"}},
		{"whiteout", [][]file{{{name: lock, body: "v1"}, {name: "etc/other", body: "o"}}, {{name: "usr/share/doc/app/.wh.pnpm-lock.yaml"}}}, map[string]string{"etc/other": "o"}},
		{"opaque", [][]file{{{name: lock, body: "v1"}}, {{name: "usr/share/doc/.wh..wh..opq"}}}, map[string]string{}},
		{"symlink", [][]file{{{name: lock, link: "../../../src/pnpm-lock.yaml"}}}, map[string]string{lock: "->../../../src/pnpm-lock.yaml"}},
		{"hard-link", [][]file{{{name: "etc/other", body: "o"}, {name: lock, hard: "etc/other"}}}, map[string]string{lock: "o", "etc/other": "o"}},
		{"dropped-for-a-directory", [][]file{{{name: lock, body: "v1"}}, {{name: lock + "/"}}}, map[string]string{}},
		{"absent", [][]file{{{name: "etc/hostname", body: "x"}}}, map[string]string{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var ls [][]byte
			for _, l := range tt.layers {
				ls = append(ls, layer(t, l...))
			}
			im, err := Open(write(t, plainConfig, ls...), "arm64")
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = im.Close() }()
			tree, err := im.Files(t.Context(), execx.OS{}, keep)
			if err != nil {
				t.Fatalf("Files() error = %v", err)
			}
			got := map[string]string{}
			for name, n := range tree {
				got[name] = string(n.Body)
				if n.Link != "" {
					got[name] = "->" + n.Link
				}
			}
			if !maps.Equal(got, tt.want) {
				t.Errorf("Files() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFilesRefuses(t *testing.T) {
	t.Parallel()
	keep := func(name string) (int64, bool) { return 4, strings.HasSuffix(name, "pnpm-lock.yaml") }
	tests := []struct {
		name  string
		files []file
		want  string
	}{
		{"past-the-limit", []file{{name: "a/pnpm-lock.yaml", body: "12345"}}, "5 bytes"},
		{"hard-link-to-what-is-not-kept", []file{{name: "src/x", body: "o"}, {name: "a/pnpm-lock.yaml", hard: "src/x"}}, "hard link"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			im, err := Open(write(t, plainConfig, layer(t, tt.files...)), "arm64")
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = im.Close() }()
			tree, err := im.Files(t.Context(), execx.OS{}, keep)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("Files() = %v, %v; want an error containing %q", slices.Sorted(maps.Keys(tree)), err, tt.want)
			}
		})
	}
}

func TestOpenRefuses(t *testing.T) {
	t.Parallel()
	if _, err := Open(filepath.Join(t.TempDir(), "absent"), "arm64"); err == nil {
		t.Error("Open(no layout) error = nil")
	}
	// The one manifest names no platform, so it stands for any arch
	// asked for; a layout holding nothing is an error
	empty := t.TempDir()
	if err := os.WriteFile(filepath.Join(empty, "index.json"), []byte(`{"schemaVersion":2,"manifests":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(empty, "arm64"); err == nil || !strings.Contains(err.Error(), "no linux/arm64 image") {
		t.Errorf("Open(empty) error = %v, want one naming linux/arm64", err)
	}
}
