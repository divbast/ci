// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

package main

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// The os-release files the tests' layouts hold: a Debian image's, and a
// Docker Hardened Image's once Docker moves it to its own model.
const (
	debianRelease = "PRETTY_NAME=\"Debian GNU/Linux 13 (trixie)\"\nID=debian\nVERSION_ID=\"13\"\n"
	dhiRelease    = "ID=dhi\nID_LIKE=debian\nVERSION_ID=\"13\"\n"
)

// What TestRun's osRelease names besides an os-release file: a layout
// with none, and no layout at all.
const (
	withoutOSRelease = "without"
	withoutLayout    = "absent"
)

// writeLayout writes an OCI layout at dir as the scan's -layout names one:
// one image manifest, naming no platform, as Podman's archives hold one,
// over one uncompressed layer holding /etc/os-release with osRelease, or
// no os-release when it is "".
func writeLayout(t *testing.T, dir, osRelease string) {
	t.Helper()
	var layer bytes.Buffer
	tw := tar.NewWriter(&layer)
	name, body := "etc/os-release", osRelease
	if osRelease == "" {
		name, body = "etc/hostname", "image\n"
	}
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte(body)); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}

	blobs := filepath.Join(dir, "blobs", "sha256")
	if err := os.MkdirAll(blobs, 0o750); err != nil {
		t.Fatal(err)
	}
	type descriptor struct {
		MediaType string `json:"mediaType"`
		Digest    string `json:"digest"`
		Size      int    `json:"size"`
	}
	put := func(mediaType string, data []byte) descriptor {
		sum := sha256.Sum256(data)
		h := hex.EncodeToString(sum[:])
		if err := os.WriteFile(filepath.Join(blobs, h), data, 0o600); err != nil {
			t.Fatal(err)
		}
		return descriptor{mediaType, "sha256:" + h, len(data)}
	}
	marshal := func(v any) []byte {
		data, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	manifest := put("application/vnd.oci.image.manifest.v1+json", marshal(map[string]any{
		"schemaVersion": 2,
		"mediaType":     "application/vnd.oci.image.manifest.v1+json",
		"config":        put("application/vnd.oci.image.config.v1+json", []byte(`{"architecture":"amd64","os":"linux"}`)),
		"layers":        []descriptor{put("application/vnd.oci.image.layer.v1.tar", layer.Bytes())},
	}))
	index := marshal(map[string]any{"schemaVersion": 2, "manifests": []descriptor{manifest}})
	if err := os.WriteFile(filepath.Join(dir, "index.json"), index, 0o600); err != nil {
		t.Fatal(err)
	}
}

// withOS is report, a JSON report from trivyReport, as Trivy writes it
// for an OS it identifies as family and name, its OS packages' result of
// type osType.
func withOS(t *testing.T, report, family, name, osType string) string {
	t.Helper()
	var rep map[string]any
	if err := json.Unmarshal([]byte(report), &rep); err != nil {
		t.Fatal(err)
	}
	metadata, _ := rep["Metadata"].(map[string]any)
	metadata["OS"] = map[string]string{"Family": family, "Name": name}
	results, _ := rep["Results"].([]any)
	for _, r := range results {
		if res, _ := r.(map[string]any); res["Class"] == "os-pkgs" {
			res["Type"] = osType
			res["Target"] = "image (" + family + " " + name + ")"
		}
	}
	data, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}
