// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

package osrelease

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/divbast/ci/internal/execx"
)

const (
	dhi    = "ID=dhi\nID_LIKE=debian\nVERSION_ID=\"13\"\n"
	debian = "ID=debian\nVERSION_ID=\"13\"\n"
)

// file is one tar file of a layer: a regular file with body, or a
// symlink to link.
type file struct{ name, body, link string }

// layer writes entries as an uncompressed tar.
func layer(t *testing.T, entries ...file) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		h := &tar.Header{Name: e.name, Mode: 0o644, Size: int64(len(e.body)), Typeflag: tar.TypeReg}
		if e.link != "" {
			h = &tar.Header{Name: e.name, Mode: 0o777, Linkname: e.link, Typeflag: tar.TypeSymlink}
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
	return buf.Bytes()
}

// gz compresses data with gzip, as most images' layers are.
func gz(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// zst compresses data with the zstd command, as a Docker Hardened Image's
// layers are. The ubuntu-26.04 runner images carry it.
func zst(t *testing.T, data []byte) []byte {
	t.Helper()
	if _, err := exec.LookPath("zstd"); err != nil {
		t.Fatalf("zstd is not on PATH, and Read needs it for zstd layers: %v", err)
	}
	in := filepath.Join(t.TempDir(), "blob")
	if err := os.WriteFile(in, data, 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := execx.OS{}.Run(t.Context(), "zstd", "-q", "-c", in)
	if err != nil || res.Code != 0 {
		t.Fatalf("zstd -q -c: %v, exit %d: %s", err, res.Code, res.Stderr)
	}
	return res.Stdout
}

// desc is an OCI content desc, as a layout's index and
// manifests name blobs.
type desc struct {
	MediaType   string            `json:"mediaType"`
	Digest      string            `json:"digest"`
	Size        int               `json:"size"`
	Platform    *platform         `json:"platform,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
}

type platform struct {
	OS           string `json:"os"`
	Architecture string `json:"architecture"`
}

// blob writes data into the layout at dir, and returns its desc.
func blob(t *testing.T, dir, mediaType string, data []byte) desc {
	t.Helper()
	sum := sha256.Sum256(data)
	hexSum := hex.EncodeToString(sum[:])
	if err := os.MkdirAll(filepath.Join(dir, "blobs", "sha256"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "blobs", "sha256", hexSum), data, 0o600); err != nil {
		t.Fatal(err)
	}
	return desc{MediaType: mediaType, Digest: "sha256:" + hexSum, Size: len(data)}
}

// jsonBlob writes v as JSON into the layout at dir.
func jsonBlob(t *testing.T, dir, mediaType string, v any) desc {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return blob(t, dir, mediaType, data)
}

const (
	ociIndex    = "application/vnd.oci.image.index.v1+json"
	ociManifest = "application/vnd.oci.image.manifest.v1+json"
	ociConfig   = "application/vnd.oci.image.config.v1+json"
	tarGzip     = "application/vnd.oci.image.layer.v1.tar+gzip"
	tarZstd     = "application/vnd.oci.image.layer.v1.tar+zstd"
)

// manifest writes an image manifest over the compressed layers, in
// order, into the layout at dir.
func writeManifest(t *testing.T, dir, layerType string, layers ...[]byte) desc {
	t.Helper()
	m := struct {
		SchemaVersion int    `json:"schemaVersion"`
		MediaType     string `json:"mediaType"`
		Config        desc   `json:"config"`
		Layers        []desc `json:"layers"`
	}{SchemaVersion: 2, MediaType: ociManifest, Config: jsonBlob(t, dir, ociConfig, map[string]string{"architecture": "amd64", "os": "linux"})}
	for _, l := range layers {
		m.Layers = append(m.Layers, blob(t, dir, layerType, l))
	}
	return jsonBlob(t, dir, ociManifest, m)
}

// index writes an index naming manifests, at dir's index.json when top,
// and as a blob otherwise.
func writeIndex(t *testing.T, dir string, top bool, manifests ...desc) desc {
	t.Helper()
	ix := struct {
		SchemaVersion int    `json:"schemaVersion"`
		MediaType     string `json:"mediaType"`
		Manifests     []desc `json:"manifests"`
	}{SchemaVersion: 2, MediaType: ociIndex, Manifests: manifests}
	if !top {
		return jsonBlob(t, dir, ociIndex, ix)
	}
	data, err := json.Marshal(ix)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, "index.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, "oci-layout"), []byte(`{"imageLayoutVersion":"1.0.0"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	return desc{}
}

// simple writes a layout of one image manifest over gzip layers, as
// Podman's oci-archive holds one, with no platform on it.
func simple(t *testing.T, layers ...[]byte) string {
	t.Helper()
	dir := t.TempDir()
	gzipped := make([][]byte, 0, len(layers))
	for _, l := range layers {
		gzipped = append(gzipped, gz(t, l))
	}
	writeIndex(t, dir, true, writeManifest(t, dir, tarGzip, gzipped...))
	return dir
}

// read reads the layout at dir for amd64, with the zstd command.
func read(t *testing.T, dir, arch string) (Info, bool, error) {
	t.Helper()
	return Read(t.Context(), execx.OS{}, dir, arch)
}

// want fails t unless Read found want.
func want(t *testing.T, dir string, want Info) {
	t.Helper()
	got, ok, err := read(t, dir, "amd64")
	if err != nil || !ok || got != want {
		t.Fatalf("Read() = %+v, %v, %v; want %+v, true, nil", got, ok, err, want)
	}
}

func TestReadPlainFile(t *testing.T) {
	t.Parallel()
	dir := simple(t, layer(t, file{name: "etc/os-release", body: dhi}))
	want(t, dir, Info{ID: "dhi", IDLike: "debian", VersionID: "13"})
}

func TestReadUsrLibFallback(t *testing.T) {
	t.Parallel()
	dir := simple(t, layer(t, file{name: "usr/lib/os-release", body: dhi}))
	want(t, dir, Info{ID: "dhi", IDLike: "debian", VersionID: "13"})
}

func TestReadEtcWinsOverUsrLib(t *testing.T) {
	t.Parallel()
	dir := simple(t, layer(t,
		file{name: "usr/lib/os-release", body: debian},
		file{name: "etc/os-release", body: dhi},
	))
	want(t, dir, Info{ID: "dhi", IDLike: "debian", VersionID: "13"})
}

func TestReadSymlink(t *testing.T) {
	t.Parallel()
	for _, link := range []string{"../usr/lib/os-release", "/usr/lib/os-release"} {
		t.Run(link, func(t *testing.T) {
			t.Parallel()
			dir := simple(t, layer(t,
				file{name: "etc/os-release", link: link},
				file{name: "usr/lib/os-release", body: dhi},
			))
			want(t, dir, Info{ID: "dhi", IDLike: "debian", VersionID: "13"})
		})
	}
}

func TestReadSymlinkFollowed(t *testing.T) {
	t.Parallel()
	// Where the link leads and the fallback disagree, the link wins: a
	// reader that treated the link as missing would read the fallback
	dir := simple(t, layer(t,
		file{name: "etc/os-release", link: "../usr/share/os-release"},
		file{name: "usr/share/os-release", body: dhi},
		file{name: "usr/lib/os-release", body: debian},
	))
	want(t, dir, Info{ID: "dhi", IDLike: "debian", VersionID: "13"})
}

func TestReadSymlinkInLowerLayer(t *testing.T) {
	t.Parallel()
	// The link in one layer, its target rewritten in a later one: the
	// link is resolved against the final rootfs
	dir := simple(t,
		layer(t, file{name: "etc/os-release", link: "../usr/lib/os-release"}, file{name: "usr/lib/os-release", body: debian}),
		layer(t, file{name: "usr/lib/os-release", body: dhi}),
	)
	want(t, dir, Info{ID: "dhi", IDLike: "debian", VersionID: "13"})
}

func TestReadSymlinkOutOfRootfs(t *testing.T) {
	t.Parallel()
	dir := simple(t, layer(t, file{name: "etc/os-release", link: "../../../../usr/lib/os-release"}, file{name: "usr/lib/os-release", body: dhi}))
	// Resolved inside the rootfs, as a container's own lookup would
	want(t, dir, Info{ID: "dhi", IDLike: "debian", VersionID: "13"})
}

func TestReadSymlinkChainRefused(t *testing.T) {
	t.Parallel()
	dir := simple(t, layer(t,
		file{name: "etc/os-release", link: "../usr/lib/os-release"},
		file{name: "usr/lib/os-release", link: "/usr/share/os-release"},
		file{name: "usr/share/os-release", body: dhi},
	))
	_, _, err := read(t, dir, "amd64")
	if err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("Read() error = %v, want one naming the second symlink", err)
	}
}

func TestReadDanglingSymlinkFallsBack(t *testing.T) {
	t.Parallel()
	// os-release(5): /usr/lib/os-release when /etc/os-release is missing,
	// which a link to nothing is
	dir := simple(t, layer(t,
		file{name: "etc/os-release", link: "../usr/share/os-release"},
		file{name: "usr/lib/os-release", body: dhi},
	))
	want(t, dir, Info{ID: "dhi", IDLike: "debian", VersionID: "13"})
}

func TestReadLaterLayerWins(t *testing.T) {
	t.Parallel()
	dir := simple(t,
		layer(t, file{name: "etc/os-release", body: debian}),
		layer(t, file{name: "./etc/os-release", body: dhi}),
	)
	want(t, dir, Info{ID: "dhi", IDLike: "debian", VersionID: "13"})
}

func TestReadWhiteout(t *testing.T) {
	t.Parallel()
	for name, whiteout := range map[string]string{
		"file":   "etc/.wh.os-release",
		"dir":    ".wh.etc",
		"opaque": "etc/.wh..wh..opq",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			dir := simple(t,
				layer(t, file{name: "etc/os-release", body: debian}, file{name: "usr/lib/os-release", body: dhi}),
				layer(t, file{name: whiteout}),
			)
			want(t, dir, Info{ID: "dhi", IDLike: "debian", VersionID: "13"})
		})
	}
}

func TestReadOpaqueKeepsItsOwnLayer(t *testing.T) {
	t.Parallel()
	// An opaque directory hides what lower layers put in it, never what
	// its own layer does, whatever the order in its tar
	dir := simple(t,
		layer(t, file{name: "etc/os-release", body: debian}),
		layer(t, file{name: "etc/os-release", body: dhi}, file{name: "etc/.wh..wh..opq"}),
	)
	want(t, dir, Info{ID: "dhi", IDLike: "debian", VersionID: "13"})
}

func TestReadZstdLayer(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	writeIndex(t, dir, true, writeManifest(t, dir, tarZstd, zst(t, layer(t, file{name: "etc/os-release", body: dhi}))))
	want(t, dir, Info{ID: "dhi", IDLike: "debian", VersionID: "13"})
}

func TestReadNone(t *testing.T) {
	t.Parallel()
	dir := simple(t, layer(t, file{name: "etc/hostname", body: "x\n"}))
	got, ok, err := read(t, dir, "amd64")
	if err != nil || ok || got != (Info{}) {
		t.Fatalf("Read() = %+v, %v, %v; want {}, false, nil", got, ok, err)
	}
}

func TestReadBuildKitLayout(t *testing.T) {
	t.Parallel()
	// What buildx --output type=oci writes with attestations on: index.json
	// names an index, which names the image for each platform and, beside
	// each, its attestation manifest, whose layers are in-toto JSON
	dir := t.TempDir()
	image := func(arch, osRelease string) desc {
		d := writeManifest(t, dir, tarZstd, zst(t, layer(t,
			file{name: "etc/os-release", link: "../usr/lib/os-release"},
			file{name: "usr/lib/os-release", body: osRelease},
		)))
		d.Platform = &platform{OS: "linux", Architecture: arch}
		return d
	}
	attestation := func(of desc) desc {
		d := writeManifest(t, dir, "application/vnd.in-toto+json", []byte(`{"_type":"https://in-toto.io/Statement/v0.1"}`))
		d.Platform = &platform{OS: "unknown", Architecture: "unknown"}
		d.Annotations = map[string]string{
			"vnd.docker.reference.type":   "attestation-manifest",
			"vnd.docker.reference.digest": of.Digest,
		}
		return d
	}
	amd, arm := image("amd64", dhi), image("arm64", debian)
	nested := writeIndex(t, dir, false, amd, attestation(amd), arm, attestation(arm))
	nested.Annotations = map[string]string{"org.opencontainers.image.ref.name": "latest"}
	writeIndex(t, dir, true, nested)

	want(t, dir, Info{ID: "dhi", IDLike: "debian", VersionID: "13"})
	got, ok, err := read(t, dir, "arm64")
	if err != nil || !ok || got.ID != "debian" {
		t.Fatalf("Read(arm64) = %+v, %v, %v; want debian's", got, ok, err)
	}
	_, _, err = read(t, dir, "riscv64")
	if err == nil || !strings.Contains(err.Error(), "linux/riscv64") {
		t.Fatalf("Read(riscv64) error = %v, want one naming linux/riscv64", err)
	}
}

func TestReadQuotedAndComments(t *testing.T) {
	t.Parallel()
	dir := simple(t, layer(t, file{name: "etc/os-release", body: strings.Join([]string{
		"# a comment",
		"",
		`PRETTY_NAME="Docker Hardened Images (Debian 13)"`,
		"  ID='dhi'  ",
		`ID_LIKE="debian \"trixie\""`,
		"VERSION_ID=13",
		"NOT A LINE",
	}, "\n")}))
	want(t, dir, Info{ID: "dhi", IDLike: `debian "trixie"`, VersionID: "13"})
}

func TestReadRefusesLargeFile(t *testing.T) {
	t.Parallel()
	dir := simple(t, layer(t, file{name: "etc/os-release", body: strings.Repeat("#", maxSize+1)}))
	if _, _, err := read(t, dir, "amd64"); err == nil {
		t.Fatal("Read() of an os-release past the limit: nil error")
	}
}

func TestReadMissingLayout(t *testing.T) {
	t.Parallel()
	if _, _, err := read(t, filepath.Join(t.TempDir(), "absent"), "amd64"); err == nil {
		t.Fatal("Read() of no layout: nil error")
	}
}
