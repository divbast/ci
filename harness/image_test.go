// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

package harness

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/divbast/ci/internal/execx"
)

// file is one entry of an archive tarball writes.
type file struct{ name, body string }

// tarball returns a tar archive holding files, in the order given.
func tarball(t *testing.T, files ...file) []byte {
	t.Helper()
	var b bytes.Buffer
	w := tar.NewWriter(&b)
	for _, f := range files {
		hdr := &tar.Header{Name: f.name, Mode: 0o644, Size: int64(len(f.body)), Typeflag: tar.TypeReg}
		if err := w.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(f.body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// configBlob is an image's configuration as BuildKit writes it, cut to
// what ImageConfig reads, with the health check both apps declare.
const configBlob = `{"architecture":"arm64","os":"linux","config":{"User":"65532:65532",` +
	`"Healthcheck":{"Test":["CMD","/usr/local/bin/frankenphp","php-cli","/x"],` +
	`"Interval":30000000000,"Timeout":10000000000,"StartPeriod":60000000000,"Retries":3}}}`

// wantConfig is what configBlob, or Docker's inspection of that image,
// holds.
var wantConfig = Config{
	User: "65532:65532",
	Healthcheck: &Healthcheck{
		Test:     []string{"CMD", "/usr/local/bin/frankenphp", "php-cli", "/x"},
		Interval: 30 * time.Second, Timeout: 10 * time.Second, StartPeriod: time.Minute, Retries: 3,
	},
}

// sameConfig reports whether two configurations say the same thing.
func sameConfig(a, b Config) bool {
	if a.User != b.User || (a.Healthcheck == nil) != (b.Healthcheck == nil) || !maps.Equal(a.Volumes, b.Volumes) {
		return false
	}
	if a.Healthcheck == nil {
		return true
	}
	x, y := *a.Healthcheck, *b.Healthcheck
	return slices.Equal(x.Test, y.Test) && x.Interval == y.Interval && x.Timeout == y.Timeout &&
		x.StartPeriod == y.StartPeriod && x.StartInterval == y.StartInterval && x.Retries == y.Retries
}

func TestArchiveConfig(t *testing.T) {
	t.Parallel()

	const manifest = `[{"Config":"abc.json","RepoTags":[],"Layers":["l1.tar"]}]`
	tests := []struct {
		name    string
		archive []byte
		wantErr bool
	}{
		{
			// The order podman save writes: layers, the configuration, then
			// the manifest last of all
			name:    "manifest-last",
			archive: tarball(t, file{"l1.tar", "a layer"}, file{"abc.json", configBlob}, file{"manifest.json", manifest}),
		},
		{
			name:    "manifest-first",
			archive: tarball(t, file{"manifest.json", manifest}, file{"l1.tar", "a layer"}, file{"abc.json", configBlob}),
		},
		{
			name:    "no-manifest",
			archive: tarball(t, file{"abc.json", configBlob}),
			wantErr: true,
		},
		{
			name:    "manifest-names-a-missing-config",
			archive: tarball(t, file{"manifest.json", manifest}, file{"other.json", configBlob}),
			wantErr: true,
		},
		{
			name: "two-images",
			archive: tarball(t, file{"abc.json", configBlob},
				file{"manifest.json", `[{"Config":"abc.json"},{"Config":"abc.json"}]`}),
			wantErr: true,
		},
		{
			name:    "not-an-archive",
			archive: []byte("this is not a tar archive, and is long enough that tar tries a header of it"),
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := archiveConfig(bytes.NewReader(tt.archive))
			if tt.wantErr {
				if err == nil {
					t.Fatalf("archiveConfig() = %q, nil; want an error", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("archiveConfig() error = %v", err)
			}
			if string(got) != configBlob {
				t.Errorf("archiveConfig() = %q, want the configuration blob", got)
			}
		})
	}
}

func TestImageConfigDocker(t *testing.T) {
	t.Parallel()

	id := []string{"docker", "image", "inspect", "--format", "{{.Id}}", "img"}
	inspect := []string{"docker", "image", "inspect", "--format", "{{json .Config}}", "img"}
	pull := []string{"docker", "pull", "-q", "img"}
	absent := execx.Result{Code: 1, Stderr: []byte("Error response from daemon: No such image: img")}
	config := execx.Result{Stdout: []byte(`{"User":"65532:65532","Healthcheck":{"Test":["CMD","/usr/local/bin/frankenphp","php-cli","/x"],` +
		`"Interval":30000000000,"Timeout":10000000000,"StartPeriod":60000000000,"Retries":3}}` + "\n")}

	tests := []struct {
		name    string
		calls   []execx.Call
		wantErr bool
	}{
		{
			name: "here",
			calls: []execx.Call{
				{Argv: id, Result: execx.Result{Stdout: []byte("sha256:abc\n")}},
				{Argv: inspect, Result: config},
			},
		},
		{
			// Pulled when it is not here, as a run would pull it
			name: "pulled",
			calls: []execx.Call{
				{Argv: id, Result: absent},
				{Argv: pull, Result: execx.Result{Stdout: []byte("img\n")}},
				{Argv: id, Result: execx.Result{Stdout: []byte("sha256:abc\n")}},
				{Argv: inspect, Result: config},
			},
		},
		{
			name: "pull-fails",
			calls: []execx.Call{
				{Argv: id, Result: absent},
				{Argv: pull, Result: execx.Result{Code: 1, Stderr: []byte("Error response from daemon: manifest unknown")}},
			},
			wantErr: true,
		},
		{
			name: "not-json",
			calls: []execx.Call{
				{Argv: id, Result: execx.Result{Stdout: []byte("sha256:abc\n")}},
				{Argv: inspect, Result: execx.Result{Stdout: []byte("<no value>\n")}},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			e := newEngine("docker", execx.NewFake(t, tt.calls...))
			got, err := e.ImageConfig(t.Context(), t, "img")
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ImageConfig() = %+v, nil; want an error", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ImageConfig() error = %v", err)
			}
			if !sameConfig(got, wantConfig) {
				t.Errorf("ImageConfig() = %+v, healthcheck %+v; want %+v", got, got.Healthcheck, wantConfig.Healthcheck)
			}
		})
	}
}

// podmanSaving answers Podman's image inspect with id, and its save by
// writing archive where -o points, as podman save would.
func podmanSaving(t *testing.T, id string, archive []byte) runFunc {
	t.Helper()
	return func(argv []string) execx.Result {
		switch {
		case slices.Equal(argv, []string{"podman", "image", "inspect", "--format", "{{.Id}}", "img"}):
			return execx.Result{Stdout: []byte(id + "\n")}
		case len(argv) == 8 && slices.Equal(argv[:6], []string{"podman", "save", "-q", "--format", "docker-archive", "-o"}) && argv[7] == id:
			if err := os.WriteFile(argv[6], archive, 0o600); err != nil {
				t.Errorf("writing the archive: %v", err)
				return execx.Result{Code: 125}
			}
			return execx.Result{}
		default:
			t.Errorf("unexpected command %q", argv)
			return execx.Result{Code: 125}
		}
	}
}

func TestImageConfigPodman(t *testing.T) {
	t.Parallel()

	digest := func(blob string) string {
		sum := sha256.Sum256([]byte(blob))
		return hex.EncodeToString(sum[:])
	}
	archive := func(blob string) []byte {
		return tarball(t, file{"l1.tar", "a layer"}, file{digest(blob) + ".json", blob},
			file{"manifest.json", `[{"Config":"` + digest(blob) + `.json","RepoTags":[],"Layers":["l1.tar"]}]`})
	}
	const noHealthcheck = `{"config":{"User":"0:0"}}`
	const volume = `{"config":{"User":"65532:65532","Volumes":{"/data":{}}}}`

	tests := []struct {
		name    string
		id      string
		archive []byte
		want    Config
		wantErr string
	}{
		{name: "healthcheck", id: digest(configBlob), archive: archive(configBlob), want: wantConfig},
		{
			// What Podman's own image inspect never shows for an OCI image is
			// absent here only when the image itself has none.
			name: "no-healthcheck", id: digest(noHealthcheck), archive: archive(noHealthcheck),
			want: Config{User: "0:0"},
		},
		{
			name: "volume", id: digest(volume), archive: archive(volume),
			want: Config{User: "65532:65532", Volumes: map[string]struct{}{"/data": {}}},
		},
		{
			// The image ID is the digest of its configuration, so a blob that
			// hashes to anything else is some other image's.
			name: "another-images-config", id: digest(noHealthcheck), archive: archive(configBlob),
			wantErr: "is not",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			e := newEngine("podman", podmanSaving(t, tt.id, tt.archive))
			got, err := e.ImageConfig(t.Context(), t, "img")
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("ImageConfig() = %+v, %v; want an error saying %q", got, err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ImageConfig() error = %v", err)
			}
			if !sameConfig(got, tt.want) {
				t.Errorf("ImageConfig() = %+v, healthcheck %+v; want %+v", got, got.Healthcheck, tt.want)
			}
		})
	}
}

// TestSaveMemoized shows podman save running once for an image however
// many times its configuration is read: each save writes out the whole
// image, some 178 MB of the fixture. The image ID is the digest of that
// configuration, so what one save read for an ID holds for good. A save
// that failed is not kept.
func TestSaveMemoized(t *testing.T) {
	t.Parallel()

	sum := sha256.Sum256([]byte(configBlob))
	id := hex.EncodeToString(sum[:])
	archive := tarball(t, file{"l1.tar", "a layer"}, file{id + ".json", configBlob},
		file{"manifest.json", `[{"Config":"` + id + `.json","RepoTags":[],"Layers":["l1.tar"]}]`})

	t.Run("once-for-many", func(t *testing.T) {
		t.Parallel()

		var saves atomic.Int32
		save := podmanSaving(t, id, archive)
		e := newEngine("podman", runFunc(func(argv []string) execx.Result {
			if argv[1] == "save" {
				saves.Add(1)
			}
			return save(argv)
		}))
		read := func() {
			if got, err := e.ImageConfig(t.Context(), t, "img"); err != nil || !sameConfig(got, wantConfig) {
				t.Errorf("ImageConfig() = %+v, %v; want %+v", got, err, wantConfig)
			}
		}
		// Checks run beside each other, and then one more after them
		var wg sync.WaitGroup
		for range 8 {
			wg.Go(read)
		}
		wg.Wait()
		read()
		if n := saves.Load(); n != 1 {
			t.Errorf("podman save ran %d times for one image, want once", n)
		}
	})

	t.Run("a-failed-save-is-not-kept", func(t *testing.T) {
		t.Parallel()

		var saves atomic.Int32
		save := podmanSaving(t, id, archive)
		e := newEngine("podman", runFunc(func(argv []string) execx.Result {
			if argv[1] == "save" && saves.Add(1) == 1 {
				return execx.Result{Code: 125, Stderr: []byte("Error: writing to /tmp: no space left on device")}
			}
			return save(argv)
		}))
		if _, err := e.ImageConfig(t.Context(), t, "img"); err == nil || !strings.Contains(err.Error(), "no space left") {
			t.Fatalf("ImageConfig() error = %v, want the failed save's", err)
		}
		if got, err := e.ImageConfig(t.Context(), t, "img"); err != nil || !sameConfig(got, wantConfig) {
			t.Errorf("ImageConfig() after a failed save = %+v, %v; want it saved again and read", got, err)
		}
		if n := saves.Load(); n != 2 {
			t.Errorf("podman save ran %d times, want twice: once failing, once again", n)
		}
	})

	// contract.Check asks for an engine of its own each time it runs, so
	// one kept for each engine would save the image for every Check.
	t.Run("shared-by-engines-from-the-environment", func(t *testing.T) {
		t.Parallel()

		a, err := EngineFromEnv()
		if err != nil {
			t.Fatal(err)
		}
		b, err := EngineFromEnv()
		if err != nil {
			t.Fatal(err)
		}
		if a.saves == nil || a.saves != b.saves {
			t.Errorf("two engines from EngineFromEnv keep what their saves read in %p and %p, want one place", a.saves, b.saves)
		}
	})
}

func TestBuild(t *testing.T) {
	t.Parallel()

	tests := []struct {
		engine string
		// format is what goes before the build arguments: Podman's default,
		// OCI, drops every HEALTHCHECK, the base image's own included.
		format []string
	}{
		{engine: "docker"},
		{engine: "podman", format: []string{"--format", "docker"}},
	}
	for _, tt := range tests {
		t.Run(tt.engine, func(t *testing.T) {
			t.Parallel()

			var ran [][]string
			e := newEngine(tt.engine, runFunc(func(argv []string) execx.Result {
				ran = append(ran, argv)
				if argv[1] == "build" {
					return execx.Result{Stdout: []byte("sha256:abc\n")}
				}
				return execx.Result{}
			}))

			var tag string
			// Registered before Build registers its own, so it runs after
			// the image is removed.
			t.Cleanup(func() {
				want := [][]string{
					slices.Concat(
						[]string{tt.engine, "build", "-q", "--label", ownLabel, "-t", tag, "-f", "testdata/mutant/Containerfile"},
						tt.format,
						[]string{"--build-arg", "A=1", "--build-arg", "B=2", "testdata/mutant"},
					),
					{tt.engine, "image", "rm", "-f", tag},
				}
				if !slices.EqualFunc(ran, want, slices.Equal) {
					t.Errorf("ran\n%q\nwant\n%q", ran, want)
				}
			})

			var err error
			tag, err = e.Build(t.Context(), t, "testdata/mutant/Containerfile", map[string]string{"B": "2", "A": "1"})
			if err != nil {
				t.Fatalf("Build() error = %v", err)
			}
			if !strings.HasPrefix(tag, "localhost/divbast-") || !strings.HasSuffix(tag, ":latest") {
				t.Errorf("Build() = %q, want a unique localhost/divbast-…:latest tag", tag)
			}
		})
	}
}

func TestBuildFails(t *testing.T) {
	t.Parallel()

	e := newEngine("docker", runFunc(func(argv []string) execx.Result {
		if argv[1] == "build" {
			return execx.Result{Code: 1, Stderr: []byte("ERROR: failed to solve: base name (${FIXTURE}) should not be blank")}
		}
		return execx.Result{Code: 1, Stderr: []byte("Error response from daemon: No such image: " + argv[len(argv)-1])}
	}))
	_, err := e.Build(t.Context(), t, "testdata/mutant/Containerfile", nil)
	if err == nil || !strings.Contains(err.Error(), "should not be blank") {
		t.Errorf("Build() error = %v, want the builder's own words", err)
	}
}

// capabilityPAX is the PAX record in which BuildKit and Buildah carry a
// file's security.capability extended attribute: cap_net_bind_service=ep,
// as setcap writes it.
const capabilityPAX = "SCHILY.xattr.security.capability"

var capabilityValue = string([]byte{1, 0, 0, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})

// entry is one file in a layer layerTar writes, with the PAX records it
// carries.
type entry struct {
	name string
	pax  map[string]string
}

// layerTar returns a layer holding entries, each an empty file.
func layerTar(t *testing.T, entries ...entry) []byte {
	t.Helper()
	var b bytes.Buffer
	w := tar.NewWriter(&b)
	for _, e := range entries {
		hdr := &tar.Header{Name: e.name, Mode: 0o755, Typeflag: tar.TypeReg, PAXRecords: e.pax, Format: tar.FormatPAX}
		if err := w.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// gzipped returns b compressed, as Docker's containerd store keeps a layer.
func gzipped(t *testing.T, b []byte) []byte {
	t.Helper()
	var out bytes.Buffer
	w := gzip.NewWriter(&out)
	if _, err := w.Write(b); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func TestLayerCapabilities(t *testing.T) {
	t.Parallel()

	capped := entry{"usr/local/bin/frankenphp", map[string]string{capabilityPAX: capabilityValue}}
	plain := entry{"usr/local/bin/other", nil}
	tests := []struct {
		name    string
		layer   []byte
		want    []string
		wantErr bool
	}{
		{name: "none", layer: layerTar(t, plain)},
		{name: "one", layer: layerTar(t, plain, capped), want: []string{"/usr/local/bin/frankenphp"}},
		{name: "gzip", layer: gzipped(t, layerTar(t, capped, plain)), want: []string{"/usr/local/bin/frankenphp"}},
		{
			// libarchive writes its own record beside SCHILY's, and either
			// alone carries the attribute
			name:  "libarchive",
			layer: layerTar(t, entry{"bin/ping", map[string]string{"LIBARCHIVE.xattr.security.capability": "AQAAAgAgAAA"}}),
			want:  []string{"/bin/ping"},
		},
		{
			// Another attribute is no capability
			name:  "selinux-label",
			layer: layerTar(t, entry{"etc/x", map[string]string{"SCHILY.xattr.security.selinux": "system_u:object_r:etc_t:s0"}}),
		},
		{name: "empty", layer: []byte{}},
		{
			// zstd, which the standard library cannot read: a layer that
			// cannot be read must not pass for one with nothing in it
			name:    "zstd",
			layer:   []byte{0x28, 0xb5, 0x2f, 0xfd, 0, 0, 0, 0},
			wantErr: true,
		},
		{name: "not-a-tar", layer: []byte(strings.Repeat("not a tar archive ", 40)), wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := layerCapabilities(bytes.NewReader(tt.layer))
			if tt.wantErr {
				if err == nil {
					t.Fatalf("layerCapabilities() = %q, nil; want an error", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("layerCapabilities() error = %v", err)
			}
			if !slices.Equal(got, tt.want) {
				t.Errorf("layerCapabilities() = %q, want %q", got, tt.want)
			}
		})
	}
}

// savedArchive is an image as either engine's save writes it, with
// configBlob as its configuration, named as Podman names it, and the
// layers given, named as Docker 29 names them.
func savedArchive(t *testing.T, layers ...[]byte) []byte {
	t.Helper()
	sum := sha256.Sum256([]byte(configBlob))
	configName := hex.EncodeToString(sum[:]) + ".json"
	files := []file{{configName, configBlob}}
	names := make([]string, len(layers))
	for i, l := range layers {
		names[i] = fmt.Sprintf("blobs/sha256/layer%d", i)
		files = append(files, file{names[i], string(l)})
	}
	manifest, err := json.Marshal([]map[string]any{{"Config": configName, "Layers": names}})
	if err != nil {
		t.Fatal(err)
	}
	return tarball(t, append(files, file{"manifest.json", string(manifest)})...)
}

func TestFileCapabilities(t *testing.T) {
	t.Parallel()

	capped := layerTar(t, entry{"usr/local/bin/frankenphp", map[string]string{capabilityPAX: capabilityValue}})
	plain := layerTar(t, entry{"etc/frankenphp/Caddyfile", nil})
	again := layerTar(t, entry{"usr/local/bin/frankenphp", map[string]string{capabilityPAX: capabilityValue}},
		entry{"usr/local/bin/helper", map[string]string{capabilityPAX: capabilityValue}})

	tests := []struct {
		name    string
		archive []byte
		want    []string
		wantErr string
	}{
		{name: "none", archive: savedArchive(t, plain, gzipped(t, plain))},
		{
			// In whichever layer, sorted, and each path once
			name:    "found",
			archive: savedArchive(t, plain, gzipped(t, capped), again),
			want:    []string{"/usr/local/bin/frankenphp", "/usr/local/bin/helper"},
		},
		{
			name: "a-layer-missing",
			archive: tarball(t, file{"blobs/sha256/config", configBlob},
				file{"manifest.json", `[{"Config":"blobs/sha256/config","Layers":["blobs/sha256/gone"]}]`}),
			wantErr: "does not hold",
		},
		{
			name:    "a-layer-it-cannot-read",
			archive: savedArchive(t, plain, []byte{0x28, 0xb5, 0x2f, 0xfd, 0, 0, 0, 0}),
			wantErr: "zstd",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Docker saves by the ID it gives, which with its containerd
			// store is the index's digest, not the configuration's.
			e := newEngine("docker", runFunc(func(argv []string) execx.Result {
				switch {
				case slices.Equal(argv, []string{"docker", "image", "inspect", "--format", "{{.Id}}", "img"}):
					return execx.Result{Stdout: []byte("sha256:abc\n")}
				case len(argv) == 5 && slices.Equal(argv[:3], []string{"docker", "save", "-o"}) && argv[4] == "sha256:abc":
					if err := os.WriteFile(argv[3], tt.archive, 0o600); err != nil {
						t.Errorf("writing the archive: %v", err)
						return execx.Result{Code: 1}
					}
					return execx.Result{}
				default:
					t.Errorf("unexpected command %q", argv)
					return execx.Result{Code: 125}
				}
			}))
			got, err := e.FileCapabilities(t.Context(), t, "img")
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("FileCapabilities() = %q, %v; want an error saying %q", got, err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("FileCapabilities() error = %v", err)
			}
			if !slices.Equal(got, tt.want) {
				t.Errorf("FileCapabilities() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestOneSaveForBoth shows Podman saving an image once for its
// configuration and its layers' capabilities alike, whichever is asked
// for first, and Docker saving it once for the capabilities, which is all
// it saves for.
func TestOneSaveForBoth(t *testing.T) {
	t.Parallel()

	sum := sha256.Sum256([]byte(configBlob))
	id := hex.EncodeToString(sum[:])
	capped := layerTar(t, entry{"usr/local/bin/frankenphp", map[string]string{capabilityPAX: capabilityValue}})
	archive := savedArchive(t, capped)

	for _, capsFirst := range []bool{false, true} {
		t.Run(fmt.Sprintf("caps-first=%t", capsFirst), func(t *testing.T) {
			t.Parallel()

			var saves atomic.Int32
			save := podmanSaving(t, id, archive)
			e := newEngine("podman", runFunc(func(argv []string) execx.Result {
				if argv[1] == "save" {
					saves.Add(1)
				}
				return save(argv)
			}))
			caps := func() {
				if got, err := e.FileCapabilities(t.Context(), t, "img"); err != nil || !slices.Equal(got, []string{"/usr/local/bin/frankenphp"}) {
					t.Errorf("FileCapabilities() = %q, %v", got, err)
				}
			}
			config := func() {
				if got, err := e.ImageConfig(t.Context(), t, "img"); err != nil || !sameConfig(got, wantConfig) {
					t.Errorf("ImageConfig() = %+v, %v; want %+v", got, err, wantConfig)
				}
			}
			if capsFirst {
				caps()
				config()
			} else {
				config()
				caps()
			}
			caps()
			if n := saves.Load(); n != 1 {
				t.Errorf("podman save ran %d times for one image, want once", n)
			}
		})
	}
}
