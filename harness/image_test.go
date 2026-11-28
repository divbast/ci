// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

package harness

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
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
	Architecture: "arm64",
	User:         "65532:65532",
	Healthcheck: &Healthcheck{
		Test:     []string{"CMD", "/usr/local/bin/frankenphp", "php-cli", "/x"},
		Interval: 30 * time.Second, Timeout: 10 * time.Second, StartPeriod: time.Minute, Retries: 3,
	},
}

// sameConfig reports whether two configurations say the same thing.
func sameConfig(a, b Config) bool {
	if a.Architecture != b.Architecture || a.User != b.User || (a.Healthcheck == nil) != (b.Healthcheck == nil) || !maps.Equal(a.Volumes, b.Volumes) {
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
	inspect := []string{"docker", "image", "inspect", "--format", `{"architecture":{{json .Architecture}},"config":{{json .Config}}}`, "img"}
	pull := []string{"docker", "pull", "-q", "img"}
	absent := execx.Result{Code: 1, Stderr: []byte("Error response from daemon: No such image: img")}
	config := execx.Result{Stdout: []byte(`{"architecture":"arm64","config":{"User":"65532:65532","Healthcheck":{"Test":["CMD","/usr/local/bin/frankenphp","php-cli","/x"],` +
		`"Interval":30000000000,"Timeout":10000000000,"StartPeriod":60000000000,"Retries":3}}}` + "\n")}

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

// TestImageConfigPullsAgain pulls an image that is not here again, 5 s
// later, while the registry answers the pull with a server error, which
// neither engine retries itself when it is a 500, and says so in the
// test's log: up to three pulls in all. Any other failure ends it at once.
func TestImageConfigPullsAgain(t *testing.T) {
	t.Parallel()

	id := []string{"docker", "image", "inspect", "--format", "{{.Id}}", "img"}
	inspect := []string{"docker", "image", "inspect", "--format", `{"architecture":{{json .Architecture}},"config":{{json .Config}}}`, "img"}
	pull := []string{"docker", "pull", "-q", "img"}
	absent := execx.Result{Code: 1, Stderr: []byte("Error response from daemon: No such image: img\n")}
	here := execx.Result{Stdout: []byte("sha256:abc\n")}
	config := execx.Result{Stdout: []byte(`{"architecture":"arm64","config":{"User":"65532:65532"}}` + "\n")}
	pulled := execx.Result{Stdout: []byte("img\n")}
	// As Docker's daemon passes on a blob request that ghcr.io failed
	serverError := func(status string) execx.Result {
		return execx.Result{Code: 1, Stderr: []byte("Error response from daemon: failed to copy: httpReadSeeker: failed open: unexpected status code " +
			"https://ghcr.io/v2/divbast/librespeed/blobs/sha256:dd64bf2dd177757451a98fcdc999a339c35dee5d9872d8f4dc69c8f3c4dd0112: " + status + "\n")}
	}
	unknown := execx.Result{Code: 1, Stderr: []byte("Error response from daemon: manifest unknown\n")}

	for _, tt := range []struct {
		name      string
		pulls     []execx.Result
		wantErr   string
		wantAgain int
	}{
		{name: "after-a-500", pulls: []execx.Result{serverError("500 Internal Server Error"), pulled}, wantAgain: 1},
		{name: "after-a-502-and-a-500", pulls: []execx.Result{serverError("502 Bad Gateway"), serverError("500 Internal Server Error"), pulled}, wantAgain: 2},
		{
			name:      "server-errors-throughout",
			pulls:     []execx.Result{serverError("500 Internal Server Error"), serverError("503 Service Unavailable"), serverError("500 Internal Server Error")},
			wantErr:   "pulling it failed: docker pull -q img, attempt 3 of 3: exit status 1: Error response from daemon: failed to copy",
			wantAgain: 2,
		},
		{name: "manifest-unknown", pulls: []execx.Result{unknown}, wantErr: "pulling it failed: docker pull -q img, attempt 1 of 3: exit status 1: Error response from daemon: manifest unknown"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			synctest.Test(t, func(t *testing.T) {
				calls := []execx.Call{{Argv: id, Result: absent}}
				for _, res := range tt.pulls {
					calls = append(calls, execx.Call{Argv: pull, Result: res})
				}
				if tt.wantErr == "" {
					calls = append(calls, execx.Call{Argv: id, Result: here}, execx.Call{Argv: inspect, Result: config})
				}
				tb := &fakeTB{TB: t}
				start := time.Now()
				got, err := newEngine("docker", execx.NewFake(t, calls...)).ImageConfig(t.Context(), tb, "img")

				if took, want := time.Since(start), time.Duration(tt.wantAgain)*5*time.Second; took != want {
					t.Errorf("ImageConfig() took %s, want %s: 5 s before each pull again", took, want)
				}
				again := 0
				for _, l := range tb.logs {
					if strings.Contains(l, "docker pull -q img") && strings.Contains(l, "so fetching again in 5s") {
						again++
					}
				}
				if again != tt.wantAgain {
					t.Errorf("ImageConfig() logged %d pulls again, want %d: %q", again, tt.wantAgain, tb.logs)
				}
				if tt.wantErr != "" {
					if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
						t.Errorf("ImageConfig() error = %v, want one holding %q", err, tt.wantErr)
					}
					return
				}
				if err != nil || got.User != "65532:65532" {
					t.Errorf("ImageConfig() = %+v, %v; want the user 65532:65532, nil", got, err)
				}
			})
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
	const noHealthcheck = `{"architecture":"amd64","config":{"User":"0:0"}}`
	const volume = `{"architecture":"arm64","config":{"User":"65532:65532","Volumes":{"/data":{}}}}`

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
			want: Config{Architecture: "amd64", User: "0:0"},
		},
		{
			name: "volume", id: digest(volume), archive: archive(volume),
			want: Config{Architecture: "arm64", User: "65532:65532", Volumes: map[string]struct{}{"/data": {}}},
		},
		{
			// Why the configuration could not be found, not merely that it
			// was not
			name: "config-missing", id: digest(configBlob),
			archive: tarball(t, file{"l1.tar", "a layer"},
				file{"manifest.json", `[{"Config":"` + digest(configBlob) + `.json","RepoTags":[],"Layers":["l1.tar"]}]`}),
			wantErr: "which the archive does not hold",
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

// TestImageConfigReturnsACopy changes the configuration ImageConfig
// returned, its volumes and its healthcheck's command, then reads the
// image's again (backlog CI-20). What the save cache holds is the image's
// own, so no check's change to what it was given reaches the next check
// that asks.
func TestImageConfigReturnsACopy(t *testing.T) {
	t.Parallel()

	const blob = `{"config":{"User":"65532:65532","Volumes":{"/data":{}},"Healthcheck":{"Test":["CMD","/probe"]}}}`
	sum := sha256.Sum256([]byte(blob))
	id := hex.EncodeToString(sum[:])
	archive := tarball(t, file{"l1.tar", "a layer"}, file{id + ".json", blob},
		file{"manifest.json", `[{"Config":"` + id + `.json","RepoTags":[],"Layers":["l1.tar"]}]`})
	e := newEngine("podman", podmanSaving(t, id, archive))
	want := Config{User: "65532:65532", Volumes: map[string]struct{}{"/data": {}}, Healthcheck: &Healthcheck{Test: []string{"CMD", "/probe"}}}

	got, err := e.ImageConfig(t.Context(), t, "img")
	if err != nil || !sameConfig(got, want) {
		t.Fatalf("ImageConfig() = %+v, %v; want %+v", got, err, want)
	}
	got.Volumes["/elsewhere"] = struct{}{}
	delete(got.Volumes, "/data")
	got.Healthcheck.Test[1] = "/another"
	got.Healthcheck.Retries = 9

	again, err := e.ImageConfig(t.Context(), t, "img")
	if err != nil {
		t.Fatal(err)
	}
	if !sameConfig(again, want) {
		t.Errorf("ImageConfig() after a change to what it returned = %+v, healthcheck %+v; want %+v, healthcheck %+v",
			again, again.Healthcheck, want, want.Healthcheck)
	}
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
						[]string{tt.engine, "build", "-q", "--label", ownLabel, "--label", ownRun, "-t", tag, "-f", "testdata/mutant/Containerfile"},
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

// zstdFrameMagic opens every zstd frame, and so every zstd layer.
var zstdFrameMagic = []byte{0x28, 0xb5, 0x2f, 0xfd}

func TestLayerCapabilities(t *testing.T) {
	t.Parallel()

	capped := entry{"usr/local/bin/frankenphp", map[string]string{capabilityPAX: capabilityValue}}
	plain := entry{"usr/local/bin/other", nil}
	// A zstd layer, every layer of a Docker Hardened Image among them, as
	// zstd is fed it, and what zstd writes back
	zstdLayer := slices.Concat(zstdFrameMagic, []byte("compressed"))
	unzstd := func(res execx.Result) []execx.Call {
		return []execx.Call{{Argv: []string{"zstd", "-dcq"}, Stdin: zstdLayer, Result: res}}
	}
	tests := []struct {
		name  string
		layer []byte
		// zstd is every run of the zstd command the layer takes
		zstd    []execx.Call
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
			// Read through the zstd command, fed the layer on its stdin
			name:  "zstd",
			layer: zstdLayer,
			zstd:  unzstd(execx.Result{Stdout: layerTar(t, plain, capped)}),
			want:  []string{"/usr/local/bin/frankenphp"},
		},
		{
			// The tar ends before what zstd writes does, as GNU tar pads
			// an archive out to a whole record: zstd still runs to its end
			name:  "zstd-padded-past-the-tar",
			layer: zstdLayer,
			zstd:  unzstd(execx.Result{Stdout: slices.Concat(layerTar(t, capped), make([]byte, 20<<10))}),
			want:  []string{"/usr/local/bin/frankenphp"},
		},
		{
			// zstd failing after a whole tar is still a layer it could
			// not read, never one with that tar's files alone
			name:    "zstd-fails",
			layer:   zstdLayer,
			zstd:    unzstd(execx.Result{Stdout: layerTar(t, plain), Stderr: []byte("zstd: corrupted block"), Code: 1}),
			wantErr: true,
		},
		{name: "not-a-tar", layer: []byte(strings.Repeat("not a tar archive ", 40)), wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := layerCapabilities(t.Context(), execx.NewFake(t, tt.zstd...), bytes.NewReader(tt.layer))
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

	// A zstd layer as Docker's containerd store saves it, every layer of
	// a Docker Hardened Image among them: what zstd is fed. The zstd the
	// engine runs writes capped back.
	zstdLayer := slices.Concat(zstdFrameMagic, []byte("compressed"))

	tests := []struct {
		name    string
		archive []byte
		// noZstd runs on a host with no zstd command
		noZstd  bool
		want    []string
		wantErr []string
	}{
		{name: "none", archive: savedArchive(t, plain, gzipped(t, plain))},
		{
			// In whichever layer, sorted, and each path once
			name:    "found",
			archive: savedArchive(t, plain, gzipped(t, capped), again),
			want:    []string{"/usr/local/bin/frankenphp", "/usr/local/bin/helper"},
		},
		{
			name:    "zstd",
			archive: savedArchive(t, plain, zstdLayer),
			want:    []string{"/usr/local/bin/frankenphp"},
		},
		{
			name: "a-layer-missing",
			archive: tarball(t, file{"blobs/sha256/config", configBlob},
				file{"manifest.json", `[{"Config":"blobs/sha256/config","Layers":["blobs/sha256/gone"]}]`}),
			wantErr: []string{"does not hold"},
		},
		{
			name:    "a-layer-it-cannot-read",
			archive: savedArchive(t, plain, []byte(strings.Repeat("not a tar archive ", 40))),
			wantErr: []string{"blobs/sha256/layer1"},
		},
		{
			// Never a layer with nothing in it: the error names the layer,
			// and the command it needs
			name:    "zstd-with-no-zstd-command",
			archive: savedArchive(t, plain, zstdLayer),
			noZstd:  true,
			wantErr: []string{"the layer blobs/sha256/layer1", "zstd -dcq", "a zstd blob needs the zstd command on PATH"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Docker saves by the ID it gives, which with its containerd
			// store is the index's digest, not the configuration's.
			run := runFunc(func(argv []string) execx.Result {
				switch {
				case slices.Equal(argv, []string{"docker", "image", "inspect", "--format", "{{.Id}}", "img"}):
					return execx.Result{Stdout: []byte("sha256:abc\n")}
				case len(argv) == 5 && slices.Equal(argv[:3], []string{"docker", "save", "-o"}) && argv[4] == "sha256:abc":
					if err := os.WriteFile(argv[3], tt.archive, 0o600); err != nil {
						t.Errorf("writing the archive: %v", err)
						return execx.Result{Code: 1}
					}
					return execx.Result{}
				case slices.Equal(argv, []string{"zstd", "-dcq"}):
					return execx.Result{Stdout: capped}
				default:
					t.Errorf("unexpected command %q", argv)
					return execx.Result{Code: 125}
				}
			})
			e := newEngine("docker", run)
			if tt.noZstd {
				e = newEngine("docker", withoutZstd{run})
			}
			got, err := e.FileCapabilities(t.Context(), t, "img")
			if tt.wantErr != nil {
				if err == nil {
					t.Fatalf("FileCapabilities() = %q, nil; want an error saying %q", got, tt.wantErr)
				}
				for _, want := range tt.wantErr {
					if !strings.Contains(err.Error(), want) {
						t.Errorf("FileCapabilities() error = %v, want one saying %q", err, want)
					}
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

// liveZstd is a runFunc whose zstd runs only while its context lives, as
// execx.OS's does: once the context is done, it runs nothing and says why.
type liveZstd struct{ runFunc }

func (l liveZstd) RunStream(ctx context.Context, stdin io.Reader, stdout io.Writer, name string, args ...string) (execx.Result, error) {
	if err := ctx.Err(); err != nil {
		return execx.Result{}, fmt.Errorf("run %s: %w", name, err)
	}
	return l.runFunc.RunStream(ctx, stdin, stdout, name, args...)
}

// TestFileCapabilitiesRetriesACancelledRead has the first caller's
// context end while zstd reads a layer, cancelled or past its deadline,
// and shows that read kept for no one: it says nothing about the image,
// so the next caller, whose context lives, saves the image again and
// reads its layers through.
func TestFileCapabilitiesRetriesACancelledRead(t *testing.T) {
	t.Parallel()

	capped := layerTar(t, entry{"usr/local/bin/frankenphp", map[string]string{capabilityPAX: capabilityValue}})
	archive := savedArchive(t, slices.Concat(zstdFrameMagic, []byte("compressed")))
	for _, tt := range []struct {
		name string
		// ends returns the first caller's context, and what ends it once
		// the image is saved, before zstd reads its layer
		ends func(*testing.T) (context.Context, func())
		want error
	}{
		{
			name: "cancelled",
			ends: func(t *testing.T) (context.Context, func()) {
				t.Helper()
				ctx, cancel := context.WithCancel(t.Context())
				t.Cleanup(cancel)
				return ctx, cancel
			},
			want: context.Canceled,
		},
		{
			// Past it from the start: of the commands here, only zstd
			// looks, as only it would run long
			name: "past-its-deadline",
			ends: func(t *testing.T) (context.Context, func()) {
				t.Helper()
				ctx, cancel := context.WithDeadline(t.Context(), time.Unix(0, 0))
				t.Cleanup(cancel)
				return ctx, func() {}
			},
			want: context.DeadlineExceeded,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctx, end := tt.ends(t)
			var saves atomic.Int32
			e := newEngine("docker", liveZstd{func(argv []string) execx.Result {
				switch {
				case slices.Equal(argv, []string{"docker", "image", "inspect", "--format", "{{.Id}}", "img"}):
					return execx.Result{Stdout: []byte("sha256:abc\n")}
				case len(argv) == 5 && slices.Equal(argv[:3], []string{"docker", "save", "-o"}) && argv[4] == "sha256:abc":
					if err := os.WriteFile(argv[3], archive, 0o600); err != nil {
						t.Errorf("writing the archive: %v", err)
						return execx.Result{Code: 1}
					}
					saves.Add(1)
					end()
					return execx.Result{}
				case slices.Equal(argv, []string{"zstd", "-dcq"}):
					return execx.Result{Stdout: capped}
				default:
					t.Errorf("unexpected command %q", argv)
					return execx.Result{Code: 125}
				}
			}})

			if got, err := e.FileCapabilities(ctx, t, "img"); !errors.Is(err, tt.want) {
				t.Fatalf("FileCapabilities() with its context ended mid-read = %q, %v; want %v", got, err, tt.want)
			}
			got, err := e.FileCapabilities(t.Context(), t, "img")
			if err != nil || !slices.Equal(got, []string{"/usr/local/bin/frankenphp"}) {
				t.Errorf("FileCapabilities() after a cut-short read = %q, %v; want the layer read again, and its capability found", got, err)
			}
			if n := saves.Load(); n != 2 {
				t.Errorf("docker save ran %d times, want twice: a read a context cut short is never kept", n)
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
