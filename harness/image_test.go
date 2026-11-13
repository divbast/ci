// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

package harness

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
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
	if a.User != b.User || (a.Healthcheck == nil) != (b.Healthcheck == nil) {
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
		if a.configs == nil || a.configs != b.configs {
			t.Errorf("two engines from EngineFromEnv keep configurations in %p and %p, want one place", a.configs, b.configs)
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
