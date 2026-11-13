// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

package harness

import (
	"archive/tar"
	"bufio"
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
	"path"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
)

// ImageConfig returns the user, the HEALTHCHECK and the volumes image
// declares, as its own configuration holds them, pulling it first if it is
// not here.
//
// Docker's image inspect reads all three from that configuration.
// Podman's reads a health check only from an image whose manifest is
// Docker's, and never from one published as OCI, so on Podman they come
// from the configuration blob itself, out of podman save, checked against
// the image ID, which is that blob's digest.
func (e Engine) ImageConfig(ctx context.Context, tb testing.TB, image string) (Config, error) {
	tb.Helper()
	id, err := e.imageID(ctx, image)
	if err != nil {
		return Config{}, err
	}
	if e.name == "podman" {
		return e.savedConfig(ctx, tb, image, id)
	}

	out, err := e.output(ctx, "image", "inspect", "--format", "{{json .Config}}", image)
	if err != nil {
		return Config{}, err
	}
	var cfg Config
	if err := json.Unmarshal(out, &cfg); err != nil {
		return Config{}, fmt.Errorf("%s image inspect %s printed what is not a configuration: %w", e.name, image, err)
	}
	return cfg, nil
}

// imageID returns image's ID, pulling it first if it is not here.
func (e Engine) imageID(ctx context.Context, image string) (string, error) {
	inspect := []string{"image", "inspect", "--format", "{{.Id}}", image}
	out, err := e.output(ctx, inspect...)
	if err != nil {
		if _, perr := e.output(ctx, "pull", "-q", image); perr != nil {
			return "", fmt.Errorf("image %s is not here (%w), and pulling it failed: %w", image, err, perr)
		}
		if out, err = e.output(ctx, inspect...); err != nil {
			return "", err
		}
	}
	return strings.TrimSpace(string(out)), nil
}

// FileCapabilities returns the path of every file in image's layers that
// carries a security.capability extended attribute, sorted and each once,
// pulling the image first if it is not here. It reads the layers as the
// engine saves them, and runs nothing, so it sees what no exec can: a
// capability with no effective bit, which the kernel runs as it would any
// other binary, and one on a file nothing runs. A file counts in whichever
// layer holds it, even one a later layer replaces or removes, since that
// layer ships in the image all the same.
//
// A layer it cannot read is an error, never a layer with nothing in it:
// one compressed with zstd, say, which the standard library cannot read.
func (e Engine) FileCapabilities(ctx context.Context, tb testing.TB, image string) ([]string, error) {
	tb.Helper()
	id, err := e.imageID(ctx, image)
	if err != nil {
		return nil, err
	}
	read, err := e.saved(ctx, tb, image, id)
	if err != nil {
		return nil, err
	}
	if read.capsErr != nil {
		return nil, fmt.Errorf("%s save of %s: %w", e.name, image, read.capsErr)
	}
	return slices.Clone(read.caps), nil
}

// saveCache holds what each save has read, by image ID, so an image is
// saved once however often it is asked about: a save writes out the whole
// image. An ID names one image for good, since it is a digest: of its
// configuration on Podman, and of its manifest or index on Docker's
// containerd store.
type saveCache struct {
	mu  sync.Mutex
	ids map[string]*savedImage
}

// savedImage is one image's place in a saveCache. Its lock is held while
// the image is saved, so a check that wants it meanwhile waits for that
// save rather than making another.
type savedImage struct {
	mu   sync.Mutex
	read *saveRead
}

// saveRead is what one save of an image held.
type saveRead struct {
	// cfg is the image's configuration, unless cfgErr says why it could
	// not be read: on Podman only, whose ID for an image is its digest.
	// Docker's image inspect reads it instead.
	cfg    Config
	cfgErr error
	// caps holds the files in its layers that carry a file capability,
	// unless capsErr says why they could not be read.
	caps    []string
	capsErr error
}

func newSaveCache() *saveCache {
	return &saveCache{ids: make(map[string]*savedImage)}
}

// sharedSaves is what every engine EngineFromEnv returns keeps what its
// saves read in: a suite asks it for an engine as often as it likes, and
// contract.Check asks for one each time it runs.
var sharedSaves = newSaveCache()

// image returns the place of the image with ID id, making it if need be.
func (c *saveCache) image(id string) *savedImage {
	c.mu.Lock()
	defer c.mu.Unlock()
	s, ok := c.ids[id]
	if !ok {
		s = &savedImage{}
		c.ids[id] = s
	}
	return s
}

// savedConfig returns the configuration of the image with ID id, out of
// Podman's docker-archive of it.
func (e Engine) savedConfig(ctx context.Context, tb testing.TB, image, id string) (Config, error) {
	tb.Helper()
	read, err := e.saved(ctx, tb, image, id)
	if err != nil {
		return Config{}, err
	}
	if read.cfgErr != nil {
		return Config{}, read.cfgErr
	}
	return read.cfg.clone(), nil
}

// saved returns what a save of the image with ID id holds, saving it only
// the first time it is asked for that ID. A save that failed is tried
// again the next time.
func (e Engine) saved(ctx context.Context, tb testing.TB, image, id string) (*saveRead, error) {
	tb.Helper()
	if e.saves == nil {
		return e.save(ctx, tb, image, id)
	}
	saved := e.saves.image(id)
	saved.mu.Lock()
	defer saved.mu.Unlock()
	if saved.read == nil {
		read, err := e.save(ctx, tb, image, id)
		if err != nil {
			return nil, err
		}
		saved.read = read
	}
	return saved.read, nil
}

// clone returns a copy of c that shares nothing with it, for a caller to
// change as it likes.
func (c Config) clone() Config {
	if c.Healthcheck != nil {
		hc := *c.Healthcheck
		hc.Test = slices.Clone(hc.Test)
		c.Healthcheck = &hc
	}
	c.Volumes = maps.Clone(c.Volumes)
	return c
}

// save is saved, saving the image every time: Podman as a docker-archive,
// which Docker's save writes without being asked, beside an OCI layout.
func (e Engine) save(ctx context.Context, tb testing.TB, image, id string) (*saveRead, error) {
	tb.Helper()
	dir := tb.TempDir()
	argv := []string{"save", "-o", filepath.Join(dir, "image.tar"), id}
	if e.name == "podman" {
		argv = []string{"save", "-q", "--format", "docker-archive", "-o", filepath.Join(dir, "image.tar"), id}
	}
	if _, err := e.output(ctx, argv...); err != nil {
		return nil, err
	}
	blob, blobErr, read, err := readSave(dir, "image.tar")
	if err != nil {
		return nil, fmt.Errorf("%s save of %s: %w", e.name, image, err)
	}
	switch {
	case e.name != "podman":
	case blobErr != nil:
		read.cfgErr = fmt.Errorf("%s save of %s: %w", e.name, image, blobErr)
	default:
		read.cfg, read.cfgErr = savedImageConfig(blob, image, id)
	}
	return read, nil
}

// savedImageConfig returns the configuration in blob, which a save of
// image held, unless blob has some other digest than id, the image's ID
// on Podman, or is not a configuration at all.
func savedImageConfig(blob []byte, image, id string) (Config, error) {
	sum := sha256.Sum256(blob)
	if got, want := hex.EncodeToString(sum[:]), strings.TrimPrefix(id, "sha256:"); got != want {
		return Config{}, fmt.Errorf("the save of %s holds a configuration whose digest, %s, is not its ID, %s", image, got, want)
	}
	var doc struct {
		Config Config `json:"config"`
	}
	if err := json.Unmarshal(blob, &doc); err != nil {
		return Config{}, fmt.Errorf("the configuration of %s: %w", image, err)
	}
	return doc.Config, nil
}

// readSave reads the docker-archive file name, in dir, for its
// configuration blob, unless blobErr says why it could not, and the file
// capabilities in its layers. Only Podman's save is read for its
// configuration: Docker 29 names its own with no .json, and readIndex
// keeps none that lacks one. It reads the file twice, since
// manifest.json, which names the rest, may come last, as Podman writes it.
func readSave(dir, name string) (blob []byte, blobErr error, read *saveRead, err error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, nil, nil, err
	}
	defer func() { err = errors.Join(err, root.Close()) }()
	f, err := root.Open(name)
	if err != nil {
		return nil, nil, nil, err
	}
	defer func() { err = errors.Join(err, f.Close()) }()

	idx, err := readIndex(f)
	if err != nil {
		return nil, nil, nil, err
	}
	blob, blobErr = idx.configBlob()
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, nil, nil, err
	}
	read = &saveRead{}
	read.caps, read.capsErr = archiveCapabilities(f, idx.layers)
	return blob, blobErr, read, nil
}

// maxConfig bounds what readIndex keeps of any one file: an image's
// configuration and the archive's manifest are a few kilobytes, and a
// layer is never kept at all.
const maxConfig = 1 << 20

// archiveIndex is what the first read of a docker-archive found: the one
// image its manifest.json describes, and the small JSON files it holds.
type archiveIndex struct {
	// configPath is the image's configuration's place in the archive,
	// and layers its layers', in order.
	configPath string
	layers     []string
	small      map[string][]byte
}

// readIndex reads a docker-archive, as podman save and docker save write
// it, for its manifest.json, which may come last, and the small JSON files
// beside it.
func readIndex(r io.Reader) (archiveIndex, error) {
	small := make(map[string][]byte)
	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return archiveIndex{}, fmt.Errorf("reading the archive: %w", err)
		}
		if hdr.Typeflag != tar.TypeReg || hdr.Size > maxConfig || path.Ext(hdr.Name) != ".json" {
			continue
		}
		body, err := io.ReadAll(tr)
		if err != nil {
			return archiveIndex{}, fmt.Errorf("reading %s from the archive: %w", hdr.Name, err)
		}
		small[path.Clean(hdr.Name)] = body
	}

	raw, ok := small["manifest.json"]
	if !ok {
		return archiveIndex{}, fmt.Errorf("the archive has no manifest.json, among %q", slices.Sorted(maps.Keys(small)))
	}
	var manifest []struct {
		Config string
		Layers []string
	}
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return archiveIndex{}, fmt.Errorf("the archive's manifest.json: %w", err)
	}
	if len(manifest) != 1 {
		return archiveIndex{}, fmt.Errorf("the archive's manifest.json describes %d images, want 1", len(manifest))
	}
	layers := make([]string, len(manifest[0].Layers))
	for i, l := range manifest[0].Layers {
		layers[i] = path.Clean(l)
	}
	return archiveIndex{configPath: path.Clean(manifest[0].Config), layers: layers, small: small}, nil
}

// configBlob returns the configuration blob the archive's manifest names.
func (a archiveIndex) configBlob() ([]byte, error) {
	blob, ok := a.small[a.configPath]
	if !ok {
		return nil, fmt.Errorf("the archive's manifest.json names the configuration %q, which the archive does not hold", a.configPath)
	}
	return blob, nil
}

// archiveConfig returns the configuration blob of the one image in a
// docker-archive.
func archiveConfig(r io.Reader) ([]byte, error) {
	idx, err := readIndex(r)
	if err != nil {
		return nil, err
	}
	return idx.configBlob()
}

// archiveCapabilities returns the path of every file in layers, entries
// of the docker-archive r, that carries a file capability, sorted and each
// once. A layer the archive lacks is an error, as is one it cannot read.
func archiveCapabilities(r io.Reader, layers []string) ([]string, error) {
	want := make(map[string]bool, len(layers))
	for _, l := range layers {
		want[l] = true
	}
	seen := make(map[string]bool, len(layers))
	var caps []string
	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("reading the archive: %w", err)
		}
		name := path.Clean(hdr.Name)
		if !want[name] || seen[name] {
			continue
		}
		// Docker before 25 saved a layer that repeats one before it as a
		// link to that one: no Docker since does, nor any Podman.
		if hdr.Typeflag != tar.TypeReg {
			return nil, fmt.Errorf("the layer %s is not a regular file, the one kind of layer this reads", name)
		}
		found, err := layerCapabilities(tr)
		if err != nil {
			return nil, fmt.Errorf("the layer %s: %w", name, err)
		}
		caps = append(caps, found...)
		seen[name] = true
	}
	for _, l := range layers {
		if !seen[l] {
			return nil, fmt.Errorf("the archive's manifest.json names the layer %q, which the archive does not hold", l)
		}
	}
	slices.Sort(caps)
	return slices.Compact(caps), nil
}

// fileCapabilityRecord ends the name of the PAX record in which a tar
// carries a file's security.capability extended attribute: SCHILY.xattr.,
// as BuildKit, Buildah and Go write it, or libarchive's LIBARCHIVE.xattr.
// with its value in base64.
const fileCapabilityRecord = ".xattr.security.capability"

// gzipMagic and zstdMagic open a layer compressed with gzip or zstd.
var (
	gzipMagic = []byte{0x1f, 0x8b}
	zstdMagic = []byte{0x28, 0xb5, 0x2f, 0xfd}
)

// layerCapabilities returns the path of every file in the layer r that
// carries a file capability, in the layer's order. r is the layer as the
// archive holds it: a tar, or one compressed with gzip, as Docker's
// containerd store keeps a layer.
func layerCapabilities(r io.Reader) (caps []string, err error) {
	br := bufio.NewReader(r)
	magic, err := br.Peek(len(zstdMagic))
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	var layer io.Reader = br
	switch {
	case bytes.HasPrefix(magic, zstdMagic):
		return nil, errors.New("it is compressed with zstd, which this cannot read")
	case bytes.HasPrefix(magic, gzipMagic):
		zr, err := gzip.NewReader(br)
		if err != nil {
			return nil, err
		}
		defer func() { err = errors.Join(err, zr.Close()) }()
		layer = zr
	}
	tr := tar.NewReader(layer)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return caps, nil
		}
		if err != nil {
			return nil, err
		}
		for key := range hdr.PAXRecords {
			if strings.HasSuffix(key, fileCapabilityRecord) {
				caps = append(caps, path.Clean("/"+hdr.Name))
				break
			}
		}
	}
}

// Build builds containerfile, with its directory as the context and args
// as build arguments, into an image of a unique tag, which it returns, and
// has tb's cleanup remove the image.
//
// Podman builds in Docker's format: its default, OCI, has no place for a
// HEALTHCHECK, and drops the one the base image declares as well as any
// of the Containerfile's own.
func (e Engine) Build(ctx context.Context, tb testing.TB, containerfile string, args map[string]string) (string, error) {
	tb.Helper()
	tag := "localhost/" + uniqueName() + ":latest"
	argv := []string{"build", "-q", "--label", e.label, "-t", tag, "-f", containerfile}
	if e.name == "podman" {
		argv = append(argv, "--format", "docker")
	}
	for _, k := range slices.Sorted(maps.Keys(args)) {
		argv = append(argv, "--build-arg", k+"="+args[k])
	}
	argv = append(argv, filepath.Dir(containerfile))

	// Registered before the build, which may leave the tag behind although
	// it failed.
	e.removeOnCleanup(ctx, tb, "image", "rm", "-f", tag)
	if _, err := e.output(ctx, argv...); err != nil {
		return "", err
	}
	return tag, nil
}
