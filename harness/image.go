// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

package harness

import (
	"archive/tar"
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
	"testing"
)

// ImageConfig returns the user and the HEALTHCHECK image declares, as its
// own configuration holds them, pulling it first if it is not here.
//
// Docker's image inspect reads both from that configuration. Podman's
// reads a health check only from an image whose manifest is Docker's, and
// never from one published as OCI, so on Podman they come from the
// configuration blob itself, out of podman save, checked against the
// image ID, which is that blob's digest.
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

// savedConfig returns the configuration of the image with ID id, out of
// Podman's docker-archive of it.
func (e Engine) savedConfig(ctx context.Context, tb testing.TB, image, id string) (Config, error) {
	tb.Helper()
	dir := tb.TempDir()
	if _, err := e.output(ctx, "save", "-q", "--format", "docker-archive", "-o", filepath.Join(dir, "image.tar"), id); err != nil {
		return Config{}, err
	}
	blob, err := archiveFileConfig(dir, "image.tar")
	if err != nil {
		return Config{}, fmt.Errorf("%s save of %s: %w", e.name, image, err)
	}

	sum := sha256.Sum256(blob)
	if got, want := hex.EncodeToString(sum[:]), strings.TrimPrefix(id, "sha256:"); got != want {
		return Config{}, fmt.Errorf("%s save of %s holds a configuration whose digest, %s, is not its ID, %s", e.name, image, got, want)
	}
	var doc struct {
		Config Config `json:"config"`
	}
	if err := json.Unmarshal(blob, &doc); err != nil {
		return Config{}, fmt.Errorf("the configuration of %s: %w", image, err)
	}
	return doc.Config, nil
}

// archiveFileConfig returns the configuration blob in the docker-archive
// file name, in dir.
func archiveFileConfig(dir, name string) (blob []byte, err error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, root.Close()) }()
	f, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, f.Close()) }()
	return archiveConfig(f)
}

// maxConfig bounds what archiveConfig keeps of any one file: an image's
// configuration and the archive's manifest are a few kilobytes, and a
// layer is never kept at all.
const maxConfig = 1 << 20

// archiveConfig returns the configuration blob of the one image in a
// docker-archive, as podman save and docker save write it: manifest.json
// names it, and may come after it, as Podman writes it last of all.
func archiveConfig(r io.Reader) ([]byte, error) {
	small := make(map[string][]byte)
	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("reading the archive: %w", err)
		}
		if hdr.Typeflag != tar.TypeReg || hdr.Size > maxConfig || path.Ext(hdr.Name) != ".json" {
			continue
		}
		body, err := io.ReadAll(tr)
		if err != nil {
			return nil, fmt.Errorf("reading %s from the archive: %w", hdr.Name, err)
		}
		small[path.Clean(hdr.Name)] = body
	}

	raw, ok := small["manifest.json"]
	if !ok {
		return nil, fmt.Errorf("the archive has no manifest.json, among %q", slices.Sorted(maps.Keys(small)))
	}
	var manifest []struct{ Config string }
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil, fmt.Errorf("the archive's manifest.json: %w", err)
	}
	if len(manifest) != 1 {
		return nil, fmt.Errorf("the archive's manifest.json describes %d images, want 1", len(manifest))
	}
	blob, ok := small[path.Clean(manifest[0].Config)]
	if !ok {
		return nil, fmt.Errorf("the archive's manifest.json names the configuration %q, which the archive does not hold", manifest[0].Config)
	}
	return blob, nil
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
