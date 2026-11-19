// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

// Package osrelease reads the os-release file of an image in an OCI
// layout: what the image says it is, before any scanner says what it
// thinks it is.
//
// A scanner reads an image's OS through its own model, and a model can be
// wrong without being blind: Trivy reads a Docker Hardened Image that says
// ID=dhi, but keeps /etc/debian_version, as plain Debian, and scans it
// against Debian's advisories. Only the image's own word shows the
// mismatch, so the scan reads it here, from the layers themselves, and
// holds the scanner's report against it.
package osrelease

import (
	"archive/tar"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"

	"github.com/divbast/ci/internal/decompress"
	"github.com/divbast/ci/internal/execx"
)

// Info is what an os-release file says of the OS: its ID, ID_LIKE and
// VERSION_ID, each as the file sets it, unquoted, or "" when it does not.
type Info struct{ ID, IDLike, VersionID string }

const (
	// maxSize bounds an os-release file, a few hundred bytes in practice.
	maxSize = 64 << 10
	// maxJSON bounds an index or a manifest.
	maxJSON = 4 << 20
	// maxDepth bounds how deep indexes may nest: buildx writes two levels.
	maxDepth = 4
)

// Read reads the os-release file of the linux/arch image in the OCI
// layout at layout, as a container of it would find it: /etc/os-release,
// or /usr/lib/os-release when that is missing, as os-release(5) says,
// across the image's layers in order, with whiteouts honoured. One
// symlink is followed, inside the image's root: /etc/os-release is
// usually one, to ../usr/lib/os-release. zstd runs the zstd command for
// zstd layers.
//
// The image is the index's manifest for linux/arch, wherever it nests,
// passing over attestation manifests, or the one image manifest the
// layout holds when none names a platform. It returns false, and no
// error, for an image with no os-release; an error for a layout it cannot
// read, one with no such image, or an os-release it cannot follow.
func Read(ctx context.Context, zstd execx.StreamRunner, layout, arch string) (Info, bool, error) {
	root, err := os.OpenRoot(layout)
	if err != nil {
		return Info{}, false, fmt.Errorf("open the OCI layout: %w", err)
	}
	defer func() { _ = root.Close() }() // read-only, so nothing to lose
	var top index
	if err = readJSON(root, "index.json", &top); err != nil {
		return Info{}, false, fmt.Errorf("%s: %w", layout, err)
	}
	found, err := images(root, top, arch, 0)
	if err != nil {
		return Info{}, false, fmt.Errorf("%s: %w", layout, err)
	}
	switch {
	case len(found) == 0:
		return Info{}, false, fmt.Errorf("%s holds no linux/%s image", layout, arch)
	case len(found) > 1:
		return Info{}, false, fmt.Errorf("%s holds %d linux/%s images, so which one was built is unclear", layout, len(found), arch)
	}
	var m manifest
	if err = readJSON(root, found[0], &m); err != nil {
		return Info{}, false, fmt.Errorf("%s: %w", layout, err)
	}
	fs := rootfs{}
	for _, l := range m.Layers {
		if err = fs.apply(ctx, zstd, root, l.Digest); err != nil {
			return Info{}, false, fmt.Errorf("%s: layer %s: %w", layout, l.Digest, err)
		}
	}
	info, ok, err := fs.osRelease()
	if err != nil {
		return Info{}, false, fmt.Errorf("%s: %w", layout, err)
	}
	return info, ok, nil
}

// descriptor is what the reader uses of an OCI content descriptor.
type descriptor struct {
	MediaType string
	Digest    string
	Platform  *struct {
		OS           string `json:"os"`
		Architecture string `json:"architecture"`
	}
	Annotations map[string]string
}

type index struct{ Manifests []descriptor }

type manifest struct{ Layers []descriptor }

// images returns the blob paths of the image manifests in ix for
// linux/arch, and of those that name no platform, looking into nested
// indexes.
func images(root *os.Root, ix index, arch string, depth int) ([]string, error) {
	if depth >= maxDepth {
		return nil, errors.New("indexes nest too deep")
	}
	var found []string
	for _, d := range ix.Manifests {
		// An attestation describes an image, and is none: buildx names one
		// beside each image, for the platform unknown/unknown
		if d.Annotations["vnd.docker.reference.type"] == "attestation-manifest" {
			continue
		}
		if d.Platform != nil && (d.Platform.OS != "linux" || d.Platform.Architecture != arch) {
			continue
		}
		p, err := blobPath(d.Digest)
		if err != nil {
			return nil, err
		}
		switch d.MediaType {
		case "application/vnd.oci.image.index.v1+json", "application/vnd.docker.distribution.manifest.list.v2+json":
			var nested index
			if err := readJSON(root, p, &nested); err != nil {
				return nil, err
			}
			more, err := images(root, nested, arch, depth+1)
			if err != nil {
				return nil, err
			}
			found = append(found, more...)
		case "application/vnd.oci.image.manifest.v1+json", "application/vnd.docker.distribution.manifest.v2+json":
			found = append(found, p)
		}
	}
	return found, nil
}

// blobPath is where a layout keeps the blob digest names.
func blobPath(digest string) (string, error) {
	alg, hex, ok := strings.Cut(digest, ":")
	if !ok || alg == "" || hex == "" || strings.ContainsAny(digest, `/\`) {
		return "", fmt.Errorf("digest %q is not one", digest)
	}
	return path.Join("blobs", alg, hex), nil
}

// readJSON decodes the JSON file at name in root into v.
func readJSON(root *os.Root, name string, v any) (err error) {
	f, err := root.Open(name)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, f.Close()) }()
	data, err := io.ReadAll(io.LimitReader(f, maxJSON+1))
	if err != nil {
		return err
	}
	if len(data) > maxJSON {
		return fmt.Errorf("%s is larger than %d bytes", name, maxJSON)
	}
	if err = json.Unmarshal(data, v); err != nil {
		return fmt.Errorf("parse %s: %w", name, err)
	}
	return nil
}

// node is a file named os-release in the image: its content, or where it
// links to.
type node struct {
	body []byte
	link string
}

// rootfs is every file named os-release the layers applied so far leave,
// by its path from the image's root, with no leading slash.
type rootfs map[string]node

// apply applies the layer whose digest is digest to fs: whiteouts first,
// which hide only what lower layers hold, then the layer's own files.
func (fs rootfs) apply(ctx context.Context, zstd execx.StreamRunner, root *os.Root, digest string) (err error) {
	p, err := blobPath(digest)
	if err != nil {
		return err
	}
	f, err := root.Open(p)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, f.Close()) }()
	r, how, err := decompress.Reader(ctx, zstd, f)
	if err != nil {
		return fmt.Errorf("read it %s: %w", how, err)
	}
	// Close is the decompressor's verdict on the whole layer
	defer func() { err = errors.Join(err, r.Close()) }()

	var (
		hidden []string // paths whiteouts remove, with all under them
		opaque []string // directories whose lower contents are removed
		// the layer's own files, by path, last entry winning; nil when it
		// puts something other than a file there
		added = map[string]*node{}
	)
	tr := tar.NewReader(r)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		name := strings.TrimPrefix(path.Clean("/"+h.Name), "/")
		dir, base := path.Dir(name), path.Base(name)
		switch {
		case base == ".wh..wh..opq":
			opaque = append(opaque, dir)
			continue
		case strings.HasPrefix(base, ".wh."):
			hidden = append(hidden, path.Join(dir, strings.TrimPrefix(base, ".wh.")))
			continue
		case base != "os-release":
			continue
		}
		n, err := entry(tr, h, name, added, fs)
		if err != nil {
			return err
		}
		added[name] = n
	}

	for p := range fs {
		for _, h := range hidden {
			if p == h || strings.HasPrefix(p, h+"/") {
				delete(fs, p)
			}
		}
		for _, d := range opaque {
			if d == "." || strings.HasPrefix(p, d+"/") {
				delete(fs, p)
			}
		}
	}
	for name, n := range added {
		if n == nil {
			delete(fs, name)
		} else {
			fs[name] = *n
		}
	}
	return nil
}

// entry reads the tar entry h, at name, of a file named os-release: its
// content, where it links, or nil for a directory or anything else that
// is no file there. A hard link takes its target's node from earlier in
// the same layer, else from below.
func entry(tr *tar.Reader, h *tar.Header, name string, layer map[string]*node, below rootfs) (*node, error) {
	switch h.Typeflag {
	case tar.TypeReg:
		if h.Size > maxSize {
			return nil, fmt.Errorf("/%s is %d bytes, larger than an os-release file should be", name, h.Size)
		}
		body, err := io.ReadAll(io.LimitReader(tr, maxSize))
		if err != nil {
			return nil, fmt.Errorf("read /%s: %w", name, err)
		}
		return &node{body: body}, nil
	case tar.TypeSymlink:
		return &node{link: h.Linkname}, nil
	case tar.TypeLink:
		target := strings.TrimPrefix(path.Clean("/"+h.Linkname), "/")
		if n, ok := layer[target]; ok && n != nil {
			return n, nil
		}
		n, ok := below[target]
		if !ok {
			return nil, fmt.Errorf("/%s is a hard link to /%s, which the reader does not keep", name, target)
		}
		return &n, nil
	default:
		return nil, nil //nolint:nilnil // nil node: something other than a file now stands at name
	}
}

// osRelease is the os-release file fs leaves, read.
func (fs rootfs) osRelease() (Info, bool, error) {
	for _, p := range []string{"etc/os-release", "usr/lib/os-release"} {
		n, ok := fs[p]
		if !ok {
			continue
		}
		if n.link != "" {
			// Resolved as the kernel would inside the image's root, where
			// ".." at the root stays there
			target := n.link
			if !path.IsAbs(target) {
				target = path.Join("/", path.Dir(p), target)
			}
			target = strings.TrimPrefix(path.Clean(target), "/")
			if path.Base(target) != "os-release" {
				return Info{}, false, fmt.Errorf("/%s is a symlink to /%s, which the reader does not keep", p, target)
			}
			t, ok := fs[target]
			if !ok {
				// A link to nothing is no file, so the next one counts
				continue
			}
			if t.link != "" {
				return Info{}, false, fmt.Errorf("/%s is a symlink to /%s, itself a symlink: the reader follows one", p, target)
			}
			n = t
		}
		return parse(n.body), true, nil
	}
	return Info{}, false, nil
}

// parse reads the variables Info holds from an os-release file, as
// os-release(5) writes them: KEY=value lines, values quoted as in a
// shell, and comments and blank lines skipped.
func parse(data []byte) Info {
	var info Info
	for line := range strings.Lines(string(data)) {
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch key {
		case "ID":
			info.ID = unquote(value)
		case "ID_LIKE":
			info.IDLike = unquote(value)
		case "VERSION_ID":
			info.VersionID = unquote(value)
		}
	}
	return info
}

// unquote undoes a value's shell quoting: single quotes keep everything,
// and elsewhere a backslash escapes the character after it.
func unquote(v string) string {
	if len(v) >= 2 && v[0] == '\'' && v[len(v)-1] == '\'' {
		return v[1 : len(v)-1]
	}
	if len(v) >= 2 && v[0] == '"' && v[len(v)-1] == '"' {
		v = v[1 : len(v)-1]
	}
	var b strings.Builder
	escaped := false
	for _, r := range v {
		if r == '\\' && !escaped {
			escaped = true
			continue
		}
		escaped = false
		b.WriteRune(r)
	}
	return b.String()
}
