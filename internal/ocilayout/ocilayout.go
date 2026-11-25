// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

// Package ocilayout reads one image of an OCI layout as a container of it
// would see it: its config, and chosen files across its layers, in order,
// with whiteouts honoured. It reads what the image says of itself, before
// any scanner says what it thinks the image is.
package ocilayout

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

const (
	// maxJSON bounds an index, a manifest or a config.
	maxJSON = 4 << 20
	// maxDepth bounds how deep indexes may nest: buildx writes two levels.
	maxDepth = 4
)

// Image is one linux image of an OCI layout, open for reading.
type Image struct {
	root *os.Root
	// name is what errors call the image.
	name     string
	manifest manifest
	platform string
}

// Open opens the linux/arch image of the OCI layout at layout: the
// index's manifest for linux/arch, wherever it nests, passing over
// attestation manifests, or the one image manifest the layout holds when
// none names a platform. With arch "", it opens the one linux image the
// layout holds, of any architecture. A layout it cannot read, or one with
// no such image or several, is an error. The caller closes the Image.
func Open(layout, arch string) (*Image, error) { return OpenAs(layout, arch, layout) }

// OpenAs opens the image as [Open] does, but every error it or the Image
// returns calls the image name, and none names the layout's path: for a
// layout copied into a temporary directory, gone once the scan is done.
func OpenAs(layout, arch, name string) (im *Image, err error) {
	root, err := os.OpenRoot(layout)
	if err != nil {
		var pe *os.PathError
		if name == layout || !errors.As(err, &pe) {
			return nil, fmt.Errorf("open the OCI layout: %w", err)
		}
		return nil, fmt.Errorf("open the OCI layout of %s: %w", name, pe.Err)
	}
	defer func() {
		if err != nil {
			_ = root.Close() // read-only, so nothing to lose
		}
	}()
	var top index
	if err = readJSON(root, "index.json", &top); err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	found, err := images(root, top, arch, 0)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	switch {
	case arch == "" && len(found) != 1:
		return nil, fmt.Errorf("%s holds %d linux images, where the scan needs one, so which to scan is unclear", name, len(found))
	case len(found) == 0:
		return nil, fmt.Errorf("%s holds no linux/%s image", name, arch)
	case len(found) > 1:
		return nil, fmt.Errorf("%s holds %d linux/%s images, so which one was built is unclear", name, len(found), arch)
	}
	im = &Image{root: root, name: name, platform: found[0].arch}
	if err = readJSON(root, found[0].path, &im.manifest); err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	return im, nil
}

// Close closes the layout.
func (im *Image) Close() error { return im.root.Close() }

// Platform is the architecture the layout's index gives the image, or ""
// when it names no platform, as Podman's archives and skopeo's oci: copies
// do not.
func (im *Image) Platform() string { return im.platform }

// Config is what an image's config says of it: its architecture, and its
// labels, as LABEL sets them.
type Config struct {
	Architecture string
	Labels       map[string]string
}

// Config reads the image's config.
func (im *Image) Config() (Config, error) {
	p, err := blobPath(im.manifest.Config.Digest)
	if err != nil {
		return Config{}, fmt.Errorf("%s: %w", im.name, err)
	}
	var raw struct {
		Architecture string
		Config       struct{ Labels map[string]string }
	}
	if err = readJSON(im.root, p, &raw); err != nil {
		return Config{}, fmt.Errorf("%s: %w", im.name, err)
	}
	return Config{Architecture: raw.Architecture, Labels: raw.Config.Labels}, nil
}

// Node is a file the image holds: its content, or where it links to.
type Node struct {
	Body []byte
	Link string
}

// Files reads every file keep keeps, across the image's layers in order,
// whiteouts honoured, and returns what the last layer leaves at each, by
// its path from the image's root with no leading slash: its content, or
// where it links. keep is asked of each path, and returns the most bytes
// a file there may hold. A path the image leaves something other than a
// file or a link at is absent. zstd runs the zstd command for zstd
// layers. A file past its limit, or a hard link to a path keep does not
// keep, is an error.
func (im *Image) Files(ctx context.Context, zstd execx.StreamRunner, keep func(name string) (limit int64, ok bool)) (map[string]Node, error) {
	fs := rootfs{}
	for _, l := range im.manifest.Layers {
		if err := fs.apply(ctx, zstd, im.root, l.Digest, keep); err != nil {
			return nil, fmt.Errorf("%s: layer %s: %w", im.name, l.Digest, err)
		}
	}
	return fs, nil
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

type manifest struct {
	Config descriptor
	Layers []descriptor
}

// image is an image manifest an index names: its blob's path, and the
// architecture the index gives it, or "" when it names no platform.
type image struct{ path, arch string }

// images returns the image manifests in ix for linux/arch, or for any
// linux architecture when arch is "", and those that name no platform,
// looking into nested indexes.
func images(root *os.Root, ix index, arch string, depth int) ([]image, error) {
	if depth >= maxDepth {
		return nil, errors.New("indexes nest too deep")
	}
	var found []image
	for _, d := range ix.Manifests {
		// An attestation describes an image, and is none: buildx names one
		// beside each image, for the platform unknown/unknown
		if d.Annotations["vnd.docker.reference.type"] == "attestation-manifest" {
			continue
		}
		if d.Platform != nil && (d.Platform.OS != "linux" || arch != "" && d.Platform.Architecture != arch) {
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
			img := image{path: p}
			if d.Platform != nil {
				img.arch = d.Platform.Architecture
			}
			found = append(found, img)
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

// rootfs is every file kept that the layers applied so far leave, by its
// path from the image's root, with no leading slash.
type rootfs map[string]Node

// apply applies the layer whose digest is digest to fs: whiteouts first,
// which hide only what lower layers hold, then the layer's own files.
func (fs rootfs) apply(ctx context.Context, zstd execx.StreamRunner, root *os.Root, digest string, keep func(string) (int64, bool)) (err error) {
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
		added = map[string]*Node{}
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
		}
		limit, ok := keep(name)
		if !ok {
			continue
		}
		n, err := entry(tr, h, name, limit, added, fs)
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

// entry reads the tar entry h, at name, of a file kept, which may hold
// limit bytes: its content, where it links, or nil for a directory or
// anything else that is no file there. A hard link takes its target's
// node from earlier in the same layer, else from below.
func entry(tr *tar.Reader, h *tar.Header, name string, limit int64, layer map[string]*Node, below rootfs) (*Node, error) {
	switch h.Typeflag {
	case tar.TypeReg:
		if h.Size > limit {
			return nil, fmt.Errorf("/%s is %d bytes, more than the %d the reader takes for it", name, h.Size, limit)
		}
		body, err := io.ReadAll(io.LimitReader(tr, limit))
		if err != nil {
			return nil, fmt.Errorf("read /%s: %w", name, err)
		}
		return &Node{Body: body}, nil
	case tar.TypeSymlink:
		return &Node{Link: h.Linkname}, nil
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
