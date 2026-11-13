// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

// Package tokenleak looks for a GitHub token in an image archive.
//
// A build gets its token through a secret mount, which never reaches a
// layer. An ARG or ENV carrying it would, and so would anything that wrote
// it to a file. So every file in the archive is read, the layers
// decompressed, which reads the config, its history and any attestation
// too: the provenance records each build argument.
package tokenleak

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"

	"github.com/divbast/ci/internal/execx"
)

// chunk is how much of a file the search holds at a time, beyond the end
// of the chunk before it.
const chunk = 32 << 10

var (
	gzipMagic = []byte{0x1f, 0x8b}
	zstdMagic = []byte{0x28, 0xb5, 0x2f, 0xfd}
)

// Scan reads every file in the tar archive at archive, without unpacking
// it, and returns how many it read and the names of those that hold token.
// An entry is a file unless its type says it holds no bytes of its own: a
// link, a device, a directory, a FIFO or a PAX global header. An entry of
// a type this does not know is read as a file.
//
// A file is decompressed by its first bytes: gzip in process, zstd by the
// zstd command, through zstd, which reads the file on its stdin, and
// anything else is read as it is. Each is searched as it is read, so no
// file is ever held whole in memory.
//
// A file that cannot be read through, an archive that is not a tar or
// holds no file, and an empty token are errors: a file this check cannot
// read is not one it has cleared. So is ctx ending, which stops the scan
// inside the file it is reading. The names found before such an error are
// returned with it. The token is in no error.
func Scan(ctx context.Context, archive string, token []byte, zstd execx.StreamRunner) (scanned int, hits []string, err error) {
	if len(token) == 0 {
		return 0, nil, errors.New("no token to look for: an empty one is in every file")
	}
	dir, err := os.OpenRoot(filepath.Dir(archive))
	if err != nil {
		return 0, nil, err
	}
	defer func() { err = errors.Join(err, dir.Close()) }()
	f, err := dir.Open(filepath.Base(archive))
	if err != nil {
		return 0, nil, err
	}
	defer func() { err = errors.Join(err, f.Close()) }()

	tr := tar.NewReader(f)
	for {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return scanned, hits, fmt.Errorf("scan %s: %w", archive, ctxErr)
		}
		hdr, nextErr := tr.Next()
		if errors.Is(nextErr, io.EOF) {
			break
		}
		if nextErr != nil {
			return scanned, hits, fmt.Errorf("read %s: %w", archive, nextErr)
		}
		switch hdr.Typeflag {
		// A hard link's bytes are those of the file it names, which the
		// archive holds, and this reads, under that name. A PAX global
		// header's are records the tar reader has already taken.
		case tar.TypeLink, tar.TypeSymlink, tar.TypeChar, tar.TypeBlock, tar.TypeDir, tar.TypeFifo, tar.TypeXGlobalHeader:
			continue
		}
		name := path.Clean(hdr.Name)
		found, how, readErr := search(ctx, tr, token, zstd)
		if ctxErr := ctx.Err(); readErr != nil && ctxErr != nil {
			return scanned, hits, fmt.Errorf("scan %s: %w", archive, ctxErr)
		}
		if readErr != nil {
			return scanned, hits, fmt.Errorf("could not read %s%s: %w; a blob this check cannot read is not a blob it has cleared",
				name, how, readErr)
		}
		if found {
			hits = append(hits, name)
		}
		scanned++
	}
	if scanned == 0 {
		return 0, hits, fmt.Errorf("%s holds no files to read", archive)
	}
	return scanned, hits, nil
}

// search reports whether the file r holds token once decompressed, and
// says how it was read, for an error to name.
func search(ctx context.Context, r io.Reader, token []byte, zstd execx.StreamRunner) (found bool, how string, err error) {
	br := bufio.NewReaderSize(r, chunk)
	// Fewer bytes than asked for is a file too short to be compressed
	magic, err := br.Peek(len(zstdMagic))
	if err != nil && !errors.Is(err, io.EOF) {
		return false, "", err
	}
	switch {
	case bytes.HasPrefix(magic, gzipMagic):
		found, err = gunzip(ctx, br, token)
		return found, " as gzip", err
	case bytes.HasPrefix(magic, zstdMagic):
		found, err = unzstd(ctx, br, token, zstd)
		return found, " with zstd -dcq", err
	default:
		found, err = contains(ctx, br, token)
		return found, "", err
	}
}

func gunzip(ctx context.Context, r io.Reader, token []byte) (bool, error) {
	zr, err := gzip.NewReader(r)
	if err != nil {
		return false, err
	}
	found, err := contains(ctx, zr, token)
	if err != nil {
		return found, err
	}
	// Close only repeats an error a read has already returned, so after
	// reads that reached the end it has nothing to add
	return found, zr.Close()
}

// unzstd decompresses r with the zstd command, which reads it on its
// stdin, and searches what it writes as it writes it.
func unzstd(ctx context.Context, r io.Reader, token []byte, zstd execx.StreamRunner) (bool, error) {
	out, in := io.Pipe()
	ran := make(chan error, 1)
	go func() {
		res, err := zstd.RunStream(ctx, r, in, "zstd", "-dcq")
		if err == nil && res.Code != 0 {
			err = fmt.Errorf("zstd exit status %d: %s", res.Code, bytes.TrimSpace(res.Stderr))
		}
		// Ends the search's reads with this error, or at the end of what
		// zstd wrote when there is none
		_ = in.CloseWithError(err)
		ran <- err
	}()
	found, err := contains(ctx, out, token)
	// A search that stopped early leaves zstd's writes nowhere to go
	_ = out.Close()
	if ranErr := <-ran; err == nil {
		err = ranErr
	}
	return found, err
}

// contains reports whether r holds token, reading it to its end, so that
// a file that fails partway is an error even after the token was seen. It
// stops with ctx's error once ctx ends.
//
// It reads chunk bytes at a time, and searches each chunk with the last
// len(token)-1 bytes of the one before, so a token split across the
// boundary between two reads is found.
func contains(ctx context.Context, r io.Reader, token []byte) (bool, error) {
	carry := len(token) - 1
	buf := make([]byte, carry+chunk)
	found := false
	kept := 0
	for {
		if err := ctx.Err(); err != nil {
			return found, err
		}
		n, err := fill(r, buf[kept:kept+chunk])
		window := buf[:kept+n]
		found = found || bytes.Contains(window, token)
		if errors.Is(err, io.EOF) {
			return found, nil
		}
		if err != nil {
			return found, err
		}
		kept = min(carry, len(window))
		copy(buf, window[len(window)-kept:])
	}
}

// fill reads from r until p is full or r ends. Its error is io.EOF only
// for an end r reported as one, so a reader that was cut short still says
// so.
func fill(r io.Reader, p []byte) (int, error) {
	n := 0
	for n < len(p) {
		m, err := r.Read(p[n:])
		n += m
		if err != nil {
			return n, err
		}
	}
	return n, nil
}
