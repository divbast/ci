// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

// Package decompress reads a blob of an image, a layer or any other file
// an image archive holds, with its compression undone as it is read.
//
// Its first bytes decide how: gzip in process, zstd through the zstd
// command, and anything else as it is. The archives ci reads record no
// media type beside a blob to go by: a docker-archive's manifest.json
// names each layer by its path alone. A Docker Hardened Image's layers are
// all zstd, which Go's standard library cannot read yet.
package decompress

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"sync"

	"github.com/divbast/ci/internal/execx"
)

var (
	gzipMagic = []byte{0x1f, 0x8b}
	zstdMagic = []byte{0x28, 0xb5, 0x2f, 0xfd}
)

// Reader returns r with its compression undone, and how it reads it, for
// an error to name: "as gzip", "with zstd -dcq", or "" for a blob read as
// it is. A blob too short to hold a magic number is read as it is. zstd
// runs the zstd command, which only a zstd blob needs.
//
// Close returns the decompressor's verdict on the whole blob: a zstd
// blob's is the command's, once Close has let it run to its end, so a
// reader may stop early, at the end of a tar, say, and still learn whether
// the blob was sound.
func Reader(ctx context.Context, zstd execx.StreamRunner, r io.Reader) (rc io.ReadCloser, how string, err error) {
	br := bufio.NewReader(r)
	// Fewer bytes than asked for is a blob too short to be compressed
	magic, err := br.Peek(len(zstdMagic))
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, "", err
	}
	switch {
	case bytes.HasPrefix(magic, gzipMagic):
		zr, err := gzip.NewReader(br)
		if err != nil {
			return nil, "as gzip", err
		}
		return zr, "as gzip", nil
	case bytes.HasPrefix(magic, zstdMagic):
		return unzstd(ctx, zstd, br), "with zstd -dcq", nil
	default:
		return io.NopCloser(br), "", nil
	}
}

// unzstd decompresses r with the zstd command, which reads it on its
// stdin, and returns what the command writes, as it writes it.
//
// It is the one place ci runs zstd. Go has accepted compress/zstd
// (golang/go#62513) but not shipped it: once it does, this returns its
// reader over r, and the command, and the runner every caller passes for
// it, go.
func unzstd(ctx context.Context, zstd execx.StreamRunner, r io.Reader) io.ReadCloser {
	out, in := io.Pipe()
	ran := make(chan error, 1)
	go func() {
		res, err := zstd.RunStream(ctx, r, in, "zstd", "-dcq")
		switch {
		case errors.Is(err, exec.ErrNotFound):
			err = fmt.Errorf("a zstd blob needs the zstd command on PATH: %w", err)
		case err == nil && res.Code != 0:
			err = fmt.Errorf("zstd exit status %d: %s", res.Code, bytes.TrimSpace(res.Stderr))
		}
		// Ends the reads with this error, or at the end of what zstd
		// wrote when there is none
		_ = in.CloseWithError(err)
		ran <- err
	}()
	return &zstdReader{PipeReader: out, close: sync.OnceValue(func() error {
		// What no one read, read and dropped, so that zstd writes to its
		// end rather than to a closed pipe
		_, _ = io.Copy(io.Discard, out)
		return <-ran
	})}
}

// zstdReader is the zstd command's output.
type zstdReader struct {
	*io.PipeReader

	close func() error
}

// Close reads what the command has still to write, waits for it to end,
// and returns how it ended: nil, or why it failed.
func (z *zstdReader) Close() error { return z.close() }
