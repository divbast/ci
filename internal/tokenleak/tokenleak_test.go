// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

package tokenleak_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"

	"github.com/divbast/ci/internal/execx"
	"github.com/divbast/ci/internal/tokenleak"
)

// chunk is the read size the matcher works in, whose boundary a token
// split across two reads must survive.
const chunk = 32 << 10

// syntheticToken returns a token made up for one test, never a real one,
// in no GitHub token's format so no secret scanner takes it for one.
func syntheticToken() []byte {
	return []byte("divbast-synthetic-token-" + rand.Text())
}

// entry is one member of a test archive.
type entry struct {
	name     string
	typeflag byte
	body     []byte
	linkname string
}

func file(name string, body []byte) entry {
	return entry{name: name, typeflag: tar.TypeReg, body: body}
}

// writeTar writes entries as a tar archive in a fresh directory and returns
// its path.
func writeTar(t *testing.T, entries ...entry) string {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		hdr := &tar.Header{Name: e.name, Typeflag: e.typeflag, Linkname: e.linkname, Mode: 0o644}
		if e.typeflag == tar.TypeReg {
			hdr.Size = int64(len(e.body))
		}
		if e.typeflag == tar.TypeDir {
			hdr.Mode = 0o755
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(e.body); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return writeFile(t, buf.Bytes())
}

// writeFile writes data to a file in a fresh directory and returns its path.
func writeFile(t *testing.T, data []byte) string {
	t.Helper()
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	if err = root.WriteFile("image.tar", data, 0o600); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(dir, "image.tar")
}

// gz compresses data with gzip. At the default level, Go stores data with
// no repeats in it as it is, token and all, which BestCompression codes.
func gz(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = zw.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// zst compresses data with the zstd command, which Scan decompresses with
// too. The ubuntu-26.04 runner images carry it.
func zst(t *testing.T, data []byte) []byte {
	t.Helper()
	if _, err := exec.LookPath("zstd"); err != nil {
		t.Fatalf("zstd is not on PATH, and Scan needs it for zstd layers: %v", err)
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

// filler is n bytes that hold no token.
func filler(n int) []byte {
	return bytes.Repeat([]byte("layer bytes "), n/12+1)[:n]
}

// noise is n random base32 letters, with no run in it a compressor would
// keep as it is, as zstd keeps a short one beside filler.
func noise(n int) []byte {
	var b []byte
	for len(b) < n {
		b = append(b, rand.Text()...)
	}
	return b[:n]
}

// hidden returns blob, a compressed file holding token, after checking that
// it does not hold token as it is. One that did would show the token to a
// search that never decompressed it, and prove nothing.
func hidden(t *testing.T, blob, token []byte) []byte {
	t.Helper()
	if bytes.Contains(blob, token) {
		t.Fatal("the compressed blob holds the token as it is")
	}
	return blob
}

// at is filler of size n with token written at offset off.
func at(n, off int, token []byte) []byte {
	b := filler(n)
	copy(b[off:], token)
	return b
}

// failing is a Runner whose every command could not run.
type failing struct{}

func (failing) Run(context.Context, string, ...string) (execx.Result, error) {
	return execx.Result{}, exec.ErrNotFound
}

func TestScan(t *testing.T) {
	t.Parallel()

	token := syntheticToken()
	withToken := slices.Concat(noise(2000), token, noise(2000))
	clean := filler(3000)
	// A token across the first boundary: half in each of the first two reads
	straddling := at(3*chunk, chunk-len(token)/2, token)
	corruptGzip := append([]byte{0x1f, 0x8b, 0x08, 0x00}, filler(100)...)
	truncatedGzip := gz(t, withToken)[:40]
	// Its CRC-32 wrong, which shows only once the token has been read
	badChecksum := gz(t, withToken)
	badChecksum[len(badChecksum)-8] ^= 0xff
	corruptZstd := append([]byte{0x28, 0xb5, 0x2f, 0xfd}, filler(100)...)
	index := file("index.json", []byte(`{"schemaVersion":2}`))

	tests := []struct {
		name        string
		archive     string
		zstd        execx.Runner
		wantScanned int
		wantHits    []string
		wantErr     bool
	}{
		{
			name:        "plain",
			archive:     writeTar(t, index, file("blobs/sha256/aa", withToken)),
			wantScanned: 2,
			wantHits:    []string{"blobs/sha256/aa"},
		},
		{
			name:        "gzip",
			archive:     writeTar(t, index, file("blobs/sha256/aa", hidden(t, gz(t, withToken), token))),
			wantScanned: 2,
			wantHits:    []string{"blobs/sha256/aa"},
		},
		{
			name:        "zstd",
			archive:     writeTar(t, index, file("blobs/sha256/aa", hidden(t, zst(t, withToken), token))),
			wantScanned: 2,
			wantHits:    []string{"blobs/sha256/aa"},
		},
		{
			name:        "split-across-the-read-boundary",
			archive:     writeTar(t, file("blobs/sha256/aa", straddling)),
			wantScanned: 1,
			wantHits:    []string{"blobs/sha256/aa"},
		},
		{
			name:        "split-across-the-read-boundary-gzip",
			archive:     writeTar(t, file("blobs/sha256/aa", hidden(t, gz(t, straddling), token))),
			wantScanned: 1,
			wantHits:    []string{"blobs/sha256/aa"},
		},
		{
			name:        "at-the-very-end",
			archive:     writeTar(t, file("blobs/sha256/aa", at(2*chunk, 2*chunk-len(token), token))),
			wantScanned: 1,
			wantHits:    []string{"blobs/sha256/aa"},
		},
		{
			name: "clean",
			archive: writeTar(t, index, file("blobs/sha256/aa", clean), file("blobs/sha256/bb", gz(t, clean)),
				file("blobs/sha256/cc", zst(t, clean)), file("manifest.json", nil)),
			wantScanned: 5,
		},
		{
			name: "every-hit-named",
			archive: writeTar(t, file("blobs/sha256/aa", hidden(t, gz(t, withToken), token)), file("blobs/sha256/bb", clean),
				file("./blobs/sha256/cc", withToken)),
			wantScanned: 3,
			wantHits:    []string{"blobs/sha256/aa", "blobs/sha256/cc"},
		},
		{
			// Only regular files hold bytes to read, as find -type f saw it.
			// A hard link's bytes are those of the file it names, read
			// already under that name.
			name: "links-and-directories-skipped",
			archive: writeTar(t,
				entry{name: "blobs/", typeflag: tar.TypeDir},
				file("blobs/sha256/aa", clean),
				entry{name: "aa/layer.tar", typeflag: tar.TypeSymlink, linkname: "../blobs/sha256/aa"},
				entry{name: "bb/layer.tar", typeflag: tar.TypeLink, linkname: "blobs/sha256/aa"}),
			wantScanned: 1,
		},
		{
			// Too short to sniff, so read as they are
			name:        "tiny-files",
			archive:     writeTar(t, file("empty", nil), file("one", []byte{0x1f}), file("three", []byte{0x28, 0xb5, 0x2f})),
			wantScanned: 3,
		},
		{
			// A token in no blob's bytes, only split between two blobs
			name:        "token-split-between-files",
			archive:     writeTar(t, file("a", token[:len(token)/2]), file("b", token[len(token)/2:])),
			wantScanned: 2,
		},
		{
			name:    "corrupt-gzip",
			archive: writeTar(t, index, file("blobs/sha256/aa", corruptGzip)),
			wantErr: true,
		},
		{
			// Read to its end, as the shell's grep without -q read it: a
			// file that fails late is unread, token or not
			name:    "token-then-bad-checksum",
			archive: writeTar(t, file("blobs/sha256/aa", hidden(t, badChecksum, token))),
			wantErr: true,
		},
		{
			name:    "truncated-gzip",
			archive: writeTar(t, file("blobs/sha256/aa", truncatedGzip)),
			wantErr: true,
		},
		{
			// What was found before stays found, and the error still stands
			name:     "hit-then-unreadable",
			archive:  writeTar(t, file("blobs/sha256/aa", withToken), file("blobs/sha256/bb", corruptGzip)),
			wantErr:  true,
			wantHits: []string{"blobs/sha256/aa"},
		},
		{
			// gzip -dc fails on both, so the shell read neither as plain
			name:    "gzip-magic-alone",
			archive: writeTar(t, file("blobs/sha256/aa", []byte{0x1f, 0x8b})),
			wantErr: true,
		},
		{
			name:    "gzip-header-not-deflate",
			archive: writeTar(t, file("blobs/sha256/aa", append([]byte{0x1f, 0x8b, 0x07, 0x00}, filler(100)...))),
			wantErr: true,
		},
		{
			name:    "corrupt-zstd",
			archive: writeTar(t, file("blobs/sha256/aa", corruptZstd)),
			wantErr: true,
		},
		{
			name:    "zstd-will-not-run",
			archive: writeTar(t, file("blobs/sha256/aa", zst(t, clean))),
			zstd:    failing{},
			wantErr: true,
		},
		{
			name:    "empty-archive",
			archive: writeTar(t),
			wantErr: true,
		},
		{
			name:    "only-directories",
			archive: writeTar(t, entry{name: "blobs/", typeflag: tar.TypeDir}),
			wantErr: true,
		},
		{
			name:    "empty-file",
			archive: writeFile(t, nil),
			wantErr: true,
		},
		{
			name:    "not-a-tar",
			archive: writeFile(t, filler(4096)),
			wantErr: true,
		},
		{
			name:    "truncated-tar",
			archive: truncated(t, writeTar(t, file("blobs/sha256/aa", clean)), 1024),
			wantErr: true,
		},
		{
			name:    "missing",
			archive: filepath.Join(t.TempDir(), "no-such-archive.tar"),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			zstd := tt.zstd
			if zstd == nil {
				zstd = execx.OS{}
			}
			scanned, hits, err := tokenleak.Scan(t.Context(), tt.archive, token, zstd)
			if (err != nil) != tt.wantErr {
				t.Fatalf("Scan() error = %v, want error %t", err, tt.wantErr)
			}
			if err != nil && bytes.Contains([]byte(err.Error()), token) {
				t.Errorf("Scan() error %q holds the token", err)
			}
			if !slices.Equal(hits, tt.wantHits) {
				t.Errorf("hits = %q, want %q", hits, tt.wantHits)
			}
			if !tt.wantErr && scanned != tt.wantScanned {
				t.Errorf("scanned = %d, want %d", scanned, tt.wantScanned)
			}
		})
	}
}

// truncated copies the file at path, cut to its first n bytes.
func truncated(t *testing.T, path string, n int) string {
	t.Helper()
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	data, err := root.ReadFile(filepath.Base(path))
	if err != nil {
		t.Fatal(err)
	}
	return writeFile(t, data[:n])
}

// Every way a token can straddle a read boundary, not only down the middle.
func TestScanEveryStraddle(t *testing.T) {
	t.Parallel()

	token := syntheticToken()
	for k := 1; k < len(token); k++ {
		// k bytes of the token end the first read, the rest start the second
		archive := writeTar(t, file("blob", at(2*chunk, chunk-k, token)))
		_, hits, err := tokenleak.Scan(t.Context(), archive, token, failing{})
		if err != nil {
			t.Fatalf("split %d/%d: Scan() error = %v", k, len(token)-k, err)
		}
		if len(hits) != 1 {
			t.Errorf("split %d/%d: hits = %q, want one", k, len(token)-k, hits)
		}
	}
}

// An empty token is in every file, so it cannot stand for the build's.
func TestScanEmptyToken(t *testing.T) {
	t.Parallel()

	archive := writeTar(t, file("blob", filler(10)))
	if _, _, err := tokenleak.Scan(t.Context(), archive, nil, failing{}); err == nil {
		t.Error("Scan() with no token: error = nil, want one")
	}
}

// A cancelled scan stops rather than reporting a clean archive.
func TestScanCancelled(t *testing.T) {
	t.Parallel()

	archive := writeTar(t, file("a", filler(10)), file("b", filler(10)))
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, _, err := tokenleak.Scan(ctx, archive, syntheticToken(), failing{}); !errors.Is(err, context.Canceled) {
		t.Errorf("Scan() error = %v, want context.Canceled", err)
	}
}
