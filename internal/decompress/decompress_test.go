// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

package decompress_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"slices"
	"strings"
	"testing"

	"github.com/divbast/ci/internal/decompress"
	"github.com/divbast/ci/internal/execx"
)

// zstdMagic opens every zstd frame.
var zstdMagic = []byte{0x28, 0xb5, 0x2f, 0xfd}

// zst compresses data with the zstd command, which Reader decompresses
// with too. The ubuntu-26.04 runner images carry it.
func zst(t *testing.T, data []byte) []byte {
	t.Helper()
	if _, err := exec.LookPath("zstd"); err != nil {
		t.Fatalf("zstd is not on PATH, and Reader needs it for a zstd blob: %v", err)
	}
	res, err := execx.OS{}.RunStdin(t.Context(), bytes.NewReader(data), "zstd", "-q", "-c")
	if err != nil || res.Code != 0 {
		t.Fatalf("zstd -q -c: %v, exit %d: %s", err, res.Code, res.Stderr)
	}
	return res.Stdout
}

func gz(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// noise is n random base32 letters, which no compressor shrinks much, so
// that a blob of it outgrows any pipe's buffer once compressed too.
func noise(n int) []byte {
	var b []byte
	for len(b) < n {
		b = append(b, rand.Text()...)
	}
	return b[:n]
}

// missing is a StreamRunner on a host with no zstd: every command fails
// to start, as execx.OS reports it.
type missing struct{}

func (missing) RunStream(_ context.Context, _ io.Reader, _ io.Writer, name string, _ ...string) (execx.Result, error) {
	return execx.Result{}, fmt.Errorf("run %s: %w", name, exec.ErrNotFound)
}

// readAll opens r with Reader, reads it to its end and closes it, and
// returns what it read, how Reader said it read it, and the first error
// any of the three gave.
func readAll(ctx context.Context, zstd execx.StreamRunner, r io.Reader) (got []byte, how string, err error) {
	rc, how, err := decompress.Reader(ctx, zstd, r)
	if err != nil {
		return nil, how, err
	}
	got, err = io.ReadAll(rc)
	if closeErr := rc.Close(); err == nil {
		err = closeErr
	}
	return got, how, err
}

func TestReader(t *testing.T) {
	t.Parallel()

	body := []byte(strings.Repeat("a layer's bytes ", 512))
	// What a Fake zstd is fed: the magic, then anything
	blob := slices.Concat(zstdMagic, []byte("compressed"))
	zstdCall := execx.Call{Argv: []string{"zstd", "-dcq"}, Stdin: blob}
	fake := func(res execx.Result) func(*testing.T) execx.StreamRunner {
		return func(t *testing.T) execx.StreamRunner {
			t.Helper()
			c := zstdCall
			c.Result = res
			return execx.NewFake(t, c)
		}
	}

	tests := []struct {
		name string
		in   []byte
		// zstd makes what runs zstd: the command itself when nil
		zstd    func(*testing.T) execx.StreamRunner
		want    []byte
		wantHow string
		wantErr string
	}{
		{name: "plain", in: body, want: body},
		{name: "gzip", in: gz(t, body), want: body, wantHow: "as gzip"},
		{name: "zstd", in: zst(t, body), want: body, wantHow: "with zstd -dcq"},
		{
			// The blob goes to zstd on its stdin, and what zstd writes is
			// what is read
			name:    "zstd-fed-the-blob",
			in:      blob,
			zstd:    fake(execx.Result{Stdout: body}),
			want:    body,
			wantHow: "with zstd -dcq",
		},
		{
			// Too short to hold a magic number, so read as it is
			name: "short",
			in:   zstdMagic[:3],
			want: zstdMagic[:3],
		},
		{name: "empty", in: []byte{}, want: []byte{}},
		{name: "corrupt-gzip", in: slices.Concat([]byte{0x1f, 0x8b, 0x08, 0x00}, body), wantHow: "as gzip", wantErr: "flate"},
		{name: "gzip-magic-alone", in: []byte{0x1f, 0x8b}, wantHow: "as gzip", wantErr: "EOF"},
		{name: "corrupt-zstd", in: slices.Concat(zstdMagic, body), wantHow: "with zstd -dcq", wantErr: "zstd exit status 1"},
		{
			// What zstd wrote before it failed is no clean read
			name:    "zstd-writes-then-fails",
			in:      blob,
			zstd:    fake(execx.Result{Stdout: body, Stderr: []byte("zstd: corrupted block\n"), Code: 1}),
			wantHow: "with zstd -dcq",
			wantErr: "zstd exit status 1: zstd: corrupted block",
		},
		{
			// Only a zstd blob needs the command, and one without it fails
			// saying so
			name:    "no-zstd-command",
			in:      blob,
			zstd:    func(*testing.T) execx.StreamRunner { return missing{} },
			wantHow: "with zstd -dcq",
			wantErr: "a zstd blob needs the zstd command on PATH: run zstd: " + exec.ErrNotFound.Error(),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var zstd execx.StreamRunner = execx.OS{}
			if tt.zstd != nil {
				zstd = tt.zstd(t)
			}
			got, how, err := readAll(t.Context(), zstd, bytes.NewReader(tt.in))
			if how != tt.wantHow {
				t.Errorf("Reader() says it read the blob %q, want %q", how, tt.wantHow)
			}
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("reading the blob: error = %v, want one saying %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("reading the blob: %v", err)
			}
			if !bytes.Equal(got, tt.want) {
				t.Errorf("read %s, want %s", clip(got), clip(tt.want))
			}
		})
	}
}

// TestReaderClosedEarly checks that a zstd blob closed before its end is
// still read through: Close lets the command run to its end, and returns
// its verdict, so a reader that stops at the end of a tar, before the
// padding after it, gets nil for a blob that decompressed, and an error
// for one that did not. The blob is larger than a pipe's buffer, so a
// command whose output no one read would be stuck, or cut short.
func TestReaderClosedEarly(t *testing.T) {
	t.Parallel()

	body := noise(1 << 20)
	for _, tt := range []struct {
		name    string
		in      []byte
		wantErr bool
	}{
		{name: "whole", in: zst(t, body)},
		{name: "truncated", in: zst(t, body)[:1<<19], wantErr: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rc, _, err := decompress.Reader(t.Context(), execx.OS{}, bytes.NewReader(tt.in))
			if err != nil {
				t.Fatal(err)
			}
			first := make([]byte, 10)
			if _, err = io.ReadFull(rc, first); err != nil {
				t.Fatalf("reading the first bytes: %v", err)
			}
			if !bytes.Equal(first, body[:10]) {
				t.Errorf("read %q first, want %q", first, body[:10])
			}
			err = rc.Close()
			if (err != nil) != tt.wantErr {
				t.Errorf("Close() = %v, want an error %t", err, tt.wantErr)
			}
			if again := rc.Close(); !errors.Is(again, err) {
				t.Errorf("Close() again = %v, want what the first said, %v", again, err)
			}
		})
	}
}

// A cancelled read of a zstd blob ends in the context's error, never in
// what zstd wrote before it was stopped passing for the whole blob.
func TestReaderCancelled(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, _, err := readAll(ctx, execx.OS{}, bytes.NewReader(zst(t, []byte("a layer"))))
	if !errors.Is(err, context.Canceled) {
		t.Errorf("reading the blob: error = %v, want context.Canceled", err)
	}
}

// clip quotes the start of b, enough to tell two blobs apart.
func clip(b []byte) string {
	const keep = 60
	if len(b) <= keep {
		return fmt.Sprintf("%q", b)
	}
	return fmt.Sprintf("%q... (%d bytes)", b[:keep], len(b))
}
