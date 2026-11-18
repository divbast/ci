// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

package verify_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/divbast/ci/internal/verify"
)

func TestWriteDockerConfig(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	if err := verify.WriteDockerConfig(dir, "ada", "s3cret:t0ken"); err != nil {
		t.Fatalf("WriteDockerConfig() error = %v", err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if cerr := root.Close(); cerr != nil {
			t.Error(cerr)
		}
	})

	raw, err := root.ReadFile("config.json")
	if err != nil {
		t.Fatal(err)
	}
	auth := base64.StdEncoding.EncodeToString([]byte("ada:s3cret:t0ken"))
	if want := `{"auths":{"dhi.io":{"auth":"` + auth + `"}}}`; string(raw) != want {
		t.Errorf("config.json = %s, want %s", raw, want)
	}
	var cfg struct {
		Auths map[string]struct{ Auth string }
	}
	if err = json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("config.json is not JSON: %v", err)
	}
	if len(cfg.Auths) != 1 || cfg.Auths["dhi.io"].Auth != auth {
		t.Errorf("config.json auths = %+v, want dhi.io alone with %s", cfg.Auths, auth)
	}

	info, err := root.Stat("config.json")
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("config.json mode = %o, want 600", got)
	}
}

func TestWriteDockerConfigRefuses(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct{ name, username, token string }{
		{"no-username", "", "token"},
		{"no-token", "ada", ""},
		{"neither", "", ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()
			err := verify.WriteDockerConfig(dir, tt.username, tt.token)
			if err == nil {
				t.Fatal("WriteDockerConfig() error = nil, want an error")
			}
			if !errors.Is(err, verify.ErrNoDHILogin) {
				t.Errorf("WriteDockerConfig() error = %v, want ErrNoDHILogin", err)
			}
			entries, rerr := os.ReadDir(dir)
			if rerr != nil || len(entries) != 0 {
				t.Errorf("WriteDockerConfig() left %v in %s (error %v), want nothing", entries, dir, rerr)
			}
		})
	}
}

// TestWriteDHIKey checks that the key divbast-verify-images and
// divbast-scan hand cosign is the embedded one, at the path returned,
// readable by its owner alone, and that a file already there is refused
// rather than written over or trusted.
func TestWriteDHIKey(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path, err := verify.WriteDHIKey(dir)
	if err != nil {
		t.Fatalf("WriteDHIKey() error = %v", err)
	}
	if want := filepath.Join(dir, "dhi-2.pub"); path != want {
		t.Errorf("WriteDHIKey() = %s, want %s", path, want)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if cerr := root.Close(); cerr != nil {
			t.Error(cerr)
		}
	})
	got, err := root.ReadFile("dhi-2.pub")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, verify.DHIPublicKey) {
		t.Errorf("dhi-2.pub = %q, want DHIPublicKey", got)
	}
	info, err := root.Stat("dhi-2.pub")
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("dhi-2.pub mode = %o, want 600", got)
	}

	if _, err = verify.WriteDHIKey(dir); !errors.Is(err, fs.ErrExist) {
		t.Errorf("WriteDHIKey() over a dhi-2.pub already there: error = %v, want fs.ErrExist", err)
	}
}
