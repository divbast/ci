// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

package verify_test

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
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
