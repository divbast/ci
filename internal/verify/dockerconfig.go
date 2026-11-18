// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

package verify

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// ErrNoDHILogin means a dhi.io image is named, and no login for dhi.io is
// given.
var ErrNoDHILogin = errors.New("dhi.io answers nothing without a login: set DHI_USERNAME and DHI_TOKEN " +
	"(in CI, pass app-check.yml the dhi-username input and the DHI_TOKEN secret)")

// WriteDockerConfig writes dir/config.json, readable by its owner alone,
// with a login for dhi.io and no other registry. It refuses an empty
// username or token, with [ErrNoDHILogin], and then writes nothing.
func WriteDockerConfig(dir, username, token string) (err error) {
	if username == "" || token == "" {
		return ErrNoDHILogin
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, root.Close()) }()
	f, err := root.OpenFile("config.json", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, f.Close()) }()
	auth := base64.StdEncoding.EncodeToString([]byte(username + ":" + token))
	_, err = fmt.Fprintf(f, `{"auths":{"dhi.io":{"auth":%q}}}`, auth)
	return err
}

// WriteDHIKey writes [DHIPublicKey] to dir/dhi-2.pub, readable by its
// owner alone, for cosign to verify against, and returns its path. It
// refuses a file already there, with an error wrapping [io/fs.ErrExist],
// rather than write over or trust what someone else put in dir.
func WriteDHIKey(dir string) (path string, err error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return "", err
	}
	defer func() { err = errors.Join(err, root.Close()) }()
	f, err := root.OpenFile("dhi-2.pub", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", err
	}
	defer func() { err = errors.Join(err, f.Close()) }()
	if _, err = f.Write(DHIPublicKey); err != nil {
		return "", err
	}
	return filepath.Join(dir, "dhi-2.pub"), nil
}
