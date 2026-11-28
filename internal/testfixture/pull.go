// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

package testfixture

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/divbast/ci/internal/execx"
	"github.com/divbast/ci/internal/fetch"
)

// pullTimeout bounds PullBeforeTests: a test binary's own -test.timeout
// starts only inside m.Run, after it.
const pullTimeout = 10 * time.Minute

// PullBeforeTests pulls images, as Pull does, into the store of the engine
// ENGINE names, for a suite's TestMain to call before m.Run. With ENGINE
// unset the suite runs no container, and it pulls nothing. A pull that
// fails is reported on stderr under suite, its package's name, and each
// test that needs the image then pulls it on its own, as without this.
func PullBeforeTests(suite string, images ...string) {
	engine := os.Getenv("ENGINE")
	if engine == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), pullTimeout)
	defer cancel()
	if err := Pull(ctx, execx.OS{}, os.Stderr, engine, images...); err != nil {
		fmt.Fprintf(os.Stderr, "%s: pulling the fixtures before the tests: %v\n", suite, err)
	}
}

// Pull makes sure each of images is in the store of engine, docker or
// podman, run through run, and pulls each that is not, through fetch.Run,
// saying on log when it pulls one again. A suite's TestMain calls it
// before the tests run, so they find the fixtures there and none fetches
// one itself: into an empty store, as each CI run starts with, every test
// that runs a container of a fixture, or builds FROM it, would pull it
// at the same time. Every image's failure is returned, joined.
func Pull(ctx context.Context, run execx.Runner, log io.Writer, engine string, images ...string) error {
	errs := make([]error, 0, len(images))
	for _, image := range images {
		if res, err := run.Run(ctx, engine, "image", "inspect", "--format", "{{.Id}}", image); err == nil && res.Code == 0 {
			continue
		}
		_, err := fetch.Run(ctx, log, engine+" pull "+image, func(ctx context.Context, _ int) (execx.Result, error) {
			return run.Run(ctx, engine, "pull", "-q", image)
		})
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}
