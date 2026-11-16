// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

package harness

import (
	"bytes"
	"context"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Network creates a network for tb, labelled, and removes it when tb ends.
// An empty name is replaced by a unique one, and an empty subnet leaves the
// engine to choose. Give a subnet to run a container at a fixed IP: a
// container run again on rootless Podman otherwise draws a new address, so
// a server that keys anything on the client's address sees a new client.
//
// internal makes a network with no route out. Network then reads back what
// the engine made, and a network that is not what was asked for is an
// error, as is every failure along the way. It returns the network's name.
// An engine with no subnet left to give is asked again, a second apart,
// for up to two minutes, since the tests running beside this one free
// theirs as they end.
func (e Engine) Network(ctx context.Context, tb testing.TB, name, subnet string, internal bool) (string, error) {
	tb.Helper()
	if name == "" {
		name = uniqueName()
	}
	args := []string{"network", "create", "--label", e.label}
	if subnet != "" {
		args = append(args, "--subnet", subnet)
	}
	if internal {
		args = append(args, "--internal")
	}
	if err := e.createNetwork(ctx, append(args, name)); err != nil {
		return "", err
	}
	e.removeOnCleanup(ctx, tb, "network", "rm", name)

	out, err := e.output(ctx, "network", "inspect", "--format", "{{.Internal}}", name)
	if err != nil {
		return "", err
	}
	if got := strings.TrimSpace(string(out)); got != strconv.FormatBool(internal) {
		return "", fmt.Errorf("network %s was created with internal %t, but %s reports internal %q", name, internal, e.name, got)
	}
	return name, nil
}

// Volume creates a named volume for tb, labelled, and removes it when tb
// ends. An empty name is replaced by a unique one. It returns the volume's
// name, for a [Mount] with Volume set.
func (e Engine) Volume(ctx context.Context, tb testing.TB, name string) (string, error) {
	tb.Helper()
	if name == "" {
		name = uniqueName()
	}
	if _, err := e.output(ctx, "volume", "create", "--label", e.label, name); err != nil {
		return "", err
	}
	e.removeOnCleanup(ctx, tb, "volume", "rm", name)
	return name, nil
}

// networkWithin bounds how long [Engine.Network] waits for a subnet to
// come free.
const networkWithin = 2 * time.Minute

// poolsFull reports whether a network create's stderr says the engine has
// none of its address pools left to give a network, in either engine's
// words: Docker has some thirty by default, and a suite running many
// tests at once, each with a network of its own, can hold them all.
func poolsFull(stderr []byte) bool {
	return bytes.Contains(stderr, []byte("all predefined address pools have been fully subnetted")) ||
		bytes.Contains(stderr, []byte("could not find free subnet"))
}

// createNetwork runs network create with args, and while the engine has
// no subnet left, runs it again a second later, until networkWithin has
// passed: a test that ends frees its network's subnet.
func (e Engine) createNetwork(ctx context.Context, args []string) error {
	deadline := time.Now().Add(networkWithin)
	for {
		res, err := e.run.RunStdin(ctx, nil, e.name, args...)
		switch {
		case err != nil:
			return err
		case res.Code == 0:
			return nil
		case !poolsFull(res.Stderr) || !time.Now().Before(deadline):
			words := fmt.Errorf("%s %s: exit status %d: %s", e.name, strings.Join(args, " "), res.Code, bytes.TrimSpace(res.Stderr))
			if poolsFull(res.Stderr) {
				return fmt.Errorf("no subnet came free within %s: %w", networkWithin, words)
			}
			return words
		}
		if err := Pause(ctx, time.Second); err != nil {
			return err
		}
	}
}
