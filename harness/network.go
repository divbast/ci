// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

package harness

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"testing"
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
	if _, err := e.output(ctx, append(args, name)...); err != nil {
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
