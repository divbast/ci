// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

package coreprobe

import (
	"context"
	"fmt"
	"path"
	"regexp"
	"strings"

	"github.com/divbast/ci/harness/probekit"
)

// commLength is the longest name the kernel keeps in comm, which is the
// executable's file name cut to fit.
const commLength = 15

// noCapabilities is a capability set with every bit clear.
const noCapabilities = "0000000000000000"

// capabilitySets are every capability set, as PID 1's status gives them:
// the server's, which is what the contract is about, and not the probe's
// own, which the engine may run with other capabilities than the
// server's. A process run as uid 65532 holds nothing in CapEff or CapPrm
// whatever the engine grants, since exec clears both for a user other
// than root without file or ambient capabilities. --cap-drop ALL empties
// the bounding set, so CapBnd is the one that shows what the engine was
// told.
var capabilitySets = []string{"CapEff", "CapPrm", "CapInh", "CapBnd", "CapAmb"}

// assertPID1 checks PID 1's whole argv, as the kernel keeps it, against
// the one given, and its comm against the executable's name. A
// supervisor, an init the engine added, or a bootstrap that never handed
// over to the server all leave something else there.
func (env *Env) assertPID1(_ context.Context, out *probekit.Output, argv []string) error {
	comm, err := env.readProc("1/comm")
	if err != nil {
		return err
	}
	name := path.Base(argv[0])
	out.Equal("PID 1 comm", name[:min(len(name), commLength)], strings.TrimSpace(comm))

	raw, err := env.readProc("1/cmdline")
	if err != nil {
		return err
	}
	found := strings.Split(strings.TrimSuffix(raw, "\x00"), "\x00")
	out.Equal("PID 1 argv", jsonList(argv), jsonList(found))
	return nil
}

// statusField returns the value of field in a status file: the text after
// "<field>:" on its own line, matched by value.
func statusField(status, field, value string) ([]string, error) {
	re := regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(field) + `:[ \t]*` + value + `[ \t]*$`)
	m := re.FindStringSubmatch(status)
	if m == nil {
		return nil, fmt.Errorf("/proc/1/status has no well-formed %s line", field)
	}
	return m[1:], nil
}

// user prints PID 1's Uid: and Gid: lines, as its status gives them, one
// after the other, each with its four IDs separated by tabs: the real,
// effective, saved set and filesystem ones. It asserts nothing: which IDs
// the server must run as is the harness's to say.
func (env *Env) user(_ context.Context, out *probekit.Output, _ []string) error {
	status, err := env.readProc("1/status")
	if err != nil {
		return err
	}
	for _, field := range []string{"Uid", "Gid"} {
		ids, err := statusField(status, field, `(\d+)[ \t]+(\d+)[ \t]+(\d+)[ \t]+(\d+)`)
		if err != nil {
			return err
		}
		if _, err := fmt.Fprintf(out, "%s:\t%s\n", field, strings.Join(ids, "\t")); err != nil {
			return err
		}
	}
	return nil
}

// assertCaps checks that every one of PID 1's capability sets is empty.
func (env *Env) assertCaps(_ context.Context, out *probekit.Output, _ []string) error {
	status, err := env.readProc("1/status")
	if err != nil {
		return err
	}
	for _, field := range capabilitySets {
		mask, err := statusField(status, field, `([0-9a-fA-F]+)`)
		if err != nil {
			return err
		}
		out.Record(strings.TrimLeft(mask[0], "0") == "", field+", every capability bit clear", noCapabilities, mask[0])
	}
	return nil
}
