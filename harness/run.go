// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

package harness

import (
	"os"
	"strconv"
	"strings"
	"sync"
)

// runKey is the key of the label that names the run, the process, that
// made something, beside the module's label: its value is the host's
// name, the process's ID and a value of the run's own, as
// host/pid/value. [Engine.Sweep] reads it to leave alone what a run of
// the same module that is still going made.
const runKey = "divbast.harness.run"

// runID names a run of a suite: the process that made something, on its
// host, and a value of its own, which tells apart two runs in one
// process, as a test of Sweep makes them.
type runID struct {
	host  string
	pid   int
	value string
}

// processRun is the run this process is, worked out once. A host whose
// name cannot be read is named "", which a host whose name can be read
// never is.
var processRun = sync.OnceValue(func() runID {
	host, _ := os.Hostname()
	return runID{host: host, pid: os.Getpid(), value: strings.TrimPrefix(uniqueName(), "divbast-")}
})

// label returns r's run label, as key=value.
func (r runID) label() string {
	return runKey + "=" + r.host + "/" + strconv.Itoa(r.pid) + "/" + r.value
}

// parseRun reads a run label's value, host/pid/value. ok is false for one
// that is not one: no host's name holds a slash.
func parseRun(s string) (r runID, ok bool) {
	host, rest, hasPID := strings.Cut(s, "/")
	pid, value, hasValue := strings.Cut(rest, "/")
	n, err := strconv.Atoi(pid)
	if !hasPID || !hasValue || err != nil || n <= 0 || value == "" || strings.Contains(value, "/") {
		return runID{}, false
	}
	return runID{host: host, pid: n, value: value}, true
}

// ended reports whether the run whose run label's value is value has
// ended, so that [Engine.Sweep] removes what it left: what carries no run
// label, as what a harness from before runs were labelled made, what e's
// own run made, and what a run of this host made whose process is no
// longer there. A run of another host, a value that is no run's, and a
// process that is there, stay, since Sweep cannot tell that they ended.
// So a run's process ID, taken since by a process that is no run, keeps
// what the run left until that process ends too.
func (e Engine) ended(value string) bool {
	if value == "" {
		return true
	}
	r, ok := parseRun(value)
	switch {
	case !ok || r.host != e.own.run.host:
		return false
	case r == e.own.run:
		return true
	}
	return !processAlive(r.pid)
}
