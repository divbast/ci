// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

// Package testcount reads a go test -json stream and says whether the run
// it records passed.
//
// go test exits 0 when every test skipped, and prints only ok, so a suite
// that never ran reads in a log as one that passed. Here a run passes only
// when at least one test passed, no test failed or skipped, no package
// failed to build, and every package the stream names ended in pass.
// Tests and subtests count alike.
package testcount

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"
)

// ErrInput marks a stream that is not go test -json's: one that could not
// be read, a line that is not an event, or no events at all.
var ErrInput = errors.New("not a go test -json stream")

// prefix opens every line Count writes of its own.
const prefix = "divbast-testcount: "

// rule closes what Count writes to errOut for a run that did not pass.
const rule = "a run passes only when a test passed, none failed or skipped, and every package built and passed"

// Result is what a stream records.
type Result struct {
	// Passed, Skipped and Failed count tests, subtests among them.
	Passed, Skipped, Failed int
	// Packages counts the packages the stream names.
	Packages int
	// Reasons says why the run did not pass, one line each. It is empty
	// for a run that passed.
	Reasons []string
}

// OK reports whether the run passed.
func (r Result) OK() bool { return len(r.Reasons) == 0 }

// Code is the exit code for what Count returned: 0 for a run that passed,
// 2 for an error wrapping ErrInput, and 1 for a run that did not pass or
// any other error, such as a write that failed.
func Code(res Result, err error) int {
	switch {
	case errors.Is(err, ErrInput):
		return 2
	case err != nil:
		return 1
	case res.OK():
		return 0
	default:
		return 1
	}
}

// event is one line of the stream, as go doc cmd/test2json describes it.
// Time and Elapsed are read only so that a line whose time is not one is
// refused; a later Go's fields are left out.
type event struct {
	Time       time.Time
	Action     string
	Package    string
	Test       string
	Elapsed    float64
	Output     string
	ImportPath string
}

// Count reads the go test -json stream r, one event a line, and writes
// each event's Output to out as it goes, unchanged, so that out reads as
// go test -v would. Once r is read through, it writes the summary to out,
// as one line:
//
//	divbast-testcount: <P> passed, <S> skipped, <F> failed in <K> package(s)
//
// and for a run that did not pass, each reason to errOut, one line each,
// then the rule the run broke. It returns what the stream recorded.
//
// An error wrapping ErrInput is a stream that is not go test -json's:
// Count stops at the first line that is not an event, and a stream with
// no events is one. It then writes no summary, since what it could not
// read is neither a run that passed nor one that failed. Any other error
// is a write that failed.
func Count(r io.Reader, out, errOut io.Writer) (Result, error) {
	t := tally{ended: map[string]bool{}}
	lines := bufio.NewReader(r)
	events := 0
	for n := 1; ; n++ {
		line, readErr := lines.ReadBytes('\n')
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return t.res, fmt.Errorf("%w: read line %d: %w", ErrInput, n, readErr)
		}
		if len(line) == 0 {
			break
		}
		e, err := parse(line)
		if err != nil {
			return t.res, fmt.Errorf("%w: line %d %w", ErrInput, n, err)
		}
		events++
		if _, err = io.WriteString(out, e.Output); err != nil {
			return t.res, fmt.Errorf("write the output: %w", err)
		}
		t.add(&e)
		if readErr != nil {
			break
		}
	}
	if events == 0 {
		return t.res, fmt.Errorf("%w: no events, so no test ran", ErrInput)
	}
	res := t.result()

	if _, err := fmt.Fprintf(out, "%s%d passed, %d skipped, %d failed in %d package(s)\n",
		prefix, res.Passed, res.Skipped, res.Failed, res.Packages); err != nil {
		return res, fmt.Errorf("write the summary: %w", err)
	}
	if res.OK() {
		return res, nil
	}
	for _, reason := range res.Reasons {
		if _, err := fmt.Fprintln(errOut, prefix+reason); err != nil {
			return res, fmt.Errorf("write why the run did not pass: %w", err)
		}
	}
	if _, err := fmt.Fprintln(errOut, prefix+rule); err != nil {
		return res, fmt.Errorf("write why the run did not pass: %w", err)
	}
	return res, nil
}

// tally is what the events so far record.
type tally struct {
	res      Result
	packages []string        // every package named, in the order first named
	ended    map[string]bool // each of those, and whether its own outcome came
}

// add counts one event.
func (t *tally) add(e *event) {
	if _, ok := t.ended[e.Package]; e.Package != "" && !ok {
		t.packages = append(t.packages, e.Package)
		t.ended[e.Package] = false
	}
	switch {
	case e.Action == "build-fail":
		t.res.Reasons = append(t.res.Reasons, "did not build: "+e.ImportPath)
	case !outcome(e.Action):
		// start, run, output and the rest say nothing of how a run ended
	case e.Test == "":
		t.ended[e.Package] = true
		switch e.Action {
		case "fail":
			t.res.Reasons = append(t.res.Reasons, "package failed: "+e.Package)
		case "skip":
			// go test's "[no test files]"
			t.res.Reasons = append(t.res.Reasons, "package ran no tests: "+e.Package)
		}
	case e.Action == "pass":
		t.res.Passed++
	case e.Action == "fail":
		t.res.Failed++
		t.res.Reasons = append(t.res.Reasons, "failed: "+e.Test+" in "+e.Package)
	default: // skip
		t.res.Skipped++
		t.res.Reasons = append(t.res.Reasons, "skipped: "+e.Test+" in "+e.Package)
	}
}

// result is what the whole stream recorded, once it has been read through.
func (t *tally) result() Result {
	res := t.res
	for _, pkg := range t.packages {
		if !t.ended[pkg] {
			res.Reasons = append(res.Reasons, "package never finished: "+pkg)
		}
	}
	if res.Passed == 0 {
		res.Reasons = append(res.Reasons, "no test passed")
	}
	res.Packages = len(t.packages)
	return res
}

// parse reads one line of the stream, its newline included, as an event.
func parse(line []byte) (event, error) {
	var e event
	err := json.Unmarshal(line, &e)
	line = bytes.TrimSuffix(line, []byte("\n")) // for the messages
	if err != nil {
		return e, fmt.Errorf("is not an event (%w): %.80q", err, line)
	}
	switch {
	case e.Action == "":
		return e, fmt.Errorf("has no Action: %.80q", line)
	case outcome(e.Action) && e.Package == "":
		return e, fmt.Errorf("has a %s with no Package: %.80q", e.Action, line)
	case e.Action == "build-fail" && e.ImportPath == "":
		return e, fmt.Errorf("has a build-fail with no ImportPath: %.80q", line)
	}
	return e, nil
}

// outcome reports whether action ends a test or a package.
func outcome(action string) bool {
	return action == "pass" || action == "fail" || action == "skip"
}
