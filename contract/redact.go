// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

package contract

import (
	"fmt"
	"io"
	"strings"
	"testing"
)

// redacting returns tb with every message passed through redact before
// tb's log has it, or tb itself when redact is nil.
func redacting(tb testing.TB, redact func(string) string) testing.TB {
	tb.Helper()
	if redact == nil {
		return tb
	}
	return &redactor{TB: tb, redact: redact}
}

// redactor is a testing.TB whose every message, failure, skip and
// attribute passes through redact first, as does what is written to its
// Output. Everything else is tb's own: its cleanups, context and state.
type redactor struct {
	testing.TB

	redact func(string) string
}

// line is args as Log, Error, Fatal and Skip put them together.
func line(args ...any) string {
	return strings.TrimSuffix(fmt.Sprintln(args...), "\n")
}

// Log implements testing.TB.
func (r *redactor) Log(args ...any) {
	r.Helper()
	r.TB.Log(r.redact(line(args...)))
}

// Logf implements testing.TB.
func (r *redactor) Logf(format string, args ...any) {
	r.Helper()
	r.TB.Log(r.redact(fmt.Sprintf(format, args...)))
}

// Error implements testing.TB.
func (r *redactor) Error(args ...any) {
	r.Helper()
	r.TB.Error(r.redact(line(args...)))
}

// Errorf implements testing.TB.
func (r *redactor) Errorf(format string, args ...any) {
	r.Helper()
	r.TB.Error(r.redact(fmt.Sprintf(format, args...)))
}

// Fatal implements testing.TB.
func (r *redactor) Fatal(args ...any) {
	r.Helper()
	r.TB.Fatal(r.redact(line(args...)))
}

// Fatalf implements testing.TB.
func (r *redactor) Fatalf(format string, args ...any) {
	r.Helper()
	r.TB.Fatal(r.redact(fmt.Sprintf(format, args...)))
}

// Skip implements testing.TB.
func (r *redactor) Skip(args ...any) {
	r.Helper()
	r.TB.Skip(r.redact(line(args...)))
}

// Skipf implements testing.TB.
func (r *redactor) Skipf(format string, args ...any) {
	r.Helper()
	r.TB.Skip(r.redact(fmt.Sprintf(format, args...)))
}

// Attr implements testing.TB.
func (r *redactor) Attr(key, value string) {
	r.Helper()
	r.TB.Attr(key, r.redact(value))
}

// Output implements testing.TB: each write passes through redact, so a
// value split across two writes is not caught.
func (r *redactor) Output() io.Writer {
	return redactingWriter{w: r.TB.Output(), redact: r.redact}
}

// redactingWriter writes to w what it is given, passed through redact.
type redactingWriter struct {
	w      io.Writer
	redact func(string) string
}

func (rw redactingWriter) Write(p []byte) (int, error) {
	if _, err := io.WriteString(rw.w, rw.redact(string(p))); err != nil {
		return 0, err
	}
	return len(p), nil
}
