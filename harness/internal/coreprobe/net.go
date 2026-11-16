// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

package coreprobe

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/divbast/ci/harness/probekit"
)

const (
	egressHost    = "9.9.9.9"
	egressPort    = "443"
	egressTimeout = 3 * time.Second

	// descriptorTries is how many times a process whose descriptors
	// cannot be read is looked at, descriptorRetry apart, before it counts
	// as one the probe cannot see into. The engine starts each exec
	// through its runtime, which joins the container as root before it
	// becomes the command it runs: a health check started as the probe
	// looks is one of those for a moment.
	descriptorTries = 20
	descriptorRetry = 100 * time.Millisecond

	tcpListen = "0A"
)

var (
	// The socket tables of the container's network namespace, one socket
	// per line after a header.
	tcpTables = []string{"net/tcp", "net/tcp6"}
	udpTables = []string{"net/udp", "net/udp6"}

	// socketLine is one socket in any of those tables: sl, the local
	// address:port and the remote one in hex, the state, five columns,
	// then the socket's inode.
	socketLine = regexp.MustCompile(`\A\s*\d+:\s+[0-9A-Fa-f]+:([0-9A-Fa-f]{4})\s+[0-9A-Fa-f]+:[0-9A-Fa-f]{4}\s+([0-9A-Fa-f]{2})(?:\s+\S+){5}\s+(\d+)\s`)
	// socketTarget is what readlink(2) gives for a descriptor that is a
	// socket.
	socketTarget = regexp.MustCompile(`\Asocket:\[(\d+)\]\z`)
	// tcpPort is a TCP port as assert-listeners takes one.
	tcpPort = regexp.MustCompile(`\A[1-9]\d{0,4}\z`)
)

// probeEgress checks, from inside the container, that a connection out
// to the Internet is refused.
func (env *Env) probeEgress(ctx context.Context, out *probekit.Output, _ []string) error {
	ctx, cancel := context.WithTimeout(ctx, egressTimeout)
	defer cancel()
	conn, err := env.Dial(ctx, "tcp", egressHost+":"+egressPort)
	found := "CONNECTED"
	if err == nil {
		_ = conn.Close()
	} else {
		reason := err.Error()
		if errno, ok := errors.AsType[syscall.Errno](err); ok {
			reason = fmt.Sprintf("errno %d: %s", int(errno), errnoText(errno))
		}
		found = "no connection (" + reason + ")"
	}
	out.Record(err != nil, "outbound TCP to "+egressHost+":"+egressPort+" is refused", "no connection", found)
	return nil
}

// descriptors returns what every open descriptor of every process in the
// container points at, and each process whose descriptors could not be
// read at all, as its PID and name. A process gone meanwhile adds nothing
// to either.
func (env *Env) descriptors(ctx context.Context) (targets, unreadable []string, err error) {
	entries, err := fs.ReadDir(env.Proc, ".")
	if err != nil {
		return nil, nil, fmt.Errorf("cannot list /proc: %w", err)
	}
	var pending []string
	for _, e := range entries {
		if e.IsDir() && e.Name()[0] >= '0' && e.Name()[0] <= '9' {
			pending = append(pending, e.Name())
		}
	}
	for try := 1; len(pending) > 0; try++ {
		unreadable = nil
		for _, pid := range pending {
			fds, err := fs.ReadDir(env.Proc, pid+"/fd")
			if err != nil {
				if info, err := fs.Stat(env.Proc, pid); err == nil && info.IsDir() {
					unreadable = append(unreadable, pid)
				}
				continue
			}
			for _, fd := range fds {
				if target, err := fs.ReadLink(env.Proc, pid+"/fd/"+fd.Name()); err == nil {
					targets = append(targets, target)
				}
			}
		}
		if try == descriptorTries {
			break
		}
		pending = unreadable
		if len(pending) > 0 {
			select {
			case <-ctx.Done():
				return nil, nil, ctx.Err()
			case <-time.After(descriptorRetry):
			}
		}
	}
	named := make([]string, len(unreadable))
	for i, pid := range unreadable {
		comm, _ := fs.ReadFile(env.Proc, pid+"/comm")
		named[i] = pid + " (" + strings.TrimSpace(string(comm)) + ")"
	}
	return targets, named, nil
}

// socketInodes returns the inode of every socket among targets.
func socketInodes(targets []string) map[uint64]bool {
	held := make(map[uint64]bool)
	for _, t := range targets {
		if m := socketTarget.FindStringSubmatch(t); m != nil {
			if inode, err := strconv.ParseUint(m[1], 10, 64); err == nil {
				held[inode] = true
			}
		}
	}
	return held
}

// heldPorts returns the local port of every socket in table, read as
// content, that a process in the container holds, by inode, and with
// listening only TCP sockets in LISTEN. A line that is not a socket is
// an error: a table this misreads must not pass for one with nothing in
// it.
func heldPorts(table, content string, held map[uint64]bool, listening bool) ([]int, error) {
	var ports []int
	for _, line := range strings.Split(strings.TrimSpace(content), "\n")[1:] {
		m := socketLine.FindStringSubmatch(line)
		if m == nil {
			return nil, fmt.Errorf("%s has a line that is not a socket: %s", table, line)
		}
		if listening && !strings.EqualFold(m[2], tcpListen) {
			continue
		}
		inode, err := strconv.ParseUint(m[3], 10, 64)
		if err != nil || !held[inode] {
			continue
		}
		port, err := strconv.ParseUint(m[1], 16, 16)
		if err != nil {
			return nil, fmt.Errorf("%s has a line that is not a socket: %s", table, line)
		}
		ports = append(ports, int(port))
	}
	return ports, nil
}

// table is one socket table: its name, for an error, and what it holds.
type table struct{ name, content string }

// listeners returns the TCP ports a process in the container listens on,
// and the UDP ports it holds a socket on, from the kernel's own tables,
// so a socket no process advertises counts too. Only sockets a process
// here holds count: Docker's resolver for a user-defined network has a
// TCP listener and a UDP socket in the same namespace, at 127.0.0.11, but
// held from outside the container.
func listeners(tcp, udp []table, held map[uint64]bool) (tcpPorts, udpPorts []int, err error) {
	for _, t := range tcp {
		p, err := heldPorts(t.name, t.content, held, true)
		if err != nil {
			return nil, nil, err
		}
		tcpPorts = append(tcpPorts, p...)
	}
	for _, t := range udp {
		p, err := heldPorts(t.name, t.content, held, false)
		if err != nil {
			return nil, nil, err
		}
		udpPorts = append(udpPorts, p...)
	}
	return sortedPorts(tcpPorts), sortedPorts(udpPorts), nil
}

// sortedPorts returns ports sorted, each once.
func sortedPorts(ports []int) []int {
	ports = slices.Clone(ports)
	slices.Sort(ports)
	return slices.Compact(ports)
}

// joinPorts returns ports separated by spaces, or none when there are
// none and none is given.
func joinPorts(ports []int, none string) string {
	if len(ports) == 0 {
		return none
	}
	words := make([]string, len(ports))
	for i, p := range ports {
		words[i] = strconv.Itoa(p)
	}
	return strings.Join(words, " ")
}

// readTables reads the socket tables names, under /proc.
func (env *Env) readTables(names []string) ([]table, error) {
	tables := make([]table, len(names))
	for i, name := range names {
		content, err := env.readProc(name)
		if err != nil {
			return nil, err
		}
		tables[i] = table{name: "/proc/" + name, content: content}
	}
	return tables, nil
}

// assertListeners checks that the TCP ports given are the only ones a
// process in the container listens on, and that no process in it holds a
// UDP socket at all. Only the sockets of a process whose descriptors the
// probe can read count, so one it cannot read is a failure of its own:
// whatever that process listened on would go unseen.
func (env *Env) assertListeners(ctx context.Context, out *probekit.Output, args []string) error {
	expected := make([]int, len(args))
	for i, a := range args {
		p, err := strconv.Atoi(a)
		if !tcpPort.MatchString(a) || err != nil || p > 65535 {
			return fmt.Errorf("'%s' is not a TCP port", a)
		}
		expected[i] = p
	}
	targets, unreadable, err := env.descriptors(ctx)
	if err != nil {
		return err
	}
	tcp, err := env.readTables(tcpTables)
	if err != nil {
		return err
	}
	udp, err := env.readTables(udpTables)
	if err != nil {
		return err
	}
	tcpPorts, udpPorts, err := listeners(tcp, udp, socketInodes(targets))
	if err != nil {
		return err
	}

	out.Equal("TCP ports a process in the container listens on", joinPorts(sortedPorts(expected), ""), joinPorts(tcpPorts, ""))
	out.Equal("UDP ports a process in the container holds a socket on", "none", joinPorts(udpPorts, "none"))
	found := "none"
	if len(unreadable) > 0 {
		found = strings.Join(unreadable, ", ")
	}
	out.Equal("processes in the container whose descriptors the probe cannot read", "none", found)
	return nil
}

// parseListeners prints "tcp <port>" for each TCP port listened on and
// "udp <port>" for each UDP port held, as assert-listeners counts them,
// from a TCP table, a UDP table and a file of descriptor targets, one per
// line. It reads the files named, not /proc, so its parsing can be tested
// anywhere.
func parseListeners(_ context.Context, out *probekit.Output, args []string) error {
	read := func(name string) (string, error) {
		b, err := os.ReadFile(name) //nolint:gosec // G304: reading the files named is what parse-listeners is for
		if err != nil {
			return "", fmt.Errorf("cannot read %s", name)
		}
		return string(b), nil
	}
	tcp, err := read(args[0])
	if err != nil {
		return err
	}
	udp, err := read(args[1])
	if err != nil {
		return err
	}
	targets, err := read(args[2])
	if err != nil {
		return err
	}
	tcpPorts, udpPorts, err := listeners([]table{{args[0], tcp}}, []table{{args[1], udp}}, socketInodes(strings.Split(targets, "\n")))
	if err != nil {
		return err
	}
	for _, p := range tcpPorts {
		if _, err := fmt.Fprintf(out, "tcp %d\n", p); err != nil {
			return err
		}
	}
	for _, p := range udpPorts {
		if _, err := fmt.Fprintf(out, "udp %d\n", p); err != nil {
			return err
		}
	}
	return nil
}

// httpRequest sends one request, as [probekit.Request] does, and prints
// the status code on the first line and the body after it. headers holds
// one "Name: value" per line.
func httpRequest(ctx context.Context, out *probekit.Output, args []string) error {
	resp, err := probekit.Request(ctx, args[0], args[1], strings.Split(args[2], "\n"), args[3])
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(out, "%d\n%s", resp.Status, resp.Body)
	return err
}
