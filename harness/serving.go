// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

package harness

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"
)

// ServeWithin bounds how long [Serving.Wait] waits for a container to
// serve, and how long [Refuses] waits for one to exit.
const ServeWithin = time.Minute

// attemptWithin bounds each request [Serving.Wait] sends while it waits,
// so one the server accepted and never answered is given up and sent
// again.
const attemptWithin = 5 * time.Second

// ServeSpec is a container to serve, as [Engine.Serve] runs it.
type ServeSpec struct {
	// Run is the container. The caller sets its Image, Confine, Env,
	// Mounts, Network and HealthCmd, and Serve sets Publish: a spec that
	// sets Publish itself is refused. An empty Network has Serve make a
	// network for the container alone, removed when the test ends.
	Run RunSpec
	// AppPort is the port the app serves on inside the container, and
	// HealthPort the one its health endpoint answers on. Each is
	// published on the host's loopback, 127.0.0.1, at a port the engine
	// picks, so no two containers, or two suites, on one host collide.
	// HealthPort 0 leaves the health port unpublished, as a deployment
	// keeps it.
	AppPort, HealthPort int
	// ReadyPath is what Serve asks for, with GET from the host, until any
	// status comes back: "/" when it is empty.
	ReadyPath string
	// ProbeApp is the app's own probe subcommands, which [InstallProbe]
	// puts beside the core probe. Nil installs the core probe alone.
	ProbeApp []byte
}

// Serving is a container serving, as [Engine.Serve] or
// [Engine.StartServing] started it, with its ports published on the
// host's loopback. Get and Do send to Base, the app port, and so do the
// assertions that take a Serving; [Serving.Health] returns one that sends
// to the health port instead.
type Serving struct {
	C *Container
	// Probe is the probe in C, installed once the container serves, and
	// again after each [Serving.Restart], since a restart empties /tmp.
	// Nil until then.
	Probe *Probe
	// Base is where the app port is from the host, as
	// http://127.0.0.1:<port>, and HealthBase where the health port is,
	// empty when it is unpublished. Restart sets both again.
	Base, HealthBase string

	appPort, healthPort int
	readyPath           string
	probeApp            []byte
	// parent is the Serving a copy Health made was taken from, whose
	// health port the copy's requests go to; nil for any other Serving.
	parent *Serving
	// transport, when set, sends Get's requests in place of the default
	// transport, so a test can answer them without a connection.
	transport http.RoundTripper
}

// Serve starts a container as sp says, waits until GET sp.ReadyPath from
// the host gets any answer, and installs the probe: [Engine.StartServing],
// then [Serving.Wait]. A container that stops first, or still does not
// answer after ServeWithin, is an error carrying its log. tb's cleanup
// removes the container, and any network Serve made for it. sp itself is
// left as it was.
func (e Engine) Serve(ctx context.Context, tb testing.TB, sp *ServeSpec) (*Serving, error) {
	tb.Helper()
	s, err := e.StartServing(ctx, tb, sp)
	if err != nil {
		return nil, err
	}
	if err := s.Wait(ctx, s.readyPath); err != nil {
		return nil, err
	}
	return s, nil
}

// StartServing starts a container as sp says, and returns once the
// engine has started it and reported where its ports are on the host,
// without waiting for the server in it, and without the probe:
// [Serving.Wait] waits for both. It publishes sp.AppPort, and
// sp.HealthPort unless that is 0, each as -p 127.0.0.1::<port>, and reads
// back the host port the engine picked from [Container.Inspect]. A
// container that stopped before its ports could be read is an error
// carrying its log.
func (e Engine) StartServing(ctx context.Context, tb testing.TB, sp *ServeSpec) (*Serving, error) {
	tb.Helper()
	if err := sp.validate(); err != nil {
		return nil, err
	}
	run := sp.Run
	if run.Network == "" {
		network, err := e.Network(ctx, tb, "", "", false)
		if err != nil {
			return nil, err
		}
		run.Network = network
	}
	run.Publish = []string{loopback(sp.AppPort)}
	if sp.HealthPort != 0 {
		run.Publish = append(run.Publish, loopback(sp.HealthPort))
	}

	c, err := e.Start(ctx, tb, &run)
	if err != nil {
		return nil, err
	}
	s := &Serving{
		C:          c,
		appPort:    sp.AppPort,
		healthPort: sp.HealthPort,
		readyPath:  cmp.Or(sp.ReadyPath, "/"),
		probeApp:   sp.ProbeApp,
	}
	if err := s.readPorts(ctx); err != nil {
		return nil, err
	}
	return s, nil
}

// validate refuses a spec Serve would run as something other than it
// says.
func (sp *ServeSpec) validate() error {
	switch {
	case len(sp.Run.Publish) > 0:
		return fmt.Errorf("the serve spec publishes %q itself: Serve publishes AppPort and HealthPort, each at a host port the engine picks", sp.Run.Publish)
	case sp.AppPort < 1 || sp.AppPort > 65535:
		return fmt.Errorf("the serve spec's AppPort is %d, which is no port", sp.AppPort)
	case sp.HealthPort < 0 || sp.HealthPort > 65535:
		return fmt.Errorf("the serve spec's HealthPort is %d, which is no port, nor 0 for none", sp.HealthPort)
	case sp.HealthPort == sp.AppPort:
		return fmt.Errorf("the serve spec's AppPort and HealthPort are both %d", sp.AppPort)
	}
	return nil
}

// loopback returns the -p value that publishes port on the host's
// loopback, at a port the engine picks.
func loopback(port int) string {
	return "127.0.0.1::" + strconv.Itoa(port)
}

// readPorts sets Base and HealthBase to where the engine has the
// published ports on the host now.
func (s *Serving) readPorts(ctx context.Context) error {
	ins, err := s.C.Inspect(ctx)
	if err != nil {
		return err
	}
	base, err := s.hostURL(ctx, &ins, s.appPort)
	if err != nil {
		return err
	}
	var health string
	if s.healthPort != 0 {
		if health, err = s.hostURL(ctx, &ins, s.healthPort); err != nil {
			return err
		}
	}
	s.Base, s.HealthBase = base, health
	return nil
}

// hostURL returns the URL from the host of port in the container, as ins
// reports it. A container that has stopped holds no port: that is an
// error carrying its log, which says why it stopped.
func (s *Serving) hostURL(ctx context.Context, ins *Inspect, port int) (string, error) {
	key := strconv.Itoa(port) + "/tcp"
	if addr, ok := ins.Ports[key]; ok {
		return "http://" + addr, nil
	}
	if !ins.State.Running {
		return "", WithLog(ctx, s.C, fmt.Errorf("container %s stopped, exit status %d, before %s reported a host port for %s",
			s.C, ins.State.ExitCode, s.C.engine.name, key))
	}
	return "", fmt.Errorf("container %s has no host port for %s: %s reports %v", s.C, key, s.C.engine.name, ins.Ports)
}

// Wait sends GET path from the host once a second until any status comes
// back, then installs the probe: an answer is all serving means here, and
// a check asserts the status itself. Each request is bounded by its own
// 5 seconds, and the whole wait by ServeWithin. A container that stops
// first, or one still not serving at the end, is an error carrying its
// log, so a server that died says why. A path that cannot go out as
// written is an error at once.
func (s *Serving) Wait(ctx context.Context, path string) error {
	deadline := time.Now().Add(ServeWithin)
	for {
		attempt, cancel := context.WithTimeout(ctx, attemptWithin)
		_, err := s.Get(attempt, path, nil)
		cancel()
		if err == nil {
			break
		}
		if errors.Is(err, errUnsendable) {
			return err
		}
		ins, ierr := s.C.Inspect(ctx)
		switch {
		case ierr != nil:
			return fmt.Errorf("%w; and then: %w", err, ierr)
		case !ins.State.Running:
			return WithLog(ctx, s.C, fmt.Errorf("container %s stopped, exit status %d, before GET %s answered", s.C, ins.State.ExitCode, path))
		case !time.Now().Before(deadline):
			return WithLog(ctx, s.C, fmt.Errorf("GET %s%s got no answer within %s: %w", s.base(), path, ServeWithin, err))
		}
		if err := Pause(ctx, time.Second); err != nil {
			return err
		}
	}
	p, err := InstallProbe(ctx, s.C, s.probeApp)
	if err != nil {
		return err
	}
	s.Probe = p
	if s.parent != nil {
		s.parent.Probe = p
	}
	return nil
}

// Restart restarts the container in place, with [Container.Restart], and
// returns once it serves again, as Serve does: it reads the ports again,
// since Docker binds others on a restart, waits at the ready path the
// Serving was started with, and installs the probe again, since a restart
// empties /tmp. Until that is done, Probe is nil. A container that does
// not come back is an error carrying its log. On a copy [Serving.Health]
// made, it restarts the Serving the copy was taken from.
func (s *Serving) Restart(ctx context.Context) error {
	if s.parent != nil {
		return s.parent.Restart(ctx)
	}
	s.Probe = nil
	if err := s.C.Restart(ctx); err != nil {
		return err
	}
	if err := s.readPorts(ctx); err != nil {
		return err
	}
	return s.Wait(ctx, s.readyPath)
}

// Health returns a copy of s that sends to the health port, so Get, Do
// and StatusIs reach it through the copy as they reach the app port
// through s. Each request goes to s's HealthBase as it is when the
// request is sent, so the copy follows s across a restart, Docker's moved
// port included, and never goes to the app port in its place: with the
// health port unpublished, every request is an error saying so. Wait on
// the copy waits on the health port, and installs the probe for s too,
// and Restart on it restarts s. The copy's own fields are s's when it was
// taken, and its Base is the HealthBase s had then.
func (s *Serving) Health() *Serving {
	root := s.root()
	h := *root
	h.Base = root.HealthBase
	h.parent = root
	return &h
}

// root returns the Serving a copy Health made was taken from, or s
// itself for any other.
func (s *Serving) root() *Serving {
	if s.parent != nil {
		return s.parent
	}
	return s
}

// base returns where s's requests go now: Base, or for a copy Health
// made, its parent's HealthBase as it is now, empty when unpublished.
func (s *Serving) base() string {
	if s.parent != nil {
		return s.parent.HealthBase
	}
	return s.Base
}

// Response is the answer to one request from the host.
type Response struct {
	Status int
	Header http.Header
	Body   []byte
}

// errUnsendable marks a request that would not go out as written, and so
// was not sent. Sending it again would not change that.
var errUnsendable = errors.New("was not sent")

// Get sends GET path from the host, with header, through [HostClient],
// and reads the whole answer, as [Serving.Do] does.
func (s *Serving) Get(ctx context.Context, path string, header http.Header) (Response, error) {
	return s.Do(ctx, nil, http.MethodGet, path, header, nil)
}

// Do sends method path to Base from the host, with client, header and
// body, and reads the whole answer. A nil client is [HostClient]'s, which
// follows no redirect, and a nil body sends none.
//
// The request goes out exactly as written, as curl --path-as-is sends
// it: path holds the query too, and no dot segment is resolved and no
// escape undone. A path Go would send any other way is an error, and is
// never sent. Each header name keeps the case it was given, as a server
// that tells them apart sees it; a Host header sets the request's host.
func (s *Serving) Do(ctx context.Context, client *http.Client, method, path string, header http.Header, body []byte) (Response, error) {
	base := s.base()
	switch {
	case base == "" && s.parent != nil:
		return Response{}, fmt.Errorf("%s %s %w: the health port is unpublished, its ServeSpec's HealthPort being 0", method, path, errUnsendable)
	case base == "":
		return Response{}, fmt.Errorf("%s %s %w: the Serving has no Base, as only Engine.Serve and Engine.StartServing set one", method, path, errUnsendable)
	}
	var r io.Reader
	if body != nil {
		r = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, base+path, r)
	if err != nil {
		return Response{}, fmt.Errorf("%s %s %w: %w", method, path, errUnsendable, err)
	}
	if sent := req.URL.RequestURI(); sent != path {
		return Response{}, fmt.Errorf("%s %s would go out as %s, so it %w", method, path, sent, errUnsendable)
	}
	for name, values := range header {
		// Go writes Host from the request's own field, and would send a
		// header of that name in any other case as a second one.
		if strings.EqualFold(name, "Host") {
			if len(values) > 0 {
				req.Host = values[0]
			}
			continue
		}
		req.Header[name] = values
	}

	if client == nil {
		client = HostClient()
		if s.transport != nil {
			client.Transport = s.transport
		}
	}
	resp, err := client.Do(req)
	if err != nil {
		return Response{}, err
	}
	b, err := io.ReadAll(resp.Body)
	if err = errors.Join(err, resp.Body.Close()); err != nil {
		return Response{}, fmt.Errorf("%s %s: reading the answer: %w", method, path, err)
	}
	return Response{Status: resp.StatusCode, Header: resp.Header, Body: b}, nil
}

// PHPIn runs PHP code in c, as c's own PHP, php-cli -r, and returns what
// it printed: its stdout, then its stderr. A non-zero exit status is an
// error, carrying both.
func PHPIn(ctx context.Context, c *Container, code string) (string, error) {
	res, err := c.Exec(ctx, nil, FrankenPHP, "php-cli", "-r", code)
	if err != nil {
		return "", err
	}
	if res.Code != 0 {
		return "", fmt.Errorf("php-cli -r in container %s: exit status %d: %s", c, res.Code, combined(res))
	}
	return string(res.Stdout) + string(res.Stderr), nil
}

// WithLog returns err with c's log added, so an error about a container
// says what the container itself said. A log that cannot be read is
// named, as is an empty one.
func WithLog(ctx context.Context, c *Container, err error) error {
	logs, lerr := c.Logs(ctx)
	switch {
	case lerr != nil:
		return fmt.Errorf("%w; its log could not be read: %w", err, lerr)
	case strings.TrimSpace(logs) == "":
		return fmt.Errorf("%w; its log is empty", err)
	default:
		return fmt.Errorf("%w; its log:\n%s", err, strings.TrimSpace(logs))
	}
}

// Pause waits for d, or until ctx is done, whichever comes first. It
// returns ctx's error if ctx ended the wait, and nil otherwise.
func Pause(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
