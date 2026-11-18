// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

package dhivex_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/divbast/ci/internal/dhivex"
	"github.com/divbast/ci/internal/execx"
	"github.com/divbast/ci/internal/verify"
)

const (
	digest = "sha256:9221d55b3bcf618cc56da297a64b1c3294458048109b95b8f3ce39d2dd8e0b33"
	// key is the path Verifier.Key names in these tests, which cosign,
	// a Fake here, never reads.
	key = "/keys/dhi-2.pub"
)

// document and bundle are what the advisories serve for name: an OpenVEX
// document and its Sigstore bundle, each its own so that a mix-up shows.
func document(name string) string {
	return `{"@context":"https://openvex.dev/ns/v0.2.0","@id":"https://dhi.docker.com/vex/` + name + `",` +
		`"author":"Docker Hardened Images <dhi@docker.com>","statements":[]}` + "\n"
}

func bundle(name string) string {
	return `{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json","for":"` + name + `"}` + "\n"
}

// documentPath and bundlePath are where the advisories keep name's.
func documentPath(name string) string { return "/vex/" + name + "/dhi-" + name + ".vex.json" }
func bundlePath(name string) string   { return documentPath(name) + ".sig" }

// advisories is the advisories repository as raw.githubusercontent.com
// serves it: each of files at its path, a 404 for anything else, unless
// status names another answer for the path. It keeps every path asked
// for, in order, and fails the test on a request that carries
// credentials: the documents are public, and nothing is sent with them.
type advisories struct {
	t      *testing.T
	files  map[string]string
	status map[string]int

	mu    sync.Mutex
	asked []string
}

func (a *advisories) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	a.asked = append(a.asked, r.URL.Path)
	a.mu.Unlock()
	if r.Method != http.MethodGet {
		a.t.Errorf("%s %s, want GET", r.Method, r.URL.Path)
	}
	for _, header := range []string{"Authorization", "Cookie"} {
		if v := r.Header.Get(header); v != "" {
			a.t.Errorf("%s %s sent %s: %q, want nothing", r.Method, r.URL.Path, header, v)
		}
	}
	if code, ok := a.status[r.URL.Path]; ok {
		w.WriteHeader(code)
		return
	}
	body, ok := a.files[r.URL.Path]
	if !ok {
		http.NotFound(w, r)
		return
	}
	if _, err := io.WriteString(w, body); err != nil {
		a.t.Errorf("serve %s: %v", r.URL.Path, err)
	}
}

func (a *advisories) paths() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return slices.Clone(a.asked)
}

// serving returns the advisories with the document and bundle of each of
// names.
func serving(t *testing.T, names ...string) *advisories {
	t.Helper()
	a := &advisories{t: t, files: map[string]string{}, status: map[string]int{}}
	for _, name := range names {
		a.files[documentPath(name)] = document(name)
		a.files[bundlePath(name)] = bundle(name)
	}
	return a
}

// verifyBlob is the cosign call that verifies name's document in dir,
// answering with code and stderr.
func verifyBlob(dir, name string, code int, stderr string) execx.Call {
	doc := filepath.Join(dir, "dhi-"+name+".vex.json")
	return execx.Call{
		Argv:   []string{"cosign", "verify-blob", "--key", key, "--bundle", doc + ".sig", doc},
		Result: execx.Result{Code: code, Stderr: []byte(stderr)},
	}
}

// seeing runs cosign through a Fake, and keeps what each file its last
// two arguments name, the bundle and the document, held when it ran: what
// was verified, which must be what is passed on.
type seeing struct {
	t    *testing.T
	fake *execx.Fake
	saw  map[string]string
}

func (s *seeing) Run(ctx context.Context, name string, args ...string) (execx.Result, error) {
	if len(args) >= 2 {
		for _, path := range args[len(args)-2:] {
			data, err := os.ReadFile(path) //nolint:gosec // G304: a path in the test's own directory
			if err != nil {
				s.t.Errorf("%s ran on %s, which it could not read: %v", name, path, err)
				continue
			}
			s.saw[filepath.Base(path)] = string(data)
		}
	}
	return s.fake.Run(ctx, name, args...)
}

func TestNames(t *testing.T) {
	t.Parallel()

	ref := func(name string, line int) verify.Ref {
		return verify.Ref{Name: name, Tag: "1", Digest: digest, Line: line}
	}
	for _, tt := range []struct {
		name    string
		refs    []verify.Ref
		want    []string
		wantErr string
	}{
		{name: "none", refs: nil},
		{name: "no-dhi", refs: []verify.Ref{ref("gcr.io/distroless/cc-debian13", 1), ref("golang", 2)}},
		{name: "one", refs: []verify.Ref{ref("golang", 1), ref("dhi.io/aspnetcore", 2)}, want: []string{"aspnetcore"}},
		{
			// Prowlarr's: one image for two stages, then others, each
			// once and in the order the Containerfile first names them
			name: "several",
			refs: []verify.Ref{
				ref("dhi.io/aspnetcore", 18), ref("dhi.io/node", 21), ref("dhi.io/node", 52),
				ref("dhi.io/dotnet", 59), ref("dhi.io/golang", 109),
			},
			want: []string{"aspnetcore", "node", "dotnet", "golang"},
		},
		{name: "upper-case-host", refs: []verify.Ref{ref("DHI.io/dotnet", 3)}, want: []string{"dotnet"}},
		{name: "nested", refs: []verify.Ref{ref("dhi.io/aspnetcore", 2), ref("dhi.io/library/node", 5)}, wantErr: "line 5"},
		{name: "upper-case-name", refs: []verify.Ref{ref("dhi.io/AspNetCore", 4)}, wantErr: "line 4"},
		{name: "dots-alone", refs: []verify.Ref{ref("dhi.io/..", 6)}, wantErr: "line 6"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := dhivex.Names(tt.refs)
			if tt.wantErr != "" {
				if !errors.Is(err, dhivex.ErrName) || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("Names() = %q, %v; want ErrName naming %s", got, err, tt.wantErr)
				}
				return
			}
			if err != nil || !slices.Equal(got, tt.want) {
				t.Errorf("Names() = %q, %v; want %q", got, err, tt.want)
			}
		})
	}
}

func TestDocuments(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name string
		// names are the images asked for, and served those the
		// advisories hold; status overrides the answer for a path.
		names, served []string
		status        map[string]int
		// cosign returns the cosign calls scripted for dir.
		cosign func(dir string) []execx.Call
		// wantAsked is every path the advisories must be asked for, in
		// order; want the documents' names in dir, on success.
		wantAsked []string
		want      []string
		wantErr   error
		// wantErrText is what the error must say, and wantLog what cosign's
		// report, passed on, must hold.
		wantErrText, wantLog []string
	}{
		{
			name:   "one",
			names:  []string{"aspnetcore"},
			served: []string{"aspnetcore"},
			cosign: func(dir string) []execx.Call {
				return []execx.Call{verifyBlob(dir, "aspnetcore", 0, "Verified OK\n")}
			},
			wantAsked: []string{documentPath("aspnetcore"), bundlePath("aspnetcore")},
			want:      []string{"dhi-aspnetcore.vex.json"},
			wantLog:   []string{"Verified OK\n"},
		},
		{
			name:   "several",
			names:  []string{"aspnetcore", "node", "dotnet"},
			served: []string{"aspnetcore", "node", "dotnet", "golang"},
			cosign: func(dir string) []execx.Call {
				return []execx.Call{
					verifyBlob(dir, "aspnetcore", 0, ""), verifyBlob(dir, "node", 0, ""), verifyBlob(dir, "dotnet", 0, ""),
				}
			},
			wantAsked: []string{
				documentPath("aspnetcore"), bundlePath("aspnetcore"), documentPath("node"), bundlePath("node"),
				documentPath("dotnet"), bundlePath("dotnet"),
			},
			want: []string{"dhi-aspnetcore.vex.json", "dhi-node.vex.json", "dhi-dotnet.vex.json"},
		},
		{
			name:   "none",
			cosign: func(string) []execx.Call { return nil },
		},
		{
			name:   "not-verified",
			names:  []string{"aspnetcore"},
			served: []string{"aspnetcore"},
			cosign: func(dir string) []execx.Call {
				return []execx.Call{verifyBlob(dir, "aspnetcore", 1, "Error: failed to verify signature: invalid signature\n")}
			},
			wantAsked:   []string{documentPath("aspnetcore"), bundlePath("aspnetcore")},
			wantErr:     dhivex.ErrNotVerified,
			wantErrText: []string{"dhi.io/aspnetcore", "dhi-2.pub", "exited 1"},
			wantLog:     []string{"invalid signature"},
		},
		{
			// The first passes, and is still not passed on
			name:   "second-not-verified",
			names:  []string{"aspnetcore", "node"},
			served: []string{"aspnetcore", "node"},
			cosign: func(dir string) []execx.Call {
				return []execx.Call{verifyBlob(dir, "aspnetcore", 0, ""), verifyBlob(dir, "node", 1, "")}
			},
			wantAsked: []string{
				documentPath("aspnetcore"), bundlePath("aspnetcore"), documentPath("node"), bundlePath("node"),
			},
			wantErr:     dhivex.ErrNotVerified,
			wantErrText: []string{"dhi.io/node"},
		},
		{
			// Asked for once: a 404 is an answer, not a failure to answer
			name:        "no-document",
			names:       []string{"aspnetcore"},
			cosign:      func(string) []execx.Call { return nil },
			wantAsked:   []string{documentPath("aspnetcore")},
			wantErr:     dhivex.ErrFetch,
			wantErrText: []string{"dhi.io/aspnetcore", "404", "dhi-aspnetcore.vex.json"},
		},
		{
			name:        "no-bundle",
			names:       []string{"aspnetcore"},
			served:      []string{"aspnetcore"},
			status:      map[string]int{bundlePath("aspnetcore"): http.StatusNotFound},
			cosign:      func(string) []execx.Call { return nil },
			wantAsked:   []string{documentPath("aspnetcore"), bundlePath("aspnetcore")},
			wantErr:     dhivex.ErrFetch,
			wantErrText: []string{"dhi.io/aspnetcore", "404", "dhi-aspnetcore.vex.json.sig"},
		},
		{
			name:        "refused",
			names:       []string{"aspnetcore"},
			served:      []string{"aspnetcore"},
			status:      map[string]int{documentPath("aspnetcore"): http.StatusForbidden},
			cosign:      func(string) []execx.Call { return nil },
			wantAsked:   []string{documentPath("aspnetcore")},
			wantErr:     dhivex.ErrFetch,
			wantErrText: []string{"dhi.io/aspnetcore", "403"},
		},
		{
			name:        "second-missing",
			names:       []string{"aspnetcore", "node"},
			served:      []string{"aspnetcore"},
			cosign:      func(dir string) []execx.Call { return []execx.Call{verifyBlob(dir, "aspnetcore", 0, "")} },
			wantAsked:   []string{documentPath("aspnetcore"), bundlePath("aspnetcore"), documentPath("node")},
			wantErr:     dhivex.ErrFetch,
			wantErrText: []string{"dhi.io/node", "404"},
		},
		{
			// Names reaches here already checked; anything else names a
			// path outside dir, and is asked for nowhere
			name:        "not-a-name",
			names:       []string{"../aspnetcore"},
			cosign:      func(string) []execx.Call { return nil },
			wantErr:     dhivex.ErrName,
			wantErrText: []string{"../aspnetcore"},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			a := serving(t, tt.served...)
			maps.Copy(a.status, tt.status)
			srv := httptest.NewServer(a)
			t.Cleanup(srv.Close)

			dir := t.TempDir()
			cosign := &seeing{t: t, fake: execx.NewFake(t, tt.cosign(dir)...), saw: map[string]string{}}
			var log bytes.Buffer
			src := dhivex.Source{Client: srv.Client(), Base: srv.URL + "/vex/"}
			got, err := dhivex.Documents(t.Context(), src, dhivex.Verifier{Cosign: cosign, Key: key, Log: &log}, dir, tt.names)

			if asked := a.paths(); !slices.Equal(asked, tt.wantAsked) {
				t.Errorf("asked the advisories for %q, want %q", asked, tt.wantAsked)
			}
			for _, want := range tt.wantLog {
				if !strings.Contains(log.String(), want) {
					t.Errorf("log = %q, want it to hold %q", log.String(), want)
				}
			}
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("Documents() = %q, %v; want an error wrapping %v", got, err, tt.wantErr)
				}
				for _, want := range tt.wantErrText {
					if !strings.Contains(err.Error(), want) {
						t.Errorf("Documents() error = %q, want it to say %q", err, want)
					}
				}
				if got != nil {
					t.Errorf("Documents() = %q with its error, want nothing to apply", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("Documents() error = %v", err)
			}
			want := make([]string, 0, len(tt.want))
			for _, name := range tt.want {
				want = append(want, filepath.Join(dir, name))
			}
			if !slices.Equal(got, want) {
				t.Errorf("Documents() = %q, want %q", got, want)
			}
			// Each document passed on is, byte for byte, what was served
			// and what cosign verified, beside the bundle it verified with
			for i, path := range got {
				name := tt.names[i]
				data, err := os.ReadFile(path) //nolint:gosec // G304: a path in the test's own directory
				if err != nil {
					t.Fatal(err)
				}
				base := filepath.Base(path)
				if string(data) != document(name) || cosign.saw[base] != document(name) {
					t.Errorf("%s holds %q, and cosign verified %q; want %q served", base, data, cosign.saw[base], document(name))
				}
				if cosign.saw[base+".sig"] != bundle(name) {
					t.Errorf("cosign verified %s with %q, want %q served", base, cosign.saw[base+".sig"], bundle(name))
				}
			}
		})
	}
}

// TestDocumentsTooLarge sends one byte more than a fetch reads, and sees
// it refused unread rather than cut short and passed on.
func TestDocumentsTooLarge(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Chunked, with no Content-Length, so only reading tells
		w.Header().Set("Content-Type", "application/json")
		if _, err := io.CopyN(w, zeros{}, dhivex.MaxSize+1); err != nil {
			t.Logf("the client stopped reading: %v", err)
		}
	}))
	t.Cleanup(srv.Close)

	src := dhivex.Source{Client: srv.Client(), Base: srv.URL + "/vex/"}
	v := dhivex.Verifier{Cosign: execx.NewFake(t), Key: key, Log: io.Discard}
	got, err := dhivex.Documents(t.Context(), src, v, t.TempDir(), []string{"golang"})
	if !errors.Is(err, dhivex.ErrFetch) || !strings.Contains(err.Error(), "dhi.io/golang") ||
		!strings.Contains(err.Error(), strconv.Itoa(dhivex.MaxSize>>20)+" MiB") {
		t.Fatalf("Documents() = %q, %v; want ErrFetch for dhi.io/golang, saying the limit", got, err)
	}
}

// zeros reads as an endless run of zero bytes.
type zeros struct{}

func (zeros) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

// TestDocumentsNoKey refuses a Verifier with no key before anything is
// fetched: cosign with no --key would look for a signer elsewhere.
func TestDocumentsNoKey(t *testing.T) {
	t.Parallel()

	a := serving(t, "aspnetcore")
	srv := httptest.NewServer(a)
	t.Cleanup(srv.Close)
	src := dhivex.Source{Client: srv.Client(), Base: srv.URL + "/vex/"}
	v := dhivex.Verifier{Cosign: execx.NewFake(t), Log: io.Discard}
	if got, err := dhivex.Documents(t.Context(), src, v, t.TempDir(), []string{"aspnetcore"}); err == nil ||
		!strings.Contains(err.Error(), "dhi-2.pub") {
		t.Errorf("Documents() = %q, %v; want an error naming the missing dhi-2.pub", got, err)
	}
	if asked := a.paths(); len(asked) != 0 {
		t.Errorf("asked the advisories for %q with no key to verify against, want nothing", asked)
	}
}

// roundTrip is an http.RoundTripper that answers in memory, so that
// synctest's clock alone decides how long anything takes.
type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// answer is one way the advisories answer a request for a document.
type answer func(*http.Request) (*http.Response, error)

func status(code int, body string) answer {
	return func(r *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: code, Status: strconv.Itoa(code) + " " + http.StatusText(code),
			Body: io.NopCloser(strings.NewReader(body)), Request: r, Header: http.Header{},
		}, nil
	}
}

var (
	errReset = errors.New("connection reset by peer")
	reset    = func(*http.Request) (*http.Response, error) { return nil, errReset }
	// hang answers nothing until the request's context ends.
	hang = func(r *http.Request) (*http.Response, error) {
		<-r.Context().Done()
		return nil, r.Context().Err()
	}
)

// TestDocumentsRetries scripts how the advisories answer each try at the
// document, the bundle always being there, and checks how many tries a
// fetch makes and how long they take on synctest's clock: one minute at
// most per try, a pause of two seconds before the second and four before
// the third, and no more. Only what a retry could fix is retried: no
// answer, a timeout, 429 and 5xx; any other answer is final.
func TestDocumentsRetries(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name string
		// answers are the answers to each try in turn, the last repeated.
		answers     []answer
		wantTries   int
		wantElapsed time.Duration
		// wantErr is nil for a fetch that succeeds.
		wantErr     error
		wantErrText string
	}{
		{name: "first-time", answers: []answer{status(200, document("aspnetcore"))}, wantTries: 1},
		{
			name:        "unavailable-once",
			answers:     []answer{status(503, ""), status(200, document("aspnetcore"))},
			wantTries:   2,
			wantElapsed: 2 * time.Second,
		},
		{
			name:        "too-many-requests-twice",
			answers:     []answer{status(429, ""), status(429, ""), status(200, document("aspnetcore"))},
			wantTries:   3,
			wantElapsed: 6 * time.Second,
		},
		{
			name:        "reset-once",
			answers:     []answer{reset, status(200, document("aspnetcore"))},
			wantTries:   2,
			wantElapsed: 2 * time.Second,
		},
		{
			name:        "always-failing",
			answers:     []answer{status(502, "")},
			wantTries:   3,
			wantElapsed: 6 * time.Second,
			wantErr:     dhivex.ErrFetch,
			wantErrText: "502 Bad Gateway, 3 times",
		},
		{
			name:        "always-reset",
			answers:     []answer{reset},
			wantTries:   3,
			wantElapsed: 6 * time.Second,
			wantErr:     errReset,
		},
		{
			name:        "never-answering",
			answers:     []answer{hang},
			wantTries:   3,
			wantElapsed: 3*time.Minute + 6*time.Second,
			wantErr:     context.DeadlineExceeded,
		},
		{
			name:        "not-found",
			answers:     []answer{status(404, "404: Not Found")},
			wantTries:   1,
			wantErr:     dhivex.ErrFetch,
			wantErrText: "404 Not Found",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			synctest.Test(t, func(t *testing.T) {
				var tries int
				client := &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
					if strings.HasSuffix(r.URL.Path, ".sig") {
						return status(200, bundle("aspnetcore"))(r)
					}
					a := tt.answers[min(tries, len(tt.answers)-1)]
					tries++
					return a(r)
				})}
				dir := t.TempDir()
				var calls []execx.Call
				if tt.wantErr == nil {
					calls = append(calls, verifyBlob(dir, "aspnetcore", 0, ""))
				}
				v := dhivex.Verifier{Cosign: execx.NewFake(t, calls...), Key: key, Log: io.Discard}
				src := dhivex.Source{Client: client, Base: "https://advisories.test/vex/"}

				start := time.Now()
				_, err := dhivex.Documents(t.Context(), src, v, dir, []string{"aspnetcore"})
				elapsed := time.Since(start)

				if tries != tt.wantTries {
					t.Errorf("tried %d times, want %d", tries, tt.wantTries)
				}
				if elapsed != tt.wantElapsed {
					t.Errorf("took %s, want %s", elapsed, tt.wantElapsed)
				}
				switch {
				case tt.wantErr == nil && err != nil:
					t.Errorf("Documents() error = %v", err)
				case tt.wantErr != nil && !errors.Is(err, tt.wantErr):
					t.Errorf("Documents() error = %v, want one wrapping %v", err, tt.wantErr)
				case tt.wantErr != nil && !strings.Contains(err.Error(), "dhi.io/aspnetcore"):
					t.Errorf("Documents() error = %q, want it to name dhi.io/aspnetcore", err)
				case tt.wantErr != nil && !strings.Contains(err.Error(), tt.wantErrText):
					t.Errorf("Documents() error = %q, want it to say %q", err, tt.wantErrText)
				}
			})
		})
	}
}

// TestDocumentsStopsWithTheCaller ends the caller's context during the
// pause after a failed try, and sees the fetch stop there with the
// caller's error, not try again or wait out the pause.
func TestDocumentsStopsWithTheCaller(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		var tries int
		client := &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
			tries++
			time.AfterFunc(time.Second, cancel)
			return status(503, "")(r)
		})}
		v := dhivex.Verifier{Cosign: execx.NewFake(t), Key: key, Log: io.Discard}
		src := dhivex.Source{Client: client, Base: "https://advisories.test/vex/"}

		start := time.Now()
		_, err := dhivex.Documents(ctx, src, v, t.TempDir(), []string{"aspnetcore"})
		if elapsed := time.Since(start); tries != 1 || elapsed != time.Second {
			t.Errorf("tried %d times in %s, want once, stopping after a second", tries, elapsed)
		}
		if !errors.Is(err, context.Canceled) {
			t.Errorf("Documents() error = %v, want context.Canceled", err)
		}
	})
}
