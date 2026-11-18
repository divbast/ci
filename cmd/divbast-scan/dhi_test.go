// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/divbast/ci/internal/dhivex"
	"github.com/divbast/ci/internal/execx"
	"github.com/divbast/ci/internal/verify"
)

// offline is a Source whose every request fails the test: a scan given
// no -containerfile, or one that names no dhi.io image, fetches nothing.
func offline(t *testing.T) dhivex.Source {
	t.Helper()
	return dhivex.Source{Client: &http.Client{Transport: refuse{t}}}
}

type refuse struct{ t *testing.T }

func (r refuse) RoundTrip(req *http.Request) (*http.Response, error) {
	r.t.Errorf("fetched %s, want nothing fetched", req.URL)
	return nil, errors.New("this scan fetches nothing")
}

// The images a Containerfile here builds from, each pinned as
// divbast-verify-images requires.
const (
	aspnetcore = "dhi.io/aspnetcore:10.0.15-debian13@sha256:9221d55b3bcf618cc56da297a64b1c3294458048109b95b8f3ce39d2dd8e0b33"
	node       = "dhi.io/node:24.22.3-debian13-dev@sha256:dee4bb11f4cb32ad31000287af8795f772ac801338a166a0e9fbbadd9674a2f8"
	dotnet     = "dhi.io/dotnet:10.0.404-sdk-debian13@sha256:40c7a4fd82c981f0df98ced709d21cabfd5491324f567c74b3b0d716477873ae"
	distroless = "gcr.io/distroless/static-debian13:nonroot@sha256:9221d55b3bcf618cc56da297a64b1c3294458048109b95b8f3ce39d2dd8e0b33"
)

// vexDocument and vexBundle are what the advisories serve for name, each
// its own so that a mix-up shows.
func vexDocument(name string) string {
	return `{"@context":"https://openvex.dev/ns/v0.2.0","@id":"https://dhi.docker.com/vex/` + name + `","statements":[]}` + "\n"
}

func vexBundle(name string) string {
	return `{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json","for":"` + name + `"}` + "\n"
}

// advisories serves the document and bundle of each of names where
// Docker's repository keeps them, a 404 for anything else, and keeps every
// path asked for. A request with credentials fails the test.
type advisories struct {
	t     *testing.T
	names []string

	mu    sync.Mutex
	asked []string
}

func (a *advisories) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	a.asked = append(a.asked, r.URL.Path)
	a.mu.Unlock()
	if v := r.Header.Get("Authorization"); v != "" {
		a.t.Errorf("GET %s sent Authorization: %q, want nothing", r.URL.Path, v)
	}
	for _, name := range a.names {
		doc := "/vex/" + name + "/dhi-" + name + ".vex.json"
		var body string
		switch r.URL.Path {
		case doc:
			body = vexDocument(name)
		case doc + ".sig":
			body = vexBundle(name)
		default:
			continue
		}
		if _, err := io.WriteString(w, body); err != nil {
			a.t.Errorf("serve %s: %v", r.URL.Path, err)
		}
		return
	}
	http.NotFound(w, r)
}

// dhiRunner runs cosign and trivy through one Fake, as trivy does, where
// {DIR} in a scripted argv stands for the directory run makes for DHI's
// documents and dhi-2.pub: known once cosign is asked to verify against
// the key in it. It keeps what each file in {DIR} that a call names held
// when each call ran.
type dhiRunner struct {
	t     *testing.T
	trivy trivy

	dir  string
	held map[string][]string
}

func (d *dhiRunner) Run(ctx context.Context, name string, args ...string) (execx.Result, error) {
	if i := slices.Index(args, "--key"); name == "cosign" && d.dir == "" && i >= 0 && i+1 < len(args) {
		d.dir = filepath.Dir(args[i+1])
	}
	argv := slices.Clone(args)
	for i, arg := range argv {
		if d.dir == "" || filepath.Dir(arg) != d.dir {
			continue
		}
		base := filepath.Base(arg)
		argv[i] = "{DIR}/" + base
		data, err := os.ReadFile(arg) //nolint:gosec // G304: a path run made, read back
		if err != nil {
			d.t.Errorf("%s ran on %s, which it could not read: %v", name, arg, err)
		}
		d.held[base] = append(d.held[base], string(data))
	}
	return d.trivy.Run(ctx, name, argv...)
}

// verifyBlob is cosign verifying name's document in {DIR}, exiting code.
func verifyBlob(name string, code int) execx.Call {
	doc := "{DIR}/dhi-" + name + ".vex.json"
	stderr := "Verified OK\n"
	if code != 0 {
		stderr = "Error: failed to verify signature: invalid signature when validating ASN.1 encoded signature\n"
	}
	return execx.Call{
		Argv:   []string{"cosign", "verify-blob", "--key", "{DIR}/dhi-2.pub", "--bundle", doc + ".sig", doc},
		Result: execx.Result{Code: code, Stderr: []byte(stderr)},
	}
}

func dhiDoc(name string) string { return "{DIR}/dhi-" + name + ".vex.json" }

// TestRunDHIVEX gives the scan a Containerfile, and checks that when its
// final stage builds on a dhi.io image, followed back through any stage
// it names and with build arguments resolved, the scan fetches that
// image's VEX document and its bundle, has cosign verify the one with the
// other against the embedded dhi-2.pub, and passes the verified document,
// after the app's own, to both of Trivy's scans; that no build stage's
// document is fetched, its packages never shipping; that a document that
// cannot be fetched or verified fails the scan, naming the image, before
// Trivy runs; and that a final stage on any other base fetches nothing
// and changes nothing.
func TestRunDHIVEX(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		containerfile string
		// served are the images whose documents the advisories hold.
		served []string
		// own are the -vex flags, the app's own documents.
		own []string
		// cosign are the verifications run, in order.
		cosign []execx.Call
		// wantVEX is each --vex both scans get, in order; nil when
		// Trivy never runs.
		wantVEX   []string
		scans     bool
		wantAsked []string
		wantCode  int
		// wantStdout is what stdout must start with, wantStderr what
		// stderr must hold.
		wantStdout string
		wantStderr []string
	}{
		{
			name:          "one",
			containerfile: "FROM " + aspnetcore + "\n",
			served:        []string{"aspnetcore"},
			cosign:        []execx.Call{verifyBlob("aspnetcore", 0)},
			wantVEX:       []string{dhiDoc("aspnetcore")},
			scans:         true,
			wantAsked:     []string{"/vex/aspnetcore/dhi-aspnetcore.vex.json", "/vex/aspnetcore/dhi-aspnetcore.vex.json.sig"},
			wantStdout: "applying the VEX document of dhi.io/aspnetcore, the final stage's base, verified against dhi-2.pub\n" +
				"compared with " + digest + "\n",
			wantStderr: []string{"Verified OK\n"},
		},
		{
			// Prowlarr's shape: dhi.io build stages, one of them twice,
			// then the runtime from a build argument naming another
			// dhi.io image, whose document alone is fetched
			name: "dhi-build-stages-and-runtime",
			containerfile: "ARG RUNTIME_IMAGE=" + aspnetcore + "\n" +
				"FROM " + node + " AS fetch\n" +
				"FROM " + node + " AS frontend\n" +
				"FROM " + dotnet + " AS backend\n" +
				"FROM ${RUNTIME_IMAGE}\n" +
				"COPY --from=backend /app /app\n",
			served:     []string{"aspnetcore", "node", "dotnet"},
			cosign:     []execx.Call{verifyBlob("aspnetcore", 0)},
			wantVEX:    []string{dhiDoc("aspnetcore")},
			scans:      true,
			wantAsked:  []string{"/vex/aspnetcore/dhi-aspnetcore.vex.json", "/vex/aspnetcore/dhi-aspnetcore.vex.json.sig"},
			wantStdout: "applying the VEX document of dhi.io/aspnetcore, the final stage's base, verified against dhi-2.pub\ncompared with",
		},
		{
			name:          "dhi-build-stage-and-another-runtime",
			containerfile: "FROM " + node + " AS build\nFROM " + distroless + "\nCOPY --from=build /out /out\n",
			served:        []string{"node"},
			scans:         true,
			wantStdout:    "compared with " + digest + "\n",
		},
		{
			name: "an-earlier-stage",
			containerfile: "FROM " + aspnetcore + " AS base\n" +
				"FROM " + node + " AS build\n" +
				"FROM base\n" +
				"COPY --from=build /out /out\n",
			served:    []string{"aspnetcore", "node"},
			cosign:    []execx.Call{verifyBlob("aspnetcore", 0)},
			wantVEX:   []string{dhiDoc("aspnetcore")},
			scans:     true,
			wantAsked: []string{"/vex/aspnetcore/dhi-aspnetcore.vex.json", "/vex/aspnetcore/dhi-aspnetcore.vex.json.sig"},
		},
		{
			// A build argument naming a stage, built on another dhi.io
			// image, while a dhi.io build stage comes after it
			name: "an-arg-naming-a-stage",
			containerfile: "ARG FINAL=runtime\n" +
				"FROM " + node + " AS runtime\n" +
				"FROM " + dotnet + " AS build\n" +
				"FROM ${FINAL}\n" +
				"COPY --from=build /app /app\n",
			served:     []string{"node", "dotnet"},
			cosign:     []execx.Call{verifyBlob("node", 0)},
			wantVEX:    []string{dhiDoc("node")},
			scans:      true,
			wantAsked:  []string{"/vex/node/dhi-node.vex.json", "/vex/node/dhi-node.vex.json.sig"},
			wantStdout: "applying the VEX document of dhi.io/node, the final stage's base, verified against dhi-2.pub\n",
		},
		{
			name: "a-chain-of-stages-to-another-runtime",
			containerfile: "FROM " + distroless + " AS base\n" +
				"FROM base AS runtime\n" +
				"FROM " + aspnetcore + " AS build\n" +
				"FROM runtime\n",
			served: []string{"aspnetcore"},
			scans:  true,
		},
		{
			name:          "scratch",
			containerfile: "FROM " + node + " AS build\nFROM scratch\nCOPY --from=build /out /\n",
			served:        []string{"node"},
			scans:         true,
		},
		{
			// The app's own first, as given, then Docker's
			name:          "with-the-apps-own",
			containerfile: "FROM " + aspnetcore + "\n",
			served:        []string{"aspnetcore"},
			own:           []string{"openvex.json"},
			cosign:        []execx.Call{verifyBlob("aspnetcore", 0)},
			wantVEX:       []string{"openvex.json", dhiDoc("aspnetcore")},
			scans:         true,
			wantAsked:     []string{"/vex/aspnetcore/dhi-aspnetcore.vex.json", "/vex/aspnetcore/dhi-aspnetcore.vex.json.sig"},
		},
		{
			name:          "no-dhi",
			containerfile: "FROM " + distroless + "\n",
			served:        []string{"aspnetcore"},
			scans:         true,
			wantStdout:    "compared with " + digest + "\n",
		},
		{
			// An empty -vex names nothing, as it always has
			name:          "no-dhi-with-the-apps-own",
			containerfile: "FROM " + distroless + "\n",
			own:           []string{"openvex.json", "", "more.openvex.json"},
			wantVEX:       []string{"openvex.json", "more.openvex.json"},
			scans:         true,
		},
		{
			name:          "not-verified",
			containerfile: "FROM " + aspnetcore + "\n",
			served:        []string{"aspnetcore"},
			cosign:        []execx.Call{verifyBlob("aspnetcore", 1)},
			wantAsked:     []string{"/vex/aspnetcore/dhi-aspnetcore.vex.json", "/vex/aspnetcore/dhi-aspnetcore.vex.json.sig"},
			wantCode:      1,
			wantStderr:    []string{"invalid signature", "dhi.io/aspnetcore: dhi-aspnetcore.vex.json not verified against dhi-2.pub"},
		},
		{
			// A build stage's document there is no stand-in for the
			// runtime's
			name:          "not-found",
			containerfile: "FROM " + node + " AS build\nFROM " + aspnetcore + "\n",
			served:        []string{"node"},
			wantAsked:     []string{"/vex/aspnetcore/dhi-aspnetcore.vex.json"},
			wantCode:      1,
			wantStderr:    []string{"dhi.io/aspnetcore: could not fetch", "dhi-aspnetcore.vex.json: it answered 404 Not Found"},
		},
		{
			name:          "unpinned",
			containerfile: "FROM dhi.io/aspnetcore:10.0.15-debian13\n",
			wantCode:      1,
			wantStderr:    []string{"CONTAINERFILE: could not apply DHI's signed VEX", "line 1 has dhi.io/aspnetcore:10.0.15-debian13"},
		},
		{
			name:       "no-containerfile",
			wantCode:   1,
			wantStderr: []string{"CONTAINERFILE: could not apply DHI's signed VEX"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			a := &advisories{t: t, names: tt.served}
			srv := httptest.NewServer(a)
			t.Cleanup(srv.Close)

			dir := t.TempDir()
			paths := map[string]string{}
			for _, p := range []string{"layout", "report.json", "baseline.json", "report.sarif", "Containerfile"} {
				paths[p] = filepath.Join(dir, p)
			}
			if tt.containerfile != "" {
				if err := os.WriteFile(paths["Containerfile"], []byte(tt.containerfile), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			args := []string{
				"-layout", paths["layout"], "-report", paths["report.json"], "-published", published,
				"-baseline", paths["baseline.json"], "-sarif", paths["report.sarif"],
				"-containerfile", paths["Containerfile"],
			}
			for _, doc := range tt.own {
				args = append(args, "-vex", doc)
			}

			calls := slices.Clone(tt.cosign)
			if tt.scans {
				var vex []string
				for _, doc := range tt.wantVEX {
					vex = append(vex, "--vex", doc)
				}
				scanArgs := slices.Concat(vex, []string{"--severity", "HIGH,CRITICAL", "--format", "json"})
				calls = append(calls,
					execx.Call{Argv: slices.Concat([]string{"trivy", "image", "--input", paths["layout"]}, scanArgs,
						[]string{"--output", paths["report.json"]})},
					execx.Call{Argv: []string{"trivy", "convert", "--format", "sarif", "--output", paths["report.sarif"], paths["report.json"]}},
					execx.Call{Argv: skopeoArgv, Result: execx.Result{Stdout: skopeoRecording(t, "skopeo-librespeed-latest.json")}},
					execx.Call{Argv: slices.Concat(
						[]string{"trivy", "image", "--image-src", "remote", "--platform", "linux/amd64", "--skip-db-update"}, scanArgs,
						[]string{"--output", paths["baseline.json"], published},
					)},
				)
			}
			runner := &dhiRunner{t: t, held: map[string][]string{}, trivy: trivy{
				fake: execx.NewFake(t, calls...),
				reports: map[string]string{
					paths["report.json"]:   report(t, "amd64", "", 3, "CVE-1"),
					paths["baseline.json"]: report(t, "amd64", digest, 3, "CVE-1"),
				},
			}}
			src := dhivex.Source{Client: srv.Client(), Base: srv.URL + "/vex/"}

			var stdout, stderr bytes.Buffer
			code := run(t.Context(), args, runner, src, func(string) string { return "" }, &stdout, &stderr)
			errText := strings.ReplaceAll(stderr.String(), paths["Containerfile"], "CONTAINERFILE")

			if code != tt.wantCode {
				t.Errorf("run() = %d, want %d; stderr: %s", code, tt.wantCode, errText)
			}
			if !strings.HasPrefix(stdout.String(), tt.wantStdout) {
				t.Errorf("stdout:\n%s\nwant it to start:\n%s", stdout.String(), tt.wantStdout)
			}
			for _, want := range tt.wantStderr {
				if !strings.Contains(errText, want) {
					t.Errorf("stderr = %q, want it to contain %q", errText, want)
				}
			}
			a.mu.Lock()
			asked := slices.Clone(a.asked)
			a.mu.Unlock()
			if !slices.Equal(asked, tt.wantAsked) {
				t.Errorf("asked the advisories for %q, want %q", asked, tt.wantAsked)
			}

			if len(tt.cosign) == 0 {
				return
			}
			// cosign verified against the embedded key, and every call
			// that named a document, cosign's and both of Trivy's, saw
			// what was served; all of it gone once run returns
			if runner.dir == "" {
				t.Fatal("cosign never named the key's directory")
			}
			for _, held := range runner.held["dhi-2.pub"] {
				if held != string(verify.DHIPublicKey) {
					t.Errorf("dhi-2.pub held %q when cosign ran, want DHIPublicKey", held)
				}
			}
			for _, name := range tt.served {
				base := "dhi-" + name + ".vex.json"
				for _, held := range runner.held[base] {
					if held != vexDocument(name) {
						t.Errorf("%s held %q when a call ran, want %q as served", base, held, vexDocument(name))
					}
				}
				for _, held := range runner.held[base+".sig"] {
					if held != vexBundle(name) {
						t.Errorf("%s.sig held %q when cosign ran, want %q as served", base, held, vexBundle(name))
					}
				}
			}
			if _, err := os.Stat(runner.dir); !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("run() left %s behind: stat error = %v", runner.dir, err)
			}
		})
	}
}
