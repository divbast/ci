// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

// Command minimal is the Go fixture: no more than a Go image needs to
// pass the contract.
//
// Usage:
//
//	minimal serve    serve the page on 8080 and /healthz on 8081
//	minimal health   exit 0, printing nothing, when both answer
//	minimal version  print the version
//
// serve listens on $MINIMAL_EXTRA_PORT as well when it is set, as an app
// with a third listener would. It stops on SIGTERM or SIGINT, as PID 1
// must, since the kernel drops a signal to PID 1 that it does not handle.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// page is what GET / answers on the app port.
const page = "minimal"

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: minimal serve|health|version")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "serve":
		if err := serve(); err != nil {
			fmt.Fprintln(os.Stderr, "minimal:", err)
			os.Exit(1)
		}
	case "health":
		if err := health(); err != nil {
			fmt.Fprintln(os.Stderr, "minimal:", err)
			os.Exit(1)
		}
	case "version":
		fmt.Println("minimal 1")
	default:
		fmt.Fprintln(os.Stderr, "usage: minimal serve|health|version")
		os.Exit(2)
	}
}

// only answers path alone, with body, and anything else 404 with nothing.
func only(path, body string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != path || (r.Method != http.MethodGet && r.Method != http.MethodHead) {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = io.WriteString(w, body)
	})
}

func serve() error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	servers := map[string]http.Handler{":8080": only("/", page), ":8081": only("/healthz", "ok")}
	if port := os.Getenv("MINIMAL_EXTRA_PORT"); port != "" {
		servers[":"+port] = only("/", page)
	}
	errs := make(chan error, len(servers))
	var running []*http.Server
	for addr, h := range servers {
		s := &http.Server{Addr: addr, Handler: h, ReadHeaderTimeout: 5 * time.Second}
		running = append(running, s)
		go func() {
			if err := s.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
				errs <- err
			}
		}()
	}
	select {
	case err := <-errs:
		return err
	case <-ctx.Done():
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, s := range running {
		if err := s.Shutdown(shutdown); err != nil {
			return err
		}
	}
	return nil
}

func health() error {
	client := &http.Client{Timeout: 4 * time.Second, Transport: &http.Transport{
		DialContext: (&net.Dialer{Timeout: 2 * time.Second}).DialContext,
	}}
	for _, url := range []string{"http://127.0.0.1:8081/healthz", "http://127.0.0.1:8080/"} {
		resp, err := client.Get(url)
		if err != nil {
			return err
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("GET %s: status %d", url, resp.StatusCode)
		}
	}
	return nil
}
