// Command app is the Go SDK's e2e status app, the counterpart of
// tests/e2e/direct-app.ts. It connects (mode auto: direct with DYNV_TOKEN,
// agent under `dynv run`) and serves its view of the environment as JSON on
// GET / at 127.0.0.1:$APP_PORT. SIGTERM exits 0.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	dynv "github.com/hoot-codes/dynv-go"
)

var (
	mu          sync.Mutex
	logs        = []string{}
	changes     = [][]string{}
	refused     = []string{}
	proxyEvents = []*string{}
)

func optional(v string, ok bool) *string {
	if !ok {
		return nil
	}
	return &v
}

func main() {
	// Before Connect: SIGTERM during the boot fetch must exit 0 too.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-sig
		os.Exit(0)
	}()

	startedAt := time.Now().UnixMilli()
	d, err := dynv.Connect(context.Background(), dynv.Options{
		BootTimeout:  3 * time.Second,
		PollInterval: 2 * time.Second,
		Logger: func(m string) {
			mu.Lock()
			logs = append(logs, m)
			mu.Unlock()
			fmt.Fprintln(os.Stderr, "dynv: "+m)
		},
		// Covers the boot-time refusal as well as every later one.
		OnError: func(err error) {
			var re *dynv.RefusedError
			if errors.As(err, &re) {
				mu.Lock()
				refused = append(refused, re.Code)
				mu.Unlock()
			}
		},
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	d.OnChange(func(e dynv.ChangeEvent) {
		mu.Lock()
		changes = append(changes, e.Changed)
		mu.Unlock()
	})
	d.OnKey("PROXY_SERVER", func(v string, ok bool) {
		mu.Lock()
		proxyEvents = append(proxyEvents, optional(v, ok))
		mu.Unlock()
	})

	http.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		tokenVisible := os.Getenv("DYNV_TOKEN") != ""
		envProxy, envOK := os.LookupEnv("PROXY_SERVER")
		mu.Lock()
		body, err := json.Marshal(map[string]any{
			"pid":                   os.Getpid(),
			"startedAt":             startedAt,
			"mode":                  d.Mode(),
			"version":               d.Version(),
			"proxy":                 optional(d.Lookup("PROXY_SERVER")),
			"shared":                optional(d.Lookup("SHARED_KEY")),
			"sharedSource":          optional(d.Source("SHARED_KEY"), d.Source("SHARED_KEY") != ""),
			"databaseUrl":           optional(d.Lookup("DATABASE_URL")),
			"databaseUrlIsTemplate": d.IsTemplate("DATABASE_URL"),
			"unresolved":            d.Unresolved(),
			"envProxy":              optional(envProxy, envOK),
			"tokenVisible":          tokenVisible,
			"changes":               changes,
			"refused":               refused,
			"proxyEvents":           proxyEvents,
			"logs":                  logs,
		})
		mu.Unlock()
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	})
	l, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", os.Getenv("APP_PORT")))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := http.Serve(l, nil); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
