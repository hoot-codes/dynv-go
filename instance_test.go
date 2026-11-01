package dynv

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"
	"time"
)

type observedClientInstance struct {
	path     string
	instance string
}

func nextClientInstance(t *testing.T, observations <-chan observedClientInstance) observedClientInstance {
	t.Helper()
	select {
	case got := <-observations:
		return got
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for a request")
		return observedClientInstance{}
	}
}

func TestDirectClientInstanceHeader(t *testing.T) {
	response := selfCase(t, "plain")[0]["response"]
	observations := make(chan observedClientInstance, 16)
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/self/watch" && r.URL.Query().Get("caps") != "fallbacks" {
			t.Errorf("watch caps = %q, want fallbacks", r.URL.Query().Get("caps"))
		}
		observations <- observedClientInstance{r.URL.Path, r.Header.Get("X-Dynv-Client-Instance")}
		switch r.URL.Path {
		case "/v1/self":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(response)
		case "/v1/self/watch":
			<-r.Context().Done()
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer api.Close()

	var processInstance string
	connect := func() {
		c, err := Connect(context.Background(), Options{
			Mode: ModeDirect, Token: vectorToken(t), URL: api.URL,
			DisableEnvMirror: true, BootTimeout: time.Second, Logger: func(string) {},
		})
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		got := nextClientInstance(t, observations)
		if got.path != "/v1/self" {
			t.Fatalf("first request path = %q, want /v1/self", got.path)
		}
		if !regexp.MustCompile(`^[A-Za-z0-9_-]{22}$`).MatchString(got.instance) {
			t.Fatalf("direct /v1/self X-Dynv-Client-Instance = %q, want 22 base64url characters", got.instance)
		}
		first := got.instance
		if processInstance == "" {
			processInstance = first
		} else if first != processInstance {
			t.Fatalf("second client instance = %q, first client instance = %q", first, processInstance)
		}
		got = nextClientInstance(t, observations)
		if got.path != "/v1/self/watch" {
			t.Fatalf("watch request path = %q, want /v1/self/watch", got.path)
		}
		if got.instance != first {
			t.Fatalf("watch instance = %q, initial request instance = %q", got.instance, first)
		}
	}

	connect()
	connect()
}

func TestAgentOmitsClientInstanceHeader(t *testing.T) {
	observations := make(chan observedClientInstance, 4)
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		observations <- observedClientInstance{r.URL.Path, r.Header.Get("X-Dynv-Client-Instance")}
		if r.URL.Path == "/v1/env" {
			json.NewEncoder(w).Encode(Snapshot{Version: 1, Vars: map[string]string{}, Apply: map[string]string{}})
			return
		}
		<-r.Context().Done()
	}))
	defer agent.Close()

	c, err := Connect(context.Background(), Options{
		Mode: ModeAgent, AgentURL: agent.URL, AgentKey: "key",
		DisableEnvMirror: true, BootTimeout: time.Second, Logger: func(string) {},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, wantPath := range []string{"/v1/env", "/v1/env/watch"} {
		got := nextClientInstance(t, observations)
		if got.path != wantPath {
			t.Errorf("request path = %q, want %q", got.path, wantPath)
		}
		if got.instance != "" {
			t.Errorf("agent %s sent X-Dynv-Client-Instance %q", got.path, got.instance)
		}
	}
	c.Close()
}
