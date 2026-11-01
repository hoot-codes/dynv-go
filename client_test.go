package dynv

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/signal"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func selfCase(t testing.TB, name string) []map[string]any {
	t.Helper()
	for _, x := range a(m(loadVectors(t, "protocol-vectors.json")["self"])["cases"]) {
		if c := m(x); s(c["name"]) == name {
			var out []map[string]any
			for _, st := range a(c["steps"]) {
				out = append(out, m(st))
			}
			return out
		}
	}
	t.Fatalf("no case %s", name)
	return nil
}

func vectorToken(t testing.TB) string {
	return s(m(loadVectors(t, "protocol-vectors.json")["self"])["token"])
}

func masterToken(t testing.TB) string {
	for _, x := range a(m(m(loadVectors(t, "protocol-vectors.json")["primitives"])["tokens"])["valid"]) {
		if s(m(x)["kind"]) == "mt" {
			return s(m(x)["token"])
		}
	}
	t.Fatal("no mt vector")
	return ""
}

// logSink collects Logger lines.
type logSink struct {
	mu    sync.Mutex
	lines []string
}

func (l *logSink) log(s string) { l.mu.Lock(); l.lines = append(l.lines, s); l.mu.Unlock() }
func (l *logSink) has(sub string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, x := range l.lines {
		if strings.Contains(x, sub) {
			return true
		}
	}
	return false
}
func (l *logSink) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Join(l.lines, "\n")
}

// fakeAPI serves /v1/self and /v1/self/watch from a settable response.
type fakeAPI struct {
	*httptest.Server
	mu     sync.Mutex
	resp   map[string]any
	status int
	auths  []string
}

func newFakeAPI(t testing.TB, resp map[string]any) *fakeAPI {
	f := &fakeAPI{resp: resp, status: 200}
	f.Server = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.Close)
	return f
}

func (f *fakeAPI) set(resp map[string]any, status int) {
	f.mu.Lock()
	f.resp, f.status = resp, status
	f.mu.Unlock()
}

func (f *fakeAPI) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.auths = append(f.auths, r.Header.Get("Authorization"))
	f.mu.Unlock()
	deadline := time.Now().Add(100 * time.Millisecond)
	for {
		f.mu.Lock()
		resp, status := f.resp, f.status
		f.mu.Unlock()
		if status != 200 {
			w.WriteHeader(status)
			fmt.Fprint(w, `{"error":"nope"}`)
			return
		}
		if r.URL.Path == "/v1/self/watch" {
			q := r.URL.Query()
			b := m(resp["blob"])
			ready := q.Get("version") != string(b["version"].(Number)) || q.Get("gen") != string(b["dek_gen"].(Number)) ||
				q.Get("sv") != svOf(resp["shared"])
			if !ready && time.Now().Before(deadline) {
				time.Sleep(10 * time.Millisecond)
				continue
			}
			if !ready {
				w.WriteHeader(204)
				return
			}
		}
		body, _ := json.Marshal(resp)
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
		return
	}
}

func waitFor(t testing.TB, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestCheckURL(t *testing.T) {
	for _, ok := range []string{"https://api.dynv.dev", "http://127.0.0.1:8080", "http://127.9.0.1", "http://localhost/", "http://[::1]:80", "https://proxy.example/dynv/"} {
		if _, err := CheckURL(ok, false); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	for _, bad := range []string{"http://10.0.0.1", "http://example.com", "https://u:p@api.dynv.dev", "https://u@api.dynv.dev",
		"https://api.dynv.dev/?x=1", "https://api.dynv.dev/?", "https://api.dynv.dev/#f", "ftp://api.dynv.dev", "api.dynv.dev", "", "http://127.0.0.1.example.com"} {
		if _, err := CheckURL(bad, false); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if _, err := CheckURL("http://10.0.0.1", true); err != nil {
		t.Error(err)
	}
	if got, _ := CheckURL(" https://proxy.example/dynv// ", false); got != "https://proxy.example/dynv" {
		t.Errorf("trailing slash: %q", got)
	}
}

func TestStrictJSON(t *testing.T) {
	for _, bad := range []string{`"\ud800"`, `"\udc00"`, `"\ud800x"`, `"\ud800A"`, "\"\xff\"", `NaN`, `Infinity`, `-Infinity`,
		`{"a":1,"a":2}`, `[1,]`, `01`, `1.`, `"a` + "\n" + `"`, `{"a" 1}`, `tru`, `1 2`} {
		if _, err := ParseJSON([]byte(bad)); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	v, err := ParseJSON([]byte(`{"__proto__":"x","e":"😀é\n","n":[1,-2,3.5e1]}`))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"__proto__": "x", "e": "😀é\n", "n": []any{Number("1"), Number("-2"), Number("3.5e1")}}
	if !reflect.DeepEqual(v, want) {
		t.Errorf("%#v", v)
	}
	for _, n := range []string{"1.0", "1e3", "0", "-1", "9007199254740992"} {
		if _, ok := Int(Number(n)); ok {
			t.Errorf("Int(%s) accepted", n)
		}
	}
	if x, ok := Int(Number("9007199254740991")); !ok || x != MaxInt {
		t.Error("2^53-1")
	}
}

func TestWireForm(t *testing.T) {
	doc := func(v string) []byte { return []byte(`{"process":"p","version":1,"vars":{"K":` + v + `}}`) }
	d, err := ParseDoc(doc(`{"template":"${A}"}`), false)
	if err != nil || d.Vars["K"] != (Var{Value: "${A}", Template: true, Apply: Restart}) {
		t.Fatalf("%v %+v", err, d)
	}
	for _, bad := range []string{`{"value":"x","template":"y"}`, `{}`, `{"apply":"hot"}`, `{"template":5}`, `{"value":null}`,
		`{"value":"x","apply":"later"}`, `"x"`, `{"value":"\ud800"}`, `{"value":"` + "\xc3" + `"}`} {
		if _, err := ParseDoc(doc(bad), false); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
	if _, err := ParseDoc([]byte(`{"process":"p","version":1.0}`), false); err == nil {
		t.Error("float version accepted")
	}
	if _, err := ParseDoc([]byte(`{"process":"p","version":1,"default_apply":"hot","vars":{"__proto__":{"value":"v"}}}`), false); err != nil {
		t.Error(err)
	}
}

func TestTemplateChains(t *testing.T) {
	t.Run("21", func(t *testing.T) { // K00 -> … -> K19 -> K20 (literal): every key taller than 16 fails on its own
		merged := map[string]Var{"K20": {Value: "end", Apply: Hot}}
		for i := 0; i < 20; i++ {
			merged[fmt.Sprintf("K%02d", i)] = Var{Value: fmt.Sprintf("${K%02d}", i+1), Template: true, Apply: Hot}
		}
		r := Resolve(merged)
		wantVals := map[string]string{}
		for i := 4; i <= 20; i++ {
			wantVals[fmt.Sprintf("K%02d", i)] = "end"
		}
		if !reflect.DeepEqual(r.Values, wantVals) {
			t.Errorf("values %v", r.Values)
		}
		wantErr := map[string]*TemplateError{}
		for _, k := range []string{"K00", "K01", "K02", "K03"} {
			wantErr[k] = &TemplateError{Code: "depth", Key: k, At: k, Message: k + ": templates nest deeper than 16 levels"}
		}
		if !reflect.DeepEqual(r.Errors, wantErr) {
			t.Errorf("errors %v", r.Errors)
		}
	})
	t.Run("1500", func(t *testing.T) {
		const n = 1500
		merged := map[string]Var{fmt.Sprintf("K%05d", n): {Value: "x", Apply: Hot}}
		for i := 0; i < n; i++ {
			merged[fmt.Sprintf("K%05d", i)] = Var{Value: fmt.Sprintf("${K%05d}", i+1), Template: true, Apply: Hot}
		}
		r := Resolve(merged)
		if r.Values[fmt.Sprintf("K%05d", n-16)] != "x" || r.Errors[fmt.Sprintf("K%05d", n-17)].Code != "depth" || len(r.Errors) != n-16 {
			t.Errorf("chain: %d errors", len(r.Errors))
		}
		if len(r.Deps["K00000"]) != n {
			t.Errorf("deps %d", len(r.Deps["K00000"]))
		}
	})
	t.Run("too-long", func(t *testing.T) { // ${A} repeated against a 64 KiB A must not build gigabytes
		merged := map[string]Var{"A": {Value: strings.Repeat("a", 65536), Apply: Hot},
			"T": {Value: strings.Repeat("${A}", 100000) + "${MISSING}", Template: true, Apply: Hot}}
		r := Resolve(merged)
		if e := r.Errors["T"]; e == nil || e.Code != "too-long" || e.Message != "T: resolved value is longer than 65536 bytes" {
			t.Errorf("%+v", e)
		}
	})
}

func TestMasterTokenRefused(t *testing.T) {
	_, err := Connect(context.Background(), Options{Mode: ModeDirect, Token: masterToken(t), URL: "https://127.0.0.1:1"})
	if err == nil || !strings.Contains(err.Error(), "master token") {
		t.Fatalf("got %v", err)
	}
	if strings.Contains(err.Error(), masterToken(t)[25:]) {
		t.Fatal("error echoes the secret")
	}
	if _, err := Connect(context.Background(), Options{Mode: ModeDirect, Token: "dynv_pt_nope"}); err == nil || strings.Contains(err.Error(), "nope") {
		t.Fatalf("malformed token: %v", err)
	}
}

func TestTokenScrubAndFile(t *testing.T) {
	steps := selfCase(t, "plain")
	api := newFakeAPI(t, m(steps[0]["response"]))
	t.Setenv("DYNV_URL", api.URL)
	t.Setenv("DYNV_AGENT_URL", "")

	t.Setenv("DYNV_TOKEN", vectorToken(t))
	c, err := Connect(context.Background(), Options{DisableEnvMirror: true})
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	if c.Mode() != ModeDirect {
		t.Errorf("mode %s", c.Mode())
	}
	if _, ok := os.LookupEnv("DYNV_TOKEN"); ok {
		t.Error("DYNV_TOKEN still in env")
	}

	t.Setenv("DYNV_TOKEN", vectorToken(t))
	c, err = Connect(context.Background(), Options{KeepTokenInEnv: true, DisableEnvMirror: true})
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	if os.Getenv("DYNV_TOKEN") != vectorToken(t) {
		t.Error("KeepTokenInEnv: token removed")
	}

	os.Unsetenv("DYNV_TOKEN")
	f := filepath.Join(t.TempDir(), "token")
	os.WriteFile(f, []byte("\n  "+vectorToken(t)+"\n"), 0o600)
	t.Setenv("DYNV_TOKEN_FILE", f)
	c, err = Connect(context.Background(), Options{DisableEnvMirror: true})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if c.Mode() != ModeDirect || c.Version() == 0 {
		t.Errorf("token file: mode %s v%d", c.Mode(), c.Version())
	}
}

func TestRedirectRefused(t *testing.T) {
	var hits []string
	var mu sync.Mutex
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits = append(hits, r.Header.Get("Authorization"))
		mu.Unlock()
	}))
	defer target.Close()
	src := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+r.URL.Path, http.StatusFound)
	}))
	defer src.Close()
	logs := &logSink{}
	_, err := Connect(context.Background(), Options{Mode: ModeDirect, Token: vectorToken(t), URL: src.URL, Require: true,
		Logger: logs.log, HTTPClient: &http.Client{}})
	var he *HTTPError
	if !errors.As(err, &he) || he.Status != http.StatusFound {
		t.Fatalf("got %v", err)
	}
	if len(hits) != 0 {
		t.Fatalf("the redirect target was contacted (%d)", len(hits))
	}
}

func TestEnvMode(t *testing.T) {
	t.Setenv("DYNV_AGENT_URL", "")
	t.Setenv("DYNV_TOKEN", "")
	t.Setenv("DYNV_TOKEN_FILE", "")
	t.Setenv("SOME_KEY", "from-env")
	c, err := Connect(context.Background(), Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if c.Mode() != ModeEnv || c.Get("SOME_KEY") != "from-env" || c.Version() != 0 || c.Source("SOME_KEY") != "" {
		t.Errorf("env mode: %s %q", c.Mode(), c.Get("SOME_KEY"))
	}
	if !reflect.DeepEqual(c.All("SOME_KEY"), []string{"from-env"}) || !reflect.DeepEqual(c.All("MISSING"), []string{}) {
		t.Errorf("env All: %v %v", c.All("SOME_KEY"), c.All("MISSING"))
	}
	if _, err := c.Require("NOT_SET_ANYWHERE"); err == nil || !strings.Contains(err.Error(), "NOT_SET_ANYWHERE") {
		t.Error(err)
	}
	if _, err := Connect(context.Background(), Options{Require: true}); err == nil {
		t.Error("Require without a token connected")
	}
	if _, err := Connect(context.Background(), Options{Mode: ModeDirect}); err == nil {
		t.Error("direct without a token connected")
	}
	if _, err := Connect(context.Background(), Options{Mode: ModeAgent}); err == nil {
		t.Error("agent without a URL connected")
	}
}

func TestCacheRoundTrip(t *testing.T) {
	steps := selfCase(t, "group-keep-last")
	token, _ := ParseToken(vectorToken(t))
	dir := t.TempDir()
	path := filepath.Join(dir, "cache.json")
	src := func() *directSource {
		return &directSource{v: NewVerifier(token, "web-vectors"), cache: path, log: func(string) {}}
	}
	a := src()
	var last *Opened
	for _, st := range steps[:2] { // v5 with group A applied, then v6 with A kept
		o, err := a.v.Open(st["response"])
		if err != nil {
			t.Fatal(err)
		}
		if err := a.accept(o); err != nil {
			t.Fatal(err)
		}
		last = o
	}
	fi, err := os.Stat(path)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v %v", fi.Mode(), err)
	}
	ents, _ := os.ReadDir(dir)
	if len(ents) != 1 || ents[0].Name() != "cache.json" {
		t.Fatalf("files left: %v", ents)
	}
	b := src()
	cached := b.loadCache()
	if cached == nil || !reflect.DeepEqual(stateOf(b.v), stateOf(a.v)) || !reflect.DeepEqual(cached.Vars, last.Vars) {
		t.Fatal("cache did not restore the state")
	}
	if _, err := b.v.Open(steps[0]["response"]); err == nil || err.(*RefusedError).Code != CodeRollback {
		t.Fatalf("after restart: %v", err) // the floor survived the restart
	}

	// A failed write refuses the update and changes nothing.
	c := src()
	c.cache = filepath.Join(dir, "missing-dir", "cache.json")
	o, _ := c.v.Open(steps[0]["response"])
	before := stateOf(c.v)
	if err := c.accept(o); err == nil || !reflect.DeepEqual(stateOf(c.v), before) {
		t.Fatalf("failed write: %v", err)
	}
}

func TestCacheGenerationFloors(t *testing.T) {
	steps := selfCase(t, "group-keep-last")
	token, _ := ParseToken(vectorToken(t))
	path := filepath.Join(t.TempDir(), "cache.json")
	src := func() *directSource {
		return &directSource{v: NewVerifier(token, "web-vectors"), cache: path, log: func(string) {}}
	}
	a := src()
	for _, st := range steps[:2] {
		o, err := a.v.Open(st["response"])
		if err != nil {
			t.Fatal(err)
		}
		if err := a.accept(o); err != nil {
			t.Fatal(err)
		}
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	cached, err := ParseJSON(data)
	if err != nil {
		t.Fatal(err)
	}
	cache := m(cached)
	same(t, "cached gen_floor", cache["gen_floor"], a.v.GenFloor)
	same(t, "cached group_gen_floors", cache["group_gen_floors"], a.v.GroupGenFloors)

	b := src()
	if b.loadCache() == nil {
		t.Fatal("cache did not load")
	}
	same(t, "restored gen_floor", b.v.GenFloor, a.v.GenFloor)
	same(t, "restored group_gen_floors", b.v.GroupGenFloors, a.v.GroupGenFloors)

	// A floor above its own cached group ciphertext must not skip that group
	// and leave the poisoned floor installed.
	entry := m(m(steps[0]["response"])["shared"].([]any)[0])
	gid := s(entry["group_id"])
	floors := m(cache["group_gen_floors"])
	floors[gid] = Number(fmt.Sprint(a.v.GroupGenFloors[gid] + 1))
	data, err = json.Marshal(cache)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	c := src()
	gen := uint64(7)
	c.v.GenFloor = &gen
	c.v.GroupGenFloors["EarlierGroup0001"] = 4
	before := stateOf(c.v)
	if c.loadCache() != nil {
		t.Fatal("cache below its stored group generation floor was accepted")
	}
	if !reflect.DeepEqual(stateOf(c.v), before) {
		t.Fatal("refused cache did not restore the previous generation floors")
	}
}

func TestBootFromCache(t *testing.T) {
	steps := selfCase(t, "rollback") // v5, v4 (rollback), v5, v6
	dir := t.TempDir()
	cache := filepath.Join(dir, "web.dynv")
	api := newFakeAPI(t, m(steps[3]["response"]))
	var emu sync.Mutex // OnError also runs on the watcher goroutine
	opts := func(logs *logSink, errs *[]error) Options {
		return Options{Mode: ModeDirect, Token: vectorToken(t), URL: api.URL, Process: "web-vectors", Cache: cache,
			BootTimeout: 2 * time.Second, PollInterval: 100 * time.Millisecond, Logger: logs.log, DisableEnvMirror: true,
			OnError: func(err error) { emu.Lock(); *errs = append(*errs, err); emu.Unlock() }}
	}
	var errs []error
	c, err := Connect(context.Background(), opts(&logSink{}, &errs))
	if err != nil {
		t.Fatal(err)
	}
	c.Close()

	// The API is down: boot on the cache.
	api.set(nil, 500)
	logs := &logSink{}
	c, err = Connect(context.Background(), opts(logs, &errs))
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	if !logs.has("using cached v6") || c.Version() != 6 || c.Get("DB_URL") != "postgres://db.example/app?v=6" {
		t.Fatalf("v%d logs:\n%s", c.Version(), logs)
	}

	// The API serves an older document: refused, the cache wins.
	api.set(m(steps[1]["response"]), 200)
	logs = &logSink{}
	var bootErrs []error
	c, err = Connect(context.Background(), opts(logs, &bootErrs))
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	emu.Lock()
	errs = bootErrs
	emu.Unlock()
	var re *RefusedError
	if !logs.has("live response refused (rollback); using cached v6") || len(errs) == 0 || !errors.As(errs[0], &re) || re.Code != CodeRollback {
		t.Fatalf("errs %v logs:\n%s", errs, logs)
	}

	// No cache, API down, Require: Connect fails.
	os.Remove(cache)
	api.set(nil, 503)
	o := opts(&logSink{}, &errs)
	o.Require = true
	if _, err := Connect(context.Background(), o); err == nil {
		t.Fatal("Require: connected")
	}
	o.Require = false
	c, err = Connect(context.Background(), o)
	if err != nil || c.Version() != 0 {
		t.Fatalf("no cache: %v", err)
	}
	c.Close()
}

func TestDirectLive(t *testing.T) {
	steps := selfCase(t, "templates") // v5 + region v2, then v5 + region v3 (DB_HOST changes)
	rollback := selfCase(t, "rollback")
	api := newFakeAPI(t, m(steps[0]["response"]))
	t.Setenv("OLD_KEY", "inherited") // tombstoned: must read as unset
	t.Setenv("DB_HOST", "inherited")
	logs := &logSink{}
	c, err := Connect(context.Background(), Options{Mode: ModeDirect, Token: vectorToken(t), URL: api.URL, Process: "web-vectors",
		BootTimeout: 2 * time.Second, PollInterval: 200 * time.Millisecond, Logger: logs.log})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if c.Version() != 5 || c.Get("DB_HOST") != "db-1.internal" || os.Getenv("DB_HOST") != "db-1.internal" || !c.IsTemplate("DATABASE_URL") || c.IsTemplate("DB_HOST") {
		t.Fatalf("boot: v%d", c.Version())
	}
	if c.Source("SHARED_ONLY") == "" || c.Source("DB_URL") != "" {
		t.Errorf("sources %q %q", c.Source("SHARED_ONLY"), c.Source("DB_URL"))
	}
	if _, ok := c.Lookup("OLD_KEY"); ok {
		t.Error("OLD_KEY reads the inherited value")
	}
	if _, ok := os.LookupEnv("OLD_KEY"); ok {
		t.Error("OLD_KEY not cleared from the env")
	}

	events := make(chan ChangeEvent, 10)
	hosts := make(chan string, 10)
	errs := make(chan error, 100)
	c.OnChange(func(ChangeEvent) { panic("listener bug") })
	c.OnChange(func(e ChangeEvent) { events <- e })
	c.OnKey("DB_HOST", func(v string, ok bool) { hosts <- v })
	cancel := c.OnKey("DB_HOST", func(string, bool) { t.Error("cancelled listener called") })
	cancel()
	c.OnError(func(err error) { errs <- err })

	api.set(m(steps[1]["response"]), 200)
	var e ChangeEvent
	select {
	case e = <-events:
	case <-time.After(5 * time.Second):
		t.Fatalf("no change event; logs:\n%s", logs)
	}
	want := []string{"DATABASE_URL", "DB_HOST", "DSN_WITH_RESTART", "SHARED_ONLY"}
	if !reflect.DeepEqual(e.Changed, want) || !e.Restart || e.Version != 6 {
		t.Errorf("event %+v", e)
	}
	if h := <-hosts; h != "db-2.internal" || c.Get("DB_HOST") != "db-2.internal" || os.Getenv("DB_HOST") != "db-2.internal" {
		t.Errorf("host %q", h)
	}
	if !logs.has("callback panicked") {
		t.Error("panic not logged")
	}

	api.set(m(rollback[1]["response"]), 200) // v4 < floor v5
	select {
	case err := <-errs:
		var re *RefusedError
		if !errors.As(err, &re) || re.Code != CodeRollback {
			t.Errorf("error %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no refusal")
	}
	waitFor(t, "log line", func() bool { return logs.has("update refused (rollback)") })
	if c.Get("DB_HOST") != "db-2.internal" || c.Version() != 6 {
		t.Error("refused update changed the env")
	}
	snap := c.Snapshot()
	snap.Vars["DB_HOST"] = "mutated"
	if c.Get("DB_HOST") != "db-2.internal" {
		t.Error("Snapshot is not a copy")
	}
	api.mu.Lock()
	auths := append([]string(nil), api.auths...)
	api.mu.Unlock()
	for _, a := range auths {
		if !strings.HasPrefix(a, "Dynv pt.") || strings.Contains(a, vectorToken(t)[25:]) {
			t.Fatalf("authorization %q", a)
		}
	}
	for _, l := range strings.Split(logs.String(), "\n") {
		if strings.Contains(l, "db-2") || strings.Contains(l, "p@ss") {
			t.Errorf("log line carries a value: %s", l)
		}
	}
}

func TestPollMode(t *testing.T) {
	steps := selfCase(t, "rollback")
	api := newFakeAPI(t, m(steps[0]["response"]))
	c, err := Connect(context.Background(), Options{Mode: ModeDirect, Token: vectorToken(t), URL: api.URL, DisableLongPoll: true,
		PollInterval: 50 * time.Millisecond, DisableEnvMirror: true, Logger: func(string) {}})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	api.set(m(steps[3]["response"]), 200)
	waitFor(t, "v6", func() bool { return c.Version() == 6 })
}

func TestAgentMode(t *testing.T) {
	const key = "agent-key-123"
	var mu sync.Mutex
	snap := Snapshot{Version: 3, Vars: map[string]string{"PROXY_SERVER": "http://p1", "SHARED_KEY": "s", "AUTH_SECRET": "new", "AUTH_SECRET_PREVIOUS": "old"},
		Apply:   map[string]string{"PROXY_SERVER": Hot, "SHARED_KEY": Restart, "AUTH_SECRET": Hot, "AUTH_SECRET_PREVIOUS": Hot},
		Managed: []string{"GONE", "PROXY_SERVER", "SHARED_KEY"}, Sources: map[string]string{"SHARED_KEY": "proxies"}, Templates: []string{},
		Fallbacks: map[string]Exposed{"AUTH_SECRET": {Name: "AUTH_SECRET_PREVIOUS", Values: []string{"old"}}}}
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+key {
			w.WriteHeader(401)
			return
		}
		deadline := time.Now().Add(100 * time.Millisecond)
		for {
			mu.Lock()
			cur := snap
			mu.Unlock()
			if r.URL.Path == "/v1/env" || r.URL.Query().Get("since") != fmt.Sprint(cur.Version) {
				json.NewEncoder(w).Encode(cur)
				return
			}
			if time.Now().After(deadline) {
				w.WriteHeader(204)
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}))
	defer agent.Close()
	t.Setenv("DYNV_AGENT_URL", agent.URL)
	t.Setenv("DYNV_AGENT_KEY", key)
	t.Setenv("DYNV_TOKEN", "")
	t.Setenv("GONE", "inherited")
	c, err := Connect(context.Background(), Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if c.Mode() != ModeAgent || c.Version() != 3 || c.Get("PROXY_SERVER") != "http://p1" || c.Source("SHARED_KEY") != "proxies" {
		t.Fatalf("boot %s v%d", c.Mode(), c.Version())
	}
	if !reflect.DeepEqual(c.All("AUTH_SECRET"), []string{"new", "old"}) || !reflect.DeepEqual(c.All("SHARED_KEY"), []string{"s"}) ||
		!reflect.DeepEqual(c.All("MISSING"), []string{}) {
		t.Errorf("All: auth=%v shared=%v missing=%v", c.All("AUTH_SECRET"), c.All("SHARED_KEY"), c.All("MISSING"))
	}
	if _, ok := c.Lookup("GONE"); ok {
		t.Error("tombstone reads the inherited value")
	}
	events := make(chan ChangeEvent, 4)
	proxies := make(chan [2]any, 4)
	c.OnChange(func(e ChangeEvent) { events <- e })
	c.OnKey("PROXY_SERVER", func(v string, ok bool) { proxies <- [2]any{v, ok} })
	mu.Lock()
	snap = Snapshot{Version: 4, Vars: map[string]string{"SHARED_KEY": "s", "AUTH_SECRET": "new", "AUTH_SECRET_PREVIOUS": "old"},
		Apply:   map[string]string{"SHARED_KEY": Restart, "AUTH_SECRET": Hot, "AUTH_SECRET_PREVIOUS": Hot},
		Managed: []string{"GONE", "PROXY_SERVER", "SHARED_KEY"}, Sources: map[string]string{"SHARED_KEY": "proxies"},
		Fallbacks: map[string]Exposed{"AUTH_SECRET": {Name: "AUTH_SECRET_PREVIOUS", Values: []string{"old"}}}}
	mu.Unlock()
	select {
	case e := <-events:
		if !reflect.DeepEqual(e.Changed, []string{"PROXY_SERVER"}) || e.Restart || e.Version != 4 {
			t.Errorf("%+v", e)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no event")
	}
	if p := <-proxies; p != [2]any{"", false} {
		t.Errorf("%v", p)
	}
	if _, ok := c.Lookup("PROXY_SERVER"); ok {
		t.Error("removed key still set")
	}

	t.Setenv("DYNV_AGENT_KEY", "wrong")
	if _, err := Connect(context.Background(), Options{Require: true}); err == nil {
		t.Error("wrong key, Require: connected")
	}
}

func TestCloseFromCallback(t *testing.T) {
	steps := selfCase(t, "rollback")
	api := newFakeAPI(t, m(steps[0]["response"]))
	c, err := Connect(context.Background(), Options{Mode: ModeDirect, Token: vectorToken(t), URL: api.URL, DisableEnvMirror: true, Logger: func(string) {}})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	c.OnChange(func(ChangeEvent) { c.Close(); close(done) })
	api.set(m(steps[3]["response"]), 200)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Close from a callback blocked")
	}
	c.Close()
}

func TestExitOnRestart(t *testing.T) {
	steps := selfCase(t, "templates") // the second step changes DSN_WITH_RESTART (restart mode)
	api := newFakeAPI(t, m(steps[0]["response"]))
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM)
	defer signal.Stop(sig)
	logs := &logSink{}
	c, err := Connect(context.Background(), Options{Mode: ModeDirect, Token: vectorToken(t), URL: api.URL, ExitOnRestart: true,
		DisableEnvMirror: true, Logger: logs.log})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	api.set(m(steps[1]["response"]), 200)
	select {
	case <-sig:
	case <-time.After(5 * time.Second):
		t.Fatalf("no SIGTERM; logs:\n%s", logs)
	}
	if !logs.has("restart-mode variables changed") {
		t.Error(logs)
	}
}

func TestAgentMustBeLoopback(t *testing.T) {
	for _, u := range []string{"http://10.1.2.3:4000", "http://example.com", "ftp://127.0.0.1", "http://u:p@127.0.0.1:1", "http://127.0.0.1:1/x", "http://127.0.0.1:1/?", "http://127.0.0.1:1#"} {
		_, err := Connect(context.Background(), Options{Mode: ModeAgent, AgentURL: u, AgentKey: "k", Logger: func(string) {}})
		if err == nil {
			t.Errorf("%s: agent URL accepted", u)
		}
	}
}
