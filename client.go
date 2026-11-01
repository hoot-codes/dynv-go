// Package dynv reads a process's Dynv environment live, without restarts.
//
// Three modes, one API:
//
//   - agent (preferred): under `dynv run`, the client reads the local agent
//     (DYNV_AGENT_URL, DYNV_AGENT_KEY). It holds no Dynv token and does no
//     crypto: the supervisor already verified and decrypted.
//   - direct: with a process token (DYNV_TOKEN or DYNV_TOKEN_FILE) and no
//     `dynv` binary, the client fetches /v1/self itself and does what
//     `dynv run` does in-process: decrypt, verify signatures, rosters and
//     rollback floors, merge shared groups, resolve templates, watch, and
//     keep a ciphertext-only cache (docs/PROTOCOL.md). The tradeoff: this
//     process holds the token.
//   - env: neither configured. Get reads the process environment and no
//     change events fire, so code written against the client works either way.
//
// Diagnostics name keys and codes only, never values.
package dynv

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// Mode is how a Client gets its values.
type Mode string

// Modes. ModeAuto (or "") picks agent when DYNV_AGENT_URL is set, else
// direct when a token is available, else env.
const (
	ModeAuto   Mode = "auto"
	ModeAgent  Mode = "agent"
	ModeDirect Mode = "direct"
	ModeEnv    Mode = "env"
)

// DefaultURL is Dynv Cloud's API. Direct mode never defaults to it: set
// Options.URL or DYNV_URL explicitly.
const DefaultURL = "https://api.dynv.dev"

// Options configures [Connect]. Zero values take the environment defaults.
type Options struct {
	Mode Mode
	// Token is a process token (dynv_pt_…). Default DYNV_TOKEN, else the
	// trimmed contents of the file named by DYNV_TOKEN_FILE.
	Token string
	// Process is the expected process name; a document for another name is
	// refused. Default DYNV_PROCESS. Recommended.
	Process string
	// URL is the API base URL. Default DYNV_URL; one of them is required in
	// direct mode (DefaultURL for Dynv Cloud).
	URL string
	// Cache is a ciphertext-only cache file (the `dynv run --cache` format).
	// Default DYNV_CACHE. Recommended: offline boot and a durable rollback floor.
	Cache string
	// Require makes Connect fail when Dynv is unreachable and there is no cache
	// (direct mode), or when the agent is unreachable (agent mode), or when no
	// token is set (auto mode).
	Require bool
	// BootTimeout bounds the first live fetch. Default 10s.
	BootTimeout time.Duration
	// PollInterval is the longest error backoff, and the poll interval with
	// DisableLongPoll. Default 120s.
	PollInterval time.Duration
	// DisableLongPoll polls GET /v1/self every PollInterval instead of
	// long-polling, for networks that kill idle connections.
	DisableLongPoll bool
	// AllowInsecureHTTP allows plain http:// to a non-loopback host. Default
	// DYNV_ALLOW_INSECURE_HTTP=1.
	AllowInsecureHTTP bool
	// KeepTokenInEnv keeps DYNV_TOKEN in the process environment. By default
	// it is unset once read, so child processes and env dumps don't carry it.
	KeepTokenInEnv bool
	// ExitOnRestart (direct mode) sends SIGTERM to this process when a
	// restart-mode variable changes, so its orchestrator restarts it.
	// Otherwise the ChangeEvent has Restart set and the app decides.
	ExitOnRestart bool
	// DisableEnvMirror stops all writes to the process environment
	// (os.Setenv / os.Unsetenv). By default the first snapshot mirrors every
	// value and unsets managed keys without values. Later snapshots mirror only
	// hot-mode keys for which IsDangerousKey is false; restart-mode and dangerous
	// changes still update Get and events, but their process-env writes wait for
	// a restart. With cgo, disable mirroring: os.Setenv concurrent with C calls
	// to getenv/setenv is a data race in libc, and C libraries may cache values.
	DisableEnvMirror bool
	// Logger receives diagnostics (key names and codes only, never values).
	// Default: stderr with a "dynv: " prefix.
	Logger func(string)
	// OnError is called for errors during Connect (a refused live response,
	// an unreachable API or agent) as well as later ones; see Client.OnError.
	OnError func(error)
	// AgentURL and AgentKey default to DYNV_AGENT_URL and DYNV_AGENT_KEY.
	AgentURL, AgentKey string
	// HTTPClient is used for every request. Its CheckRedirect is replaced:
	// redirects are never followed.
	HTTPClient *http.Client
}

// ChangeEvent describes an applied change. It never carries values.
type ChangeEvent struct {
	Version uint64
	// Changed are the sorted names of keys whose value was added, changed or removed.
	Changed []string
	// Restart is true when any changed key is in restart mode. Under
	// `dynv run` the supervisor restarts the app itself.
	Restart bool
}

// Snapshot is the environment as the `dynv run` agent serves it.
type Snapshot struct {
	// Version is a local revision: strictly increasing per applied change,
	// equal to the process document's version when no groups are attached.
	Version uint64            `json:"version"`
	Vars    map[string]string `json:"vars"`
	Apply   map[string]string `json:"apply"`
	// Managed are the current keys plus signed deletion tombstones.
	Managed []string `json:"managed,omitempty"`
	// Sources maps a key to the shared group that provides it.
	Sources map[string]string `json:"sources,omitempty"`
	// Templates are the keys resolved from a template.
	Templates []string `json:"templates,omitempty"`
	// Unresolved are templates that currently fail to resolve.
	Unresolved []string `json:"unresolved,omitempty"`
	// Fallbacks maps a key to its fallback name and live older values, newest first.
	Fallbacks map[string]Exposed `json:"fallbacks,omitempty"`
}

func (s Snapshot) clone() Snapshot {
	c := s
	c.Vars = cloneMap(s.Vars)
	c.Apply = cloneMap(s.Apply)
	c.Sources = cloneMap(s.Sources)
	c.Managed = append([]string(nil), s.Managed...)
	c.Templates = append([]string(nil), s.Templates...)
	c.Unresolved = append([]string(nil), s.Unresolved...)
	if s.Fallbacks != nil {
		c.Fallbacks = make(map[string]Exposed, len(s.Fallbacks))
		for k, f := range s.Fallbacks {
			f.Values = append([]string(nil), f.Values...)
			c.Fallbacks[k] = f
		}
	}
	return c
}

func cloneMap(m map[string]string) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// Client is a connected Dynv environment. All methods are safe for
// concurrent use.
type Client struct {
	mode    Mode
	mirror  bool
	exit    bool
	log     func(string)
	onError func(error)

	mu      sync.RWMutex
	snap    Snapshot
	managed map[string]bool

	lmu      sync.Mutex
	nextID   int
	onChange map[int]func(ChangeEvent)
	onKey    map[string]map[int]func(string, bool)
	onErr    map[int]func(error)

	ctx         context.Context
	cancel      context.CancelFunc
	wg          sync.WaitGroup
	dispatching atomic.Bool
	closeOnce   sync.Once
}

func newClient(mode Mode, opts *Options) *Client {
	logf := opts.Logger
	if logf == nil {
		logf = func(m string) { fmt.Fprintln(os.Stderr, "dynv: "+m) }
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Client{
		mode: mode, mirror: !opts.DisableEnvMirror, exit: opts.ExitOnRestart, log: logf, onError: opts.OnError,
		snap:     Snapshot{Vars: map[string]string{}, Apply: map[string]string{}},
		managed:  map[string]bool{},
		onChange: map[int]func(ChangeEvent){}, onKey: map[string]map[int]func(string, bool){}, onErr: map[int]func(error){},
		ctx: ctx, cancel: cancel,
	}
}

func envOr(v, key string) string {
	if v != "" {
		return v
	}
	return os.Getenv(key)
}

// Connect picks the mode (see Options.Mode), loads the first snapshot and
// starts watching. ctx bounds only the connection, not the watch: call
// Close to stop.
func Connect(ctx context.Context, opts Options) (*Client, error) {
	mode := opts.Mode
	if mode == "" {
		mode = ModeAuto
	}
	if opts.BootTimeout <= 0 {
		opts.BootTimeout = 10 * time.Second
	}
	if opts.PollInterval <= 0 {
		opts.PollInterval = 120 * time.Second
	}
	agentURL := envOr(opts.AgentURL, "DYNV_AGENT_URL")
	switch mode {
	case ModeAuto, ModeAgent, ModeDirect, ModeEnv:
	default:
		return nil, fmt.Errorf("dynv: unknown mode %q", mode)
	}
	if mode == ModeAgent || (mode == ModeAuto && agentURL != "") {
		if agentURL == "" {
			return nil, errors.New("dynv: agent mode needs DYNV_AGENT_URL (start the app with `dynv run`)")
		}
		c := newClient(ModeAgent, &opts)
		if err := c.startAgent(ctx, agentURL, envOr(opts.AgentKey, "DYNV_AGENT_KEY"), &opts); err != nil {
			c.Close()
			return nil, err
		}
		return c, nil
	}
	if mode == ModeEnv {
		return newClient(ModeEnv, &opts), nil
	}
	raw, err := tokenFrom(&opts)
	if err != nil {
		return nil, err
	}
	if raw == "" {
		if mode == ModeDirect || opts.Require {
			return nil, errors.New("dynv: no token: set DYNV_TOKEN (or DYNV_TOKEN_FILE), or pass Options.Token")
		}
		return newClient(ModeEnv, &opts), nil
	}
	token, err := ParseToken(raw)
	if err != nil {
		return nil, errors.New("dynv: DYNV_TOKEN is not a valid Dynv token")
	}
	if token.Kind != "pt" {
		return nil, errors.New("dynv: direct mode takes a process token (dynv_pt_…); never give an app a master token")
	}
	allowHTTP := opts.AllowInsecureHTTP || os.Getenv("DYNV_ALLOW_INSECURE_HTTP") == "1"
	rawURL := envOr(opts.URL, "DYNV_URL")
	if rawURL == "" { // no silent default: a token must go only where the operator says
		return nil, errors.New("dynv: set DYNV_URL (" + DefaultURL + " for Dynv Cloud)")
	}
	base, err := CheckURL(rawURL, allowHTTP)
	if err != nil {
		return nil, err
	}
	c := newClient(ModeDirect, &opts)
	src := &directSource{
		v:     NewVerifier(token, envOr(opts.Process, "DYNV_PROCESS")),
		base:  base,
		auth:  token.Authorization(),
		cache: envOr(opts.Cache, "DYNV_CACHE"),
		http:  noRedirect(opts.HTTPClient),
		poll:  opts.PollInterval,
		long:  !opts.DisableLongPoll,
		log:   c.log,
	}
	if err := c.startDirect(ctx, src, &opts); err != nil {
		c.Close()
		return nil, err
	}
	return c, nil
}

// tokenFrom returns Options.Token, else DYNV_TOKEN, else the trimmed
// contents of DYNV_TOKEN_FILE. A token read from DYNV_TOKEN is unset from
// the environment unless KeepTokenInEnv.
func tokenFrom(opts *Options) (string, error) {
	if opts.Token != "" {
		return opts.Token, nil
	}
	if v := os.Getenv("DYNV_TOKEN"); v != "" {
		if !opts.KeepTokenInEnv {
			os.Unsetenv("DYNV_TOKEN")
		}
		return v, nil
	}
	if f := os.Getenv("DYNV_TOKEN_FILE"); f != "" {
		b, err := os.ReadFile(f)
		if err != nil {
			return "", fmt.Errorf("dynv: cannot read DYNV_TOKEN_FILE: %w", err)
		}
		return strings.TrimSpace(string(b)), nil
	}
	return "", nil
}

// Mode is "agent" under `dynv run`, "direct" with a token, else "env".
func (c *Client) Mode() Mode { return c.mode }

// Version is the local revision of the current snapshot (0 before the first
// one, and always in env mode).
func (c *Client) Version() uint64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.snap.Version
}

// Lookup returns the current value. A key Dynv has ever managed (a value or
// a tombstone) without a value reads as unset, never as an inherited
// variable; other keys fall back to the process environment.
func (c *Client) Lookup(key string) (string, bool) {
	c.mu.RLock()
	v, ok := c.snap.Vars[key]
	managed := c.managed[key]
	c.mu.RUnlock()
	if ok {
		return v, true
	}
	if managed {
		return "", false
	}
	return os.LookupEnv(key)
}

// Get is Lookup without the flag ("" when unset).
func (c *Client) Get(key string) string {
	v, _ := c.Lookup(key)
	return v
}

// All returns the current value followed by its live fallback values, newest
// first. It returns an empty slice when key is unset.
func (c *Client) All(key string) []string {
	c.mu.RLock()
	current, ok := c.snap.Vars[key]
	managed := c.managed[key]
	var older []string
	if ok {
		older = append(older, c.snap.Fallbacks[key].Values...)
	}
	c.mu.RUnlock()
	if !ok && !managed {
		current, ok = os.LookupEnv(key)
	}
	if !ok {
		return []string{}
	}
	return append([]string{current}, older...)
}

// Require returns the value, or an error naming the key when it is unset.
func (c *Client) Require(key string) (string, error) {
	v, ok := c.Lookup(key)
	if !ok {
		return "", fmt.Errorf("dynv: %s is not set", key)
	}
	return v, nil
}

// Source is the name of the shared group that provides key, or "" for
// process-local, unset or unknown keys.
func (c *Client) Source(key string) string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if _, ok := c.snap.Vars[key]; !ok {
		return ""
	}
	return c.snap.Sources[key]
}

// IsTemplate reports whether key's value was resolved from a template. Get
// already returns the resolved value.
func (c *Client) IsTemplate(key string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	for _, k := range c.snap.Templates {
		if k == key {
			return true
		}
	}
	return false
}

// Unresolved are the templates that currently don't resolve (they keep their
// last good value, or are unset). Key names only; never nil.
func (c *Client) Unresolved() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return append([]string{}, c.snap.Unresolved...)
}

// Snapshot returns a copy of the current snapshot.
func (c *Client) Snapshot() Snapshot {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.snap.clone()
}

func (c *Client) id() int {
	c.nextID++
	return c.nextID
}

// OnChange calls fn after each applied change (not for the first snapshot),
// on the watcher goroutine. It returns a function that removes fn.
func (c *Client) OnChange(fn func(ChangeEvent)) (cancel func()) {
	c.lmu.Lock()
	defer c.lmu.Unlock()
	id := c.id()
	c.onChange[id] = fn
	return func() { c.lmu.Lock(); delete(c.onChange, id); c.lmu.Unlock() }
}

// OnKey calls fn when key is added, changed or removed (ok false), on the
// watcher goroutine. Not for the first snapshot.
func (c *Client) OnKey(key string, fn func(value string, ok bool)) (cancel func()) {
	c.lmu.Lock()
	defer c.lmu.Unlock()
	id := c.id()
	if c.onKey[key] == nil {
		c.onKey[key] = map[int]func(string, bool){}
	}
	c.onKey[key][id] = fn
	return func() { c.lmu.Lock(); delete(c.onKey[key], id); c.lmu.Unlock() }
}

// OnError calls fn for API or agent errors and refused updates (a
// *RefusedError or *HTTPError among them). The client keeps the last good
// environment and retries with backoff.
func (c *Client) OnError(fn func(error)) (cancel func()) {
	c.lmu.Lock()
	defer c.lmu.Unlock()
	id := c.id()
	c.onErr[id] = fn
	return func() { c.lmu.Lock(); delete(c.onErr, id); c.lmu.Unlock() }
}

// Close stops watching. Called from outside a callback, it waits for the
// watcher goroutine to finish. It always returns nil.
func (c *Client) Close() error {
	c.closeOnce.Do(func() {
		c.cancel()
		if !c.dispatching.Load() {
			c.wg.Wait()
		}
	})
	return nil
}

func sortedIDs[T any](m map[int]T) []T {
	ids := make([]int, 0, len(m))
	for id := range m {
		ids = append(ids, id)
	}
	sort.Ints(ids)
	out := make([]T, 0, len(ids))
	for _, id := range ids {
		out = append(out, m[id])
	}
	return out
}

// call runs one callback; a panic is recovered and logged, so it can't kill
// the watcher.
func (c *Client) call(what string, fn func()) {
	defer func() {
		if r := recover(); r != nil {
			c.log(fmt.Sprintf("%s callback panicked (%T); recovered", what, r))
		}
	}()
	fn()
}

func (c *Client) fail(err error) {
	c.dispatching.Store(true)
	defer c.dispatching.Store(false)
	if c.onError != nil {
		c.call("OnError", func() { c.onError(err) })
	}
	c.lmu.Lock()
	fns := sortedIDs(c.onErr)
	c.lmu.Unlock()
	for _, fn := range fns {
		c.call("OnError", func() { fn(err) })
	}
}

// apply installs next as the current snapshot and fires events.
func (c *Client) apply(next Snapshot) {
	if next.Vars == nil {
		next.Vars = map[string]string{}
	}
	if next.Apply == nil {
		next.Apply = map[string]string{}
	}
	c.mu.Lock()
	prev := c.snap
	if next.Version == prev.Version {
		c.mu.Unlock()
		return
	}
	var changed []string
	for k, v := range prev.Vars {
		if nv, ok := next.Vars[k]; !ok || nv != v {
			changed = append(changed, k)
		}
	}
	for k := range next.Vars {
		if _, ok := prev.Vars[k]; !ok {
			changed = append(changed, k)
		}
	}
	sort.Strings(changed)
	restart := false
	for _, k := range changed {
		mode, ok := next.Apply[k]
		if _, has := next.Vars[k]; !has {
			mode, ok = prev.Apply[k]
		}
		if !ok || mode == Restart {
			restart = true
		}
	}
	c.snap = next
	// Keys managed for the first time (a new tombstone included) are mirror
	// candidates too, even when no value changed. Live writes are filtered below.
	var fresh []string
	for _, k := range next.Managed {
		if !c.managed[k] {
			fresh = append(fresh, k)
		}
		c.managed[k] = true
	}
	for k := range next.Vars {
		c.managed[k] = true
	}
	first := prev.Version == 0
	if c.mirror {
		// A removed variable never falls back to an inherited value (what
		// `dynv run` does at spawn).
		touch := append(append([]string(nil), changed...), fresh...)
		if first {
			touch = append(append([]string(nil), next.Managed...), mapKeys(next.Vars)...)
		}
		for _, k := range touch {
			if !first {
				mode, ok := next.Apply[k]
				if _, has := next.Vars[k]; !has {
					mode, ok = prev.Apply[k]
				}
				if !ok || mode != Hot || IsDangerousKey(k) {
					continue
				}
			}
			if v, ok := next.Vars[k]; ok {
				os.Setenv(k, v) // keys the OS can't hold (with "=" or NUL) are skipped
			} else {
				os.Unsetenv(k)
			}
		}
	}
	c.mu.Unlock()
	if first {
		return // the first snapshot is the starting point, not a change
	}

	c.dispatching.Store(true)
	defer c.dispatching.Store(false)
	ev := ChangeEvent{Version: next.Version, Changed: changed, Restart: restart}
	c.lmu.Lock()
	changeFns := sortedIDs(c.onChange)
	type keyFn struct {
		key string
		fn  func(string, bool)
	}
	var keyFns []keyFn
	for _, k := range changed {
		for _, fn := range sortedIDs(c.onKey[k]) {
			keyFns = append(keyFns, keyFn{k, fn})
		}
	}
	c.lmu.Unlock()
	for _, fn := range changeFns {
		if c.ctx.Err() != nil {
			return
		}
		e := ev
		e.Changed = append([]string(nil), changed...)
		c.call("OnChange", func() { fn(e) })
	}
	for _, kf := range keyFns {
		if c.ctx.Err() != nil {
			return
		}
		v, ok := next.Vars[kf.key]
		c.call("OnKey", func() { kf.fn(v, ok) })
	}
	if restart && c.mode == ModeDirect && c.exit {
		c.log(fmt.Sprintf("restart-mode variables changed: %v -> SIGTERM", changed))
		if p, err := os.FindProcess(os.Getpid()); err == nil {
			p.Signal(syscall.SIGTERM)
		}
	}
}

func mapKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// sleep waits d or until the client is closed; it reports whether it is
// still open.
func (c *Client) sleep(d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-c.ctx.Done():
		return false
	}
}
