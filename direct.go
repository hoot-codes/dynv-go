package dynv

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"
)

// directSource is the I/O around a Verifier: fetch, cache, watch (§5, §8, §9).
type directSource struct {
	v     *Verifier
	base  string
	auth  string
	cache string
	http  *http.Client
	poll  time.Duration
	long  bool
	log   func(string)
}

func trimDynv(err error) string { return strings.TrimPrefix(err.Error(), "dynv: ") }

func (s *directSource) warn(o *Opened) {
	for _, w := range o.Warnings {
		s.log(w)
	}
}

// accept is §6.10: persist first (a failed write refuses the update and
// changes nothing), then advance the state.
func (s *directSource) accept(o *Opened) error {
	if s.cache != "" {
		data, err := o.CacheJSON()
		if err == nil {
			err = WriteCache(s.cache, data)
		}
		if err != nil {
			return fmt.Errorf("dynv: cache write failed, update refused: %w", err)
		}
	}
	s.v.Remember(o)
	return nil
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-ctx.Done():
		return false
	}
}

// fetch is GET /v1/self, open and accept, retrying gen_mismatch every 250 ms
// for ~5 s (§6 step 3).
func (s *directSource) fetch(ctx context.Context) (*Opened, error) {
	for i := 0; i < 20; i++ {
		r, err := get(ctx, s.http, s.base+"/v1/self", s.auth, directClientInstance())
		if err != nil {
			return nil, err
		}
		if r == nil {
			return nil, errors.New("dynv: empty response")
		}
		o, err := s.v.Open(r)
		var re *RefusedError
		if errors.As(err, &re) && re.Code == CodeGenMismatch {
			if !sleepCtx(ctx, 250*time.Millisecond) {
				return nil, ctx.Err()
			}
			continue
		}
		if err != nil {
			return nil, err
		}
		s.warn(o)
		if err := s.accept(o); err != nil {
			return nil, err
		}
		return o, nil
	}
	return nil, refused(CodeGenMismatch)
}

// loadCache is §9 boot step 1: open + accept the cache without writing.
// A cache that doesn't open is ignored with a log line.
func (s *directSource) loadCache() (opened *Opened) {
	if s.cache == "" {
		return nil
	}
	var oldGen *uint64
	if s.v.GenFloor != nil {
		gen := *s.v.GenFloor
		oldGen = &gen
	}
	oldGroups := make(map[string]uint64, len(s.v.GroupGenFloors))
	for gid, gen := range s.v.GroupGenFloors {
		oldGroups[gid] = gen
	}
	defer func() {
		if opened == nil {
			s.v.GenFloor = oldGen
			s.v.GroupGenFloors = oldGroups
		}
	}()

	data, err := os.ReadFile(s.cache)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		s.log("cache ignored: cannot read it")
		return nil
	}
	r, err := ParseJSON(data)
	if err != nil {
		s.log("cache ignored: not JSON")
		return nil
	}
	resp, ok := r.(map[string]any)
	if !ok {
		s.log("cache ignored: not an object")
		return nil
	}
	invalidFloors := func() {
		s.log("cache ignored: invalid generation floors")
	}
	if raw, ok := resp["gen_floor"]; ok {
		gen, valid := Int(raw)
		if !valid {
			invalidFloors()
			return nil
		}
		if s.v.GenFloor != nil {
			gen = max(gen, *s.v.GenFloor)
		}
		s.v.GenFloor = &gen
	}
	cachedGroups := map[string]uint64{}
	if raw, ok := resp["group_gen_floors"]; ok {
		entries, ok := raw.(map[string]any)
		if !ok {
			invalidFloors()
			return nil
		}
		for gid, rawGen := range entries {
			gen, valid := Int(rawGen)
			if !IsID(gid) || !valid {
				invalidFloors()
				return nil
			}
			cachedGroups[gid] = gen
			s.v.GroupGenFloors[gid] = max(s.v.GroupGenFloors[gid], gen)
		}
	}
	shared, _ := resp["shared"].([]any)
	for _, raw := range shared {
		entry, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		gid, ok := entry["group_id"].(string)
		if !ok {
			continue
		}
		floor, ok := cachedGroups[gid]
		if !ok {
			continue
		}
		blob, ok := entry["blob"].(map[string]any)
		gen, valid := Int(blob["dek_gen"])
		if !ok || !valid || gen < floor {
			invalidFloors()
			return nil
		}
	}
	o, err := s.v.Open(resp)
	if err != nil {
		s.log("cache ignored: " + trimDynv(err))
		return nil
	}
	s.warn(o)
	s.v.Remember(o)
	return o
}

func refusalCode(err error) string {
	var re *RefusedError
	if errors.As(err, &re) {
		return re.Code
	}
	return trimDynv(err)
}

// effKey is the identity of an effective environment, to skip no-op updates
// (any value, apply mode, tombstone or source, §8).
type effKey struct {
	Version    uint64
	Vars       map[string]EffVar
	Removed    []string
	Sources    map[string]string
	Templates  []string
	Unresolved []string
	Fallbacks  map[string]Exposed
}

func keyOf(o *Opened) effKey {
	if o == nil {
		return effKey{}
	}
	return effKey{Version: o.Doc.Version, Vars: o.Vars, Removed: o.Removed, Sources: o.Sources,
		Templates: o.Templates, Unresolved: o.Unresolved, Fallbacks: o.Fallbacks}
}

// toSnapshot is the effective environment in the agent's snapshot shape.
func toSnapshot(o *Opened, rev uint64) Snapshot {
	s := Snapshot{Version: rev, Vars: map[string]string{}, Apply: map[string]string{}, Sources: cloneMap(o.Sources),
		Templates: append([]string(nil), o.Templates...), Unresolved: append([]string(nil), o.Unresolved...)}
	managed := map[string]bool{}
	for k, v := range o.Vars {
		s.Vars[k], s.Apply[k] = v.Value, v.Apply
		managed[k] = true
	}
	for _, k := range o.Removed {
		managed[k] = true
	}
	for k := range managed {
		s.Managed = append(s.Managed, k)
	}
	sort.Strings(s.Managed)
	if len(o.Fallbacks) > 0 {
		s.Fallbacks = make(map[string]Exposed, len(o.Fallbacks))
		for k, f := range o.Fallbacks {
			f.Values = append([]string(nil), f.Values...)
			s.Fallbacks[k] = f
		}
	}
	return s
}

// directState serializes network updates and clock-driven fallback retirement.
type directState struct {
	mu      sync.Mutex
	rev     uint64
	key     effKey
	current *Opened
	wake    chan struct{}
}

func (c *Client) applyDirect(state *directState, o *Opened) {
	state.mu.Lock()
	defer state.mu.Unlock()
	state.current = o
	key := keyOf(o)
	if !reflect.DeepEqual(key, state.key) {
		state.key = key
		state.rev = max(state.rev+1, o.Version())
		c.apply(toSnapshot(o, state.rev))
	}
	select {
	case state.wake <- struct{}{}:
	default:
	}
}

// retireDirect re-materializes at next, without needing a server or keyholder.
func (c *Client) retireDirect(state *directState) {
	for {
		state.mu.Lock()
		current := state.current
		state.mu.Unlock()
		var timer *time.Timer
		var expired <-chan time.Time
		if current != nil && current.Next != nil {
			delay := time.Until(time.Unix(*current.Next, 0)) + time.Second
			if delay < 0 {
				delay = 0
			}
			timer = time.NewTimer(delay)
			expired = timer.C
		}
		select {
		case <-c.ctx.Done():
			if timer != nil {
				timer.Stop()
			}
			return
		case <-state.wake:
			if timer != nil {
				timer.Stop()
			}
			continue
		case <-expired:
		}

		state.mu.Lock()
		if state.current != current || current == nil || current.Resolved == nil {
			state.mu.Unlock()
			continue
		}
		materialized := Materialize(current.Resolved, current.Resolved.Name, time.Now().Unix())
		next := *current
		next.Vars = make(map[string]EffVar, len(materialized.Doc.Vars))
		for k, v := range materialized.Doc.Vars {
			next.Vars[k] = EffVar{Value: v.Value, Apply: v.Apply}
		}
		next.Removed = materialized.Doc.Removed
		next.Fallbacks = materialized.Fallbacks
		next.Next = materialized.Next
		next.Collisions = materialized.Collisions
		state.mu.Unlock()
		c.applyDirect(state, &next)
	}
}

func (c *Client) startDirect(ctx context.Context, s *directSource, opts *Options) error {
	// Cache first: it sets the rollback floors before any live response.
	cached := s.loadCache()
	bootCtx, cancel := context.WithTimeout(ctx, opts.BootTimeout)
	initial, err := s.fetch(bootCtx)
	timedOut := bootCtx.Err() != nil && ctx.Err() == nil
	cancel()
	if err != nil {
		var re *RefusedError
		why := "live fetch failed (" + trimDynv(err) + ")"
		if errors.As(err, &re) {
			why = "live response refused (" + re.Code + ")"
		} else if timedOut {
			why = "live fetch failed (timed out)"
		}
		c.fail(err)
		switch {
		case cached != nil:
			c.log(fmt.Sprintf("%s; using cached v%d", why, cached.Version()))
			initial = cached
		case opts.Require:
			return fmt.Errorf("dynv: cannot load env (%s) and Require is set: %w", why, err)
		default:
			c.log(why + "; starting with inherited env only")
		}
	}
	// Local revision: strictly increasing per applied change (groups
	// included), equal to the document version when no groups are attached.
	var rev uint64
	if initial != nil {
		rev = initial.Version()
		c.apply(toSnapshot(initial, rev))
	}
	state := &directState{rev: rev, key: keyOf(initial), current: initial, wake: make(chan struct{}, 1)}
	c.wg.Add(2)
	go func() {
		defer c.wg.Done()
		c.watchDirect(s, initial, state)
	}()
	go func() {
		defer c.wg.Done()
		c.retireDirect(state)
	}()
	return nil
}

// watchDirect is the §8 loop.
func (c *Client) watchDirect(s *directSource, start *Opened, state *directState) {
	var version, gen uint64
	if start != nil {
		version = start.Version()
	}
	sv := "" // gen 0 never matches, so the first watch returns at once and re-syncs
	first := min(time.Second, s.poll)
	backoff := first
	lastWarn := ""
	if start != nil {
		lastWarn = strings.Join(start.Warnings, "\n")
	}
	failed := func(err error) bool {
		c.fail(err)
		ok := c.sleep(backoff)
		backoff = min(backoff*2, s.poll)
		return ok
	}
	for c.ctx.Err() == nil {
		var r any
		var err error
		if s.long {
			q := url.Values{"version": {fmt.Sprint(version)}, "gen": {fmt.Sprint(gen)}, "timeout": {"50"}, "sv": {sv}, "caps": {"fallbacks"}}
			ctx, cancel := context.WithTimeout(c.ctx, 70*time.Second)
			r, err = get(ctx, s.http, s.base+"/v1/self/watch?"+q.Encode(), s.auth, directClientInstance())
			cancel()
		} else {
			if !c.sleep(s.poll) {
				return
			}
			ctx, cancel := context.WithTimeout(c.ctx, 30*time.Second)
			r, err = get(ctx, s.http, s.base+"/v1/self", s.auth, directClientInstance())
			cancel()
		}
		if err != nil {
			if c.ctx.Err() != nil {
				return
			}
			c.log("watch failed (" + trimDynv(err) + "); keeping the current environment")
			if !failed(err) {
				return
			}
			continue
		}
		backoff = first
		if r == nil {
			continue // 204
		}
		o, err := s.v.Open(r)
		var re *RefusedError
		if errors.As(err, &re) && re.Code == CodeGenMismatch {
			if !c.sleep(250 * time.Millisecond) {
				return
			}
			continue
		}
		if err != nil {
			c.log("update refused (" + refusalCode(err) + "); keeping the current environment")
			if !failed(err) {
				return
			}
			continue
		}
		if w := strings.Join(o.Warnings, "\n"); w != lastWarn {
			s.warn(o)
			lastWarn = w
		}
		if err := s.accept(o); err != nil {
			c.log(trimDynv(err))
			if !failed(err) {
				return
			}
			continue
		}
		version = o.Version()
		gen, _ = Int(r.(map[string]any)["blob"].(map[string]any)["dek_gen"])
		sv = svOf(r.(map[string]any)["shared"])
		c.applyDirect(state, o)
	}
}

// ---------------------------------------------------------------- agent

func (c *Client) agentGet(ctx context.Context, hc *http.Client, u, auth string) (*Snapshot, error) {
	body, err := getBody(ctx, hc, u, auth, "")
	if err != nil || body == nil {
		return nil, err
	}
	var s Snapshot
	if err := json.Unmarshal(body, &s); err != nil {
		return nil, errors.New("dynv: agent response is not a snapshot")
	}
	return &s, nil
}

// startAgent reads the `dynv run` agent (GET /v1/env, then long-polls
// /v1/env/watch?since=V; it answers 204 after 30 s).
func (c *Client) startAgent(ctx context.Context, agentURL, key string, opts *Options) error {
	base := strings.TrimRight(strings.TrimSpace(agentURL), "/")
	u, err := url.Parse(base)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" ||
		strings.ContainsAny(base, "?#") || (u.Path != "" && u.Path != "/") {
		return errors.New("dynv: DYNV_AGENT_URL must be http(s)://<loopback>:<port> (no credentials, path, query or fragment)")
	}
	// The agent is plain http next to the app: its key must never leave the host.
	if !isLoopback(u.Hostname()) {
		return errors.New("dynv: DYNV_AGENT_URL must be a loopback address")
	}
	hc := noRedirect(opts.HTTPClient)
	auth := "Bearer " + key
	bootCtx, cancel := context.WithTimeout(ctx, opts.BootTimeout)
	s, err := c.agentGet(bootCtx, hc, base+"/v1/env", auth)
	cancel()
	if err != nil {
		c.fail(err)
		if opts.Require {
			return fmt.Errorf("dynv: cannot reach the agent and Require is set: %w", err)
		}
		c.log("agent unreachable (" + trimDynv(err) + "); starting with inherited env only")
	} else if s != nil {
		c.apply(*s)
	}
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		backoff := 500 * time.Millisecond
		for c.ctx.Err() == nil {
			ctx, cancel := context.WithTimeout(c.ctx, 45*time.Second)
			s, err := c.agentGet(ctx, hc, fmt.Sprintf("%s/v1/env/watch?since=%d", base, c.Version()), auth)
			cancel()
			if err != nil {
				if c.ctx.Err() != nil {
					return
				}
				c.fail(err)
				if !c.sleep(backoff) {
					return
				}
				backoff = min(backoff*2, 30*time.Second)
				continue
			}
			backoff = 500 * time.Millisecond
			if s != nil {
				c.apply(*s)
			}
		}
	}()
	return nil
}
