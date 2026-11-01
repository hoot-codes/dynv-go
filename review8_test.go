package dynv

// The eighth-pass review items, ported from direct-api's TS/Rust/Python fixes.

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestDirectRequiresAnExplicitURL(t *testing.T) {
	t.Setenv("DYNV_URL", "")
	t.Setenv("DYNV_AGENT_URL", "")
	_, err := Connect(context.Background(), Options{Mode: ModeDirect, Token: vectorToken(t), Logger: func(string) {}})
	if err == nil || !strings.Contains(err.Error(), "set DYNV_URL (https://api.dynv.dev for Dynv Cloud)") {
		t.Fatalf("got %v", err)
	}
}

func TestTokenScrubbedEvenWhenRefused(t *testing.T) {
	t.Setenv("DYNV_AGENT_URL", "")
	for _, tok := range []string{masterToken(t), "dynv_pt_nope", vectorToken(t)} {
		t.Setenv("DYNV_TOKEN", tok)
		t.Setenv("DYNV_URL", "") // the vector token then fails on the missing URL
		if _, err := Connect(context.Background(), Options{Logger: func(string) {}}); err == nil {
			t.Fatalf("%.12s…: accepted", tok)
		}
		if _, ok := os.LookupEnv("DYNV_TOKEN"); ok {
			t.Fatalf("%.12s…: DYNV_TOKEN left in the environment", tok)
		}
	}
}

func TestBaseURLFragmentRejected(t *testing.T) {
	for _, u := range []string{"https://api.dynv.dev/#x", "https://api.dynv.dev#", "https://api.dynv.dev/?", "https://u@api.dynv.dev"} {
		if _, err := CheckURL(u, false); err == nil {
			t.Errorf("%s accepted", u)
		}
	}
}

func clone(t *testing.T, x any) any {
	b, err := json.Marshal(x)
	if err != nil {
		t.Fatal(err)
	}
	v, err := ParseJSON(b)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// Whatever `shared` holds, Open and the watch fingerprint never panic, and a
// broken entry costs only its own group.
func TestMalformedSharedEntriesNeverPanic(t *testing.T) {
	step := selfCase(t, "groups-merge")[0]
	token, _ := ParseToken(vectorToken(t))
	base := m(clone(t, step["response"]))
	good := a(base["shared"])
	num := func(s string) any { return Number(s) }
	variants := []any{
		nil, "x", num("1"), map[string]any{}, []any{nil}, []any{"x", num("2")}, []any{[]any{}},
		[]any{map[string]any{"group_id": num("5")}},
		[]any{map[string]any{"group_id": m(good[0])["group_id"], "blob": "x"}},
		[]any{map[string]any{"group_id": m(good[0])["group_id"], "blob": map[string]any{"version": "1"}}},
		[]any{map[string]any{"group_id": m(good[0])["group_id"], "process_gen": num("0"), "slot_ct": num("1"), "blob": map[string]any{"version": num("0"), "dek_gen": num("-1")}}},
		[]any{map[string]any{"group_id": m(good[0])["group_id"], "process_gen": num("1e3"), "slot_ct": "", "blob": map[string]any{"version": num("1.5"), "dek_gen": num("99999999999999999999"), "ct": num("1"), "sig": nil, "signer": []any{}}}},
	}
	for i, sh := range variants {
		r := m(clone(t, base))
		r["shared"] = sh
		_ = svOf(sh)
		o, err := NewVerifier(token, "web-vectors").Open(r)
		if err != nil {
			t.Fatalf("variant %d: the whole response was refused (%v); only the group should be", i, err)
		}
		for gid, f := range o.Fates {
			if f.Status == "applied" {
				t.Fatalf("variant %d: group %s applied from a broken entry", i, gid)
			}
		}
	}
	// Every listed group gets a fate, never a crash, when entries are garbage.
	r := m(clone(t, base))
	r["shared"] = []any{map[string]any{"group_id": m(good[0])["group_id"], "blob": "x"}}
	o, err := NewVerifier(token, "web-vectors").Open(r)
	if err != nil {
		t.Fatal(err)
	}
	if f := o.Fates[s(m(good[0])["group_id"])]; f.Status != "skipped" || f.Reason != "blob" {
		t.Fatalf("got %+v", f)
	}
}

func TestVersionAndGenerationZeroRefused(t *testing.T) {
	step := selfCase(t, "plain")[0]
	token, _ := ParseToken(vectorToken(t))
	for _, f := range []string{"version", "dek_gen"} {
		r := m(clone(t, step["response"]))
		m(r["blob"])[f] = Number("0")
		_, err := NewVerifier(token, "web-vectors").Open(r)
		if re, ok := err.(*RefusedError); !ok || re.Code != CodeBlob {
			t.Errorf("%s 0: got %v, want a blob refusal", f, err)
		}
	}
}

// §8: a change of only a source or only a tombstone is still a change, and
// a new tombstone clears the inherited value from the process environment.
func TestSourceOnlyAndTombstoneOnlyChangesFire(t *testing.T) {
	t.Setenv("GONE_REVIEW8", "inherited")
	c := newClient(ModeDirect, &Options{Logger: func(string) {}})
	var events []ChangeEvent
	c.OnChange(func(e ChangeEvent) { events = append(events, e) })
	vars := map[string]string{"A": "1"}
	apply := map[string]string{"A": "hot", "GONE_REVIEW8": "hot"}
	c.apply(Snapshot{Version: 1, Vars: vars, Apply: apply, Managed: []string{"A"}})
	c.apply(Snapshot{Version: 2, Vars: vars, Apply: apply, Managed: []string{"A", "GONE_REVIEW8"}})
	if len(events) != 1 {
		t.Fatalf("tombstone-only change: %d events", len(events))
	}
	if _, ok := os.LookupEnv("GONE_REVIEW8"); ok {
		t.Fatal("a new tombstone left the inherited value in the environment")
	}
	if v, ok := c.Lookup("GONE_REVIEW8"); ok {
		t.Fatalf("tombstoned key reads %q", v)
	}
	c.apply(Snapshot{Version: 3, Vars: vars, Apply: apply, Managed: []string{"A", "GONE_REVIEW8"}, Sources: map[string]string{"A": "egress"}})
	if len(events) != 2 || c.Source("A") != "egress" {
		t.Fatalf("source-only change: %d events, source %q", len(events), c.Source("A"))
	}
}
