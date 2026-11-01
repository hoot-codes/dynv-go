package dynv

import (
	"fmt"
	"os"
	"reflect"
	"testing"
	"time"
)

func TestFallbackVectors(t *testing.T) {
	v := loadVectors(t, "fallback-vectors.json")
	doc, err := ParseDoc([]byte(s(v["doc_wire"])), false)
	if err != nil {
		t.Fatal(err)
	}
	for _, rawCase := range a(v["cases"]) {
		c := m(rawCase)
		process := s(c["process"])
		now := int64(mustInt(t, c["now"]))
		t.Run(fmt.Sprintf("%s@%d", process, now), func(t *testing.T) {
			materialized := Materialize(doc, process, now)
			expected := m(c["expect"])
			vars := map[string]any{}
			for key, v := range materialized.Doc.Vars {
				vars[key] = map[string]any{"value": v.Value, "apply": v.Apply}
			}
			same(t, "vars", vars, expected["vars"])
			same(t, "removed", materialized.Doc.Removed, expected["removed"])
			same(t, "fallbacks", materialized.Fallbacks, expected["fallbacks"])
			var next any
			if materialized.Next != nil {
				next = *materialized.Next
			}
			same(t, "next", next, expected["next"])
			same(t, "collisions", materialized.Collisions, expected["collisions"])
			jitters := map[string]int64{}
			for key := range m(expected["jitter"]) {
				jitters[key] = Jitter(process, key, doc.Vars[key].Fallback)
			}
			same(t, "jitter", jitters, expected["jitter"])
			for key, v := range materialized.Doc.Vars {
				if v.Fallback != nil {
					t.Errorf("%s: fallback survived materialization", key)
				}
			}
		})
	}
}

func TestDirectFallbackRetirement(t *testing.T) {
	until := time.Now().Unix() + 3
	zero := uint32(0)
	resolved := &Doc{Name: "web", Version: 1, DefaultApply: Restart, Vars: map[string]Var{
		"AUTH_SECRET": {Value: "new", Apply: Hot, Fallback: &Fallback{Values: []FallbackValue{
			{Value: "old-2", Until: &until}, {Value: "old-1"},
		}, Jitter: &zero}},
	}}
	materialized := Materialize(resolved, resolved.Name, time.Now().Unix())
	o := &Opened{Doc: resolved, Resolved: resolved, Removed: materialized.Doc.Removed,
		Sources: map[string]string{}, Fallbacks: materialized.Fallbacks, Next: materialized.Next}
	o.Vars = make(map[string]EffVar, len(materialized.Doc.Vars))
	for k, v := range materialized.Doc.Vars {
		o.Vars[k] = EffVar{Value: v.Value, Apply: v.Apply}
	}
	c := newClient(ModeDirect, &Options{DisableEnvMirror: true, Logger: func(string) {}})
	state := &directState{rev: 1, key: keyOf(o), current: o, wake: make(chan struct{}, 1)}
	c.apply(toSnapshot(o, 1))
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		c.retireDirect(state)
	}()
	defer c.Close()
	if !reflect.DeepEqual(c.All("AUTH_SECRET"), []string{"new", "old-2", "old-1"}) {
		t.Fatalf("initial All: %v", c.All("AUTH_SECRET"))
	}
	waitFor(t, "fallback retirement", func() bool {
		return reflect.DeepEqual(c.All("AUTH_SECRET"), []string{"new", "old-1"})
	})
	if got := c.Get("AUTH_SECRET_PREVIOUS"); got != "old-1" {
		t.Errorf("exposed fallback: %q", got)
	}
}

func TestDirectFallbackNamesStayManaged(t *testing.T) {
	until := time.Now().Unix() + 3
	zero := uint32(0)
	resolved := &Doc{Name: "web", Version: 1, DefaultApply: Hot, Vars: map[string]Var{
		"AUTH_SECRET": {Value: "new", Apply: Hot, Fallback: &Fallback{Values: []FallbackValue{{Value: "old", Until: &until}}, Jitter: &zero}},
		"API_TOKEN":   {Value: "token-new", Apply: Hot, Fallback: &Fallback{Values: []FallbackValue{{Value: "token-old"}}, Jitter: &zero}},
	}}
	opened := func(doc *Doc) *Opened {
		materialized := Materialize(doc, doc.Name, time.Now().Unix())
		o := &Opened{Doc: doc, Resolved: doc, Removed: materialized.Doc.Removed,
			Sources: map[string]string{}, Fallbacks: materialized.Fallbacks, Next: materialized.Next}
		o.Vars = make(map[string]EffVar, len(materialized.Doc.Vars))
		for k, v := range materialized.Doc.Vars {
			o.Vars[k] = EffVar{Value: v.Value, Apply: v.Apply}
		}
		return o
	}
	initial := opened(resolved)
	t.Setenv("AUTH_SECRET_PREVIOUS", "inherited")
	t.Setenv("API_TOKEN_PREVIOUS", "inherited")
	c := newClient(ModeDirect, &Options{Logger: func(string) {}})
	state := &directState{rev: 1, key: keyOf(initial), current: initial, wake: make(chan struct{}, 1)}
	c.apply(toSnapshot(initial, 1))
	if got := os.Getenv("AUTH_SECRET_PREVIOUS"); got != "old" {
		t.Fatalf("initial mirrored fallback: %q", got)
	}
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		c.retireDirect(state)
	}()
	defer c.Close()
	waitFor(t, "fallback tombstone", func() bool {
		_, ok := c.Lookup("AUTH_SECRET_PREVIOUS")
		return !ok
	})
	if _, ok := os.LookupEnv("AUTH_SECRET_PREVIOUS"); ok {
		t.Fatal("retirement restored the inherited environment name")
	}
	if got := c.Get("API_TOKEN_PREVIOUS"); got != "token-old" {
		t.Fatalf("unrelated fallback: %q", got)
	}

	updated := &Doc{Name: "web", Version: 2, DefaultApply: Hot, Vars: map[string]Var{
		"AUTH_SECRET": {Value: "new", Apply: Hot},
		"API_TOKEN":   {Value: "token-new", Apply: Hot},
	}}
	c.applyDirect(state, opened(updated))
	if _, ok := c.Lookup("API_TOKEN_PREVIOUS"); ok {
		t.Fatal("dropping the fallback restored its inherited name")
	}
	if _, ok := os.LookupEnv("API_TOKEN_PREVIOUS"); ok {
		t.Fatal("dropping the fallback left its mirrored name behind")
	}
}

func TestFallbackUntilPlusJitterSaturates(t *testing.T) {
	const maximum = int64(1<<63 - 1)
	until := maximum - 1
	jitter := uint32(MaxJitter)
	doc := &Doc{Name: "api", Version: 1, DefaultApply: Hot, Vars: map[string]Var{
		"K": {Value: "new", Apply: Hot, Fallback: &Fallback{
			Values: []FallbackValue{{Value: "old", Until: &until}}, Jitter: &jitter,
		}},
	}}
	materialized := Materialize(doc, "api", until)
	if got := materialized.Doc.Vars["K_PREVIOUS"].Value; got != "old" {
		t.Fatalf("saturated retirement happened early: %q", got)
	}
	materialized = Materialize(doc, "api", maximum)
	if _, ok := materialized.Doc.Vars["K_PREVIOUS"]; ok {
		t.Fatal("fallback outlived the saturated retirement time")
	}
	if !reflect.DeepEqual(materialized.Doc.Removed, []string{"K_PREVIOUS"}) {
		t.Fatalf("retired fallback is not tombstoned: %v", materialized.Doc.Removed)
	}
}

func TestFallbackWireForm(t *testing.T) {
	doc := func(v string) []byte { return []byte(`{"process":"p","version":1,"vars":{"K":` + v + `}}`) }
	fallback := `{"values":[{"value":"old"}]}`
	for _, bad := range []string{
		`{"template":"${A}","fallback":` + fallback + `}`,
		`{"value":"new","fallback":{"values":[]}}`,
		`{"value":"new","fallback":{"values":[{"value":"0"},{"value":"1"},{"value":"2"},{"value":"3"},{"value":"4"},{"value":"5"},{"value":"6"},{"value":"7"},{"value":"8"}]}}`,
	} {
		if _, err := ParseDoc(doc(bad), false); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
	parsed, err := ParseDoc(doc(`{"value":"new","future":true,"fallback":`+fallback+`}`), false)
	if err != nil || parsed.Vars["K"].Fallback == nil || parsed.Vars["K"].Fallback.Values[0].Value != "old" {
		t.Fatalf("literal fallback: %+v, %v", parsed, err)
	}
}
