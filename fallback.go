package dynv

import (
	"crypto/sha256"
	"encoding/binary"
	"math"
	"sort"
	"strings"
)

// Fallback limits (SECRET-LIFECYCLE §4.4).
const (
	MaxFallbacks  = 8
	DefaultJitter = 300
	MaxJitter     = 3600
)

// FallbackName is the name key's fallback is exposed under.
func FallbackName(key string, f *Fallback) string {
	if f.As != nil {
		return *f.As
	}
	return key + "_PREVIOUS"
}

// Jitter is this process's deterministic delay after until for key (seconds).
func Jitter(process, key string, f *Fallback) int64 {
	maximum := uint64(DefaultJitter)
	if f.Jitter != nil {
		maximum = uint64(*f.Jitter)
	}
	if maximum > MaxJitter {
		maximum = MaxJitter
	}
	if maximum == 0 {
		return 0
	}
	h := sha256.Sum256([]byte("dynv/v1/fallback-jitter|" + process + "|" + key))
	return int64(binary.BigEndian.Uint64(h[:8]) % (maximum + 1))
}

// Exposed is one variable's live fallback, with values newest first.
type Exposed struct {
	Name   string   `json:"as"`
	Values []string `json:"values"`
}

// Materialized is a resolved document with its currently live fallbacks.
type Materialized struct {
	Doc        *Doc
	Fallbacks  map[string]Exposed
	Next       *int64
	Collisions []string
}

// Materialize exposes fallbacks after template resolution, exactly like
// dynv-proto's fallback.rs. Fallback names never override real variables.
func Materialize(doc *Doc, process string, now int64) *Materialized {
	out := *doc
	out.Vars = make(map[string]Var, len(doc.Vars))
	for key, v := range doc.Vars {
		out.Vars[key] = v
	}
	removed := make(map[string]bool, len(doc.Removed))
	for _, key := range doc.Removed {
		removed[key] = true
	}
	m := &Materialized{Doc: &out, Fallbacks: map[string]Exposed{}}
	taken := map[string]bool{}
	keys := make([]string, 0, len(doc.Vars))
	for key := range doc.Vars {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		v := doc.Vars[key]
		f := v.Fallback
		if f == nil {
			continue
		}
		name := FallbackName(key, f)
		if _, exists := doc.Vars[name]; !validName([]rune(name)) || exists || IsDangerousKey(name) || removed[name] || taken[name] {
			m.Collisions = append(m.Collisions, name)
			continue
		}
		taken[name] = true
		delay := Jitter(process, key, f)
		live := []string{}
		for _, fv := range f.Values {
			if fv.Until == nil {
				live = append(live, fv.Value)
				continue
			}
			retire := *fv.Until
			if retire > math.MaxInt64-delay {
				retire = math.MaxInt64
			} else {
				retire += delay
			}
			if retire <= now {
				continue
			}
			if m.Next == nil || retire < *m.Next {
				next := retire
				m.Next = &next
			}
			live = append(live, fv.Value)
		}
		if len(live) == 0 {
			removed[name] = true
			continue
		}
		value := live[0]
		if f.Format == "list" {
			ordered := live
			if f.Order == "oldest-first" {
				ordered = append([]string(nil), live...)
				for i, j := 0, len(ordered)-1; i < j; i, j = i+1, j-1 {
					ordered[i], ordered[j] = ordered[j], ordered[i]
				}
			}
			sep := ","
			if f.Sep != nil {
				sep = *f.Sep
			}
			value = strings.Join(ordered, sep)
		}
		apply := v.Apply
		if f.Retire != "" {
			apply = f.Retire
		}
		delete(removed, name)
		out.Vars[name] = Var{Value: value, Apply: apply}
		m.Fallbacks[key] = Exposed{Name: name, Values: live}
	}
	for key, v := range out.Vars {
		v.Fallback = nil
		out.Vars[key] = v
	}
	out.Removed = make([]string, 0, len(removed))
	for key := range removed {
		out.Removed = append(out.Removed, key)
	}
	sort.Strings(out.Removed)
	return m
}
