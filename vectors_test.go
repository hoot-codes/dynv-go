package dynv

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
)

const testdata = "testdata"

func loadVectors(t testing.TB, name string) map[string]any {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(testdata, name))
	if err != nil {
		t.Fatal(err)
	}
	v, err := ParseJSON(data)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return v.(map[string]any)
}

// generic turns any value into the ParseJSON shape, for comparison with vectors.
func generic(t testing.TB, x any) any {
	t.Helper()
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

func same(t testing.TB, what string, got, want any) {
	t.Helper()
	g := generic(t, got)
	w := generic(t, want)
	if !reflect.DeepEqual(g, w) {
		gb, _ := json.Marshal(g)
		wb, _ := json.Marshal(w)
		t.Errorf("%s:\n got %s\nwant %s", what, trunc(gb), trunc(wb))
	}
}

func trunc(b []byte) string {
	if len(b) > 2000 {
		return string(b[:2000]) + "…"
	}
	return string(b)
}

func m(x any) map[string]any { return x.(map[string]any) }
func a(x any) []any          { return x.([]any) }
func s(x any) string         { return x.(string) }

func mustB64(t testing.TB, x any) []byte {
	t.Helper()
	b, err := B64uDecode(s(x))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

var counts = map[string]int{}

func count(group string) { counts[group]++ }

func TestMain(m *testing.M) {
	code := m.Run()
	if len(counts) > 0 && os.Getenv("DYNV_VECTOR_COUNTS") != "" {
		keys := make([]string, 0, len(counts))
		for k := range counts {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Printf("vectors %s: %d\n", k, counts[k])
		}
	}
	os.Exit(code)
}

func TestPrimitives(t *testing.T) {
	P := m(loadVectors(t, "protocol-vectors.json")["primitives"])

	t.Run("base64url", func(t *testing.T) {
		for _, x := range a(m(P["base64url"])["valid"]) {
			v := m(x)
			raw, err := B64uDecode(s(v["b64"]))
			if err != nil || hex.EncodeToString(raw) != s(v["hex"]) || B64u(raw) != s(v["b64"]) {
				t.Errorf("valid %q: %x %v", v["b64"], raw, err)
			}
			count("base64url")
		}
		for _, x := range a(m(P["base64url"])["invalid"]) {
			if _, err := B64uDecode(s(x)); err == nil {
				t.Errorf("invalid %q accepted", x)
			}
			count("base64url")
		}
	})

	t.Run("tokens", func(t *testing.T) {
		for _, x := range a(m(P["tokens"])["valid"]) {
			v := m(x)
			tok, err := ParseToken(s(v["token"]))
			if err != nil {
				t.Fatalf("%s: %v", v["id"], err)
			}
			if tok.Kind != s(v["kind"]) || tok.ID != s(v["id"]) || hex.EncodeToString(tok.Secret()) != s(v["secret_hex"]) ||
				B64u(tok.AuthKey()) != s(v["auth_key_b64"]) || B64u(tok.WrapKey()) != s(v["wrap_key_b64"]) ||
				tok.Verifier() != s(v["verifier"]) || tok.Authorization() != s(v["authorization"]) {
				t.Errorf("token %s mismatch", v["id"])
			}
			count("tokens")
		}
		for _, x := range a(m(P["tokens"])["invalid"]) {
			if _, err := ParseToken(s(x)); err == nil {
				t.Errorf("invalid token accepted: %q", x)
			}
			count("tokens")
		}
	})

	t.Run("aad", func(t *testing.T) {
		for _, x := range a(P["aad"]) {
			v := m(x)
			if got := AAD(s(v["kind"]), a(v["args"])...); got != s(v["aad"]) {
				t.Errorf("aad %q, want %q", got, v["aad"])
			}
			count("aad")
		}
	})

	t.Run("aead", func(t *testing.T) {
		for i, x := range a(P["aead"]) {
			v := m(x)
			pt, err := AEADOpen(mustB64(t, v["key_b64"]), s(v["sealed"]), s(v["aad"]))
			if _, bad := v["error"]; bad {
				if err == nil {
					t.Errorf("aead %d: opened", i)
				}
			} else if err != nil || hex.EncodeToString(pt) != s(v["plaintext_hex"]) {
				t.Errorf("aead %d: %x %v", i, pt, err)
			}
			count("aead")
		}
	})

	t.Run("padding", func(t *testing.T) {
		for _, x := range a(P["padding"]) {
			v := m(x)
			jl, want := mustInt(t, v["json_len"]), mustInt(t, v["padded_len"])
			if got := PaddedLen(jl); got != want {
				t.Errorf("padded_len(%d) = %d, want %d", jl, got, want)
			}
			count("padding")
		}
	})

	t.Run("blob", func(t *testing.T) {
		b := m(P["blob"])
		sealed := m(b["sealed"])
		if got := AAD("blob", b["account_id"], b["process_id"], sealed["version"], sealed["dek_gen"]); got != s(b["aad"]) {
			t.Errorf("aad %q", got)
		}
		signers := []string{}
		for _, x := range a(b["signers"]) {
			signers = append(signers, s(x))
		}
		raw, err := BlobOpenRaw(sealed, mustB64(t, b["dek_b64"]), signers, s(b["aad"]))
		if err != nil || string(raw) != s(b["doc_json"]) {
			t.Errorf("open: %v", err)
		}
		if BlobHash(sealed) != s(b["hash"]) {
			t.Errorf("hash %s", BlobHash(sealed))
		}
		doc, err := OpenDoc(sealed, mustB64(t, b["dek_b64"]), signers, s(b["aad"]), false)
		if v, _ := Int(sealed["version"]); err != nil || doc.Version != v {
			t.Errorf("open doc: %v", err)
		}
		if _, err := BlobOpenRaw(sealed, mustB64(t, b["dek_b64"]), nil, s(b["aad"])); err == nil {
			t.Error("opened with no trusted signer")
		}
		count("blob")
	})

	t.Run("signatures", func(t *testing.T) {
		for i, x := range a(P["signatures"]) {
			v := m(x)
			pub, _ := B64uDecode(s(v["public_key"]))
			sig, _ := B64uDecode(s(v["sig"]))
			if got := Ed25519Verify(pub, sig, []byte(s(v["message_utf8"]))); got != v["valid"].(bool) {
				t.Errorf("signature %d: %v", i, got)
			}
			count("signatures")
		}
	})

	t.Run("shared_fingerprint", func(t *testing.T) {
		for _, x := range a(P["shared_fingerprint"]) {
			v := m(x)
			var entries []SVEntry
			for _, e := range a(v["entries"]) {
				f := a(e)
				entries = append(entries, SVEntry{s(f[0]), uint64(mustInt(t, f[1])), uint64(mustInt(t, f[2])), uint64(mustInt(t, f[3]))})
			}
			if got := SVFingerprint(entries); got != s(v["sv"]) {
				t.Errorf("sv %s, want %s", got, v["sv"])
			}
			count("shared_fingerprint")
		}
	})
}

func mustInt(t testing.TB, x any) int {
	t.Helper()
	var n int
	if _, err := fmt.Sscan(string(x.(Number)), &n); err != nil {
		t.Fatal(err)
	}
	return n
}

type vstate struct {
	Floor          *Head
	GroupFloors    map[string]Head
	GenFloor       *uint64
	GroupGenFloors map[string]uint64
	LastGroups     map[string]string
	LastValues     map[string]string
}

func stateOf(v *Verifier) vstate {
	st := vstate{GroupFloors: map[string]Head{}, GroupGenFloors: map[string]uint64{},
		LastGroups: map[string]string{}, LastValues: map[string]string{}}
	if v.Floor != nil {
		f := *v.Floor
		st.Floor = &f
	}
	for k, h := range v.GroupFloors {
		st.GroupFloors[k] = h
	}
	if v.GenFloor != nil {
		g := *v.GenFloor
		st.GenFloor = &g
	}
	for gid, gen := range v.GroupGenFloors {
		st.GroupGenFloors[gid] = gen
	}
	for k, g := range v.lastGroups {
		st.LastGroups[k] = g.Hash
	}
	for k, x := range v.lastValues {
		st.LastValues[k] = x
	}
	return st
}

func envOf(o *Opened) map[string]any {
	return map[string]any{"version": o.Version(), "vars": o.Vars, "removed": o.Removed, "sources": o.Sources,
		"templates": o.Templates, "unresolved": o.Unresolved}
}

func TestSelfCases(t *testing.T) {
	S := m(loadVectors(t, "protocol-vectors.json")["self"])
	token, err := ParseToken(s(S["token"]))
	if err != nil {
		t.Fatal(err)
	}
	for _, x := range a(S["cases"]) {
		c := m(x)
		t.Run(s(c["name"]), func(t *testing.T) {
			name, _ := c["process"].(string) // null = no pin
			v := NewVerifier(token, name)
			for i, y := range a(c["steps"]) {
				step := m(y)
				exp := m(step["expect"])
				before := stateOf(v)
				o, err := v.Open(step["response"])
				if !reflect.DeepEqual(stateOf(v), before) {
					t.Fatalf("step %d: Open changed state", i)
				}
				if s(exp["result"]) == "error" {
					re, ok := err.(*RefusedError)
					if !ok || re.Code != s(exp["error"]) {
						t.Fatalf("step %d: got %v, want refusal %s", i, err, exp["error"])
					}
					count("self steps")
					continue
				}
				if err != nil {
					t.Fatalf("step %d: %v", i, err)
				}
				same(t, fmt.Sprintf("step %d groups", i), o.Fates, exp["groups"])
				v.Remember(o)
				same(t, fmt.Sprintf("step %d env", i), envOf(o), exp["env"])
				same(t, fmt.Sprintf("step %d floor", i), v.Floor, exp["floor"])
				same(t, fmt.Sprintf("step %d group_floors", i), v.GroupFloors, exp["group_floors"])
				same(t, fmt.Sprintf("step %d gen_floor", i), v.GenFloor, exp["gen_floor"])
				same(t, fmt.Sprintf("step %d group_gen_floors", i), v.GroupGenFloors, exp["group_gen_floors"])
				count("self steps")
			}
			count("self cases")
		})
	}
}

func varsFrom(t testing.TB, raw map[string]any, def string) map[string]Var {
	out := map[string]Var{}
	for k, x := range raw {
		v := m(x)
		apply := def
		if ap, ok := v["apply"].(string); ok {
			apply = ap
		}
		if tpl, ok := v["template"].(string); ok {
			out[k] = Var{Value: tpl, Template: true, Apply: apply}
		} else {
			out[k] = Var{Value: s(v["value"]), Apply: apply}
		}
	}
	return out
}

func resolutionJSON(r *Resolution) map[string]any {
	return map[string]any{"values": r.Values, "apply": r.Apply, "errors": r.Errors, "deps": r.Deps}
}

func TestTemplateVectors(t *testing.T) {
	T := loadVectors(t, "template-vectors.json")
	t.Run("parse", func(t *testing.T) {
		for _, x := range a(T["parse"]) {
			v := m(x)
			parts, err := ParseTemplate(s(v["input"]))
			if want, bad := v["error"]; bad {
				se, ok := err.(*TemplateSyntaxError)
				if !ok {
					t.Errorf("%q: got %v", v["input"], err)
					continue
				}
				same(t, s(v["input"]), map[string]any{"pos": se.Pos, "reason": se.Reason}, want)
			} else {
				got := []map[string]string{}
				for _, p := range parts {
					if p.Ref {
						got = append(got, map[string]string{"ref": p.Text})
					} else {
						got = append(got, map[string]string{"lit": p.Text})
					}
				}
				same(t, s(v["input"]), got, v["parts"])
			}
			count("template parse")
		}
	})
	t.Run("resolve", func(t *testing.T) {
		for _, x := range a(T["resolve"]) {
			v := m(x)
			r := Resolve(varsFrom(t, m(v["vars"]), s(v["default_apply"])))
			same(t, s(v["name"]), resolutionJSON(r), v["expect"])
			count("template resolve")
		}
	})
}

// §2: objects may gain fields (e.g. a future blob.head for chained blobs).
func TestUnknownBlobFieldsAreIgnored(t *testing.T) {
	S := m(loadVectors(t, "protocol-vectors.json")["self"])
	token, err := ParseToken(s(S["token"]))
	if err != nil {
		t.Fatal(err)
	}
	for _, x := range a(S["cases"]) {
		c := m(x)
		if s(c["name"]) != "groups-merge" {
			continue
		}
		step := m(a(c["steps"])[0])
		resp := m(step["response"])
		m(resp["blob"])["head"] = map[string]any{"hh": "x", "hsig": "y", "asig": "z"}
		for _, e := range a(resp["shared"]) {
			m(m(e)["blob"])["head"] = map[string]any{"hh": "x"}
		}
		resp["future"] = json.Number("1")
		name, _ := c["process"].(string)
		v := NewVerifier(token, name)
		o, err := v.Open(resp)
		if err != nil {
			t.Fatal(err)
		}
		exp := m(step["expect"])
		same(t, "groups", o.Fates, exp["groups"])
		v.Remember(o)
		same(t, "floor", v.Floor, exp["floor"])
		return
	}
	t.Fatal("case groups-merge not found")
}

// §5 URL rules, shared with the TS, Rust and Python clients.
func TestBaseURLVectors(t *testing.T) {
	P := m(loadVectors(t, "protocol-vectors.json")["primitives"])
	cases := a(P["base_url"])
	if len(cases) < 15 {
		t.Fatalf("only %d base_url vectors", len(cases))
	}
	for _, x := range cases {
		c := m(x)
		got, err := CheckURL(s(c["url"]), c["allow_insecure_http"].(bool))
		if c["ok"].(bool) {
			if err != nil || got != s(c["base"]) {
				t.Errorf("%s: got %q, %v; want %q", s(c["url"]), got, err, c["base"])
			}
		} else if err == nil {
			t.Errorf("%s: accepted as %q", s(c["url"]), got)
		}
		count("base_url")
	}
}
