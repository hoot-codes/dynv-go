package dynv

import (
	"encoding/json"
	"sort"
	"time"
)

// Refusal codes for a whole response (§6).
const (
	CodeMalformedID        = "malformed_id"
	CodeEnvelope           = "envelope"
	CodeGenerationRollback = "generation_rollback"
	CodeGenMismatch        = "gen_mismatch"
	CodeBlob               = "blob"
	CodeProcessName        = "process_name"
	CodeFeature            = "feature"
	CodeRollback           = "rollback"
	CodeFork               = "fork"
)

// RefusedError is a response this client refused (§6). The previous
// environment stays in place. Code is one of the Code* constants.
type RefusedError struct {
	Code string
}

func (e *RefusedError) Error() string { return "dynv: response refused (" + e.Code + ")" }

func refused(code string) error { return &RefusedError{Code: code} }

// Fate is what happened to one listed shared group (§6.7). Status is
// "applied", "kept" or "skipped"; Version is set unless skipped; Reason
// (a §6.7 reason code) unless applied.
type Fate struct {
	Status  string `json:"status"`
	Version uint64 `json:"version,omitempty"`
	Reason  string `json:"reason,omitempty"`
}

// Group is one verified shared group: the delivered entry (ciphertext, for
// the cache), its document and its content hash.
type Group struct {
	ID    string
	Entry map[string]any
	Doc   *Doc
	Hash  string
}

// EffVar is one variable of the effective, resolved environment.
type EffVar struct {
	Value string `json:"value"`
	Apply string `json:"apply"`
}

// Head is a floor: the version and content hash of the newest accepted document.
type Head struct {
	Version uint64 `json:"version"`
	Hash    string `json:"hash"`
}

// Opened is a verified response, not yet accepted.
type Opened struct {
	Response       map[string]any
	Doc            *Doc
	Hash           string
	Fates          map[string]Fate
	Groups         []*Group // applied and kept groups, in doc.shared order
	GenFloor       uint64
	GroupGenFloors map[string]uint64
	Vars           map[string]EffVar  // effective, resolved
	Sources        map[string]string  // key → group name
	Removed        []string           // sorted tombstones (plus templates left unset)
	Templates      []string           // every template key, sorted
	Unresolved     []string           // templates that failed this time, sorted
	Warnings       []string           // log lines; key names only
	Fallbacks      map[string]Exposed // live fallback views, newest first
	Next           *int64             // next fallback retirement, seconds
	Collisions     []string
	Resolved       *Doc // resolved document before materialization, for retirement
}

// Version is the process document's version.
func (o *Opened) Version() uint64 { return o.Doc.Version }

// CacheJSON is §9: the response with `shared` = exactly the applied and
// kept entries.
func (o *Opened) CacheJSON() ([]byte, error) {
	r := map[string]any{}
	for _, k := range []string{"account_id", "process_id", "envelope_ct", "blob"} {
		r[k] = o.Response[k]
	}
	shared := make([]any, 0, len(o.Groups))
	for _, g := range o.Groups {
		shared = append(shared, g.Entry)
	}
	r["shared"] = shared
	// Cache-only, client-generated state; never accepted from the network.
	r["gen_floor"] = o.GenFloor
	r["group_gen_floors"] = o.GroupGenFloors
	return json.Marshal(r)
}

// Verifier is the §6 state machine without I/O. Open never changes state;
// Remember (§6.10 steps 2–5) does. Not safe for concurrent use.
type Verifier struct {
	token          *Token
	wrapKey        []byte
	Name           string // "" = no pin
	Floor          *Head
	GroupFloors    map[string]Head
	GenFloor       *uint64 // nil until the first accept
	GroupGenFloors map[string]uint64
	lastGroups     map[string]*Group
	lastValues     map[string]string // §6.9 fallback, in memory only
}

// NewVerifier makes a fresh verifier for token, pinned to process name
// (empty for none).
func NewVerifier(token *Token, name string) *Verifier {
	return &Verifier{token: token, wrapKey: token.WrapKey(), Name: name,
		GroupFloors: map[string]Head{}, GroupGenFloors: map[string]uint64{},
		lastGroups: map[string]*Group{}, lastValues: map[string]string{}}
}

type envelope struct {
	dekGen  uint64
	dek     []byte
	signers []string
}

func (v *Verifier) openEnvelope(sealed any, acct, proc string) (*envelope, error) {
	ct, _ := sealed.(string)
	pt, err := AEADOpen(v.wrapKey, ct, AAD("envelope", acct, proc, v.token.ID))
	if err != nil {
		return nil, err
	}
	x, err := ParseJSON(pt)
	if err != nil {
		return nil, err
	}
	m, _ := x.(map[string]any)
	a, _ := m["account_id"].(string)
	p, _ := m["process_id"].(string)
	gen, okGen := Int(m["dek_gen"])
	dekText, okDek := m["dek"].(string)
	arr, okSig := m["signers"].([]any)
	if m == nil || a != acct || p != proc || !okGen || !okDek || !okSig {
		return nil, errBlob
	}
	dek, err := B64uDecode(dekText)
	if err != nil || len(dek) != 32 {
		return nil, errBlob
	}
	signers := make([]string, 0, len(arr))
	for _, s := range arr {
		str, ok := s.(string)
		if !ok {
			return nil, errBlob
		}
		if k, err := B64uDecode(str); err != nil || len(k) != 32 {
			return nil, errBlob
		}
		signers = append(signers, str)
	}
	return &envelope{gen, dek, signers}, nil
}

// Open verifies a parsed SelfResp (see [ParseJSON]). It returns a
// *RefusedError and never changes state. Whatever the server sends, it never
// panics: an unexpected shape is a `blob` refusal, so the watcher keeps going.
func (v *Verifier) Open(response any) (o *Opened, err error) {
	defer func() {
		if r := recover(); r != nil {
			o, err = nil, refused(CodeBlob)
		}
	}()
	return v.open(response)
}

func (v *Verifier) open(response any) (*Opened, error) {
	resp, _ := response.(map[string]any)
	if !isIDValue(resp["account_id"]) || !isIDValue(resp["process_id"]) {
		return nil, refused(CodeMalformedID) // step 1
	}
	acct, proc := resp["account_id"].(string), resp["process_id"].(string)
	blob, ok := blobShapeOK(resp["blob"]) // §5 shape, in step 1: before any decryption
	if !ok {
		return nil, refused(CodeBlob)
	}
	env, err := v.openEnvelope(resp["envelope_ct"], acct, proc) // step 2
	if err != nil {
		return nil, refused(CodeEnvelope)
	}
	version, _ := Int(blob["version"])
	dekGen, _ := Int(blob["dek_gen"])
	if v.GenFloor != nil && (env.dekGen < *v.GenFloor || dekGen < *v.GenFloor) {
		return nil, refused(CodeGenerationRollback)
	}
	if env.dekGen != dekGen {
		return nil, refused(CodeGenMismatch) // step 3: the caller retries
	}
	doc, err := OpenDoc(blob, env.dek, env.signers, AAD("blob", acct, proc, version, dekGen), false) // step 4
	if err != nil {
		return nil, refused(CodeBlob)
	}
	if v.Name != "" && doc.Name != v.Name {
		return nil, refused(CodeProcessName) // step 5
	}
	if doc.UnknownCritical() != "" {
		return nil, refused(CodeFeature) // step 5a, §6.6a
	}
	h := BlobHash(blob) // step 6
	if v.Floor != nil && doc.Version < v.Floor.Version {
		return nil, refused(CodeRollback)
	}
	if v.Floor != nil && doc.Version == v.Floor.Version && h != v.Floor.Hash {
		return nil, refused(CodeFork)
	}

	// Step 7, §6.7. The server's `shared` is unsigned: only a key carrier.
	delivered := map[string]map[string]any{}
	shared, _ := resp["shared"].([]any)
	for _, x := range shared {
		if e, ok := x.(map[string]any); ok {
			if gid, ok := e["group_id"].(string); ok {
				if _, seen := delivered[gid]; !seen {
					delivered[gid] = e
				}
			}
		}
	}
	o := &Opened{Response: resp, Doc: doc, Hash: h, Fates: map[string]Fate{}}
	for _, gid := range doc.Shared {
		if _, seen := o.Fates[gid]; seen {
			continue
		}
		g, code := v.openGroup(gid, delivered[gid], acct, proc, env)
		switch {
		case code == "":
			o.Groups = append(o.Groups, g)
			o.Fates[gid] = Fate{Status: "applied", Version: g.Doc.Version}
		case v.lastGroups[gid] != nil:
			last := v.lastGroups[gid]
			o.Groups = append(o.Groups, last)
			o.Fates[gid] = Fate{Status: "kept", Version: last.Doc.Version, Reason: code}
			o.Warnings = append(o.Warnings, "group "+gid+" kept ("+code+")")
		default:
			o.Fates[gid] = Fate{Status: "skipped", Reason: code}
			o.Warnings = append(o.Warnings, "group "+gid+" skipped ("+code+")")
		}
	}

	// Step 8, §6.8.
	effective := map[string]Var{}
	o.Sources = map[string]string{}
	removed := map[string]bool{}
	for _, g := range o.Groups {
		for k, x := range g.Doc.Vars {
			effective[k] = x
			o.Sources[k] = g.Doc.Name
		}
		for _, k := range g.Doc.Removed {
			removed[k] = true
		}
	}
	for k, x := range doc.Vars {
		effective[k] = x
		delete(o.Sources, k)
	}
	for _, k := range doc.Removed {
		removed[k] = true
	}

	// Step 9, §6.9: against the merged vars only.
	res := Resolve(effective)
	resolvedVars := make(map[string]Var, len(effective))
	keys := make([]string, 0, len(effective))
	for k := range effective {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	o.Templates, o.Unresolved = []string{}, []string{}
	for _, k := range keys {
		if effective[k].Template {
			o.Templates = append(o.Templates, k)
		}
		if val, ok := res.Values[k]; ok {
			resolvedVars[k] = Var{Value: val, Apply: res.Apply[k], Fallback: effective[k].Fallback}
			continue
		}
		o.Unresolved = append(o.Unresolved, k)
		if last, ok := v.lastValues[k]; ok {
			resolvedVars[k] = Var{Value: last, Apply: res.Apply[k], Fallback: effective[k].Fallback}
			o.Warnings = append(o.Warnings, "template "+res.Errors[k].Message+"; keeping its last good value")
		} else { // unset and tombstoned, never inherited (sources stay as merged)
			removed[k] = true
			o.Warnings = append(o.Warnings, "template "+res.Errors[k].Message+"; it stays unset until fixed")
		}
	}
	o.Removed = make([]string, 0, len(removed))
	for k := range removed {
		o.Removed = append(o.Removed, k)
	}
	sort.Strings(o.Removed)
	// SECRET-LIFECYCLE §4.4: fallback names are added only after templates resolve.
	resolved := *doc
	resolved.Vars = resolvedVars
	resolved.Removed = append([]string(nil), o.Removed...)
	materialized := Materialize(&resolved, doc.Name, time.Now().Unix())
	o.Vars = make(map[string]EffVar, len(materialized.Doc.Vars))
	for k, v := range materialized.Doc.Vars {
		o.Vars[k] = EffVar{Value: v.Value, Apply: v.Apply}
	}
	o.Removed = materialized.Doc.Removed
	o.Fallbacks = materialized.Fallbacks
	o.Next = materialized.Next
	o.Collisions = materialized.Collisions
	o.Resolved = &resolved

	o.GenFloor = dekGen
	if v.GenFloor != nil {
		o.GenFloor = max(o.GenFloor, *v.GenFloor)
	}
	o.GroupGenFloors = make(map[string]uint64, len(v.GroupGenFloors)+len(o.Groups))
	for gid, gen := range v.GroupGenFloors {
		o.GroupGenFloors[gid] = gen
	}
	for _, g := range o.Groups {
		blob := g.Entry["blob"].(map[string]any)
		gen, _ := Int(blob["dek_gen"])
		o.GroupGenFloors[g.ID] = max(o.GroupGenFloors[g.ID], gen)
	}
	return o, nil
}

// openGroup is one row of §6.7; it returns the group or a reason code.
func (v *Verifier) openGroup(gid string, entry map[string]any, acct, proc string, env *envelope) (*Group, string) {
	if entry == nil {
		return nil, "not_delivered"
	}
	if !IsID(gid) {
		return nil, "malformed_id"
	}
	blob, ok := blobShapeOK(entry["blob"])
	slot, okSlot := entry["slot_ct"].(string)
	pgen, okGen := Int(entry["process_gen"])
	if !ok || !okSlot || !okGen {
		return nil, "blob" // §5 shape, before the slot (its AAD needs blob.dek_gen)
	}
	version, _ := Int(blob["version"])
	dekGen, _ := Int(blob["dek_gen"])
	if v.GenFloor != nil && pgen < *v.GenFloor {
		return nil, CodeGenerationRollback
	}
	if floor, ok := v.GroupGenFloors[gid]; ok && dekGen < floor {
		return nil, CodeGenerationRollback
	}
	if pgen != env.dekGen {
		return nil, "slot_gen"
	}
	gdek, err := AEADOpen(env.dek, slot, AAD("shared-slot", acct, gid, proc, pgen, dekGen))
	if err != nil || len(gdek) != 32 {
		return nil, "slot"
	}
	g, err := OpenDoc(blob, gdek, env.signers, AAD("shared-blob", acct, gid, version, dekGen), true)
	if err != nil {
		return nil, "blob"
	}
	listed := false
	for _, p := range g.Processes {
		if p == proc {
			listed = true
			break
		}
	}
	if !listed {
		return nil, "roster"
	}
	if g.UnknownCritical() != "" {
		return nil, CodeFeature
	}
	h := BlobHash(blob)
	if fl, ok := v.GroupFloors[gid]; ok {
		if g.Version < fl.Version {
			return nil, CodeRollback
		}
		if g.Version == fl.Version && h != fl.Hash {
			return nil, CodeFork
		}
	}
	return &Group{ID: gid, Entry: entry, Doc: g, Hash: h}, ""
}

// Remember advances the state to an accepted response (§6.10 steps 2–5).
// The caller persists first.
func (v *Verifier) Remember(o *Opened) {
	v.Floor = &Head{o.Doc.Version, o.Hash}
	genFloor := o.GenFloor
	v.GenFloor = &genFloor
	v.GroupGenFloors = make(map[string]uint64, len(o.GroupGenFloors))
	for gid, gen := range o.GroupGenFloors {
		v.GroupGenFloors[gid] = gen
	}
	last := make(map[string]*Group, len(o.Groups))
	for _, g := range o.Groups {
		if fl, ok := v.GroupFloors[g.ID]; !ok || g.Doc.Version >= fl.Version {
			v.GroupFloors[g.ID] = Head{g.Doc.Version, g.Hash}
		}
		last[g.ID] = g
	}
	v.lastGroups = last
	resolved := o.Vars
	if o.Resolved != nil {
		resolved = make(map[string]EffVar, len(o.Resolved.Vars))
		for k, x := range o.Resolved.Vars {
			resolved[k] = EffVar{Value: x.Value, Apply: x.Apply}
		}
	}
	vals := make(map[string]string, len(resolved))
	for k, x := range resolved {
		vals[k] = x.Value
	}
	v.lastValues = vals
}
