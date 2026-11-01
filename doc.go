package dynv

import (
	"errors"
	"strconv"
)

// Apply modes (§7.2).
const (
	Hot     = "hot"
	Restart = "restart"
)

// Var is one variable of a document: a literal (Template false, Value is the
// value) or a template (Template true, Value is the template text), with its
// apply mode already defaulted.
type Var struct {
	Value    string
	Template bool
	Apply    string
	Fallback *Fallback
}

// FallbackValue is one older value, newest first. Until nil means open-ended.
type FallbackValue struct {
	Value string
	Until *int64
}

// Fallback describes older values exposed after a rotation (SECRET-LIFECYCLE §4.4).
type Fallback struct {
	Values []FallbackValue
	As     *string
	Format string
	Sep    *string
	Order  string
	Retire string
	Jitter *uint32
}

// Doc is a parsed EnvDoc (§7.2) or SharedEnvDoc (§7.3). Name is `process`
// or `group`.
type Doc struct {
	Name         string
	Version      uint64
	DefaultApply string
	Vars         map[string]Var
	Removed      []string
	Shared       []string // EnvDoc only
	Processes    []string // SharedEnvDoc only
	Critical     []string // features a runtime must implement to apply it (§6.6a)
}

// KnownFeatures are the document features this client implements (§6.6a).
var KnownFeatures = map[string]bool{"fallbacks": true}

// UnknownCritical returns the first critical feature this client doesn't
// implement, or "".
func (d *Doc) UnknownCritical() string {
	for _, f := range d.Critical {
		if !KnownFeatures[f] {
			return f
		}
	}
	return ""
}

var errDoc = errors.New("document")

func strList(d map[string]any, k string) ([]string, error) {
	v, ok := d[k]
	if !ok {
		return []string{}, nil
	}
	arr, ok := v.([]any)
	if !ok {
		return nil, errDoc
	}
	out := make([]string, 0, len(arr))
	for _, x := range arr {
		s, ok := x.(string)
		if !ok {
			return nil, errDoc
		}
		out = append(out, s)
	}
	return out, nil
}

func applyOK(x any) (string, bool) {
	s, ok := x.(string)
	return s, ok && (s == Hot || s == Restart)
}

func parseFallback(raw any) (*Fallback, error) {
	obj, ok := raw.(map[string]any)
	if !ok {
		return nil, errDoc
	}
	values, ok := obj["values"].([]any)
	if !ok || len(values) == 0 || len(values) > MaxFallbacks {
		return nil, errDoc
	}
	f := &Fallback{Values: make([]FallbackValue, 0, len(values))}
	for _, rawValue := range values {
		item, ok := rawValue.(map[string]any)
		if !ok {
			return nil, errDoc
		}
		value, ok := item["value"].(string)
		if !ok {
			return nil, errDoc
		}
		fv := FallbackValue{Value: value}
		if rawUntil := item["until"]; rawUntil != nil {
			n, ok := rawUntil.(Number)
			if !ok {
				return nil, errDoc
			}
			until, err := strconv.ParseInt(string(n), 10, 64)
			if err != nil {
				return nil, errDoc
			}
			fv.Until = &until
		}
		f.Values = append(f.Values, fv)
	}
	for _, key := range []string{"as", "sep"} {
		if rawText := obj[key]; rawText != nil {
			text, ok := rawText.(string)
			if !ok {
				return nil, errDoc
			}
			if key == "as" {
				f.As = &text
			} else {
				f.Sep = &text
			}
		}
	}
	for _, rule := range []struct {
		key     string
		allowed []string
		dst     *string
	}{{"format", []string{"single", "list"}, &f.Format},
		{"order", []string{"newest-first", "oldest-first"}, &f.Order},
		{"retire", []string{Hot, Restart}, &f.Retire}} {
		if rawChoice := obj[rule.key]; rawChoice != nil {
			choice, ok := rawChoice.(string)
			if !ok || choice != rule.allowed[0] && choice != rule.allowed[1] {
				return nil, errDoc
			}
			*rule.dst = choice
		}
	}
	if rawJitter := obj["jitter"]; rawJitter != nil {
		n, ok := rawJitter.(Number)
		if !ok {
			return nil, errDoc
		}
		parsed, err := strconv.ParseUint(string(n), 10, 32)
		if err != nil {
			return nil, errDoc
		}
		jitter := uint32(parsed)
		f.Jitter = &jitter
	}
	return f, nil
}

// ParseDoc parses a document's JSON (strictly, see [ParseJSON]).
func ParseDoc(raw []byte, group bool) (*Doc, error) {
	v, err := ParseJSON(raw)
	if err != nil {
		return nil, errDoc
	}
	d, ok := v.(map[string]any)
	if !ok {
		return nil, errDoc
	}
	nameField := "process"
	if group {
		nameField = "group"
	}
	name, ok := d[nameField].(string)
	if !ok {
		return nil, errDoc
	}
	version, ok := Int(d["version"])
	if !ok {
		return nil, errDoc
	}
	def := Restart
	if x, present := d["default_apply"]; present {
		if def, ok = applyOK(x); !ok {
			return nil, errDoc
		}
	}
	rawVars := map[string]any{}
	if x, present := d["vars"]; present {
		if rawVars, ok = x.(map[string]any); !ok {
			return nil, errDoc
		}
	}
	vars := make(map[string]Var, len(rawVars))
	for k, x := range rawVars {
		// Exactly one of a string "value" (literal) or a string "template" (§6.9).
		obj, ok := x.(map[string]any)
		if !ok {
			return nil, errDoc
		}
		val, hasV := obj["value"]
		tpl, hasT := obj["template"]
		if hasV == hasT {
			return nil, errDoc
		}
		text, ok := val.(string)
		if hasT {
			text, ok = tpl.(string)
		}
		if !ok {
			return nil, errDoc
		}
		apply := def
		if a, present := obj["apply"]; present {
			if apply, ok = applyOK(a); !ok {
				return nil, errDoc
			}
		}
		var fallback *Fallback
		if rawFallback := obj["fallback"]; rawFallback != nil {
			if hasT {
				return nil, errDoc
			}
			fallback, err = parseFallback(rawFallback)
			if err != nil {
				return nil, errDoc
			}
		}
		vars[k] = Var{Value: text, Template: hasT, Apply: apply, Fallback: fallback}
	}
	if _, err := strList(d, "tokens"); err != nil {
		return nil, err
	}
	doc := &Doc{Name: name, Version: version, DefaultApply: def, Vars: vars, Shared: []string{}, Processes: []string{}}
	if doc.Removed, err = strList(d, "removed"); err != nil {
		return nil, err
	}
	if group {
		doc.Processes, err = strList(d, "processes")
	} else {
		doc.Shared, err = strList(d, "shared")
	}
	if err != nil {
		return nil, err
	}
	if doc.Critical, err = strList(d, "critical"); err != nil {
		return nil, err
	}
	return doc, nil
}

// OpenDoc is §4.3 steps 1–6: open the blob and require document.version ==
// blob.version.
func OpenDoc(blob map[string]any, dek []byte, signers []string, aad string, group bool) (*Doc, error) {
	raw, err := BlobOpenRaw(blob, dek, signers, aad)
	if err != nil {
		return nil, err
	}
	doc, err := ParseDoc(raw, group)
	if err != nil {
		return nil, err
	}
	if v, _ := Int(blob["version"]); doc.Version != v {
		return nil, errDoc
	}
	return doc, nil
}
