package dynv

import (
	"fmt"
	"sort"
	"strings"
)

// Template limits (§6.9).
const (
	MaxTemplateDepth = 16
	MaxResolved      = 65_536 // UTF-8 bytes
)

var templateReasons = map[string]string{
	"bare-dollar": `lone "$" (write "$$" for a literal "$" or "${NAME}" for a reference)`,
	"unclosed":    `"${" without a closing "}"`,
	"bad-name":    `invalid variable name inside "${...}"`,
}

// TemplateSyntaxError is a malformed template. Pos counts code points.
type TemplateSyntaxError struct {
	Pos    int
	Reason string // "bare-dollar", "unclosed" or "bad-name"
}

func (e *TemplateSyntaxError) Error() string {
	return fmt.Sprintf("malformed template at character %d: %s", e.Pos, templateReasons[e.Reason])
}

// TemplatePart is a literal text (Ref false) or a `${NAME}` reference (Ref true).
type TemplatePart struct {
	Ref  bool
	Text string
}

func validName(n []rune) bool {
	if len(n) == 0 || len(n) > 256 {
		return false
	}
	for i, c := range n {
		alpha := c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c == '_'
		if !alpha && (i == 0 || c < '0' || c > '9') {
			return false
		}
	}
	return !strings.HasPrefix(string(n), "DYNV_")
}

func indexRune(rs []rune, r rune, from int) int {
	for i := from; i < len(rs); i++ {
		if rs[i] == r {
			return i
		}
	}
	return -1
}

// ParseTemplate parses §6.9 syntax into parts; adjacent literals are joined
// and `$$` becomes `$`. A malformed text returns a *TemplateSyntaxError.
func ParseTemplate(text string) ([]TemplatePart, error) {
	rs := []rune(text)
	parts := []TemplatePart{}
	var lit []rune
	i := 0
	for {
		j := indexRune(rs, '$', i)
		if j < 0 {
			break
		}
		lit = append(lit, rs[i:j]...)
		var next rune
		if j+1 < len(rs) {
			next = rs[j+1]
		}
		if next == '$' {
			lit = append(lit, '$')
			i = j + 2
			continue
		}
		if next != '{' {
			return nil, &TemplateSyntaxError{j, "bare-dollar"}
		}
		end := indexRune(rs, '}', j+2)
		if end < 0 {
			return nil, &TemplateSyntaxError{j, "unclosed"}
		}
		if !validName(rs[j+2 : end]) {
			return nil, &TemplateSyntaxError{j, "bad-name"}
		}
		if len(lit) > 0 {
			parts = append(parts, TemplatePart{Text: string(lit)})
		}
		parts = append(parts, TemplatePart{Ref: true, Text: string(rs[j+2 : end])})
		lit, i = nil, end+1
	}
	if tail := append(lit, rs[i:]...); len(tail) > 0 {
		parts = append(parts, TemplatePart{Text: string(tail)})
	}
	return parts, nil
}

// TemplateError is why one template failed (§6.9). At is the key where the
// problem is; Message is the full text, `<key>: [depends on <at>: ]<detail>`.
type TemplateError struct {
	Code    string   `json:"code"` // syntax, missing, cycle, depth, too-long
	Key     string   `json:"key"`
	At      string   `json:"at"`
	Message string   `json:"message"`
	Path    []string `json:"path,omitempty"`   // cycle
	Pos     *int     `json:"pos,omitempty"`    // syntax
	Reason  string   `json:"reason,omitempty"` // syntax
	Name    string   `json:"name,omitempty"`   // missing
}

func (e *TemplateError) Error() string { return e.Message }

// Resolution is the result of [Resolve].
type Resolution struct {
	Values map[string]string         // literals and the templates that resolved
	Apply  map[string]string         // every key's effective mode, restart propagated
	Errors map[string]*TemplateError // failed template → why
	Deps   map[string][]string       // template → sorted transitive dependencies that exist
}

type tplFrame struct {
	key    string
	i      int
	buf    strings.Builder
	height int
	size   int
}

type tplFail struct {
	at, code string
	path     []string
	syntax   *TemplateSyntaxError
	name     string
}

func (f *tplFail) toError(key string) *TemplateError {
	e := &TemplateError{Code: f.code, Key: key, At: f.at}
	var why string
	switch f.code {
	case "syntax":
		pos := f.syntax.Pos
		e.Pos, e.Reason = &pos, f.syntax.Reason
		why = f.syntax.Error()
	case "missing":
		e.Name = f.name
		why = fmt.Sprintf("references ${%s}, which is not set in the effective environment", f.name)
	case "cycle":
		e.Path = f.path
		why = "reference cycle: " + strings.Join(f.path, " -> ")
	case "depth":
		why = fmt.Sprintf("templates nest deeper than %d levels", MaxTemplateDepth)
	case "too-long":
		why = fmt.Sprintf("resolved value is longer than %d bytes", MaxResolved)
	}
	if f.at == key {
		e.Message = key + ": " + why
	} else {
		e.Message = key + ": depends on " + f.at + ": " + why
	}
	return e
}

type resolved struct {
	value  string
	height int
}

// Resolve resolves templates (§6.9) over merged vars, exactly as the
// reference does: each template from a fresh stack, in byte order, memoizing
// successes only; the depth limit is checked on the way down (so the stack
// never exceeds 16 frames and nothing recurses), and the byte cap fails as
// soon as it is crossed.
func Resolve(merged map[string]Var) *Resolution {
	parsed := map[string][]TemplatePart{}
	bad := map[string]*TemplateSyntaxError{}
	var roots []string
	for k, v := range merged {
		if !v.Template {
			continue
		}
		roots = append(roots, k)
		p, err := ParseTemplate(v.Value)
		if err != nil {
			bad[k] = err.(*TemplateSyntaxError)
		} else {
			parsed[k] = p
		}
	}
	sort.Strings(roots)
	done := map[string]resolved{}
	errs := map[string]*TemplateError{}

	// enter returns the value of x if known now (height 0 for a literal);
	// otherwise it pushes x's frame.
	enter := func(x string, stack *[]*tplFrame) (resolved, bool, *tplFail) {
		v := merged[x]
		if !v.Template {
			return resolved{v.Value, 0}, true, nil
		}
		if r, ok := done[x]; ok {
			if len(*stack)+r.height > MaxTemplateDepth {
				return resolved{}, false, &tplFail{at: (*stack)[0].key, code: "depth"}
			}
			return r, true, nil
		}
		for i, fr := range *stack {
			if fr.key == x {
				path := make([]string, 0, len(*stack)-i+1)
				for _, f := range (*stack)[i:] {
					path = append(path, f.key)
				}
				return resolved{}, false, &tplFail{at: x, code: "cycle", path: append(path, x)}
			}
		}
		if len(*stack)+1 > MaxTemplateDepth {
			return resolved{}, false, &tplFail{at: (*stack)[0].key, code: "depth"}
		}
		if se := bad[x]; se != nil {
			return resolved{}, false, &tplFail{at: x, code: "syntax", syntax: se}
		}
		*stack = append(*stack, &tplFrame{key: x, height: 1})
		return resolved{}, false, nil
	}
	add := func(f *tplFrame, piece string) *tplFail {
		f.size += len(piece)
		if f.size > MaxResolved {
			return &tplFail{at: f.key, code: "too-long"}
		}
		f.buf.WriteString(piece)
		return nil
	}

	for _, root := range roots {
		var stack []*tplFrame
		ret, ok, fail := enter(root, &stack)
		for fail == nil && len(stack) > 0 {
			f := stack[len(stack)-1]
			parts := parsed[f.key]
			switch {
			case ok: // the value of the ref at f.i
				f.height = max(f.height, ret.height+1)
				fail = add(f, ret.value)
				f.i, ok = f.i+1, false
			case f.i == len(parts):
				stack = stack[:len(stack)-1]
				ret, ok = resolved{f.buf.String(), f.height}, true
				done[f.key] = ret
			case !parts[f.i].Ref:
				fail = add(f, parts[f.i].Text)
				f.i++
			default:
				if _, exists := merged[parts[f.i].Text]; !exists { // refs in order: the first failure wins
					fail = &tplFail{at: f.key, code: "missing", name: parts[f.i].Text}
				} else {
					ret, ok, fail = enter(parts[f.i].Text, &stack)
				}
			}
		}
		if fail != nil {
			errs[root] = fail.toError(root)
		}
	}

	// The static reference graph; a malformed template has no edges.
	deps := make(map[string][]string, len(roots))
	for _, k := range roots {
		seen := map[string]bool{}
		var todo []string
		push := func(n string) {
			for _, p := range parsed[n] {
				if _, exists := merged[p.Text]; p.Ref && exists {
					todo = append(todo, p.Text)
				}
			}
		}
		push(k)
		for len(todo) > 0 {
			n := todo[len(todo)-1]
			todo = todo[:len(todo)-1]
			if !seen[n] {
				seen[n] = true
				push(n)
			}
		}
		d := make([]string, 0, len(seen))
		for n := range seen {
			d = append(d, n)
		}
		sort.Strings(d)
		deps[k] = d
	}
	apply := make(map[string]string, len(merged))
	values := make(map[string]string, len(merged))
	for k, v := range merged {
		a := v.Apply
		for _, d := range deps[k] {
			if merged[d].Apply == Restart {
				a = Restart
			}
		}
		if a != Restart {
			a = Hot
		}
		apply[k] = a
		if !v.Template {
			values[k] = v.Value
		} else if r, ok := done[k]; ok {
			values[k] = r.value
		}
	}
	return &Resolution{Values: values, Apply: apply, Errors: errs, Deps: deps}
}
