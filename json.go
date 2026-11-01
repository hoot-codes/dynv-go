package dynv

import (
	"errors"
	"strconv"
	"unicode/utf16"
	"unicode/utf8"
)

// Number is a JSON number exactly as it was written. Documents only use
// integers (PROTOCOL.md §2); see [Int].
type Number string

// MarshalJSON writes the number back unchanged (the cache stores what the
// server sent).
func (n Number) MarshalJSON() ([]byte, error) { return []byte(n), nil }

// MaxInt is the largest integer a document may carry (2^53−1, §2).
const MaxInt = 1<<53 - 1

// Int reports whether x is an integer JSON number in 1 … 2^53−1, written
// without a fraction or exponent, and returns it.
func Int(x any) (uint64, bool) {
	n, ok := x.(Number)
	if !ok || len(n) == 0 || n[0] == '-' || n[0] == '0' {
		return 0, false
	}
	for i := 0; i < len(n); i++ {
		if n[i] < '0' || n[i] > '9' {
			return 0, false
		}
	}
	v, err := strconv.ParseUint(string(n), 10, 64)
	if err != nil || v < 1 || v > MaxInt {
		return 0, false
	}
	return v, true
}

var errJSON = errors.New("invalid JSON")

// maxJSONDepth bounds nesting; nothing in the protocol nests deeper than 4.
const maxJSONDepth = 512

// ParseJSON decodes RFC 8259 JSON strictly, where encoding/json is lenient:
// invalid UTF-8 and lone-surrogate escapes (`\ud800`) are errors (not
// U+FFFD), duplicate object keys are errors, and numbers stay [Number].
// The result is built from map[string]any, []any, string, Number, bool and
// nil.
func ParseJSON(data []byte) (any, error) {
	if !utf8.Valid(data) {
		return nil, errJSON
	}
	p := parser{b: data}
	p.ws()
	v, err := p.value(0)
	if err != nil {
		return nil, err
	}
	p.ws()
	if p.i != len(p.b) {
		return nil, errJSON
	}
	return v, nil
}

type parser struct {
	b []byte
	i int
}

func (p *parser) ws() {
	for p.i < len(p.b) {
		switch p.b[p.i] {
		case ' ', '\t', '\n', '\r':
			p.i++
		default:
			return
		}
	}
}

func (p *parser) lit(s string) bool {
	if len(p.b)-p.i >= len(s) && string(p.b[p.i:p.i+len(s)]) == s {
		p.i += len(s)
		return true
	}
	return false
}

func (p *parser) value(depth int) (any, error) {
	if depth > maxJSONDepth || p.i >= len(p.b) {
		return nil, errJSON
	}
	switch c := p.b[p.i]; {
	case c == '{':
		p.i++
		m := map[string]any{}
		p.ws()
		if p.lit("}") {
			return m, nil
		}
		for {
			p.ws()
			if p.i >= len(p.b) || p.b[p.i] != '"' {
				return nil, errJSON
			}
			k, err := p.str()
			if err != nil {
				return nil, err
			}
			if _, dup := m[k]; dup {
				return nil, errJSON
			}
			p.ws()
			if !p.lit(":") {
				return nil, errJSON
			}
			p.ws()
			v, err := p.value(depth + 1)
			if err != nil {
				return nil, err
			}
			m[k] = v
			p.ws()
			if p.lit("}") {
				return m, nil
			}
			if !p.lit(",") {
				return nil, errJSON
			}
		}
	case c == '[':
		p.i++
		a := []any{}
		p.ws()
		if p.lit("]") {
			return a, nil
		}
		for {
			p.ws()
			v, err := p.value(depth + 1)
			if err != nil {
				return nil, err
			}
			a = append(a, v)
			p.ws()
			if p.lit("]") {
				return a, nil
			}
			if !p.lit(",") {
				return nil, errJSON
			}
		}
	case c == '"':
		return p.str()
	case c == 't' && p.lit("true"):
		return true, nil
	case c == 'f' && p.lit("false"):
		return false, nil
	case c == 'n' && p.lit("null"):
		return nil, nil
	case c == '-' || (c >= '0' && c <= '9'):
		return p.num()
	}
	return nil, errJSON
}

func (p *parser) digits() int {
	s := p.i
	for p.i < len(p.b) && p.b[p.i] >= '0' && p.b[p.i] <= '9' {
		p.i++
	}
	return p.i - s
}

func (p *parser) num() (any, error) {
	s := p.i
	p.lit("-")
	if p.lit("0") {
		// no leading zeros
	} else if p.digits() == 0 {
		return nil, errJSON
	}
	if p.lit(".") && p.digits() == 0 {
		return nil, errJSON
	}
	if p.i < len(p.b) && (p.b[p.i] == 'e' || p.b[p.i] == 'E') {
		p.i++
		if !p.lit("+") {
			p.lit("-")
		}
		if p.digits() == 0 {
			return nil, errJSON
		}
	}
	return Number(p.b[s:p.i]), nil
}

func hex4(b []byte) (rune, bool) {
	var r rune
	for _, c := range b {
		switch {
		case c >= '0' && c <= '9':
			r = r<<4 | rune(c-'0')
		case c >= 'a' && c <= 'f':
			r = r<<4 | rune(c-'a'+10)
		case c >= 'A' && c <= 'F':
			r = r<<4 | rune(c-'A'+10)
		default:
			return 0, false
		}
	}
	return r, true
}

// str reads a string starting at the opening quote. The input is already
// valid UTF-8; escapes must not produce a lone surrogate.
func (p *parser) str() (string, error) {
	p.i++ // opening quote
	start := p.i
	for p.i < len(p.b) && p.b[p.i] != '"' && p.b[p.i] != '\\' && p.b[p.i] >= 0x20 {
		p.i++
	}
	if p.i < len(p.b) && p.b[p.i] == '"' {
		p.i++
		return string(p.b[start : p.i-1]), nil
	}
	out := append([]byte(nil), p.b[start:p.i]...)
	for {
		if p.i >= len(p.b) {
			return "", errJSON
		}
		c := p.b[p.i]
		switch {
		case c == '"':
			p.i++
			return string(out), nil
		case c < 0x20:
			return "", errJSON
		case c != '\\':
			out = append(out, c)
			p.i++
			continue
		}
		if p.i+1 >= len(p.b) {
			return "", errJSON
		}
		e := p.b[p.i+1]
		p.i += 2
		switch e {
		case '"', '\\', '/':
			out = append(out, e)
		case 'b':
			out = append(out, '\b')
		case 'f':
			out = append(out, '\f')
		case 'n':
			out = append(out, '\n')
		case 'r':
			out = append(out, '\r')
		case 't':
			out = append(out, '\t')
		case 'u':
			if len(p.b)-p.i < 4 {
				return "", errJSON
			}
			r, ok := hex4(p.b[p.i : p.i+4])
			if !ok {
				return "", errJSON
			}
			p.i += 4
			if utf16.IsSurrogate(r) {
				// Only a high surrogate followed by an escaped low one is a character.
				if r >= 0xDC00 || len(p.b)-p.i < 6 || p.b[p.i] != '\\' || p.b[p.i+1] != 'u' {
					return "", errJSON
				}
				r2, ok := hex4(p.b[p.i+2 : p.i+6])
				if !ok || r2 < 0xDC00 || r2 > 0xDFFF {
					return "", errJSON
				}
				p.i += 6
				r = utf16.DecodeRune(r, r2)
			}
			out = utf8.AppendRune(out, r)
		default:
			return "", errJSON
		}
	}
}
