// Command template-diff compares the Go template resolver with the TS
// reference's output: it reads the case file written by
// clients/python/differential/gen.ts and exits 1 on any mismatch in values,
// apply modes, deps or errors (code, at, message). See check.py there.
//
//	go run ./cmd/template-diff cases.json
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"sort"

	dynv "github.com/hoot-codes/dynv-go"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: template-diff <cases.json>")
		os.Exit(2)
	}
	data, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	v, err := dynv.ParseJSON(data)
	if err != nil {
		fmt.Fprintln(os.Stderr, "cases file is not JSON:", err)
		os.Exit(2)
	}
	cases, _ := v.([]any)
	bad := map[string][]int{}
	firstGot := map[string]any{}
	for i, x := range cases {
		c, _ := x.(map[string]any)
		env, _ := c["env"].(map[string]any)
		merged := map[string]dynv.Var{}
		for k, y := range env {
			e, _ := y.(map[string]any)
			apply, _ := e["apply"].(string)
			if t, ok := e["template"].(string); ok {
				merged[k] = dynv.Var{Value: t, Template: true, Apply: apply}
			} else {
				val, _ := e["value"].(string)
				merged[k] = dynv.Var{Value: val, Apply: apply}
			}
		}
		r := dynv.Resolve(merged)
		errs := map[string]any{}
		for k, e := range r.Errors {
			errs[k] = map[string]string{"code": e.Code, "at": e.At, "message": e.Message}
		}
		got := map[string]any{"values": r.Values, "apply": r.Apply, "deps": r.Deps, "errors": errs}
		for _, f := range []string{"values", "apply", "deps", "errors"} {
			if !reflect.DeepEqual(generic(got[f]), generic(c[f])) {
				if bad[f] == nil {
					firstGot[f] = got[f]
				}
				bad[f] = append(bad[f], i)
			}
		}
	}
	fields := make([]string, 0, len(bad))
	for f := range bad {
		fields = append(fields, f)
	}
	sort.Strings(fields)
	for _, f := range fields {
		i := bad[f][0]
		fmt.Printf("%s: %d mismatches; first: case %d\n", f, len(bad[f]), i)
		want, _ := json.Marshal(cases[i].(map[string]any)[f])
		got, _ := json.Marshal(firstGot[f])
		fmt.Printf("  ts=%s\n  go=%s\n", clip(want), clip(got))
	}
	status := "OK"
	if len(bad) > 0 {
		status = "MISMATCH"
	}
	fmt.Println("checked", len(cases), status)
	if len(bad) > 0 {
		os.Exit(1)
	}
}

// generic normalizes a value to the ParseJSON shape.
func generic(x any) any {
	b, err := json.Marshal(x)
	if err != nil {
		return err.Error()
	}
	v, err := dynv.ParseJSON(b)
	if err != nil {
		return err.Error()
	}
	return v
}

func clip(b []byte) string {
	if len(b) > 400 {
		return string(b[:400]) + "…"
	}
	return string(b)
}
