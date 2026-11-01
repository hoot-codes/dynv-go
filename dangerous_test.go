package dynv

import (
	"encoding/json"
	"os"
	"testing"
)

func TestDangerousKeyVectorsMatchProtocol(t *testing.T) {
	data, err := os.ReadFile("testdata/dangerous-keys.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors struct {
		Dangerous []string `json:"dangerous"`
		Safe      []string `json:"safe"`
	}
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	for _, key := range vectors.Dangerous {
		if !IsDangerousKey(key) {
			t.Errorf("%s is dangerous in the protocol vectors, but IsDangerousKey returned false", key)
		}
	}
	for _, key := range vectors.Safe {
		if IsDangerousKey(key) {
			t.Errorf("%s is safe in the protocol vectors, but IsDangerousKey returned true", key)
		}
	}
}
