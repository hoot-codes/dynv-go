package dynv

import (
	"os"
	"reflect"
	"testing"
)

func TestLiveEnvMirrorOnlyHotSafeKeys(t *testing.T) {
	keys := []string{
		"DYNV_GO_TEST_HOT",
		"DYNV_GO_TEST_RESTART",
		"LD_PRELOAD",
		"DYNV_GO_TEST_HOT_REMOVED",
		"DYNV_GO_TEST_RESTART_REMOVED",
		"LD_LIBRARY_PATH",
		"DYNV_GO_TEST_BOOT_HOT_GONE",
		"DYNV_GO_TEST_BOOT_RESTART_GONE",
		"GIT_CONFIG_TEST_BOOT_GONE",
	}
	for _, key := range keys {
		t.Setenv(key, "inherited")
	}

	c := newClient(ModeAgent, &Options{Logger: func(string) {}})
	defer c.Close()
	first := Snapshot{
		Version: 1,
		Vars: map[string]string{
			"DYNV_GO_TEST_HOT":             "hot-1",
			"DYNV_GO_TEST_RESTART":         "restart-1",
			"LD_PRELOAD":                   "dangerous-1",
			"DYNV_GO_TEST_HOT_REMOVED":     "hot-present",
			"DYNV_GO_TEST_RESTART_REMOVED": "restart-present",
			"LD_LIBRARY_PATH":              "dangerous-present",
		},
		Apply: map[string]string{
			"DYNV_GO_TEST_HOT":               Hot,
			"DYNV_GO_TEST_RESTART":           Restart,
			"LD_PRELOAD":                     Hot,
			"DYNV_GO_TEST_HOT_REMOVED":       Hot,
			"DYNV_GO_TEST_RESTART_REMOVED":   Restart,
			"LD_LIBRARY_PATH":                Hot,
			"DYNV_GO_TEST_BOOT_HOT_GONE":     Hot,
			"DYNV_GO_TEST_BOOT_RESTART_GONE": Restart,
			"GIT_CONFIG_TEST_BOOT_GONE":      Hot,
		},
		Managed: []string{
			"DYNV_GO_TEST_HOT",
			"DYNV_GO_TEST_RESTART",
			"LD_PRELOAD",
			"DYNV_GO_TEST_HOT_REMOVED",
			"DYNV_GO_TEST_RESTART_REMOVED",
			"LD_LIBRARY_PATH",
			"DYNV_GO_TEST_BOOT_HOT_GONE",
			"DYNV_GO_TEST_BOOT_RESTART_GONE",
			"GIT_CONFIG_TEST_BOOT_GONE",
		},
	}
	c.apply(first)
	for key, want := range map[string]string{
		"DYNV_GO_TEST_HOT":             "hot-1",
		"DYNV_GO_TEST_RESTART":         "restart-1",
		"LD_PRELOAD":                   "dangerous-1",
		"DYNV_GO_TEST_HOT_REMOVED":     "hot-present",
		"DYNV_GO_TEST_RESTART_REMOVED": "restart-present",
		"LD_LIBRARY_PATH":              "dangerous-present",
	} {
		if got := os.Getenv(key); got != want {
			t.Errorf("first snapshot %s = %q, want %q", key, got, want)
		}
	}
	for _, key := range []string{"DYNV_GO_TEST_BOOT_HOT_GONE", "DYNV_GO_TEST_BOOT_RESTART_GONE", "GIT_CONFIG_TEST_BOOT_GONE"} {
		if got, ok := os.LookupEnv(key); ok {
			t.Errorf("first snapshot left managed valueless key %s = %q", key, got)
		}
	}

	var events []ChangeEvent
	c.OnChange(func(event ChangeEvent) { events = append(events, event) })
	second := Snapshot{
		Version: 2,
		Vars: map[string]string{
			"DYNV_GO_TEST_HOT":     "hot-2",
			"DYNV_GO_TEST_RESTART": "restart-2",
			"LD_PRELOAD":           "dangerous-2",
		},
		Apply: map[string]string{
			"DYNV_GO_TEST_HOT":     Hot,
			"DYNV_GO_TEST_RESTART": Restart,
			"LD_PRELOAD":           Hot,
		},
		Managed: first.Managed,
	}
	c.apply(second)

	for key, want := range map[string]string{
		"DYNV_GO_TEST_HOT":             "hot-2",
		"DYNV_GO_TEST_RESTART":         "restart-1",
		"LD_PRELOAD":                   "dangerous-1",
		"DYNV_GO_TEST_RESTART_REMOVED": "restart-present",
		"LD_LIBRARY_PATH":              "dangerous-present",
	} {
		if got := os.Getenv(key); got != want {
			t.Errorf("after live snapshot %s = %q, want %q", key, got, want)
		}
	}
	if got, ok := os.LookupEnv("DYNV_GO_TEST_HOT_REMOVED"); ok {
		t.Errorf("hot safe removal left %s = %q", "DYNV_GO_TEST_HOT_REMOVED", got)
	}
	for key, want := range map[string]string{
		"DYNV_GO_TEST_HOT":     "hot-2",
		"DYNV_GO_TEST_RESTART": "restart-2",
		"LD_PRELOAD":           "dangerous-2",
	} {
		if got := c.Get(key); got != want {
			t.Errorf("Get(%s) = %q, want live value %q", key, got, want)
		}
	}
	for _, key := range []string{"DYNV_GO_TEST_HOT_REMOVED", "DYNV_GO_TEST_RESTART_REMOVED", "LD_LIBRARY_PATH"} {
		if got, ok := c.Lookup(key); ok {
			t.Errorf("Lookup(%s) = %q, true after removal", key, got)
		}
	}
	wantChanged := []string{
		"DYNV_GO_TEST_HOT",
		"DYNV_GO_TEST_HOT_REMOVED",
		"DYNV_GO_TEST_RESTART",
		"DYNV_GO_TEST_RESTART_REMOVED",
		"LD_LIBRARY_PATH",
		"LD_PRELOAD",
	}
	if len(events) != 1 || !reflect.DeepEqual(events[0].Changed, wantChanged) || !events[0].Restart {
		t.Errorf("live events = %+v, want one restart event with changes %v", events, wantChanged)
	}
}
