package store

import (
	"path/filepath"
	"testing"
	"time"
)

func open(t *testing.T) *Store {
	t.Helper()
	st, err := Open(filepath.Join(t.TempDir(), "douane.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func TestFeedRoundTripAndReplace(t *testing.T) {
	st := open(t)

	if payload, _, err := st.Feed("kev"); err != nil || payload != nil {
		t.Fatalf("empty cache = %q, %v; want a miss with no error", payload, err)
	}
	if err := st.SaveFeed("kev", []byte("first")); err != nil {
		t.Fatalf("save: %v", err)
	}
	payload, at, err := st.Feed("kev")
	if err != nil || string(payload) != "first" {
		t.Fatalf("Feed = %q, %v; want \"first\"", payload, err)
	}
	if time.Since(at) > time.Minute {
		t.Fatalf("fetched = %v, want roughly now", at)
	}
	if err := st.SaveFeed("kev", []byte("second")); err != nil {
		t.Fatalf("resave: %v", err)
	}
	if payload, _, _ := st.Feed("kev"); string(payload) != "second" {
		t.Fatalf("Feed = %q after replace, want \"second\" — the upsert is not replacing", payload)
	}
}

func TestEPSSHonoursTheFreshnessWindow(t *testing.T) {
	st := open(t)
	if err := st.SaveEPSS(map[string]float64{"CVE-1": 0.5, "CVE-2": -1}); err != nil {
		t.Fatalf("save: %v", err)
	}

	fresh, err := st.EPSS(time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if fresh["CVE-1"] != 0.5 {
		t.Fatalf("CVE-1 = %v, want 0.5", fresh["CVE-1"])
	}
	if got, ok := fresh["CVE-2"]; !ok || got != -1 {
		t.Fatalf("CVE-2 = %v (present %v), want the -1 sentinel — an unscored CVE must stay cached", got, ok)
	}

	stale, err := st.EPSS(time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(stale) != 0 {
		t.Fatalf("rows outside the window = %d, want 0", len(stale))
	}
}

func TestEPSSReplacesAScore(t *testing.T) {
	st := open(t)
	if err := st.SaveEPSS(map[string]float64{"CVE-1": -1}); err != nil {
		t.Fatalf("save: %v", err)
	}
	if err := st.SaveEPSS(map[string]float64{"CVE-1": 0.9}); err != nil {
		t.Fatalf("resave: %v", err)
	}
	got, err := st.EPSS(time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if got["CVE-1"] != 0.9 {
		t.Fatalf("CVE-1 = %v, want 0.9 — a later score must replace the sentinel", got["CVE-1"])
	}
}
