package httpx_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/FacileStudio/douane/internal/httpx"
)

func client() *httpx.Client {
	return httpx.New("douane/test").WithBackoff(time.Millisecond, 2*time.Millisecond)
}

func TestJSONRefusesNonOKBeforeDecoding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"code":3,"message":"invalid ecosystem"}`))
	}))
	defer srv.Close()

	var out struct {
		Results []struct{} `json:"results"`
	}
	err := client().JSON(context.Background(), http.MethodPost, srv.URL, []byte("{}"), &out)
	if err == nil {
		t.Fatal("a 400 whose body decodes cleanly must be an error, not an empty result")
	}
	var se *httpx.StatusError
	if !errors.As(err, &se) {
		t.Fatalf("want a StatusError, got %T: %v", err, err)
	}
	if !strings.Contains(se.Snippet, "invalid ecosystem") {
		t.Fatalf("the snippet must carry the upstream message, got %q", se.Snippet)
	}
}

func TestClientErrorIsNotRetried(t *testing.T) {
	for _, code := range []int{http.StatusNotFound, http.StatusNotImplemented} {
		var calls atomic.Int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls.Add(1)
			w.WriteHeader(code)
		}))
		var out struct{}
		_ = client().JSON(context.Background(), http.MethodGet, srv.URL, nil, &out)
		srv.Close()
		if got := calls.Load(); got != 1 {
			t.Errorf("status %d was attempted %d times, want 1", code, got)
		}
	}
}

func TestRetriesThenSucceeds(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) < 3 {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	var out struct {
		OK bool `json:"ok"`
	}
	if err := client().JSON(context.Background(), http.MethodGet, srv.URL, nil, &out); err != nil {
		t.Fatalf("want success on the third attempt, got %v", err)
	}
	if !out.OK || calls.Load() != 3 {
		t.Fatalf("ok=%t after %d calls", out.OK, calls.Load())
	}
}

func TestGivesUpAfterAttempts(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	var out struct{}
	err := client().WithAttempts(3).JSON(context.Background(), http.MethodGet, srv.URL, nil, &out)
	if err == nil {
		t.Fatal("a permanently failing upstream must be an error, never a clean empty result")
	}
	if got := calls.Load(); got != 3 {
		t.Fatalf("attempted %d times, want 3", got)
	}
	var se *httpx.StatusError
	if !errors.As(err, &se) || se.Code != http.StatusServiceUnavailable {
		t.Fatalf("the underlying status must survive the retry wrapper, got %v", err)
	}
}

func TestRetryAfterSecondsIsHonoured(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	start := time.Now()
	var out struct{}
	if err := client().JSON(context.Background(), http.MethodGet, srv.URL, nil, &out); err != nil {
		t.Fatal(err)
	}
	if got := time.Since(start); got < time.Second {
		t.Fatalf("waited %v, want at least the 1s the server asked for", got)
	}
}

func TestRetryAfterOverBudgetGivesUp(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Retry-After", "3600")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	var out struct{}
	err := client().JSON(context.Background(), http.MethodGet, srv.URL, nil, &out)
	if err == nil || !strings.Contains(err.Error(), "budget") {
		t.Fatalf("an hour-long Retry-After must fail fast, got %v", err)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("attempted %d times, want 1 — it must not sleep an hour", got)
	}
}

func TestCancelledContextIsNotRetried(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var out struct{}
	if err := client().JSON(ctx, http.MethodGet, srv.URL, nil, &out); err == nil {
		t.Fatal("a cancelled context must be an error")
	}
	if got := calls.Load(); got != 0 {
		t.Fatalf("made %d requests on a cancelled context, want 0", got)
	}
}

func TestSetsUserAgent(t *testing.T) {
	got := make(chan string, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got <- r.Header.Get("User-Agent")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	var out struct{}
	if err := httpx.New("douane/1.2.3").JSON(context.Background(), http.MethodGet, srv.URL, nil, &out); err != nil {
		t.Fatal(err)
	}
	if ua := <-got; ua != "douane/1.2.3" {
		t.Fatalf("User-Agent = %q, want douane/1.2.3", ua)
	}
}
