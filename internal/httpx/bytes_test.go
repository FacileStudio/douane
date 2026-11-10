package httpx_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func bodyServer(t *testing.T, body string) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func TestBytesRefusesABodyOverTheLimit(t *testing.T) {
	url := bodyServer(t, strings.Repeat("x", 11))

	_, err := client().WithMaxBody(10).WithAttempts(1).Bytes(context.Background(), url)

	if err == nil || !strings.Contains(err.Error(), "exceeds 10 bytes") {
		t.Fatalf("err = %v, want an over-limit error rather than a truncated body", err)
	}
}

func TestBytesReturnsABodyAtTheLimit(t *testing.T) {
	url := bodyServer(t, strings.Repeat("x", 10))

	got, err := client().WithMaxBody(10).Bytes(context.Background(), url)

	if err != nil || len(got) != 10 {
		t.Fatalf("got %d bytes, err %v; want the whole 10-byte body", len(got), err)
	}
}
