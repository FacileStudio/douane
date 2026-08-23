package httpx

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/http"
	"strconv"
	"time"
)

var timeNow = time.Now

// StatusError is a non-2xx response. It carries a bounded snippet of the body
// because the failures that matter here — an Akamai 403 with an HTML body, an
// OSV error envelope that decodes to zero results — are indistinguishable from
// success without it.
type StatusError struct {
	URL     string
	Code    int
	Status  string
	Snippet string
}

func (e *StatusError) Error() string {
	if e.Snippet == "" {
		return fmt.Sprintf("%s: %s", e.URL, e.Status)
	}
	return fmt.Sprintf("%s: %s: %s", e.URL, e.Status, e.Snippet)
}

type retryable struct {
	error
	after    time.Duration
	hasAfter bool
}

func (r *retryable) Unwrap() error { return r.error }

// Retryable reports whether err is worth another attempt.
func Retryable(err error) bool {
	var r *retryable
	return errors.As(err, &r)
}

func (c *Client) pause(ctx context.Context, attempt int, last error) error {
	d := c.backoff(attempt - 1)
	var r *retryable
	if errors.As(last, &r) && r.hasAfter {
		if r.after > c.maxWait {
			return fmt.Errorf("upstream asked for %s, over the %s budget: %w", r.after, c.maxWait, last)
		}
		d = r.after
	}
	return sleep(ctx, d)
}

// backoff returns a full-jitter delay: random over the whole exponential
// window rather than a fixed step, which spreads a fleet of retries instead of
// synchronising them.
func (c *Client) backoff(n int) time.Duration {
	d := c.base << n
	if d > c.ceiling || d <= 0 {
		d = c.ceiling
	}
	return time.Duration(rand.Int64N(int64(d) + 1))
}

func sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return context.Cause(ctx)
	case <-t.C:
		return nil
	}
}

// retryStatus reports whether a status is worth another attempt. 501 is the
// one 5xx that is not: it says the server will never implement this.
func retryStatus(code int) bool {
	switch code {
	case http.StatusTooManyRequests,
		http.StatusInternalServerError,
		http.StatusBadGateway,
		http.StatusServiceUnavailable,
		http.StatusGatewayTimeout:
		return true
	}
	return false
}

// retryAfter reads the header in both permitted forms, seconds and HTTP-date.
// A date already in the past means retry now, not a negative timer.
func retryAfter(h http.Header, now time.Time) (time.Duration, bool) {
	v := h.Get("Retry-After")
	if v == "" {
		return 0, false
	}
	if secs, err := strconv.Atoi(v); err == nil {
		if secs < 0 {
			return 0, false
		}
		return time.Duration(secs) * time.Second, true
	}
	if t, err := http.ParseTime(v); err == nil {
		if d := t.Sub(now); d > 0 {
			return d, true
		}
		return 0, true
	}
	return 0, false
}
