package httpx

import (
	"net/http"
	"time"
)

const (
	drainLimit   = 64 << 10
	snippetLimit = 512
	defaultBody  = 64 << 20
	defaultTries = 4
	defaultBase  = 200 * time.Millisecond
	defaultCap   = 5 * time.Second
	defaultWait  = 30 * time.Second
	defaultReq   = 30 * time.Second
)

// Client is an HTTP client that checks the status before decoding, retries the
// failures worth retrying, honours Retry-After, and bounds every body it
// reads. Every douane upstream goes through it, because they have to behave
// identically for the exit code to mean anything.
type Client struct {
	http     *http.Client
	agent    string
	attempts int
	base     time.Duration
	ceiling  time.Duration
	maxWait  time.Duration
	maxBody  int64
}

// New returns a Client identifying itself as agent.
func New(agent string) *Client {
	return &Client{
		http:     &http.Client{Timeout: defaultReq},
		agent:    agent,
		attempts: defaultTries,
		base:     defaultBase,
		ceiling:  defaultCap,
		maxWait:  defaultWait,
		maxBody:  defaultBody,
	}
}

// WithMaxBody bounds how much of a response body will be read.
func (c *Client) WithMaxBody(n int64) *Client {
	c.maxBody = n
	return c
}

// WithBackoff sets the first retry delay and the ceiling it grows to.
func (c *Client) WithBackoff(base, ceiling time.Duration) *Client {
	c.base, c.ceiling = base, ceiling
	return c
}

// WithMaxWait sets how long an upstream may ask douane to wait before it gives
// up instead.
func (c *Client) WithMaxWait(d time.Duration) *Client {
	c.maxWait = d
	return c
}

// WithAttempts sets how many times a retryable failure is tried in total.
func (c *Client) WithAttempts(n int) *Client {
	if n > 0 {
		c.attempts = n
	}
	return c
}
