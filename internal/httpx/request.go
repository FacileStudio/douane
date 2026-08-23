package httpx

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// JSON sends a request and decodes a JSON response into out. A non-2xx status
// is an error before anything is decoded, which is the whole point: every
// upstream douane talks to answers errors with a body that decodes cleanly
// into an empty result.
func (c *Client) JSON(ctx context.Context, method, url string, body []byte, out any) error {
	return c.do(ctx, method, url, body, func(r io.Reader) error {
		return json.NewDecoder(r).Decode(out)
	})
}

// Bytes sends a GET and returns the whole body, bounded by the client's limit.
func (c *Client) Bytes(ctx context.Context, url string) ([]byte, error) {
	var out []byte
	err := c.do(ctx, http.MethodGet, url, nil, func(r io.Reader) error {
		b, err := io.ReadAll(r)
		out = b
		return err
	})
	return out, err
}

func (c *Client) do(ctx context.Context, method, url string, body []byte, read func(io.Reader) error) error {
	var last error
	for attempt := range c.attempts {
		if attempt > 0 {
			if err := c.pause(ctx, attempt, last); err != nil {
				return err
			}
		}
		err := c.attempt(ctx, method, url, body, read)
		if err == nil {
			return nil
		}
		last = err
		if !Retryable(err) {
			return err
		}
	}
	return fmt.Errorf("after %d attempts: %w", c.attempts, last)
}

func (c *Client) attempt(ctx context.Context, method, url string, body []byte, read func(io.Reader) error) error {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, reader)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", c.agent)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.http.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return err
		}
		return &retryable{error: fmt.Errorf("%s: %w", url, err)}
	}
	defer drain(resp.Body)

	if resp.StatusCode/100 != 2 {
		return c.statusError(resp, url)
	}
	if err := read(io.LimitReader(resp.Body, c.maxBody)); err != nil {
		return fmt.Errorf("%s: %w", url, err)
	}
	return nil
}

func (c *Client) statusError(resp *http.Response, url string) error {
	snippet, _ := io.ReadAll(io.LimitReader(resp.Body, snippetLimit))
	err := &StatusError{URL: url, Code: resp.StatusCode, Status: resp.Status, Snippet: string(snippet)}
	if !retryStatus(resp.StatusCode) {
		return err
	}
	after, ok := retryAfter(resp.Header, timeNow())
	return &retryable{error: err, after: after, hasAfter: ok}
}

// drain reads a bounded remainder of the body before closing it, so the
// connection goes back to the pool. An undrained body costs connection reuse;
// an unbounded drain costs memory on a hostile response.
func drain(body io.ReadCloser) {
	io.Copy(io.Discard, io.LimitReader(body, drainLimit))
	body.Close()
}
