package permit

import (
	"strings"
	"time"
)

// parser reads douane.yml one line at a time. It understands the one shape the
// file has, a top-level permits list of flat key: value entries, and refuses
// everything else by line: a general YAML reader would accept a misspelt key
// or a nested block and quietly drop it, and a permit file that fails open
// looks maintained while it is not.
type parser struct {
	today   time.Time
	inList  bool
	empty   bool
	cur     *entry
	dashCol int
	keyCol  int
	permits []Permit
}

// entry is the permit being read, with the keys it has set so far.
type entry struct {
	permit Permit
	seen   map[string]bool
}

// Parse reads a douane.yml document. Every entry needs an id, a reason and an
// expiry no more than MaxAhead past today; an entry missing one is refused
// with the line it starts on, and a malformed value with its own line.
func Parse(data []byte, today time.Time) ([]Permit, error) {
	p := &parser{today: today, dashCol: -1}
	text := strings.TrimPrefix(string(data), "\ufeff")
	for i, raw := range strings.Split(text, "\n") {
		if err := p.line(i+1, strings.TrimSuffix(raw, "\r")); err != nil {
			return nil, err
		}
	}
	if err := p.finish(); err != nil {
		return nil, err
	}
	return p.permits, nil
}

func (p *parser) line(n int, raw string) error {
	body := strings.TrimLeft(raw, " ")
	indent := len(raw) - len(body)
	switch {
	case strings.TrimSpace(body) == "" || strings.HasPrefix(body, "#"):
		return nil
	case strings.HasPrefix(body, "\t"):
		return &Error{n, "indent with spaces, YAML does not allow tabs"}
	case strings.HasPrefix(body, "-"):
		return p.item(n, indent, body)
	case indent == 0:
		return p.top(n, body)
	}
	return p.field(n, indent, body)
}

func (p *parser) top(n int, body string) error {
	key, value, ok := splitKey(body)
	if !ok || key != "permits" {
		return &Error{n, "unknown top-level entry, douane.yml holds only permits:"}
	}
	if p.inList {
		return &Error{n, "permits: is declared twice"}
	}
	p.inList = true
	switch strings.TrimSpace(stripComment(value)) {
	case "":
		return nil
	case "[]":
		p.empty = true
		return nil
	}
	return &Error{n, "permits: must be a list of entries, one per line starting with -"}
}

func (p *parser) item(n, indent int, body string) error {
	if !p.inList || p.empty {
		return &Error{n, "a list entry outside permits:"}
	}
	if p.dashCol >= 0 && indent != p.dashCol {
		return &Error{n, "this entry is indented differently from the first one"}
	}
	rest := body[1:]
	key := strings.TrimLeft(rest, " ")
	if key == "" || key == rest {
		return &Error{n, "expected - key: value"}
	}
	if err := p.finish(); err != nil {
		return err
	}
	p.dashCol = indent
	p.keyCol = indent + 1 + len(rest) - len(key)
	p.cur = &entry{permit: Permit{Line: n}, seen: map[string]bool{}}
	return p.field(n, p.keyCol, key)
}

func (p *parser) field(n, indent int, body string) error {
	if p.cur == nil {
		return &Error{n, "expected a list entry starting with -"}
	}
	if indent != p.keyCol {
		return &Error{n, "this key does not line up with the first key of its entry"}
	}
	key, raw, ok := splitKey(body)
	if !ok {
		return &Error{n, "expected key: value"}
	}
	value, err := scalar(raw)
	if err != nil {
		return &Error{n, err.Error()}
	}
	return p.set(n, key, value)
}

// finish closes the entry being read, refusing it when a required key never
// came. The message names the line the entry starts on, which is where the
// missing key belongs.
func (p *parser) finish() error {
	e := p.cur
	if e == nil {
		return nil
	}
	p.cur = nil
	for _, key := range []string{"id", "reason", "expires"} {
		if !e.seen[key] {
			return &Error{e.permit.Line, "permit is missing " + key}
		}
	}
	p.permits = append(p.permits, e.permit)
	return nil
}

// splitKey cuts "key: value" at its first colon. A colon that is not followed
// by a space or the end of the line is part of a word, not a separator.
func splitKey(body string) (string, string, bool) {
	key, value, ok := strings.Cut(body, ":")
	if !ok || key == "" || strings.ContainsAny(key, " \t\"'") {
		return "", "", false
	}
	if value != "" && value[0] != ' ' && value[0] != '\t' {
		return "", "", false
	}
	return key, value, true
}
