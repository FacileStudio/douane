package permit

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

const dateLayout = "2006-01-02"

// scalar decodes one value: plain, single-quoted or double-quoted, with an
// optional trailing comment. A plain value may not open with a character YAML
// reads as an anchor, a tag, a block scalar or a flow collection: each would
// need a real YAML reader to mean what the author meant, and quoting it says
// the same thing in the subset this file speaks. An npm scope's @ is one.
func scalar(raw string) (string, error) {
	v := strings.TrimSpace(raw)
	switch {
	case v == "" || v[0] == '#':
		return "", nil
	case v[0] == '"':
		return doubleQuoted(v)
	case v[0] == '\'':
		return singleQuoted(v)
	case strings.ContainsRune("[{|>&*!%@`", rune(v[0])):
		return "", fmt.Errorf("quote a value that starts with %q, YAML reads it as something else", v[0])
	}
	v = strings.TrimSpace(stripComment(v))
	if strings.Contains(v, ": ") || strings.HasSuffix(v, ":") {
		return "", errors.New("quote a value that contains a colon followed by a space")
	}
	return v, nil
}

// stripComment drops a plain value's trailing comment, which YAML starts at a
// # preceded by whitespace. A # inside a word, as in "issue#12", is text.
func stripComment(v string) string {
	for i := 1; i < len(v); i++ {
		if v[i] == '#' && (v[i-1] == ' ' || v[i-1] == '\t') {
			return v[:i]
		}
	}
	return v
}

func doubleQuoted(v string) (string, error) {
	for i := 1; i < len(v); i++ {
		switch v[i] {
		case '\\':
			i++
		case '"':
			s, err := strconv.Unquote(v[:i+1])
			if err != nil {
				return "", errors.New("invalid escape in a double-quoted value")
			}
			return s, trailing(v[i+1:])
		}
	}
	return "", errors.New("a double-quoted value is not closed on its line")
}

func singleQuoted(v string) (string, error) {
	var b strings.Builder
	for i := 1; i < len(v); i++ {
		if v[i] != '\'' {
			b.WriteByte(v[i])
			continue
		}
		if i+1 < len(v) && v[i+1] == '\'' {
			b.WriteByte('\'')
			i++
			continue
		}
		return b.String(), trailing(v[i+1:])
	}
	return "", errors.New("a single-quoted value is not closed on its line")
}

// trailing accepts what may follow a closing quote: nothing, or a comment.
func trailing(rest string) error {
	if rest = strings.TrimSpace(rest); rest == "" || rest[0] == '#' {
		return nil
	}
	return errors.New("unexpected text after a quoted value")
}

// set stores one key of the current entry, refusing unknown and repeated keys
// and empty values: a misspelt "expire:" read as nothing would leave a permit
// with no end, which is the one thing this file exists to prevent.
func (p *parser) set(n int, key, value string) error {
	e := p.cur
	if e.seen[key] {
		return &Error{n, key + " is set twice in one entry"}
	}
	e.seen[key] = true
	if value == "" {
		return &Error{n, key + " is empty"}
	}
	switch key {
	case "id":
		e.permit.ID = value
	case "package":
		e.permit.Package = value
	case "reason":
		e.permit.Reason = value
	case "expires":
		return p.expires(n, value)
	default:
		return &Error{n, fmt.Sprintf("unknown key %q, an entry takes id, package, reason and expires", key)}
	}
	return nil
}

func (p *parser) expires(n int, value string) error {
	day, err := time.Parse(dateLayout, value)
	if err != nil {
		return &Error{n, fmt.Sprintf("expires %q is not a date in YYYY-MM-DD form", value)}
	}
	if day.Sub(p.today) > MaxAhead {
		return &Error{n, fmt.Sprintf("expires %s is more than 365 days ahead, a permit is temporary", value)}
	}
	p.cur.permit.Expires = day
	return nil
}
