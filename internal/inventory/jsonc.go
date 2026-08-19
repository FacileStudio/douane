package inventory

// stripJSONC removes comments and trailing commas from a JSON-with-extensions
// document. It tracks string state, because bun.lock carries base64 integrity
// hashes that legitimately contain "//".
func stripJSONC(src []byte) []byte {
	out := make([]byte, 0, len(src))
	s := &scanner{src: src}
	for s.i < len(src) {
		out = s.step(out)
	}
	return out
}

type scanner struct {
	src      []byte
	i        int
	inString bool
	escaped  bool
}

func (s *scanner) step(out []byte) []byte {
	c := s.src[s.i]
	if s.inString {
		s.i++
		s.advanceString(c)
		return append(out, c)
	}
	switch {
	case c == '"':
		s.inString = true
		s.i++
		return append(out, c)
	case s.peekIs('/'):
		s.skipLineComment()
		return append(out, '\n')
	case s.peekIs('*'):
		s.skipBlockComment()
		return out
	case c == ',' && s.trailingComma():
		s.i++
		return out
	}
	s.i++
	return append(out, c)
}

func (s *scanner) advanceString(c byte) {
	switch {
	case s.escaped:
		s.escaped = false
	case c == '\\':
		s.escaped = true
	case c == '"':
		s.inString = false
	}
}

func (s *scanner) peekIs(next byte) bool {
	return s.src[s.i] == '/' && s.i+1 < len(s.src) && s.src[s.i+1] == next
}

func (s *scanner) skipLineComment() {
	for s.i < len(s.src) && s.src[s.i] != '\n' {
		s.i++
	}
	s.i++
}

func (s *scanner) skipBlockComment() {
	s.i += 2
	for s.i+1 < len(s.src) && !(s.src[s.i] == '*' && s.src[s.i+1] == '/') {
		s.i++
	}
	s.i += 2
}

func (s *scanner) trailingComma() bool {
	j := s.i + 1
	for j < len(s.src) && (s.src[j] == ' ' || s.src[j] == '\t' || s.src[j] == '\n' || s.src[j] == '\r') {
		j++
	}
	return j < len(s.src) && (s.src[j] == '}' || s.src[j] == ']')
}
