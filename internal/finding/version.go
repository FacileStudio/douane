// Version display ordering for grouped output. Lexical sort puts 1.10 before
// 1.9, which reads as a downgrade; these helpers compare numeric runs as
// numbers and everything else lexically. Not a semver parser — installed
// versions arrive from npm, Go toolchains and Cargo alike.

package finding

// lessVersion orders version strings numerically where both sides are digits,
// lexically elsewhere, so 4.11.0 sorts after 4.9.0 instead of before 4.9.
func lessVersion(a, b string) bool {
	for a != "" && b != "" {
		if isDigit(a[0]) && isDigit(b[0]) {
			na, nb := leadingNumber(a), leadingNumber(b)
			if na != nb {
				return na < nb
			}
			a, b = a[digits(a):], b[digits(b):]
			continue
		}
		if a[0] != b[0] {
			return a[0] < b[0]
		}
		a, b = a[1:], b[1:]
	}
	return len(a) < len(b)
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func leadingNumber(s string) int {
	n, i := 0, 0
	for i < len(s) && isDigit(s[i]) {
		n = n*10 + int(s[i]-'0')
		i++
	}
	return n
}

func digits(s string) int {
	i := 0
	for i < len(s) && isDigit(s[i]) {
		i++
	}
	return i
}
