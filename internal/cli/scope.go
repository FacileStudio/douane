package cli

import (
	"fmt"
	"os"

	"github.com/FacileStudio/douane/internal/finding"
)

// resolveScope validates -scope. prod, dev and all are the only values sweep
// understands; anything else is a usage error and stops the invocation.
func resolveScope(opts *options) int {
	if _, ok := parseScope(opts.scope); ok {
		return exitClear
	}
	fmt.Fprintf(os.Stderr, "douane: unknown -scope value %q\n", opts.scope)
	return exitUsage
}

// scopeFilter is which findings survive -scope, read from the value
// resolveScope already validated.
func (o options) scopeFilter() finding.ScopeFilter {
	f, _ := parseScope(o.scope)
	return f
}

func parseScope(s string) (finding.ScopeFilter, bool) {
	switch s {
	case "prod":
		return finding.FilterProd, true
	case "dev":
		return finding.FilterDev, true
	case "all":
		return finding.FilterAll, true
	}
	return finding.FilterAll, false
}
