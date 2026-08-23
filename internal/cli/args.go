package cli

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
)

// options is one invocation, already parsed and validated. done marks a run
// that finished during parsing: -h prints the usage and leaves nothing to
// scan, so asking for help still exits 0.
type options struct {
	path     string
	format   string
	failOn   string
	fail     threshold
	dbPath   string
	noEnrich bool
	refresh  bool
	done     bool
}

// parseArgs reads the flags and the single optional path. The path is taken
// from either side of the flags because `douane sweep -fail high /repos` is the
// natural CI line, and reading it only from the front made that one scan $PWD
// while reporting success.
func parseArgs(name string, args []string) (options, int) {
	opts := options{path: ".", dbPath: defaultDB()}
	paths, err := positional(newFlagSet(name, &opts), args)
	if errors.Is(err, flag.ErrHelp) {
		fmt.Print(usage)
		opts.done = true
		return opts, exitClear
	}
	if err != nil {
		fmt.Fprint(os.Stderr, usage)
		return opts, exitUsage
	}
	if len(paths) > 1 {
		fmt.Fprintf(os.Stderr, "douane: %s takes one path, got %d: %s\n",
			name, len(paths), strings.Join(paths, " "))
		return opts, exitUsage
	}
	if len(paths) == 1 {
		opts.path = paths[0]
	}
	return opts, resolveFail(&opts)
}

// newFlagSet declares the flags. Its usage function is empty on purpose: the
// flag package would list flags that carry no help text of their own, and the
// usage block above is where douane documents itself.
func newFlagSet(name string, opts *options) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() {}
	fs.StringVar(&opts.format, "format", "auto", "")
	fs.StringVar(&opts.failOn, "fail", "never", "")
	fs.StringVar(&opts.dbPath, "db", opts.dbPath, "")
	fs.BoolVar(&opts.noEnrich, "no-enrich", false, "")
	fs.BoolVar(&opts.refresh, "refresh", false, "")
	return fs
}

// positional parses one flag at a time, collecting what is not a flag. A
// single Parse stops dead at the first non-flag argument, which leaves both
// the path and every flag after it unread and unreported.
func positional(fs *flag.FlagSet, args []string) ([]string, error) {
	var out []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		rest := fs.Args()
		if len(rest) == 0 {
			return out, nil
		}
		out = append(out, rest[0])
		args = rest[1:]
	}
}

// resolveFail turns -fail into the threshold the exit code is judged against.
// kev is refused under -no-enrich: the KEV flag is then false on every finding,
// so the gate would pass having evaluated nothing at all.
func resolveFail(opts *options) int {
	t, ok := parseFail(opts.failOn)
	if !ok {
		fmt.Fprintf(os.Stderr, "douane: unknown -fail value %q\n", opts.failOn)
		return exitUsage
	}
	if t.kev && opts.noEnrich {
		fmt.Fprint(os.Stderr, "douane: -fail kev needs the KEV feed, which -no-enrich turns off\n")
		return exitUsage
	}
	opts.fail = t
	return exitClear
}
