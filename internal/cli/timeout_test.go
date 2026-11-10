package cli

import (
	"testing"
	"time"
)

func TestParseArgsTakesATimeout(t *testing.T) {
	opts, code := parseArgs("scan", []string{"-timeout", "90s", "."})
	if code != exitClear || opts.timeout != 90*time.Second {
		t.Fatalf("timeout = %s, code %d; want 90s and a clean parse", opts.timeout, code)
	}
	if opts, _ := parseArgs("scan", []string{"."}); opts.timeout != defaultTimeout {
		t.Fatalf("default timeout = %s, want %s", opts.timeout, defaultTimeout)
	}
}

func TestParseArgsRejectsANonPositiveTimeout(t *testing.T) {
	for _, value := range []string{"0s", "-5m"} {
		if _, code := parseArgs("scan", []string{"-timeout", value, "."}); code != exitUsage {
			t.Errorf("-timeout %s = %d, want %d", value, code, exitUsage)
		}
	}
}
