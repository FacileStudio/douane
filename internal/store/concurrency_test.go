package store

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

// stBusy reports whether err is any flavour of SQLITE_BUSY. The extended code
// is masked off rather than the message matched, because the two that matter
// here read differently: 5 is a lock douane can wait for, 517 is
// SQLITE_BUSY_SNAPSHOT, which no amount of waiting resolves.
func stBusy(err error) bool {
	var e *sqlite.Error
	return errors.As(err, &e) && e.Code()&0xff == sqlite3.SQLITE_BUSY
}

// stWrite runs the history round trip cli performs per repository: read the
// previous keys, then save over them.
func stWrite(st *Store, target string, each int, count func(error)) {
	for range each {
		if _, err := st.PreviousKeys(target); err != nil {
			count(err)
		}
		if err := st.Save(target, 1, stFindings(4)); err != nil {
			count(err)
		}
	}
}

// stHammer runs that round trip from writers goroutines at once and reports
// how many of them went busy, and how many failed for any other reason.
func stHammer(st *Store, prefix string, writers, each int) (int64, int64) {
	var busy, failed atomic.Int64
	count := func(err error) {
		if stBusy(err) {
			busy.Add(1)
		} else {
			failed.Add(1)
		}
	}
	var wg sync.WaitGroup
	for w := range writers {
		wg.Go(func() { stWrite(st, fmt.Sprintf("%s-%d", prefix, w), each, count) })
	}
	wg.Wait()
	return busy.Load(), failed.Load()
}

// TestConcurrentSavesNeverGoBusy is the regression test for the DSN. Before
// the immediate transaction lock and the busy timeout, 8 writers landed 21 of
// 400 saves and lost the rest to SQLITE_BUSY.
func TestConcurrentSavesNeverGoBusy(t *testing.T) {
	st := open(t)
	const writers, each = 8, 25
	busy, failed := stHammer(st, "repo", writers, each)
	if busy != 0 || failed != 0 {
		t.Fatalf("busy = %d, other failures = %d; want 0 and 0", busy, failed)
	}
	if got := stCount(t, st, `SELECT count(*) FROM sweeps`); got != writers*each {
		t.Fatalf("sweeps = %d, want %d — writes were lost", got, writers*each)
	}
}

// TestConcurrentProcessesShareOneDatabase covers the deployment target: two CI
// jobs pointed at the same ~/.douane.db. WAL takes real file locks in this
// driver, so it holds across processes as well as goroutines — but only on a
// local filesystem, never a network one.
func TestConcurrentProcessesShareOneDatabase(t *testing.T) {
	if testing.Short() {
		t.Skip("re-execs the test binary")
	}
	path := filepath.Join(t.TempDir(), "shared.db")
	st, err := Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	var wg sync.WaitGroup
	out := make([]string, 2)
	errs := make([]error, 2)
	for i := range out {
		wg.Go(func() {
			cmd := exec.Command(os.Args[0], "-test.run=TestStoreChildWriter")
			cmd.Env = append(os.Environ(), "DOUANE_STORE_CHILD="+path,
				fmt.Sprintf("DOUANE_STORE_CHILD_ID=%d", i))
			b, err := cmd.CombinedOutput()
			out[i], errs[i] = string(b), err
		})
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("child %d: %v\n%s", i, err, out[i])
		}
	}
	if got := stCount(t, st, `SELECT count(*) FROM sweeps`); got != 2*4*25 {
		t.Fatalf("sweeps = %d, want %d — a process lost its writes", got, 2*4*25)
	}
}

// TestStoreChildWriter is the other half of the test above: it runs only when
// the parent re-execs this binary with a database to write to.
func TestStoreChildWriter(t *testing.T) {
	path := os.Getenv("DOUANE_STORE_CHILD")
	if path == "" {
		t.Skip("not a child process")
	}
	st, err := Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()
	busy, failed := stHammer(st, "child-"+os.Getenv("DOUANE_STORE_CHILD_ID"), 4, 25)
	if busy != 0 || failed != 0 {
		t.Fatalf("child %s: busy = %d, other failures = %d; want 0 and 0",
			os.Getenv("DOUANE_STORE_CHILD_ID"), busy, failed)
	}
}
