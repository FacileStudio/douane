package store

import (
	"database/sql"
	"net/url"
	"runtime"
	"strings"

	_ "modernc.org/sqlite"
)

// params is the DSN every connection opens with, and _txlock=immediate is the
// one that earns its place. Save reads before it writes; a deferred
// transaction takes its read snapshot on the first SELECT, so a commit from
// another connection makes the upgrade to a write fail with
// SQLITE_BUSY_SNAPSHOT — the one busy code SQLite never runs the busy handler
// for, because waiting cannot help. Measured over 8 writers × 50 read-then-
// write transactions: 6 of 400 rows survived without it, 400 with it. Two CI
// jobs sharing ~/.douane.db is the deployment target, so this is the normal
// case, not the pathological one.
//
// These are the validated shorthands the driver added in v1.57.0. A typo in
// one fails Open before a single PRAGMA runs, where a bad _pragma= value is
// executed verbatim and can leave the file half-converted to WAL.
const params = "_busy_timeout=5000&_journal_mode=WAL&_fk=1&_txlock=immediate"

// Open creates or opens the sweep database at path.
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", dsn(path))
	if err != nil {
		return nil, err
	}
	tune(db)
	if _, err := db.Exec(schema + cacheSchema); err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

// dsn renders path as a file: URI, which is the only DSN form the driver reads
// parameters from. url.URL escapes the ?, # and % a path may legally contain —
// without that, a database under a directory whose name holds a question mark
// truncates the DSN and silently loses every parameter. A path opening with
// two slashes is the one shape a file: URI cannot carry, since it parses as an
// authority, so collapse it: on every platform douane runs on it names the
// same file.
func dsn(path string) string {
	if strings.HasPrefix(path, "//") {
		path = "/" + strings.TrimLeft(path, "/")
	}
	u := url.URL{Scheme: "file", OmitHost: true, Path: path, RawQuery: params}
	return u.String()
}

// tune sizes the connection pool. Serialising it with SetMaxOpenConns(1) also
// answers the busy problem, but costs about 1.8x on the read side, and reads
// are what a sweep does most of. Idle connections are held rather than the
// default two because every new one replays the whole pragma sequence.
func tune(db *sql.DB) {
	db.SetMaxOpenConns(max(4, runtime.NumCPU()))
	db.SetMaxIdleConns(4)
	db.SetConnMaxLifetime(0)
}
