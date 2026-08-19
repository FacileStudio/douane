package store

import (
	"database/sql"

	"github.com/FacileStudio/douane/internal/finding"
	_ "modernc.org/sqlite"
)

const schema = `
CREATE TABLE IF NOT EXISTS sweeps (
	id        INTEGER PRIMARY KEY AUTOINCREMENT,
	target    TEXT NOT NULL,
	started   TEXT NOT NULL,
	packages  INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS findings (
	sweep_id  INTEGER NOT NULL REFERENCES sweeps(id) ON DELETE CASCADE,
	key       TEXT NOT NULL,
	id        TEXT NOT NULL,
	package   TEXT NOT NULL,
	ecosystem TEXT NOT NULL,
	installed TEXT NOT NULL,
	fixed_in  TEXT NOT NULL,
	severity  INTEGER NOT NULL,
	kev       INTEGER NOT NULL,
	epss      REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS findings_sweep ON findings(sweep_id);
`

// Store is douane's sweep history. It exists so a sweep can report what is new
// since the last one, which is the only reason a nightly run is bearable.
type Store struct{ db *sql.DB }

// Open creates or opens the sweep database at path.
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	if _, err := db.Exec(schema + cacheSchema); err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

// Close releases the database handle.
func (s *Store) Close() error { return s.db.Close() }

// PreviousKeys returns the finding keys recorded by the most recent sweep of
// target, so the caller can mark everything else as new.
func (s *Store) PreviousKeys(target string) (map[string]bool, error) {
	row := s.db.QueryRow(`SELECT id FROM sweeps WHERE target = ? ORDER BY id DESC LIMIT 1`, target)
	var sweepID int64
	if err := row.Scan(&sweepID); err != nil {
		if err == sql.ErrNoRows {
			return map[string]bool{}, nil
		}
		return nil, err
	}
	rows, err := s.db.Query(`SELECT key FROM findings WHERE sweep_id = ?`, sweepID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var k string
		if err := rows.Scan(&k); err != nil {
			return nil, err
		}
		out[k] = true
	}
	return out, rows.Err()
}

// Save records one sweep and its findings.
func (s *Store) Save(target string, packages int, fs []finding.Finding) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	res, err := tx.Exec(`INSERT INTO sweeps (target, started, packages) VALUES (?, ?, ?)`,
		target, stamp(), packages)
	if err != nil {
		return err
	}
	sweepID, err := res.LastInsertId()
	if err != nil {
		return err
	}
	stmt, err := tx.Prepare(`INSERT INTO findings
		(sweep_id, key, id, package, ecosystem, installed, fixed_in, severity, kev, epss)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, f := range fs {
		if _, err := stmt.Exec(sweepID, f.Key(), f.ID, f.Package, f.Ecosystem,
			f.Installed, f.FixedIn, int(f.Severity), f.Exploit.KEV, f.Exploit.EPSS); err != nil {
			return err
		}
	}
	return tx.Commit()
}
