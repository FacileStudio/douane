package store

import (
	"database/sql"
	"errors"
	"time"
)

const cacheSchema = `
CREATE TABLE IF NOT EXISTS feed_cache (
	name    TEXT PRIMARY KEY,
	fetched TEXT NOT NULL,
	payload BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS epss_cache (
	cve     TEXT PRIMARY KEY,
	score   REAL NOT NULL,
	fetched TEXT NOT NULL
);
`

// Feed returns the cached payload for name and the time it was fetched. A miss
// returns a nil payload and no error: an absent cache is normal, not a fault.
func (s *Store) Feed(name string) ([]byte, time.Time, error) {
	row := s.db.QueryRow(`SELECT payload, fetched FROM feed_cache WHERE name = ?`, name)
	var payload []byte
	var fetched string
	if err := row.Scan(&payload, &fetched); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, time.Time{}, nil
		}
		return nil, time.Time{}, err
	}
	at, err := time.Parse(time.RFC3339, fetched)
	if err != nil {
		return nil, time.Time{}, err
	}
	return payload, at, nil
}

// SaveFeed stores a feed payload, replacing any earlier copy.
func (s *Store) SaveFeed(name string, payload []byte) error {
	_, err := s.db.Exec(`INSERT INTO feed_cache (name, fetched, payload) VALUES (?, ?, ?)
		ON CONFLICT(name) DO UPDATE SET fetched = excluded.fetched, payload = excluded.payload`,
		name, stamp(), payload)
	return err
}

// EPSS returns every cached score fetched at or after since. The caller keeps
// the ones it asked for; reading the whole table avoids a query variable per
// CVE, and the table holds one row per advisory ever seen, not per sweep.
func (s *Store) EPSS(since time.Time) (map[string]float64, error) {
	rows, err := s.db.Query(`SELECT cve, score FROM epss_cache WHERE fetched >= ?`,
		since.UTC().Format(time.RFC3339))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]float64{}
	for rows.Next() {
		var cve string
		var score float64
		if err := rows.Scan(&cve, &score); err != nil {
			return nil, err
		}
		out[cve] = score
	}
	return out, rows.Err()
}

// SaveEPSS stores one score per CVE, replacing any earlier copy.
func (s *Store) SaveEPSS(scores map[string]float64) error {
	if len(scores) == 0 {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	stmt, err := tx.Prepare(`INSERT INTO epss_cache (cve, score, fetched) VALUES (?, ?, ?)
		ON CONFLICT(cve) DO UPDATE SET score = excluded.score, fetched = excluded.fetched`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	now := stamp()
	for cve, score := range scores {
		if _, err := stmt.Exec(cve, score, now); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func stamp() string { return time.Now().UTC().Format(time.RFC3339) }
