package enrich

import (
	"regexp"
	"strings"

	"github.com/FacileStudio/douane/internal/finding"
)

// epssJoinLimit is the character cap the API puts on the joined cve
// parameter. Measured against api.first.org on 2026-08-23: a 2000-character
// value answers 142 scores, a 2001-character one answers
// {"status":"OK","total":0,"data":[]}. The cap is on the decoded value, so
// percent-encoding the separators does not spend against it.
const epssJoinLimit = 2000

// epssShape is what an identifier has to look like before it goes into a
// query string. A CVE- prefix is not enough: aliases are written by whoever
// filed the advisory, and "CVE-2026-1&envelope=false&pretty=true" passes a
// prefix check while being three query parameters rather than one identifier.
var epssShape = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)

// epssIDs splits the CVE-shaped identifiers of fs from the ones that only
// start like one. Order follows the findings so that two runs over the same
// input send the same requests.
func epssIDs(fs []finding.Finding) (ids, malformed []string) {
	seen := map[string]bool{}
	for _, f := range fs {
		for _, id := range identifiers(f) {
			if !strings.HasPrefix(id, "CVE-") || seen[id] {
				continue
			}
			seen[id] = true
			if epssShape.MatchString(id) {
				ids = append(ids, id)
				continue
			}
			malformed = append(malformed, id)
		}
	}
	return ids, malformed
}

// epssBatches groups ids into requests the API will answer whole. It measures
// the joined string rather than counting ids because the count is the wrong
// unit: past epssJoinLimit the API returns an empty array with a 200 and a
// status of OK, which is indistinguishable from "none of these are scored",
// and how many ids fit depends entirely on how long they are. An id longer
// than the whole budget still gets its own request — it will answer nothing,
// but it cannot stall the loop or poison the batch it was in.
func epssBatches(ids []string) [][]string {
	var out [][]string
	var batch []string
	size := 0
	for _, id := range ids {
		cost := len(id)
		if len(batch) > 0 {
			cost++
		}
		if len(batch) > 0 && size+cost > epssJoinLimit {
			out = append(out, batch)
			batch, size, cost = nil, 0, len(id)
		}
		batch = append(batch, id)
		size += cost
	}
	if len(batch) > 0 {
		out = append(out, batch)
	}
	return out
}
