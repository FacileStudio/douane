package output

import "github.com/FacileStudio/douane/internal/finding"

// isRebuild reports whether rebuilding the artifact already clears f, because
// the fix landed on the release line its image builds from. Whether the image
// has actually been rebuilt since is a question douane cannot answer, so this
// never suppresses a finding, only labels the action that clears it.
func isRebuild(r Report, f finding.Finding) bool {
	return finding.SameLine(r.BuildLines[f.Target], f.FixedIn)
}

func rebuiltFn(r Report) func(finding.Finding) bool {
	return func(f finding.Finding) bool { return isRebuild(r, f) }
}
