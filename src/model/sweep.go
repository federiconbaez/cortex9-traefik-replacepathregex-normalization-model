package model

// SweepTokens are the pieces appended after "/api" in the fixed sweep with
// the GHSA PoC configuration (regex `^/api(.*)`, replacement `/$1`).
var SweepTokens = []string{"", "/", ".", "..", "%2e", "%2e%2e", "%2E%2E%2F", "%2F", "admin", "x"}

// SweepRegex and SweepReplacement are the configuration used by Sweep.
const (
	SweepRegex       = `^/api(.*)`
	SweepReplacement = "/$1"
)

// Sweep enumerates every target "/api" + t1 + t2 + t3 (tokens may repeat),
// in a fixed order, so results/sweep.csv is byte-identical across runs.
func Sweep() []Case {
	var out []Case
	seen := map[string]bool{}
	for _, a := range SweepTokens {
		for _, b := range SweepTokens {
			for _, c := range SweepTokens {
				t := "/api" + a + b + c
				if seen[t] {
					continue
				}
				seen[t] = true
				out = append(out, Case{ID: "s" + itoa(len(out)+1), Target: t, Regex: SweepRegex, Replacement: SweepReplacement, Mode: ModeRouter})
			}
		}
	}
	return out
}
