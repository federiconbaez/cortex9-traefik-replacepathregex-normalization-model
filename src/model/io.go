package model

import (
	"fmt"
	"os"
	"strings"
)

// LoadCases reads fixtures/cases.tsv (id, target, regex, replacement, mode).
func LoadCases(file string) ([]Case, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	var out []Case
	for n, line := range strings.Split(string(data), "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) != 5 {
			return nil, fmt.Errorf("%s:%d: want 5 fields, got %d", file, n+1, len(f))
		}
		out = append(out, Case{ID: f[0], Target: f[1], Regex: f[2], Replacement: f[3], Mode: f[4]})
	}
	return out, nil
}

// SweepCSV renders the sweep: one line per target with the pre and post label.
func SweepCSV() string {
	var b strings.Builder
	b.WriteString("id,target,pre_label,pre_backend_raw,pre_backend_decoded,post_label,post_backend_raw,post_backend_decoded\n")
	for _, c := range Sweep() {
		pre, post := Run(c, Pre), Run(c, Post)
		b.WriteString(strings.Join([]string{c.ID, c.Target, pre.Label, pre.BackendRaw, pre.BackendDecoded, post.Label, post.BackendRaw, post.BackendDecoded}, ",") + "\n")
	}
	return b.String()
}
