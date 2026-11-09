// Tests for the ReplacePathRegex model. "diff:N" is a line of the saved fix
// diff CVE-2026-65600_traefik_3f10dd442479.diff (see SOURCES.md).
package tests

import (
	"os"
	"path"
	"strings"
	"testing"

	"github.com/federiconbaez/cortex9-traefik-replacepathregex-normalization-model/src/model"
)

func loadCases(t *testing.T) map[string]model.Case {
	t.Helper()
	cs, err := model.LoadCases("../fixtures/cases.tsv")
	if err != nil {
		t.Fatal(err)
	}
	m := map[string]model.Case{}
	for _, c := range cs {
		m[c.ID] = c
	}
	return m
}

func run(t *testing.T, id, version string) model.Outcome {
	t.Helper()
	c, ok := loadCases(t)[id]
	if !ok {
		t.Fatalf("fixture %s missing", id)
	}
	return model.Run(c, version)
}

// The model must agree row by row with scripts/derive_expected.py.
func TestFixturesMatchIndependentDerivation(t *testing.T) {
	data, err := os.ReadFile("../fixtures/expected.tsv")
	if err != nil {
		t.Fatal(err)
	}
	want := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
	if want[0] != model.Header {
		t.Fatalf("header: %q", want[0])
	}
	cs, err := model.LoadCases("../fixtures/cases.tsv")
	if err != nil {
		t.Fatal(err)
	}
	got := []string{model.Header}
	for _, c := range cs {
		got = append(got, model.Run(c, model.Pre).Row(), model.Run(c, model.Post).Row())
	}
	if len(got) != len(want) {
		t.Fatalf("rows: got %d want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("row %d:\n got %s\nwant %s", i, got[i], want[i])
		}
	}
}

// The diff's own test table (diff:60-73, 143-155, 157-169, 195-203).
func TestDiffTestExpectations(t *testing.T) {
	if o := run(t, "d01_path_with_dotdot", model.Post); o.Status != 400 {
		t.Errorf("diff:195-203 expects 400 for /foo../bar, got %d", o.Status)
	}
	if o := run(t, "d01_path_with_dotdot", model.Pre); o.Status != 200 || o.Path != "/../bar" {
		t.Errorf("pre forwards /../bar unchanged, got %+v", o)
	}
	for _, v := range []string{model.Pre, model.Post} {
		o := run(t, "d02_simple_regex", v)
		if o.Path != "/who-am-i/and/whoami" || o.RequestURI != "/who-am-i/and/whoami" { // diff:69,71
			t.Errorf("%s d02: %+v", v, o)
		}
		o = run(t, "d03_replacement_escaped", v)
		if o.Path != "/foo/bar" || o.RawPath != "/foo%2Fbar" || o.RequestURI != "/foo%2Fbar" { // diff:150-153
			t.Errorf("%s d03: %+v", v, o)
		}
		o = run(t, "d04_path_regex_escaped", v)
		if o.Path != "/foo/bar" || o.RequestURI != "/foo/bar" { // diff:165,167
			t.Errorf("%s d04: %+v", v, o)
		}
	}
	// diff:67 (removed) expected RawPath "/who-am-i/and/whoami"; the new table
	// (diff:69-72) has no expectedRawPath, i.e. "" after JoinPath (diff:23).
	if o := run(t, "d02_simple_regex", model.Pre); o.RawPath != "/who-am-i/and/whoami" {
		t.Errorf("pre RawPath: %q", o.RawPath)
	}
	if o := run(t, "d02_simple_regex", model.Post); o.RawPath != "" {
		t.Errorf("post RawPath: %q", o.RawPath)
	}
}

// GHSA attack flow: /api../admin -> public router -> /../admin -> backend /admin.
func TestGHSAAttackFlow(t *testing.T) {
	pre := run(t, "p01_ghsa_dotdot", model.Pre)
	if pre.Router != model.RouterPublic || pre.Label != model.LabelBypassBoth || pre.BackendRaw != "/admin" {
		t.Errorf("pre: %+v", pre)
	}
	if post := run(t, "p01_ghsa_dotdot", model.Post); post.Label != model.LabelReject {
		t.Errorf("post: %+v", post)
	}
	if o := run(t, "n05_admin_direct", model.Pre); o.Label != model.LabelAuth {
		t.Errorf("control /admin: %+v", o)
	}
}

func TestPositivesPreBypassPostRejectedForLiteralDots(t *testing.T) {
	for _, id := range []string{"p01_ghsa_dotdot", "p03_single_dot", "p04_trailing_slash", "p06_nested", "n02_separator_regex_dotdot"} {
		if pre := run(t, id, model.Pre); !model.IsBypass(pre.Label) {
			t.Errorf("%s pre: %s", id, pre.Label)
		}
		if post := run(t, id, model.Post); post.Label != model.LabelReject {
			t.Errorf("%s post: %s", id, post.Label)
		}
	}
}

// Unverified model observation (LIMITATIONS.md): encoded dots survive the
// check because JoinPath cleans the escaped form (diff:23) and the decoded
// Path is unchanged (diff:27). Only a decode-then-normalize backend resolves
// /admin. This test pins the model behaviour; it is not a finding.
func TestEncodedDotsObservation(t *testing.T) {
	for _, id := range []string{"p02_ghsa_encoded_dotdot", "p05_encoded_dot_slash"} {
		post := run(t, id, model.Post)
		if post.Label != model.LabelBypassDecoded() || post.BackendRaw == "/admin" {
			t.Errorf("%s post: %+v", id, post)
		}
	}
}

func TestNegativesUnchanged(t *testing.T) {
	for _, id := range []string{"n01_separator_regex", "n03_root", "n04_no_match", "n05_admin_direct", "n06_other", "n07_config_maps_to_admin", "d02_simple_regex", "d03_replacement_escaped", "d04_path_regex_escaped"} {
		pre, post := run(t, id, model.Pre), run(t, id, model.Post)
		if pre.Label != post.Label || pre.Status != post.Status || pre.RequestURI != post.RequestURI {
			t.Errorf("%s changed: %+v -> %+v", id, pre, post)
		}
		if model.IsBypass(pre.Label) {
			t.Errorf("%s negative is a bypass: %s", id, pre.Label)
		}
	}
}

// Invariants on the fixed sweep (748 targets).
func TestSweepInvariants(t *testing.T) {
	cs := model.Sweep()
	if len(cs) != 748 {
		t.Fatalf("sweep size %d", len(cs))
	}
	var preLiteralBypass, postDecoded int
	for _, c := range cs {
		pre, post := model.Run(c, model.Pre), model.Run(c, model.Post)
		literal := !strings.Contains(c.Target, "%")
		if post.Label == model.LabelBypassRaw || post.Label == model.LabelBypassBoth {
			t.Errorf("%s: post bypass with a raw-normalizing backend: %s", c.Target, post.Label)
		}
		if post.Label == model.LabelBypassDecoded() {
			postDecoded++
			if literal {
				t.Errorf("%s: post decoded bypass without percent-encoding", c.Target)
			}
		}
		if literal && model.IsBypass(pre.Label) {
			preLiteralBypass++
			if post.Label != model.LabelReject {
				t.Errorf("%s: literal pre bypass not rejected post: %s", c.Target, post.Label)
			}
		}
		if post.Status == 200 && post.Path != "" {
			// independent of JoinPath: a forwarded Path is already clean.
			want := path.Clean(post.Path)
			if strings.HasSuffix(post.Path, "/") && want != "/" {
				want += "/"
			}
			if post.Path != want && !strings.Contains(post.RawPath, "%") {
				t.Errorf("%s: post forwards unclean literal path %q", c.Target, post.Path)
			}
		}
		if pre.Label == model.LabelReject {
			t.Errorf("%s: pre never answers 400", c.Target)
		}
		if post.Label != model.LabelReject && pre.Label != post.Label {
			t.Errorf("%s: label changed without rejection: %s -> %s", c.Target, pre.Label, post.Label)
		}
	}
	if preLiteralBypass == 0 || postDecoded == 0 {
		t.Errorf("expected both classes in the sweep: literal pre bypass %d, post decoded %d", preLiteralBypass, postDecoded)
	}
}

func TestAdversarialInputs(t *testing.T) {
	long := "/api" + strings.Repeat("a", 600)
	bad := []model.Case{
		{Target: "", Regex: "^/api(.*)", Replacement: "/$1", Mode: model.ModeRouter},
		{Target: "api../admin", Regex: "^/api(.*)", Replacement: "/$1", Mode: model.ModeRouter},
		{Target: long, Regex: "^/api(.*)", Replacement: "/$1", Mode: model.ModeRouter},
		{Target: "/api\x00/admin", Regex: "^/api(.*)", Replacement: "/$1", Mode: model.ModeRouter},
		{Target: "/api\u00e9", Regex: "^/api(.*)", Replacement: "/$1", Mode: model.ModeRouter},
		{Target: "/api%", Regex: "^/api(.*)", Replacement: "/$1", Mode: model.ModeRouter},
		{Target: "/api%2", Regex: "^/api(.*)", Replacement: "/$1", Mode: model.ModeRouter},
		{Target: "/api#x", Regex: "^/api(.*)", Replacement: "/$1", Mode: model.ModeRouter},
		{Target: "/api", Regex: "^/api(.*)", Replacement: "/$", Mode: model.ModeRouter},
		{Target: "/api", Regex: "^/api(.*)", Replacement: "/${1}", Mode: model.ModeRouter},
		{Target: "/api", Regex: "^/api(.*)", Replacement: "/$1", Mode: "other"},
	}
	for _, c := range bad {
		for _, v := range []string{model.Pre, model.Post} {
			if o := model.Run(c, v); o.Label != model.LabelBadInput {
				t.Errorf("%q %q %s: %s", c.Target, c.Replacement, v, o.Label)
			}
		}
	}
	ok := model.Case{Target: "/api/x", Regex: "^/api(.*)", Replacement: "/$1", Mode: model.ModeRouter}
	if o := model.Run(ok, "master"); o.Label != model.LabelBadInput {
		t.Errorf("unknown version: %s", o.Label)
	}
}

func TestResultsMatchCommittedSweep(t *testing.T) {
	data, err := os.ReadFile("../results/sweep.csv")
	if err != nil {
		t.Fatal(err)
	}
	a, b := model.SweepCSV(), model.SweepCSV()
	if a != b {
		t.Fatal("SweepCSV is not deterministic")
	}
	if a != string(data) {
		t.Fatal("results/sweep.csv differs from the model; run scripts/build.sh results")
	}
}

// PRACTICE.md levels.
func TestPracticeLevels(t *testing.T) {
	c := func(target, re, repl string) model.Case {
		return model.Case{Target: target, Regex: re, Replacement: repl, Mode: model.ModeRouter}
	}
	// 1: normal rewrite.
	if o := model.Run(c("/api/users", "^/api/(.*)", "/$1"), model.Pre); o.RequestURI != "/users" || o.Label != model.LabelOK {
		t.Errorf("level 1: %+v", o)
	}
	// 2: the capture without separator.
	if o := model.Run(c("/api../admin", "^/api(.*)", "/$1"), model.Pre); o.Path != "/../admin" || o.Router != model.RouterPublic {
		t.Errorf("level 2: %+v", o)
	}
	// 3: backend normalization.
	if o := model.Run(c("/api../admin", "^/api(.*)", "/$1"), model.Pre); o.BackendRaw != "/admin" {
		t.Errorf("level 3: %+v", o)
	}
	// 4: the fix.
	if o := model.Run(c("/api../admin", "^/api(.*)", "/$1"), model.Post); o.Status != 400 {
		t.Errorf("level 4: %+v", o)
	}
	// 5: separator in the regex.
	if o := model.Run(c("/api../admin", "^/api/(.*)", "/$1"), model.Pre); o.Label != model.LabelOK || o.RequestURI != "/api../admin" {
		t.Errorf("level 5: %+v", o)
	}
	// 6: side effect: double slash rejected after the fix.
	if o := model.Run(c("/api/users", "^/api(.*)", "/$1"), model.Post); o.Status != 400 {
		t.Errorf("level 6: %+v", o)
	}
	// 7: encoded dots (unverified observation).
	if o := model.Run(c("/api%2e%2e/admin", "^/api(.*)", "/$1"), model.Post); o.Label != model.LabelBypassDecoded() || o.BackendRaw != "/%2e%2e/admin" {
		t.Errorf("level 7: %+v", o)
	}
	// 8: config maps to /admin without traversal.
	if o := model.Run(c("/apiadmin", "^/api(.*)", "/$1"), model.Post); o.Label != model.LabelConfigAdmin {
		t.Errorf("level 8: %+v", o)
	}
}
