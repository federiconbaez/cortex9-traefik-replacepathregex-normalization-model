// Package model is an offline model of the ReplacePathRegex middleware of
// Traefik before and after commit 3f10dd442479530560f010167cac2947676d9b29
// (CVE-2026-65600, GHSA-cxjq-mrr5-89rv).
//
// Line references "diff:N" point to the saved fix diff
// CVE-2026-65600_traefik_3f10dd442479.diff (see SOURCES.md). No Traefik code
// is imported or run; only the Go standard library (net/url, path, regexp).
package model

import (
	"net/url"
	"path"
	"regexp"
	"strings"
)

// Case modes.
const (
	ModeRouter     = "router"
	ModeMiddleware = "mw"
)

// Versions of the middleware.
const (
	Pre  = "pre"  // parent of 3f10dd4
	Post = "post" // 3f10dd4
)

// Router names of the modelled Traefik configuration (the GHSA PoC layout).
const (
	RouterPublic    = "public-api"      // PathPrefix(`/api`), priority 1, rewrite middleware
	RouterProtected = "protected-admin" // PathPrefix(`/admin`), priority 2, auth middleware
	RouterNone      = "none"
)

// Labels.
const (
	LabelOK          = "OK"             // forwarded, backend does not resolve to /admin
	LabelAuth        = "AUTH_401"       // protected router: auth middleware answers
	LabelReject      = "REJECT_400"     // post: normalization check (diff:27-30)
	LabelNoRouter    = "NO_ROUTER_404"  // no router rule matches
	LabelUnescape    = "UNESCAPE_500"   // replaced path is not valid percent-encoding
	LabelBadInput    = "BAD_INPUT"      // outside the model's input domain
	LabelBypassRaw   = "BYPASS_RAW"     // a raw-normalizing backend resolves /admin
	LabelBypassDec   = "BYPASS_DECODED" // only a decode-then-normalize backend resolves /admin
	LabelBypassBoth  = "BYPASS_BOTH"    // both backends resolve /admin
	LabelConfigAdmin = "CONFIG_ADMIN"   // the rewrite itself yields /admin without traversal (not the CVE)
	maxInput         = 512
	adminPrefix      = "/admin"
	publicPrefix     = "/api"
	protectedPrefix  = "/admin"
	allowedTarget    = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~/%"
	allowedRepl      = allowedTarget + "$"
	statusOK         = 200
	statusBad        = 400
	statusAuth       = 401
	statusNotFound   = 404
	statusServerFail = 500
)

// Case is one request against one ReplacePathRegex configuration.
type Case struct {
	ID          string
	Target      string // request-target as sent (origin-form path, no query)
	Regex       string
	Replacement string
	Mode        string // "router": PoC router layout in front; "mw": middleware alone (diff tests)
}

// Outcome is what the model observes for one case and one version.
type Outcome struct {
	ID, Version, Label, Router string
	Status                     int
	Path, RawPath, RequestURI  string // as seen by the next handler (backend)
	BackendRaw, BackendDecoded string // backend-normalized paths ("-" if not forwarded)
}

func onlyChars(s, allowed string) bool {
	for i := 0; i < len(s); i++ {
		if !strings.ContainsRune(allowed, rune(s[i])) {
			return false
		}
	}
	return true
}

// validate keeps inputs inside the domain where the independent derivation
// (scripts/derive_expected.py) and this model are comparable.
func validate(c Case) (*regexp.Regexp, bool) {
	if len(c.Target) == 0 || len(c.Target) > maxInput || len(c.Regex) > maxInput || len(c.Replacement) > maxInput {
		return nil, false
	}
	if c.Target[0] != '/' || !onlyChars(c.Target, allowedTarget) || !onlyChars(c.Replacement, allowedRepl) {
		return nil, false
	}
	for i := 0; i < len(c.Replacement); i++ { // only $1..$9 not followed by a name character
		if c.Replacement[i] == '$' {
			if i+1 >= len(c.Replacement) || c.Replacement[i+1] < '1' || c.Replacement[i+1] > '9' {
				return nil, false
			}
			if i+2 < len(c.Replacement) && isNameChar(c.Replacement[i+2]) {
				return nil, false
			}
		}
	}
	re, err := regexp.Compile(c.Regex)
	if err != nil {
		return nil, false
	}
	return re, true
}

func isNameChar(b byte) bool {
	return b == '_' || b >= '0' && b <= '9' || b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z'
}

// route models router selection on the decoded request path (model
// assumption, not in the diff): higher priority first.
func route(p string) string {
	switch {
	case strings.HasPrefix(p, protectedPrefix):
		return RouterProtected
	case strings.HasPrefix(p, publicPrefix):
		return RouterPublic
	}
	return RouterNone
}

// clean is the backend normalization (like path.posix.normalize in the GHSA
// PoC backend) on the path part of the request-URI it receives.
func clean(p string) string {
	if p == "" {
		return "/"
	}
	c := path.Clean(p)
	if strings.HasSuffix(p, "/") && c != "/" {
		c += "/"
	}
	return c
}

func underAdmin(p string) bool {
	return p == adminPrefix || strings.HasPrefix(p, adminPrefix+"/")
}

// Run evaluates one case for one version.
func Run(c Case, version string) Outcome {
	o := Outcome{ID: c.ID, Version: version, Router: RouterNone, Path: "-", RawPath: "-", RequestURI: "-", BackendRaw: "-", BackendDecoded: "-"}
	re, ok := validate(c)
	if !ok || (version != Pre && version != Post) || (c.Mode != ModeRouter && c.Mode != ModeMiddleware) {
		o.Label = LabelBadInput
		return o
	}
	u, err := url.ParseRequestURI(c.Target) // what net/http gives the entrypoint
	if err != nil {
		o.Label = LabelBadInput
		return o
	}
	if c.Mode == ModeMiddleware {
		o.Router = "-"
	} else {
		o.Router = route(u.Path)
	}
	switch o.Router {
	case RouterNone:
		o.Label, o.Status = LabelNoRouter, statusNotFound
		return o
	case RouterProtected:
		o.Label, o.Status = LabelAuth, statusAuth
		return o
	}

	// ReplacePathRegex.ServeHTTP.
	currentPath := u.RawPath // diff:11
	if currentPath == "" {   // diff:12
		currentPath = u.EscapedPath() // diff:13
	}
	requestURI := u.RequestURI()
	if re.MatchString(currentPath) {
		// Reconstructed (between hunks, not in the diff): RawPath is the regex
		// replacement of currentPath and Path its unescaped form; consistent
		// with the expectations at diff:144-153 and diff:157-168.
		u.RawPath = re.ReplaceAllString(currentPath, c.Replacement)
		u.Path, err = url.PathUnescape(u.RawPath)
		if err != nil {
			o.Label, o.Status = LabelUnescape, statusServerFail
			return o
		}
		requestURI = u.RequestURI() // diff:17

		if version == Post {
			p := u.Path  // diff:21
			if p != "" { // diff:22
				u = u.JoinPath() // diff:23
			}
			if p != u.Path { // diff:27
				o.Label, o.Status = LabelReject, statusBad // diff:29-30
				return o
			}
		}
	}

	o.Status = statusOK
	o.Path, o.RawPath, o.RequestURI = u.Path, u.RawPath, requestURI
	o.BackendRaw = clean(requestURI)
	if dec, derr := url.PathUnescape(requestURI); derr == nil {
		o.BackendDecoded = clean(dec)
	} else {
		o.BackendDecoded = "!"
	}
	// A bypass needs the backend normalization: the forwarded form is not
	// under /admin, the normalized form is. If the forwarded form already is
	// under /admin, the configuration itself maps there (CONFIG_ADMIN).
	dec, derr := url.PathUnescape(requestURI)
	if underAdmin(requestURI) || (derr == nil && underAdmin(dec)) {
		o.Label = LabelConfigAdmin
		return o
	}
	raw, decd := underAdmin(o.BackendRaw), underAdmin(o.BackendDecoded)
	switch {
	case raw && decd:
		o.Label = LabelBypassBoth
	case raw:
		o.Label = LabelBypassRaw
	case decd:
		o.Label = LabelBypassDec
	default:
		o.Label = LabelOK
	}
	return o
}

// IsBypass reports whether the label is one of the BYPASS_* labels.
func IsBypass(label string) bool { return strings.HasPrefix(label, "BYPASS_") }

// Header and Row give the TSV form shared with fixtures/expected.tsv.
const Header = "id\tversion\tlabel\tstatus\trouter\tpath\traw_path\trequest_uri\tbackend_raw\tbackend_decoded"

// Row renders an outcome as one TSV line. Empty strings are written as "”".
func (o Outcome) Row() string {
	f := func(s string) string {
		if s == "" {
			return "''"
		}
		return s
	}
	st := "-"
	if o.Status != 0 {
		st = itoa(o.Status)
	}
	return strings.Join([]string{o.ID, o.Version, o.Label, st, o.Router, f(o.Path), f(o.RawPath), f(o.RequestURI), f(o.BackendRaw), f(o.BackendDecoded)}, "\t")
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// LabelBypassDecoded returns the BYPASS_DECODED label (helper for tests).
func LabelBypassDecoded() string { return LabelBypassDec }
