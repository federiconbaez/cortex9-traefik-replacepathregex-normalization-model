#!/usr/bin/env python3
"""Independent derivation of fixtures/expected.tsv (and, with "sweep", of
results/sweep.csv).

Written from the saved fix diff (CVE-2026-65600_traefik_3f10dd442479.diff,
lines 11-13, 17 and 21-31), the GHSA/NVD text and the documented behaviour
of Go's net/url (setPath, EscapedPath, RequestURI, JoinPath) and path.Clean.
It does not import, call or read the Go model: the URL rules, the dot-segment
removal and the labels are re-implemented here in plain Python.
"""
import re
import sys
from pathlib import Path

HEX = "0123456789abcdefABCDEF"
TARGET_CHARS = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~/%")
REPL_CHARS = TARGET_CHARS | {"$"}


class BadEscape(Exception):
    pass


def unescape(s):
    out, i = bytearray(), 0
    b = s.encode()
    while i < len(b):
        if b[i] == 0x25:  # '%'
            if i + 2 >= len(b) or chr(b[i + 1]) not in HEX or chr(b[i + 2]) not in HEX:
                raise BadEscape(s)
            out.append(int(b[i + 1:i + 3], 16))
            i += 3
        else:
            out.append(b[i])
            i += 1
    return out.decode("latin-1")


def keep_in_path(ch):
    # Go url.shouldEscape(c, encodePath) == false
    return ch.isascii() and (ch.isalnum() or ch in "-_.~$&+,/:;=@")


def escape(p):
    return "".join(ch if keep_in_path(ch) else "%%%02X" % ord(ch) for ch in p)


def valid_encoded(raw):
    for ch in raw:
        if ch in "!$&'()*+,;=:@[]%":
            continue
        if not keep_in_path(ch):
            return False
    return True


class URL:
    def __init__(self, path="", raw=""):
        self.path, self.raw = path, raw

    def set_path(self, p):
        self.path = unescape(p)
        self.raw = "" if escape(self.path) == p else p

    def escaped_path(self):
        if self.raw and valid_encoded(self.raw):
            try:
                if unescape(self.raw) == self.path:
                    return self.raw
            except BadEscape:
                pass
        return escape(self.path)

    def request_uri(self):
        r = self.escaped_path()
        return r if r else "/"


def remove_dots(p):
    """Lexical cleaning of a path like Go path.Clean."""
    if p == "":
        return "."
    rooted = p.startswith("/")
    stack = []
    for seg in p.split("/"):
        if seg in ("", "."):
            continue
        if seg == "..":
            if stack and stack[-1] != "..":
                stack.pop()
            elif not rooted:
                stack.append("..")
            continue
        stack.append(seg)
    s = "/".join(stack)
    if rooted:
        return "/" + s
    return s if s else "."


def join_path(u):
    """Go URL.JoinPath() with no elements."""
    e = u.escaped_path()
    if not e.startswith("/"):
        p = remove_dots("/" + e)[1:]
    else:
        p = remove_dots(e)
    if e.endswith("/") and not p.endswith("/"):
        p += "/"
    n = URL()
    n.set_path(p)
    return n


def backend_norm(p):
    if p == "":
        return "/"
    c = remove_dots(p)
    if p.endswith("/") and c != "/":
        c += "/"
    return c


def under_admin(p):
    return p == "/admin" or p.startswith("/admin/")


def in_domain(target, regex, repl):
    if not target or len(target) > 512 or len(regex) > 512 or len(repl) > 512:
        return None
    if target[0] != "/" or set(target) - TARGET_CHARS or set(repl) - REPL_CHARS:
        return None
    for i, ch in enumerate(repl):
        if ch == "$":
            if i + 1 >= len(repl) or repl[i + 1] not in "123456789":
                return None
            if i + 2 < len(repl) and (repl[i + 2].isalnum() or repl[i + 2] == "_"):
                return None
    try:
        return re.compile(regex)
    except re.error:
        return None


def derive(target, regex, repl, mode, version):
    row = dict(label="BAD_INPUT", status="-", router="none", path="-", raw="-", ruri="-", braw="-", bdec="-")
    rx = in_domain(target, regex, repl)
    if rx is None or mode not in ("router", "mw"):
        return row
    u = URL()
    try:
        u.set_path(target)
    except BadEscape:
        return row
    if mode == "mw":
        row["router"] = "-"
    elif u.path.startswith("/admin"):
        row.update(router="protected-admin", label="AUTH_401", status="401")
        return row
    elif u.path.startswith("/api"):
        row["router"] = "public-api"
    else:
        row.update(label="NO_ROUTER_404", status="404")
        return row
    current = u.raw if u.raw else u.escaped_path()
    ruri = u.request_uri()
    if rx.search(current):
        py_repl = re.sub(r"\$(\d)", r"\\g<\1>", repl)
        u.raw = rx.sub(py_repl, current)
        try:
            u.path = unescape(u.raw)
        except BadEscape:
            row.update(label="UNESCAPE_500", status="500")
            return row
        ruri = u.request_uri()
        if version == "post":
            before = u.path
            if before != "":
                u = join_path(u)
            if before != u.path:
                row.update(label="REJECT_400", status="400")
                return row
    row.update(status="200", path=u.path, raw=u.raw, ruri=ruri, braw=backend_norm(ruri))
    try:
        dec = unescape(ruri)
        row["bdec"] = backend_norm(dec)
    except BadEscape:
        dec, row["bdec"] = None, "!"
    if under_admin(ruri) or (dec is not None and under_admin(dec)):
        row["label"] = "CONFIG_ADMIN"
        return row
    r, d = under_admin(row["braw"]), under_admin(row["bdec"])
    row["label"] = "BYPASS_BOTH" if r and d else "BYPASS_RAW" if r else "BYPASS_DECODED" if d else "OK"
    return row


TOKENS = ["", "/", ".", "..", "%2e", "%2e%2e", "%2E%2E%2F", "%2F", "admin", "x"]


def sweep():
    """Same grid as results/sweep.csv, derived here independently."""
    out = ["id,target,pre_label,pre_backend_raw,pre_backend_decoded,post_label,post_backend_raw,post_backend_decoded"]
    seen = []
    for a in TOKENS:
        for b in TOKENS:
            for c in TOKENS:
                t = "/api" + a + b + c
                if t in seen:
                    continue
                seen.append(t)
                pre = derive(t, r"^/api(.*)", "/$1", "router", "pre")
                post = derive(t, r"^/api(.*)", "/$1", "router", "post")
                out.append(",".join(["s%d" % len(seen), t, pre["label"], pre["braw"], pre["bdec"],
                                     post["label"], post["braw"], post["bdec"]]))
    sys.stdout.write("\n".join(out) + "\n")


def main():
    if sys.argv[1:] == ["sweep"]:
        sweep()
        return
    root = Path(__file__).resolve().parent.parent
    out = ["id\tversion\tlabel\tstatus\trouter\tpath\traw_path\trequest_uri\tbackend_raw\tbackend_decoded"]
    for line in (root / "fixtures" / "cases.tsv").read_text().splitlines():
        if not line or line.startswith("#"):
            continue
        cid, target, regex, repl, mode = line.split("\t")
        for version in ("pre", "post"):
            r = derive(target, regex, repl, mode, version)
            f = lambda s: "''" if s == "" else s
            out.append("\t".join([cid, version, r["label"], r["status"], r["router"],
                                  f(r["path"]), f(r["raw"]), f(r["ruri"]), f(r["braw"]), f(r["bdec"])]))
    sys.stdout.write("\n".join(out) + "\n")


if __name__ == "__main__":
    main()
