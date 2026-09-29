#!/usr/bin/env python3
"""A public, self-serve email-authentication posture check.

One domain in, a plain reading of what its public DNS says about SPF, DMARC,
DKIM and MTA-STS out - the same records a cyber-insurance questionnaire asks an
MSP to attest to. It reads only public DNS over DoH: it runs no scan against
anyone's servers, installs nothing, and stores nothing. Every figure it prints
carries the resolver that answered and the UTC instant of the query, so the
reader can re-run it and see what we saw.

Stdlib only, on purpose - no framework, no database, nothing to reap.
"""
import html
import json
import os
import re
import sys
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

from email_auth_dns import posture, DnsError

PORT = int(os.environ.get("PORT", "8080"))

# A domain label as it may legally appear. Deliberately strict: reject anything
# that is not a plausible hostname before spending DNS queries on it.
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
                        r"[A-Za-z]{2,63}$")

STYLE = """
:root{--ink:#14213d;--muted:#5b6b86;--line:#e4e8f0;--bg:#f6f8fc;--card:#fff;
--good:#1a7f4b;--bad:#b42318;--warn:#9a6700;--accent:#2f4b8f}
*{box-sizing:border-box}
body{margin:0;font:16px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
color:var(--ink);background:var(--bg)}
.wrap{max-width:820px;margin:0 auto;padding:32px 20px 80px}
header h1{font-size:26px;margin:0 0 6px}
header p.lead{color:var(--muted);margin:0 0 22px;font-size:16px}
form.check{display:flex;gap:10px;flex-wrap:wrap;margin:0 0 8px}
input[type=text]{flex:1 1 260px;min-width:0;padding:13px 14px;font-size:16px;
border:1px solid var(--line);border-radius:9px;background:var(--card)}
input[type=text]:focus{outline:2px solid var(--accent);border-color:var(--accent)}
button{padding:13px 22px;font-size:16px;font-weight:600;color:#fff;background:var(--accent);
border:0;border-radius:9px;cursor:pointer}
button:hover{background:#26407c}
.note{color:var(--muted);font-size:13.5px;margin:6px 0 26px}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;
padding:20px 22px;margin:0 0 18px}
.card h2{font-size:16px;margin:0 0 2px;display:flex;align-items:center;gap:9px;justify-content:space-between}
.card h2 .name{display:flex;align-items:center;gap:9px}
.badge{font-size:12px;font-weight:700;letter-spacing:.02em;padding:3px 9px;border-radius:999px;
text-transform:uppercase}
.b-good{color:#0a5c34;background:#e3f5ec}
.b-bad{color:#8a1710;background:#fbe6e3}
.b-warn{color:#7a5200;background:#fbf1d6}
.b-info{color:#274a7a;background:#e7eefb}
.card p.d{margin:9px 0 0;color:#33415c}
.rec{margin:11px 0 0;padding:10px 12px;background:#f3f5fa;border:1px solid var(--line);
border-radius:8px;font:13.5px/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
white-space:pre-wrap;word-break:break-word;color:#243b66}
.finding{margin:9px 0 0;padding-left:14px;border-left:3px solid var(--warn);color:#5a4a1a}
.finding.hard{border-left-color:var(--bad);color:#6f1a12}
.summary{display:flex;gap:14px;flex-wrap:wrap;margin:0 0 20px}
.stat{flex:1 1 120px;background:var(--card);border:1px solid var(--line);border-radius:10px;
padding:12px 14px;text-align:center}
.stat b{display:block;font-size:22px;line-height:1.2}
.stat span{font-size:12.5px;color:var(--muted)}
.prov{color:var(--muted);font-size:12.5px;margin:2px 0 24px;line-height:1.6}
.err{background:#fbe6e3;border:1px solid #f2b8b1;color:#8a1710;padding:14px 16px;border-radius:9px;margin:0 0 22px}
footer{margin-top:40px;padding-top:20px;border-top:1px solid var(--line);color:var(--muted);font-size:13.5px}
footer a{color:var(--accent)}
a.back{display:inline-block;margin:4px 0 20px;color:var(--accent);text-decoration:none}
ul.what{margin:8px 0 0;padding-left:20px;color:var(--muted);font-size:14px}
ul.what li{margin:3px 0}
"""

DISCLOSURE = (
    "Built by Florian Standhartinger while developing a monthly security-and-compliance "
    "report for small MSPs. It is offered free and unconditionally: no sign-up, no price, "
    "no follow-up, and nothing you enter is stored. The check reads only public DNS."
)

# Self-hosted, cookieless Umami. The search string (which holds the domain you
# check) is never sent, so the domain stays out of the statistics.
ANALYTICS = ('<script defer src="https://bh-analytics.app.mintapis.com/script.js" '
             'data-website-id="0ad1bb05-cbc2-454a-8e19-1ed261791338" data-domains="mailposture.app.mintapis.com" '
             'data-exclude-search="true" data-do-not-track="true"></script>')
ANALYTICS_NOTE = ("We use Umami, a self-hosted, cookieless analytics tool on servers in "
                  "Germany; no personal data is stored, and the domain you check is never "
                  "part of it.")

# Findings that a recipient cannot reasonably argue with. spf-soft and
# dkim-unknown are deliberately excluded: Google itself publishes ~all, and a
# missing DKIM selector is not proof of an unsigned domain.
HARD = {"spf-missing", "spf-multiple", "spf-syntax", "spf-no-all", "spf-lookups",
        "dmarc-missing", "dmarc-none", "dmarc-pct", "no-mx"}


def page(body, title="Email authentication check"):
    return ("<!doctype html><html lang=en><head><meta charset=utf-8>"
            "<meta name=viewport content='width=device-width,initial-scale=1'>"
            f"<title>{html.escape(title)}</title><style>{STYLE}</style>"
            f"{ANALYTICS}</head>"
            f"<body><div class=wrap>{body}"
            "<footer>" + html.escape(DISCLOSURE) +
            "<br><br>Sources: your domain's public DNS, read over DNS-over-HTTPS from "
            "Cloudflare and Google. Records are shown verbatim so you can re-run any "
            "query yourself &mdash; e.g. <code>dig +short TXT _dmarc.yourdomain.com</code>."
            "<br><br>" + html.escape(ANALYTICS_NOTE) +
            "</footer></div></body></html>")


FORM = f"""
<header>
<h1>Email authentication check</h1>
<p class=lead>Read what your domain's public DNS says about SPF, DMARC, DKIM and MTA-STS
&mdash; the records a cyber-insurance questionnaire asks you to attest to.</p>
</header>
<form class=check method=get action=/check>
<input type=text name=domain placeholder="yourclient.com" autofocus autocomplete=off
 autocapitalize=off spellcheck=false>
<button type=submit>Check</button>
</form>
<p class=note>Reads public DNS only. No scan against your servers, nothing installed,
nothing stored. Every result shows the resolver and the UTC time it was read.</p>
<div class=card>
<h2><span class=name>What it checks</span></h2>
<ul class=what>
<li><b>SPF</b> &mdash; is a sender policy published, and does it actually reject forgeries (<code>-all</code>) or only softfail (<code>~all</code>)?</li>
<li><b>DMARC</b> &mdash; is a policy published, and is it enforcing (<code>quarantine</code>/<code>reject</code>) or only reporting (<code>p=none</code>)?</li>
<li><b>DKIM</b> &mdash; is a signing key findable at the common selectors? (A miss is "not found here", never "unsigned".)</li>
<li><b>MTA-STS</b> &mdash; is transport-security enforcement published?</li>
</ul>
</div>
"""


def esc(s):
    return html.escape(str(s)) if s is not None else ""


def render_section(name, ok, badge_class, badge_text, detail, record, findings):
    fblocks = ""
    for code, msg in findings:
        cls = "finding hard" if code in HARD else "finding"
        fblocks += f'<p class="{cls}">{esc(msg)}</p>'
    rec = f'<div class=rec>{esc(record)}</div>' if record else ""
    det = f'<p class=d>{esc(detail)}</p>' if detail else ""
    return (f'<div class=card><h2><span class=name>{esc(name)}</span>'
            f'<span class="badge {badge_class}">{esc(badge_text)}</span></h2>'
            f'{det}{rec}{fblocks}</div>')


def find_for(p, prefixes):
    return [(c, m) for c, m in p["findings"] if any(c.startswith(x) for x in prefixes)]


def render_result(p):
    dom = esc(p["domain"])
    if not p.get("resolves", True):
        msg = p["findings"][0][1] if p["findings"] else "This domain does not resolve."
        body = (f'<a class=back href=/>&larr; check another domain</a>'
                f'<header><h1>{dom}</h1></header>'
                f'<div class=err>{esc(msg)}</div>')
        return page(body, f"{p['domain']} — not resolvable")

    spf, dm, dk, sts, mx = p["spf"], p["dmarc"], p["dkim"], p["mta_sts"], p["mx"]
    hard = sum(1 for c, _ in p["findings"] if c in HARD)
    total = len(p["findings"])

    # SPF
    if spf.get("multiple"):
        sb, st = "b-bad", "broken"; sdet = f"{len(spf['records'])} SPF records are published — this is a permanent error and SPF fails for every message."
    elif not spf["published"]:
        sb, st = "b-bad", "missing"; sdet = "No SPF record is published."
    elif spf["bad_terms"]:
        sb, st = "b-bad", "broken"; sdet = "The SPF record contains a term no receiver can evaluate."
    elif spf["qualifier"] == "-":
        sb, st = "b-good", "enforcing"; sdet = "SPF ends in -all: senders not listed are rejected."
    elif spf["qualifier"] in ("~", "?", "+"):
        sb, st = "b-warn", "soft"; sdet = f"SPF ends in {spf['qualifier']}all: unlisted senders are not rejected."
    else:
        sb, st = "b-warn", "no -all"; sdet = "SPF has no all mechanism."
    spf_sec = render_section("SPF", None, sb, st, sdet, spf.get("record"),
                             find_for(p, ["spf"]))

    # DMARC
    if not dm["published"]:
        db, dt = "b-bad", "missing"; ddet = "No DMARC record: nothing tells receivers what to do with mail that fails authentication."
    elif dm["policy"] == "none":
        db, dt = "b-warn", "reporting only"; ddet = "DMARC is published at p=none: it reports, it does not act on failures."
    elif dm["policy"] in ("quarantine", "reject"):
        pct = dm.get("pct") or 100
        if pct < 100:
            db, dt = "b-warn", f"p={dm['policy']} @ {pct}%"; ddet = f"DMARC enforces on {pct}% of mail."
        else:
            db, dt = "b-good", f"p={dm['policy']}"; ddet = f"DMARC is enforcing (p={dm['policy']}, 100%)."
    else:
        db, dt = "b-info", esc(dm["policy"]); ddet = ""
    dmarc_sec = render_section("DMARC", None, db, dt, ddet, dm.get("record"),
                               find_for(p, ["dmarc"]))

    # DKIM
    if dk["found"]:
        sels = ", ".join(f["selector"] for f in dk["found"])
        kb, kt = "b-good", "key found"; kdet = f"A DKIM key was found at: {sels}."
    else:
        kb, kt = "b-info", "not found"
        kdet = (f"No DKIM key at {dk['selectors_tried']} common selectors. This is not proof "
                "the domain is unsigned — the selector cannot be discovered from DNS.")
    dkim_sec = render_section("DKIM", None, kb, kt, kdet,
                              dk["found"][0]["record"] if dk["found"] else None,
                              find_for(p, ["dkim"]))

    # MTA-STS
    if sts["published"]:
        mb, mt, mdet = "b-good", "published", "An MTA-STS policy is published."
    else:
        mb, mt, mdet = "b-info", "not published", "No MTA-STS policy. This is optional; many small senders do not publish one."
    mta_sec = render_section("MTA-STS", None, mb, mt, mdet, sts.get("record"), [])

    # MX
    prov = mx.get("provider") or (mx["hosts"][0]["host"] if mx["hosts"] else None)
    if mx["hosts"]:
        xb, xt, xdet = "b-info", esc(prov or "present"), f"Mail is handled by {esc(prov or mx['hosts'][0]['host'])}."
    else:
        xb, xt, xdet = "b-warn", "none", "No MX record: this domain does not receive mail."
    mx_sec = render_section("MX (mail host)", None, xb, xt, xdet, None, find_for(p, ["no-mx"]))

    summary = (
        '<div class=summary>'
        f'<div class=stat><b>{total}</b><span>findings</span></div>'
        f'<div class=stat><b style="color:var(--bad)">{hard}</b><span>an insurer would flag</span></div>'
        f'<div class=stat><b>{p["queries"]}</b><span>DNS queries</span></div>'
        f'<div class=stat><b>{p["elapsed_ms"]}</b><span>ms to read</span></div>'
        '</div>')

    prov_line = (f'Read at {esc(p["fetched_at"])} via resolver(s) '
                 f'{esc("+".join(p["resolvers_used"]))}; '
                 f'DNSSEC-validated by the resolver: {"yes" if p["dnssec_validated"] else "no"}. '
                 f'These are live records — re-run any query above and you will see the same thing '
                 f'(until the domain owner changes it).')

    body = (f'<a class=back href=/>&larr; check another domain</a>'
            f'<header><h1>{dom}</h1>'
            f'<p class=lead>Email-authentication posture, read live from public DNS.</p></header>'
            f'{summary}{spf_sec}{dmarc_sec}{dkim_sec}{mta_sec}{mx_sec}'
            f'<p class=prov>{prov_line}</p>')
    return page(body, f"{p['domain']} — email authentication")


class H(BaseHTTPRequestHandler):
    server_version = "mailposture"

    def _send(self, code, body, ctype="text/html; charset=utf-8"):
        b = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(b)))
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(b)

    def log_message(self, *a):
        pass

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        u = urlparse(self.path)
        if u.path == "/healthz":
            self._send(200, "ok", "text/plain; charset=utf-8"); return
        if u.path in ("/", "/index.html"):
            self._send(200, page(FORM)); return
        if u.path == "/check":
            q = parse_qs(u.query)
            domain = (q.get("domain", [""])[0] or "").strip().lower()
            domain = domain.split("//")[-1].split("/")[0].lstrip("@").strip(". ")
            if not domain or not _DOMAIN_RE.match(domain):
                body = ('<a class=back href=/>&larr; back</a>'
                        '<header><h1>That does not look like a domain</h1></header>'
                        '<div class=err>Enter a bare domain such as <b>example.com</b> — '
                        'not a URL, an email address, or an IP.</div>')
                self._send(400, page(body, "Invalid domain")); return
            try:
                p = posture(domain)
            except DnsError as e:
                body = (f'<a class=back href=/>&larr; back</a>'
                        f'<header><h1>{esc(domain)}</h1></header>'
                        f'<div class=err>The DNS lookup did not complete: {esc(e)}. '
                        f'Try again in a moment.</div>')
                self._send(502, page(body, "Lookup failed")); return
            except Exception:
                traceback.print_exc(file=sys.stderr)
                self._send(500, page('<div class=err>Something went wrong reading DNS.</div>',
                                     "Error")); return
            self._send(200, render_result(p)); return
        self._send(404, page('<header><h1>Not found</h1></header>'
                             '<a class=back href=/>&larr; home</a>', "Not found"))


def main():
    srv = ThreadingHTTPServer(("0.0.0.0", PORT), H)
    sys.stderr.write(f"mailposture listening on :{PORT}\n")
    srv.serve_forever()


if __name__ == "__main__":
    main()
