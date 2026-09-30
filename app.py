#!/usr/bin/env python3
"""A public, self-serve email-authentication posture check.

One domain in, a plain reading of what its public DNS says about SPF, DMARC,
DKIM and MTA-STS out - the same records a cyber-insurance questionnaire asks an
MSP to attest to. It reads only public DNS over DoH: it runs no scan against
anyone's servers, installs nothing, and stores nothing. Every figure it prints
carries the resolver that answered and the UTC instant of the query, so the
reader can re-run it and see what we saw.

Stdlib only, on purpose - no framework, no database, nothing to reap. Pages are
server-rendered; the only third-party request is the cookieless analytics
script below (privacy-gated, search string excluded).
"""
import html
import json
import os
import re
import sys
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

import pages
from email_auth_dns import posture, DnsError

PORT = int(os.environ.get("PORT", "8080"))

# Canonical origin. Every absolute URL the site emits (canonical link, Open
# Graph, sitemap, JSON-LD) is built from this one string.
SITE_URL = "https://mailposture.app.mintapis.com"
INDEXNOW_KEY = "869c7049df43e0112f5e6b2ad9b195c0"
SITE_NAME = "MailPosture"
SITE_DESC = ("Free, anonymous email-authentication check. See what a domain's public DNS "
             "says about SPF, DMARC, DKIM and MTA-STS - the records a cyber-insurance "
             "questionnaire asks you to attest to.")

# A domain label as it may legally appear. Deliberately strict: reject anything
# that is not a plausible hostname before spending DNS queries on it.
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
                        r"[A-Za-z]{2,63}$")

STYLE = """
:root{
--ink:#101b34;--muted:#55627c;--line:#e2e7f1;--line-strong:#cfd8e8;--bg:#f5f7fb;--card:#fff;
--accent:#234ea3;--accent-strong:#1a3c80;--accent-soft:#e9effc;--accent-line:#c8d6f4;
--good:#0f7a45;--good-bg:#e2f4ea;--bad:#b42318;--bad-bg:#fbe6e3;
--warn:#8a5a00;--warn-bg:#fbf0d2;--info:#28497e;--info-bg:#e7eefb;
--radius:12px;--radius-lg:18px;--maxw:940px;
--shadow:0 1px 2px rgba(16,27,52,.05),0 10px 30px -18px rgba(16,27,52,.25);
--font:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
--mono:ui-monospace,SFMono-Regular,"SF Mono",Menlo,Consolas,monospace;
}
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{margin:0;font:16px/1.6 var(--font);color:var(--ink);background:var(--bg);
-webkit-font-smoothing:antialiased;text-rendering:optimizeLegibility}
img,svg{max-width:100%}
a{color:var(--accent)}
a:hover{color:var(--accent-strong)}
:focus-visible{outline:2px solid var(--accent);outline-offset:2px;border-radius:4px}
.visually-hidden{position:absolute!important;width:1px;height:1px;margin:-1px;padding:0;
border:0;clip:rect(0 0 0 0);clip-path:inset(50%);overflow:hidden;white-space:nowrap}
.skip{position:absolute;left:-9999px;top:0;background:var(--accent);color:#fff;padding:10px 16px;
border-radius:0 0 10px 0;z-index:50}
.skip:focus{left:0;color:#fff}

.wrap{width:100%;max-width:var(--maxw);margin:0 auto;padding:0 18px}

/* header */
.site-header{background:rgba(255,255,255,.86);backdrop-filter:saturate(140%) blur(8px);
border-bottom:1px solid var(--line);position:sticky;top:0;z-index:20}
.site-header .wrap{display:flex;align-items:center;gap:14px;min-height:60px;flex-wrap:wrap}
.brand{display:inline-flex;align-items:center;gap:9px;font-weight:750;font-size:17px;
color:var(--ink);text-decoration:none;letter-spacing:-.01em}
.brand:hover{color:var(--ink)}
.brand .mark{display:block;flex:none}
.site-nav{margin-left:auto;display:flex;gap:2px;overflow-x:auto;-webkit-overflow-scrolling:touch;
max-width:100%}
.site-nav a{padding:12px 12px;border-radius:9px;color:var(--muted);text-decoration:none;
font-size:14.5px;font-weight:600;white-space:nowrap}
.site-nav a:hover{background:var(--accent-soft);color:var(--accent-strong)}
.site-nav a[aria-current=page]{background:var(--accent-soft);color:var(--accent-strong)}

main{display:block;padding:0 0 8px}
.section{margin:0 0 40px}
.eyebrow{display:inline-flex;align-items:center;gap:8px;margin:0 0 14px;padding:5px 12px;
border-radius:999px;background:var(--accent-soft);color:var(--accent-strong);
font-size:13px;font-weight:700;letter-spacing:.01em}
.eyebrow::before{content:"";width:7px;height:7px;border-radius:50%;background:var(--good)}

/* hero */
.hero{padding:34px 0 8px;text-align:center}
.hero h1{font-size:clamp(28px,6vw,42px);line-height:1.12;letter-spacing:-.022em;
margin:0 auto 14px;max-width:20ch}
.hero .lead{font-size:clamp(16px,2.6vw,18.5px);color:var(--muted);margin:0 auto 26px;max-width:56ch}
.hero .lead strong{color:var(--ink);font-weight:650}

/* checker form */
form.check{display:flex;gap:10px;flex-wrap:wrap;max-width:620px;margin:0 auto 12px}
form.check .field{flex:1 1 320px;min-width:0;position:relative;display:flex}
input[type=text]{width:100%;padding:15px 16px;font-size:16px;font-family:var(--font);
border:1.5px solid var(--line-strong);border-radius:var(--radius);background:var(--card);
color:var(--ink);box-shadow:var(--shadow)}
input[type=text]::placeholder{color:#93a0b8}
input[type=text]:focus{outline:none;border-color:var(--accent);
box-shadow:0 0 0 4px var(--accent-soft),var(--shadow)}
form.check button{flex:0 0 auto}
button{padding:15px 26px;font-size:16px;font-weight:700;font-family:var(--font);color:#fff;
background:var(--accent);border:0;border-radius:var(--radius);cursor:pointer;
box-shadow:var(--shadow);transition:background .15s ease}
button:hover{background:var(--accent-strong)}
.note{color:var(--muted);font-size:13.5px;margin:10px auto 0;max-width:60ch}
.trust{list-style:none;display:flex;flex-wrap:wrap;gap:8px 18px;justify-content:center;
margin:20px 0 0;padding:0;color:var(--muted);font-size:13.5px;font-weight:600}
.trust li{display:inline-flex;align-items:center;gap:7px}
.trust svg{flex:none;color:var(--good)}

/* visual */
.visual{margin:26px auto 0;max-width:820px}
.visual-card{background:var(--card);border:1px solid var(--line);border-radius:var(--radius-lg);
padding:18px 18px 10px;box-shadow:var(--shadow)}
.posture-visual{display:block;width:100%;height:auto}
.posture-visual .panel{fill:var(--card);stroke:var(--line)}
.posture-visual .panel-strong{fill:var(--accent-soft);stroke:var(--accent-line)}
.posture-visual .accent{fill:var(--accent)}
.posture-visual .good{fill:var(--good)}
.posture-visual .accent-line{stroke:var(--accent);stroke-width:2;fill:none}
.posture-visual .check{stroke:#fff;stroke-width:4;fill:none;stroke-linecap:round;stroke-linejoin:round}
.posture-visual .chip{fill:var(--card);stroke:var(--line-strong)}
.posture-visual .t-muted{fill:var(--muted);font-size:11.5px;font-weight:700;letter-spacing:.1em}
.posture-visual .t-ink{fill:var(--ink);font-size:15px;font-weight:700}
.posture-visual .t-mono{fill:var(--ink);font-size:14.5px;font-weight:600;font-family:var(--mono)}
.posture-visual .t-chip{fill:var(--ink);font-size:13px;font-weight:650}
.posture-visual .t-note{fill:var(--muted);font-size:11.5px;font-weight:600}

/* cards / grid */
.grid{display:grid;grid-template-columns:1fr;gap:14px}
.check-grid{list-style:none;margin:0;padding:0}
.check-item{background:var(--card);border:1px solid var(--line);border-radius:var(--radius);
padding:18px 18px 16px;box-shadow:var(--shadow)}
.check-item h3{margin:0 0 6px;font-size:16px;display:flex;align-items:center;gap:8px}
.check-item .tag{font:700 11px/1 var(--mono);letter-spacing:.04em;color:var(--accent-strong);
background:var(--accent-soft);padding:4px 7px;border-radius:6px}
.check-item p{margin:0;color:var(--muted);font-size:14.5px}
.check-item code{font-family:var(--mono);font-size:.92em;background:var(--bg);padding:1px 5px;
border-radius:5px}

.section h2{font-size:clamp(21px,3.6vw,26px);letter-spacing:-.015em;margin:0 0 6px}
.section .section-lead{color:var(--muted);margin:0 0 20px;max-width:62ch}

/* guides */
.guide-grid{display:grid;grid-template-columns:1fr;gap:14px}
.guide-card{display:block;background:var(--card);border:1px solid var(--line);
border-radius:var(--radius);padding:18px;text-decoration:none;color:inherit;
box-shadow:var(--shadow);transition:border-color .15s ease,transform .15s ease}
.guide-card:hover{border-color:var(--accent-line);transform:translateY(-2px)}
.guide-card .tag{font:700 11.5px/1 var(--mono);color:var(--accent-strong);
background:var(--accent-soft);padding:4px 8px;border-radius:6px;display:inline-block;margin-bottom:10px}
.guide-card h3{margin:0 0 5px;font-size:17px}
.guide-card p{margin:0;color:var(--muted);font-size:14.5px}

/* faq */
.faq-item{background:var(--card);border:1px solid var(--line);border-radius:var(--radius);
padding:18px 18px 16px;box-shadow:var(--shadow)}
.faq-item h3{margin:0 0 7px;font-size:16px}
.faq-item .faq-a{color:#33415c;font-size:14.5px}
.faq-item .faq-a p{margin:0}
.faq-a code{font-family:var(--mono);font-size:.92em;background:var(--bg);padding:1px 5px;border-radius:5px}

/* guides article */
.page-head{padding:30px 0 6px;max-width:68ch}
.page-head h1{font-size:clamp(26px,5vw,36px);letter-spacing:-.02em;margin:0 0 12px}
.page-head .lead{font-size:17px;color:var(--muted);margin:0}
.back{display:inline-block;margin:22px 0 0;color:var(--accent);text-decoration:none;font-size:14.5px;font-weight:600}
.back:hover{text-decoration:underline}
.prose{max-width:70ch;margin:26px auto 0}
.prose h2{font-size:21px;letter-spacing:-.01em;margin:38px 0 10px;scroll-margin-top:80px}
.prose p{margin:0 0 14px}
.prose ul,.prose ol{margin:0 0 16px;padding-left:22px}
.prose li{margin:7px 0}
.prose code{font-family:var(--mono);font-size:.9em;background:var(--bg);border:1px solid var(--line);
padding:1px 5px;border-radius:5px;word-break:break-word}
.prose pre.code{background:#0f1b33;color:#e6ecf7;border-radius:var(--radius);padding:14px 16px;
overflow-x:auto;font-size:13.5px;line-height:1.5;margin:0 0 18px}
.prose pre.code code{background:none;border:0;color:inherit;padding:0;font-size:inherit}
.prose strong{font-weight:700}
.cta{background:var(--card);border:1px solid var(--line);border-radius:var(--radius-lg);
padding:22px;margin:34px 0 0;box-shadow:var(--shadow);text-align:center}
.cta h2{margin:0 0 6px;font-size:19px}
.cta p{margin:0 0 16px;color:var(--muted);font-size:14.5px}
.cta form.check{margin:0 auto}
.related{margin:26px 0 0}
.related h2{font-size:18px;margin:0 0 12px}

/* results */
.summary{display:grid;grid-template-columns:repeat(2,1fr);gap:10px;margin:0 0 20px}
.stat{background:var(--card);border:1px solid var(--line);border-radius:var(--radius);
padding:14px 12px;text-align:center;box-shadow:var(--shadow)}
.stat b{display:block;font-size:24px;line-height:1.15;font-variant-numeric:tabular-nums}
.stat span{font-size:12.5px;color:var(--muted)}
.card{background:var(--card);border:1px solid var(--line);border-radius:var(--radius);
padding:20px 20px 18px;margin:0 0 14px;box-shadow:var(--shadow)}
.card h2{font-size:16px;margin:0 0 2px;display:flex;align-items:center;gap:10px;
justify-content:space-between;flex-wrap:wrap}
.card h2 .name{display:flex;align-items:center;gap:9px;font-weight:700}
.badge{font-size:11.5px;font-weight:750;letter-spacing:.03em;padding:4px 10px;border-radius:999px;
text-transform:uppercase;white-space:nowrap}
.b-good{color:#0a5c34;background:var(--good-bg)}
.b-bad{color:#8a1710;background:var(--bad-bg)}
.b-warn{color:#7a5200;background:var(--warn-bg)}
.b-info{color:#274a7a;background:var(--info-bg)}
.card p.d{margin:10px 0 0;color:#33415c}
.rec{margin:12px 0 0;padding:11px 13px;background:var(--bg);border:1px solid var(--line);
border-radius:9px;font:13px/1.55 var(--mono);white-space:pre-wrap;word-break:break-word;color:#243b66}
.finding{margin:11px 0 0;padding:9px 12px;border-left:3px solid var(--warn);background:var(--warn-bg);
color:#5a4a1a;border-radius:0 8px 8px 0;font-size:14px}
.finding.hard{border-left-color:var(--bad);background:var(--bad-bg);color:#6f1a12}
.prov{color:var(--muted);font-size:12.5px;margin:6px 0 24px;line-height:1.65}
.err{background:var(--bad-bg);border:1px solid #f2b8b1;color:#8a1710;padding:15px 16px;
border-radius:var(--radius);margin:0 0 20px}
ul.what{margin:8px 0 0;padding-left:20px;color:var(--muted);font-size:14.5px}
ul.what li{margin:5px 0}
ul.what code{font-family:var(--mono);font-size:.92em}

/* footer */
.site-footer{margin-top:54px;border-top:1px solid var(--line);background:#fff}
.site-footer .wrap{padding:30px 18px 44px}
.site-footer p{margin:0 0 12px;color:var(--muted);font-size:13.5px;max-width:74ch}
.site-footer .footnav{display:flex;flex-wrap:wrap;gap:8px 20px;margin:0 0 18px;padding:0;list-style:none}
.site-footer .footnav a{color:var(--muted);text-decoration:none;font-size:13.5px;font-weight:600}
.site-footer .footnav a:hover{color:var(--accent-strong)}
.site-footer code{font-family:var(--mono);font-size:12.5px;background:var(--bg);padding:1px 5px;
border-radius:5px}
.site-footer .fine{color:var(--muted);font-size:12.5px}

@media (min-width:640px){
.grid{grid-template-columns:1fr 1fr}
.check-grid{display:grid;grid-template-columns:1fr 1fr;gap:14px}
.guide-grid{grid-template-columns:1fr 1fr}
.faq-grid{display:grid;grid-template-columns:1fr;gap:14px}
.summary{grid-template-columns:repeat(4,1fr)}
}
@media (min-width:880px){
.guide-grid{grid-template-columns:repeat(2,1fr)}
}
@media (prefers-reduced-motion:reduce){
*{animation:none!important;transition:none!important;scroll-behavior:auto!important}
.guide-card:hover{transform:none}
}
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

BRAND_MARK = ('<svg class="mark" width="22" height="22" viewBox="0 0 24 24" aria-hidden="true" '
              'focusable="false"><path d="M4 5.5h16a1.5 1.5 0 0 1 1.5 1.5v10a1.5 1.5 0 0 1-1.5 1.5H4'
              'A1.5 1.5 0 0 1 2.5 17V7A1.5 1.5 0 0 1 4 5.5Z" fill="none" stroke="#234ea3" '
              'stroke-width="1.7"/><path d="m3.4 7 8.6 6 8.6-6" fill="none" stroke="#0f7a45" '
              'stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"/></svg>')

CHECK_ICON = ('<svg width="15" height="15" viewBox="0 0 20 20" aria-hidden="true" focusable="false">'
              '<path d="m4 10.5 4 4 8-9" fill="none" stroke="currentColor" stroke-width="2.2" '
              'stroke-linecap="round" stroke-linejoin="round"/></svg>')

# An original diagram built from inline SVG (no stock imagery): a domain is read
# at public DNS, the four records are inspected, and a receiver verifies the
# result. Purely decorative illustration of the checks described below.
VISUAL = """
<svg class="posture-visual" viewBox="0 0 900 250" role="img" aria-labelledby="vis-title vis-desc"
 xmlns="http://www.w3.org/2000/svg" preserveAspectRatio="xMidYMid meet">
 <title id="vis-title">How MailPosture reads a domain</title>
 <desc id="vis-desc">An email domain is read at public DNS, where its SPF, DMARC, DKIM and
 MTA-STS records are inspected, and a receiving server verifies the result.</desc>
 <defs>
  <marker id="arrow" viewBox="0 0 10 10" refX="7.5" refY="5" markerWidth="6.5" markerHeight="6.5"
   orient="auto-start-reverse"><path d="M0 0 10 5 0 10Z" class="accent"/></marker>
 </defs>

 <rect x="3" y="55" width="198" height="140" rx="16" class="panel"/>
 <text x="24" y="86" class="t-muted">SENDS AS</text>
 <text x="24" y="114" class="t-mono">yourclient.com</text>
 <rect x="24" y="134" width="58" height="38" rx="7" class="panel-strong"/>
 <path d="M24 137 53 158 82 137" class="accent-line" stroke-linecap="round" stroke-linejoin="round"/>
 <text x="94" y="158" class="t-note">envelope sender</text>

 <path d="M209 125H268" class="accent-line" marker-end="url(#arrow)"/>
 <text x="238" y="115" class="t-note" text-anchor="middle">TXT</text>

 <rect x="282" y="22" width="356" height="206" rx="18" class="panel-strong"/>
 <text x="306" y="52" class="t-muted">PUBLIC DNS (DoH)</text>
 <g>
  <rect x="306" y="66" width="308" height="30" rx="9" class="chip"/>
  <circle cx="325" cy="81" r="6" class="good"/>
  <text x="344" y="86" class="t-chip">SPF</text>
  <text x="596" y="86" class="t-note" text-anchor="end">v=spf1</text>
 </g>
 <g>
  <rect x="306" y="104" width="308" height="30" rx="9" class="chip"/>
  <circle cx="325" cy="119" r="6" class="good"/>
  <text x="344" y="124" class="t-chip">DMARC</text>
  <text x="596" y="124" class="t-note" text-anchor="end">_dmarc</text>
 </g>
 <g>
  <rect x="306" y="142" width="308" height="30" rx="9" class="chip"/>
  <circle cx="325" cy="157" r="6" class="accent"/>
  <text x="344" y="162" class="t-chip">DKIM</text>
  <text x="596" y="162" class="t-note" text-anchor="end">_domainkey</text>
 </g>
 <g>
  <rect x="306" y="180" width="308" height="30" rx="9" class="chip"/>
  <circle cx="325" cy="195" r="6" class="good"/>
  <text x="344" y="200" class="t-chip">MTA-STS</text>
  <text x="596" y="200" class="t-note" text-anchor="end">_mta-sts</text>
 </g>

 <path d="M644 125H692" class="accent-line" marker-end="url(#arrow)"/>
 <text x="668" y="115" class="t-note" text-anchor="middle">verdict</text>

 <rect x="699" y="55" width="198" height="140" rx="16" class="panel"/>
 <text x="720" y="86" class="t-muted">RECEIVER</text>
 <path d="M798 96l26 10v20c0 20-15 33-26 38-11-5-26-18-26-38v-20Z" class="accent"/>
 <path d="m787 126 7 7 15-16" class="check"/>
</svg>
"""


def esc(s):
    return html.escape(str(s)) if s is not None else ""


def abs_url(path):
    if path.startswith("http"):
        return path
    if path in ("", "/"):
        return SITE_URL + "/"
    return SITE_URL + path


def _plain(s):
    """Turn an HTML fragment into plain text for structured data."""
    return re.sub(r"\s+", " ", html.unescape(re.sub(r"<[^>]+>", "", s))).strip()


def _jsonld(obj):
    return ('<script type="application/ld+json">'
            + json.dumps(obj, ensure_ascii=False, separators=(",", ":")) + "</script>")


def _org_jsonld():
    return _jsonld({
        "@context": "https://schema.org",
        "@type": "Organization",
        "name": SITE_NAME,
        "url": SITE_URL,
        "description": SITE_DESC,
        "founder": {"@type": "Person", "name": "Florian Standhartinger"},
    })


def _app_jsonld():
    return _jsonld({
        "@context": "https://schema.org",
        "@type": "SoftwareApplication",
        "name": SITE_NAME,
        "url": SITE_URL,
        "applicationCategory": "SecurityApplication",
        "operatingSystem": "Web browser",
        "description": SITE_DESC,
        "isAccessibleForFree": True,
        "offers": {"@type": "Offer", "price": "0", "priceCurrency": "EUR"},
    })


def _faq_jsonld():
    return _jsonld({
        "@context": "https://schema.org",
        "@type": "FAQPage",
        "mainEntity": [
            {"@type": "Question", "name": q,
             "acceptedAnswer": {"@type": "Answer", "text": _plain(a)}}
            for q, a in pages.FAQ
        ],
    })


# --------------------------------------------------------------- layout -----

def page(body, *, title, description, path, og_type="website", jsonld=(), active=None,
         noindex=False):
    nav = ""
    for g in pages.GUIDES:
        cur = ' aria-current="page"' if active == g["slug"] else ""
        nav += f'<a href="/{g["slug"]}"{cur}>{esc(g["short"])}</a>'
    cur_home = ' aria-current="page"' if active == "home" else ""
    nav = f'<a href="/"{cur_home}>Home</a>' + nav

    structured = "".join(jsonld)
    robots = "<meta name=robots content='noindex,follow'>" if noindex else ""
    doc = (
        "<!doctype html><html lang=en><head><meta charset=utf-8>"
        "<meta name=viewport content='width=device-width,initial-scale=1'>"
        f"<title>{esc(title)}</title>"
        f"{robots}"
        f"<meta name=description content=\"{esc(description)}\">"
        f"<link rel=canonical href=\"{esc(abs_url(path))}\">"
        f"<meta property='og:site_name' content='{SITE_NAME}'>"
        f"<meta property='og:type' content='{esc(og_type)}'>"
        f"<meta property='og:title' content=\"{esc(title)}\">"
        f"<meta property='og:description' content=\"{esc(description)}\">"
        f"<meta property='og:url' content=\"{esc(abs_url(path))}\">"
        f"<meta property='og:image' content='{SITE_URL}/social-card.svg'>"
        "<meta property='og:image:width' content='1200'>"
        "<meta property='og:image:height' content='630'>"
        f"<meta property='og:image:alt' content='MailPosture: a free email-authentication check'>"
        "<meta name=twitter:card content='summary_large_image'>"
        f"<meta name=twitter:title content=\"{esc(title)}\">"
        f"<meta name=twitter:description content=\"{esc(description)}\">"
        f"<meta name=twitter:image content='{SITE_URL}/social-card.svg'>"
        f"<meta name=theme-color content='#f5f7fb'>"
        f"<link rel=icon type='image/svg+xml' href='/favicon.svg'>"
        f"{structured}<style>{STYLE}</style>{ANALYTICS}</head>"
        f"<body><a class=skip href=#main>Skip to content</a>"
        "<header class=site-header><div class=wrap>"
        f"<a class=brand href='/'>{BRAND_MARK}<span>{SITE_NAME}</span></a>"
        f"<nav class=site-nav aria-label=Primary>{nav}</nav>"
        "</div></header>"
        f"<main id=main><div class=wrap>{body}</div></main>"
        "<footer class=site-footer><div class=wrap>"
        f"<ul class=footnav><li><a href='/'>Home</a></li>"
        + "".join(f'<li><a href="/{g["slug"]}">{esc(g["name"])}</a></li>' for g in pages.GUIDES)
        + "<li><a href='/llms.txt'>llms.txt</a></li><li><a href='/sitemap.xml'>Sitemap</a></li></ul>"
        f"<p>{esc(DISCLOSURE)}</p>"
        "<p>Sources: your domain's public DNS, read over DNS-over-HTTPS from Cloudflare and "
        "Google. Records are shown verbatim so you can re-run any query yourself &mdash; e.g. "
        "<code>dig +short TXT _dmarc.yourdomain.com</code>.</p>"
        f"<p class=fine>{esc(ANALYTICS_NOTE)}</p>"
        "</div></footer></body></html>")
    return doc


def checker_form(action="/check", autofocus=False):
    af = " autofocus" if autofocus else ""
    return (f'<form class=check method=get action="{esc(action)}">'
            '<label class=visually-hidden for=domain>Domain to check</label>'
            f'<span class=field><input id=domain type=text name=domain '
            f'placeholder="yourclient.com" autocomplete=off autocapitalize=off spellcheck=false{af}></span>'
            '<button type=submit>Check domain</button></form>')


# ----------------------------------------------------------- home page ------

def home_body():
    checks = [
        ("SPF", "spf", "Is a sender policy published, and does it actually reject forgeries "
                      "(<code>-all</code>) or only softfail (<code>~all</code>)?",
         "v=spf1"),
        ("DMARC", "dmarc", "Is a policy published, and is it enforcing "
                           "(<code>quarantine</code>/<code>reject</code>) or only reporting "
                           "(<code>p=none</code>)?", "p=reject"),
        ("DKIM", "dkim", "Is a signing key findable at the common selectors? A miss is "
                         "<em>not found here</em>, never <em>unsigned</em>.", "p=key"),
        ("MTA-STS", "mta-sts", "Is transport-security enforcement published, so senders deliver "
                               "over verified TLS?", "v=STSv1"),
    ]
    check_html = "".join(
        f'<li class=check-item><h3><span class=tag>{esc(tag)}</span>{esc(name)}</h3>'
        f'<p>{detail}</p></li>'
        for name, tag, detail, _ in checks)

    def faq_html():
        w = "".join(
            f'<div class=faq-item><h3>{q}</h3><div class=faq-a><p>{a}</p></div></div>'
            for q, a in pages.FAQ)
        return f'<div class=faq-grid>{w}</div>'

    guide_html = "".join(
        f'<a class=guide-card href="/{g["slug"]}"><span class=tag>{esc(g["short"])}</span>'
        f'<h3>{esc(g["name"])}</h3><p>{esc(g["desc"])}</p></a>'
        for g in pages.GUIDES)

    body = f"""
<section class=hero>
 <span class=eyebrow>Free &middot; anonymous &middot; public DNS only</span>
 <h1>See how your email authentication really looks</h1>
 <p class=lead>Type a domain and read what its public DNS says about
 <strong>SPF, DMARC, DKIM and MTA-STS</strong> &mdash; the records a cyber-insurance
 questionnaire asks you to attest to.</p>
 {checker_form(autofocus=True)}
 <p class=note>Reads public DNS only. No scan against your servers, nothing installed,
 nothing stored. Every result shows the resolver that answered and the UTC time it was read.</p>
 <ul class=trust>
  <li>{CHECK_ICON}No sign-up</li>
  <li>{CHECK_ICON}No database</li>
  <li>{CHECK_ICON}Records shown verbatim</li>
 </ul>
 <div class=visual><div class=visual-card>{VISUAL}</div></div>
</section>

<section class="section" aria-labelledby=h-checks>
 <h2 id=h-checks>What the check reads</h2>
 <p class=section-lead>Four records, each a control an insurer or auditor may ask about.
 The check reports what is published and flags what is missing or merely reporting.</p>
 <ul class=check-grid>{check_html}</ul>
</section>

<section class="section" aria-labelledby=h-guides>
 <h2 id=h-guides>Guides</h2>
 <p class=section-lead>Understand each record, the mistakes that quietly break it, and how to
 fix it &mdash; with the limits of a DNS-only check stated plainly.</p>
 <div class=guide-grid>{guide_html}</div>
</section>

<section class="section" aria-labelledby=h-faq id=faq>
 <h2 id=h-faq>Frequently asked questions</h2>
 {faq_html()}
</section>
"""
    return body


# --------------------------------------------------------- result pages -----

def render_section(name, badge_class, badge_text, detail, record, findings):
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
                f'<header class=page-head><h1>{dom}</h1></header>'
                f'<div class=err>{esc(msg)}</div>')
        return page(body, title=f"{p['domain']} — not resolvable",
                    description=f"MailPosture could not resolve {p['domain']}: the domain is "
                                f"not registered or not delegated.",
                    path="/check", active="home", noindex=True)

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
    spf_sec = render_section("SPF", sb, st, sdet, spf.get("record"), find_for(p, ["spf"]))

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
    dmarc_sec = render_section("DMARC", db, dt, ddet, dm.get("record"), find_for(p, ["dmarc"]))

    # DKIM
    if dk["found"]:
        sels = ", ".join(f["selector"] for f in dk["found"])
        kb, kt = "b-good", "key found"; kdet = f"A DKIM key was found at: {sels}."
    else:
        kb, kt = "b-info", "not found"
        kdet = (f"No DKIM key at {dk['selectors_tried']} common selectors. This is not proof "
                "the domain is unsigned — the selector cannot be discovered from DNS.")
    dkim_sec = render_section("DKIM", kb, kt, kdet,
                              dk["found"][0]["record"] if dk["found"] else None,
                              find_for(p, ["dkim"]))

    # MTA-STS
    if sts["published"]:
        mb, mt, mdet = "b-good", "published", "An MTA-STS policy is published."
    else:
        mb, mt, mdet = "b-info", "not published", "No MTA-STS policy. This is optional; many small senders do not publish one."
    mta_sec = render_section("MTA-STS", mb, mt, mdet, sts.get("record"), [])

    # MX
    prov = mx.get("provider") or (mx["hosts"][0]["host"] if mx["hosts"] else None)
    if mx["hosts"]:
        xb, xt, xdet = "b-info", esc(prov or "present"), f"Mail is handled by {esc(prov or mx['hosts'][0]['host'])}."
    else:
        xb, xt, xdet = "b-warn", "none", "No MX record: this domain does not receive mail."
    mx_sec = render_section("MX (mail host)", xb, xt, xdet, None, find_for(p, ["no-mx"]))

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
            f'<header class=page-head><h1>{dom}</h1>'
            f'<p class=lead>Email-authentication posture, read live from public DNS.</p></header>'
            f'{summary}{spf_sec}{dmarc_sec}{dkim_sec}{mta_sec}{mx_sec}'
            f'<p class=prov>{prov_line}</p>')
    return page(body, title=f"{p['domain']} — email authentication",
                description=f"Live SPF, DMARC, DKIM and MTA-STS posture for {p['domain']}, "
                            f"read from public DNS.",
                path="/check", active="home", noindex=True)


# ----------------------------------------------------------- guide pages ----

def guide_body(g):
    others = [x for x in pages.GUIDES if x["slug"] != g["slug"]]
    related = "".join(
        f'<a class=guide-card href="/{x["slug"]}"><span class=tag>{esc(x["short"])}</span>'
        f'<h3>{esc(x["name"])}</h3><p>{esc(x["desc"])}</p></a>' for x in others)
    body = f"""
<a class=back href=/>&larr; Home</a>
<header class=page-head>
 <h1>{esc(g["h1"])}</h1>
 <p class=lead>{esc(g["lede"])}</p>
</header>
<article class=prose>{g["body"]}</article>
<div class=cta>
 <h2>Check a domain now</h2>
 <p>Free, anonymous, and reads public DNS only.</p>
 {checker_form()}
</div>
<section class="section related" aria-labelledby=h-related>
 <h2 id=h-related>Related guides</h2>
 <div class=guide-grid>{related}</div>
</section>
"""
    return body


def guide_page(g):
    return page(
        guide_body(g),
        title=g["title"],
        description=g["desc"],
        path="/" + g["slug"],
        og_type="article",
        jsonld=(_jsonld({
            "@context": "https://schema.org",
            "@type": "Article",
            "headline": g["h1"],
            "description": g["desc"],
            "url": abs_url("/" + g["slug"]),
            "mainEntityOfPage": abs_url("/" + g["slug"]),
            "author": {"@type": "Person", "name": "Florian Standhartinger"},
            "publisher": {"@type": "Organization", "name": SITE_NAME, "url": SITE_URL},
        }),),
        active=g["slug"])


# ------------------------------------------------------ static resources ----

def robots_txt():
    return ("User-agent: *\n"
            "Allow: /\n\n"
            f"Sitemap: {SITE_URL}/sitemap.xml\n")


def sitemap_xml():
    paths = ["/"] + ["/" + g["slug"] for g in pages.GUIDES]
    urls = "".join(f"<url><loc>{abs_url(p)}</loc></url>" for p in paths)
    return ('<?xml version="1.0" encoding="UTF-8"?>'
            '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
            f"{urls}</urlset>")


def llms_txt():
    lines = [
        f"# {SITE_NAME}",
        "",
        f"> {SITE_DESC}",
        "",
        "MailPosture is a free, anonymous, database-free email-authentication check. It reads "
        "public DNS over DNS-over-HTTPS (Cloudflare, with Google as fallback), runs no scan "
        "against any server, and stores nothing. It reports SPF, DMARC, DKIM and MTA-STS as "
        "published, prints records verbatim, and shows the resolver and UTC time of each lookup.",
        "",
        "Important limits, stated on every page: a DKIM key can only be probed at common "
        "selectors (the selector is not discoverable from DNS), the SPF DNS-lookup count is a "
        "floor for the top-level record, only public DNS is read, and no domain history or "
        "database is kept.",
        "",
        "## Pages",
        "",
        f"- [Home]({SITE_URL}/): run the check.",
    ]
    for g in pages.GUIDES:
        lines.append(f"- [{g['name']}]({SITE_URL}/{g['slug']}): {g['desc']}")
    lines += ["", f"## Sitemap", "", f"{SITE_URL}/sitemap.xml", ""]
    return "\n".join(lines)


def favicon_svg():
    return ('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24">'
            '<rect width="24" height="24" rx="5" fill="#234ea3"/>'
            '<path d="M4 7h16a1.5 1.5 0 0 1 1.5 1.5v7A1.5 1.5 0 0 1 20 17H4a1.5 1.5 0 0 1-1.5-1.5v-7'
            'A1.5 1.5 0 0 1 4 7Z" fill="none" stroke="#fff" stroke-width="1.6"/>'
            '<path d="m3.6 8.2 8.4 6 8.4-6" fill="none" stroke="#8fd3ad" stroke-width="1.6" '
            'stroke-linecap="round" stroke-linejoin="round"/></svg>')


def social_card_svg():
    return ('<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="630" '
            'viewBox="0 0 1200 630">'
            '<defs><linearGradient id="g" x1="0" y1="0" x2="1" y2="1">'
            '<stop offset="0" stop-color="#101b34"/><stop offset="1" stop-color="#234ea3"/>'
            '</linearGradient></defs>'
            '<rect width="1200" height="630" fill="url(#g)"/>'
            '<text x="80" y="200" fill="#8fd3ad" font-family="Arial,Helvetica,sans-serif" '
            'font-size="30" font-weight="700" letter-spacing="4">MAILPOSTURE</text>'
            '<text x="80" y="300" fill="#ffffff" font-family="Arial,Helvetica,sans-serif" '
            'font-size="64" font-weight="700">See your email</text>'
            '<text x="80" y="378" fill="#ffffff" font-family="Arial,Helvetica,sans-serif" '
            'font-size="64" font-weight="700">authentication posture</text>'
            '<text x="80" y="470" fill="#c8d6f4" font-family="Arial,Helvetica,sans-serif" '
            'font-size="34">Free SPF &#183; DMARC &#183; DKIM &#183; MTA-STS check from public DNS</text>'
            '<rect x="80" y="520" width="440" height="8" rx="4" fill="#8fd3ad"/></svg>')


# -------------------------------------------------------------- handler -----

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
        path = u.path
        if path == "/healthz":
            self._send(200, "ok", "text/plain; charset=utf-8"); return
        if path in ("/", "/index.html"):
            self._send(200, page(
                home_body(),
                title=f"{SITE_NAME} — free SPF, DMARC, DKIM & MTA-STS check",
                description=SITE_DESC,
                path="/",
                jsonld=(_org_jsonld(), _app_jsonld(), _faq_jsonld()),
                active="home")); return
        if path.lstrip("/") in pages.GUIDE_BY_SLUG:
            self._send(200, guide_page(pages.GUIDE_BY_SLUG[path.lstrip("/")])); return
        if path == "/robots.txt":
            self._send(200, robots_txt(), "text/plain; charset=utf-8"); return
        if path == "/sitemap.xml":
            self._send(200, sitemap_xml(), "application/xml; charset=utf-8"); return
        if path == "/llms.txt":
            self._send(200, llms_txt(), "text/plain; charset=utf-8"); return
        if path == "/favicon.svg":
            self._send(200, favicon_svg(), "image/svg+xml; charset=utf-8"); return
        if path == "/social-card.svg":
            self._send(200, social_card_svg(), "image/svg+xml; charset=utf-8"); return
        if path == f"/{INDEXNOW_KEY}.txt":
            self._send(200, INDEXNOW_KEY, "text/plain; charset=utf-8"); return
        if path == "/check":
            self._check(u)
            return
        self._send(404, page('<a class=back href=/>&larr; home</a>'
                             '<header class=page-head><h1>Not found</h1></header>'
                             '<div class=err>That page does not exist. The home page has the '
                             'domain check and the guides.</div>',
                             title="Not found", description="Page not found on MailPosture.",
                             path="/", active="home"))

    def _check(self, u):
        q = parse_qs(u.query)
        domain = (q.get("domain", [""])[0] or "").strip().lower()
        domain = domain.split("//")[-1].split("/")[0].lstrip("@").strip(". ")
        if not domain or not _DOMAIN_RE.match(domain):
            body = ('<a class=back href=/>&larr; back</a>'
                    '<header class=page-head><h1>That does not look like a domain</h1></header>'
                    '<div class=err>Enter a bare domain such as <b>example.com</b> — '
                    'not a URL, an email address, or an IP.</div>')
            self._send(400, page(body, title="Invalid domain",
                                 description="Enter a bare domain such as example.com.",
                                 path="/", active="home", noindex=True)); return
        try:
            p = posture(domain)
        except DnsError as e:
            body = (f'<a class=back href=/>&larr; back</a>'
                    f'<header class=page-head><h1>{esc(domain)}</h1></header>'
                    f'<div class=err>The DNS lookup did not complete: {esc(e)}. '
                    f'Try again in a moment.</div>')
            self._send(502, page(body, title="Lookup failed",
                                 description="The DNS lookup did not complete.",
                                 path="/", active="home", noindex=True)); return
        except Exception:
            traceback.print_exc(file=sys.stderr)
            self._send(500, page('<div class=err>Something went wrong reading DNS.</div>',
                                 title="Error", description="Something went wrong reading DNS.",
                                 path="/", active="home", noindex=True)); return
        self._send(200, render_result(p))


def main():
    srv = ThreadingHTTPServer(("0.0.0.0", PORT), H)
    sys.stderr.write(f"mailposture listening on :{PORT}\n")
    srv.serve_forever()


if __name__ == "__main__":
    main()
