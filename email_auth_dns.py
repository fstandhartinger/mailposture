"""Live email-authentication posture, read from real DNS over DoH.

Why this source exists: every other source in this pipeline is a fixture, and a
fixture cannot answer the question a buyer asks second ("what does it say about
*my* client?"). This one needs no vendor account, no partner agreement and no
agent on anyone's machine - it reads the client's own public DNS - and the thing
it measures is on the cyber-insurance questionnaire verbatim: is SPF published,
is DMARC published, and is DMARC actually enforcing.

Provenance rule, same as the rest of the pipeline: every derived flag carries the
exact record text it was derived from, the resolver that answered, the DNS
response status and the UTC instant of the query. A live source is only usable in
an audit artifact if the reader can re-run the query and see what you saw.

Determinism: this source is live, so it is NOT reproducible by seed. The report
that prints it must print `fetched_at` and `resolver` next to it. That is the
honest form - a fixed number with no timestamp would be the dishonest one.
"""
import ipaddress
import json
import re
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

RESOLVERS = [
    ("cloudflare", "https://cloudflare-dns.com/dns-query"),
    ("google", "https://dns.google/resolve"),
]

# Selectors worth probing. A DKIM key lives at <selector>._domainkey.<domain> and
# the selector is not discoverable from DNS, so a probe list is the only option
# short of reading a signed message. These are the defaults published by the
# senders an SMB actually uses; a miss here means "not found with these
# selectors", never "not signed", and the report has to say so.
DKIM_SELECTORS = [
    ("selector1", "Microsoft 365"),
    ("selector2", "Microsoft 365"),
    ("google", "Google Workspace"),
    ("k1", "Mailchimp / Mandrill"),
    ("s1", "SendGrid / generic"),
    ("default", "generic"),
    ("dkim", "generic"),
    ("mail", "generic"),
]

_UA = "msp-compliance-report/0.1 (+DNS posture check)"


class DnsError(RuntimeError):
    pass


def _query(name, rtype, resolver=None, timeout=10):
    """One DoH query. Returns (resolver_name, url, parsed_json)."""
    last = None
    pool = RESOLVERS if resolver is None else [r for r in RESOLVERS if r[0] == resolver]
    for rname, base in pool:
        url = base + "?" + urllib.parse.urlencode({"name": name, "type": rtype})
        req = urllib.request.Request(url, headers={
            "accept": "application/dns-json", "user-agent": _UA})
        try:
            with urllib.request.urlopen(req, timeout=timeout,
                                        context=ssl.create_default_context()) as r:
                return rname, url, json.loads(r.read().decode())
        except (urllib.error.URLError, ssl.SSLError, TimeoutError, OSError) as exc:
            last = "%s: %s" % (rname, exc)
            continue
    raise DnsError("no resolver answered for %s/%s (%s)" % (name, rtype, last))


def _txt_strings(ans):
    """DoH returns TXT rdata quoted, and long records arrive as adjacent quoted
    chunks that must be concatenated with no separator (RFC 7208 s3.3). Doing
    this wrong silently truncates a long SPF record and turns a pass into a fail."""
    out = []
    for a in ans:
        if a.get("type") != 16:
            continue
        raw = a.get("data", "")
        parts = re.findall(r'"((?:[^"\\]|\\.)*)"', raw)
        out.append("".join(parts) if parts else raw)
    return out


def _rec(name, rtype):
    rname, url, js = _query(name, rtype)
    return {
        "query": name,
        "type": rtype,
        "resolver": rname,
        "url": url,
        "status": js.get("Status"),          # 0 = NOERROR, 3 = NXDOMAIN
        "ad": bool(js.get("AD")),            # resolver validated DNSSEC
        "answers": js.get("Answer", []) or [],
    }


# ---------------------------------------------------------------- SPF ------

_SPF_ALL = re.compile(r'(?:^|\s)([-~?+])all(?:\s|$)')
# A DNS name as it may legally appear in an SPF domain-spec. Macros (%{...}) are
# legal too and are deliberately not validated here - a record using them is
# reported as fine rather than risk calling a valid record broken.
_SPF_NAME = re.compile(r'^[A-Za-z0-9_%{}.:\-]+$')
_SPF_BARE = {"all", "a", "mx", "ptr"}


def _spf_bad_terms(rec):
    """Terms in an SPF record that no receiver can evaluate.

    Only clearly-broken terms are returned. RFC 7208 s4.6 makes an unrecognised
    term a permerror, which fails SPF for every message - but calling a valid
    record broken is the worse error here, so anything uncertain (macros, novel
    modifiers) is left alone.
    """
    bad = []
    for term in rec.split()[1:]:               # skip the v=spf1 version token
        t = term[1:] if term[:1] in "-~?+" else term
        low = t.lower()
        if low in _SPF_BARE:
            continue
        if ":" in low or "=" in low:
            kind, _, val = re.split(r'([:=])', low, maxsplit=1)[0], None, low.split(":", 1)[-1] if ":" in low else low.split("=", 1)[-1]
            if kind in ("ip4", "ip6"):
                try:
                    ipaddress.ip_network(val, strict=False)
                except ValueError:
                    bad.append(term)
                continue
            if kind in ("a", "mx", "ptr", "include", "exists", "redirect", "exp"):
                name = val.split("/")[0]
                if not name or not _SPF_NAME.match(name):
                    bad.append(term)
                elif "%" not in name and ("." not in name.strip(".")
                                          or not re.search(r'\.[A-Za-z]{2,}$', name.rstrip("."))):
                    bad.append(term)
                continue
            # An unknown modifier (name=value) is ignored by receivers, not an
            # error. An unknown mechanism (name:value) is a permerror.
            if ":" in low:
                bad.append(term)
            continue
        # A bare token that is not a known mechanism.
        bad.append(term)
    return bad


def read_spf(domain):
    r = _rec(domain, "TXT")
    records = [s for s in _txt_strings(r["answers"]) if s.lower().startswith("v=spf1")]
    out = {"probe": r, "records": records, "record": None, "qualifier": None,
           "lookups": None, "published": len(records) > 0, "enforcing": False,
           "multiple": len(records) > 1, "bad_terms": []}
    if len(records) != 1:
        # More than one SPF record is itself a permerror (RFC 7208 s4.5) and mail
        # will fail SPF regardless of what either record says, so it is a finding.
        return out
    rec = records[0]
    out["record"] = rec
    m = _SPF_ALL.search(rec)
    out["qualifier"] = m.group(1) if m else None
    out["bad_terms"] = _spf_bad_terms(rec)
    out["redirect"] = bool(re.search(r'(?:^|\s)redirect=', rec))
    # '-all' rejects unlisted senders; '~all' softfails; '?all'/'+all' assert
    # nothing. A broken term voids the whole record whatever the qualifier says.
    out["enforcing"] = out["qualifier"] == "-" and not out["bad_terms"]
    # RFC 7208 s4.6.4 caps DNS-querying mechanisms at 10; over that is a permerror.
    out["lookups"] = len(re.findall(
        r'(?:^|\s)[-~?+]?(?:include:|a[:/\s]|mx[:/\s]|ptr[:\s]|exists:|redirect=)',
        " " + rec + " "))
    return out


# --------------------------------------------------------------- DMARC -----

def read_dmarc(domain):
    r = _rec("_dmarc." + domain, "TXT")
    records = [s for s in _txt_strings(r["answers"]) if s.lower().startswith("v=dmarc1")]
    out = {"probe": r, "records": records, "record": None, "tags": {},
           "published": False, "policy": None, "pct": None, "rua": [], "enforcing": False}
    if len(records) != 1:
        out["multiple"] = len(records) > 1
        return out
    rec = records[0]
    out["record"] = rec
    out["published"] = True
    tags = {}
    for part in rec.split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            tags[k.strip().lower()] = v.strip()
    out["tags"] = tags
    out["policy"] = tags.get("p")
    out["subdomain_policy"] = tags.get("sp")
    out["pct"] = int(tags["pct"]) if tags.get("pct", "").isdigit() else 100
    out["rua"] = [u.strip() for u in tags.get("rua", "").split(",") if u.strip()]
    # p=none publishes a policy but asks receivers to do nothing about failures.
    # An insurer asking "do you have DMARC" means enforcement, so both are printed.
    out["enforcing"] = out["policy"] in ("quarantine", "reject") and out["pct"] == 100
    return out


# ---------------------------------------------------------------- DKIM -----

def read_dkim(domain, selectors=DKIM_SELECTORS):
    found, probes = [], []
    for sel, who in selectors:
        r = _rec("%s._domainkey.%s" % (sel, domain), "TXT")
        probes.append({"selector": sel, "vendor": who, "status": r["status"],
                       "query": r["query"], "resolver": r["resolver"]})
        for s in _txt_strings(r["answers"]):
            if "p=" in s and ("v=DKIM1" in s or "k=rsa" in s):
                found.append({"selector": sel, "vendor": who,
                              "record": s[:120] + ("..." if len(s) > 120 else ""),
                              "key_bits_hint": len(s)})
                break
    return {"found": found, "probes": probes, "selectors_tried": len(selectors)}


# ----------------------------------------------------------------- MX ------

def read_mx(domain):
    r = _rec(domain, "MX")
    hosts = []
    for a in r["answers"]:
        if a.get("type") == 15:
            parts = (a.get("data") or "").split(None, 1)
            if len(parts) == 2:
                hosts.append({"pref": int(parts[0]), "host": parts[1].rstrip(".")})
    hosts.sort(key=lambda h: h["pref"])
    return {"probe": r, "hosts": hosts, "provider": _guess_provider(hosts)}


_PROVIDERS = [
    ("outlook.com", "Microsoft 365"),
    ("protection.outlook.com", "Microsoft 365"),
    ("google.com", "Google Workspace"),
    ("googlemail.com", "Google Workspace"),
    ("pphosted.com", "Proofpoint"),
    ("mimecast.com", "Mimecast"),
    ("barracudanetworks.com", "Barracuda"),
    ("mailgun.org", "Mailgun"),
    ("zoho.com", "Zoho"),
    ("ionos.de", "IONOS"),
    ("kasserver.com", "All-Inkl"),
]


def _guess_provider(hosts):
    for h in hosts:
        for suffix, name in _PROVIDERS:
            if h["host"].lower().endswith(suffix):
                return name
    return None


# ------------------------------------------------------------- MTA-STS -----

def read_mta_sts(domain):
    r = _rec("_mta-sts." + domain, "TXT")
    recs = [s for s in _txt_strings(r["answers"]) if s.lower().startswith("v=stsv1")]
    return {"probe": r, "published": len(recs) == 1, "record": recs[0] if recs else None}


# -------------------------------------------------------------- posture ----

def posture(domain):
    """Everything the report needs about one domain, with its provenance."""
    t0 = time.time()
    fetched_at = datetime.now(timezone.utc).replace(microsecond=0)
    mx = read_mx(domain)
    spf = read_spf(domain)
    dmarc = read_dmarc(domain)
    dkim = read_dkim(domain)
    sts = read_mta_sts(domain)

    findings = []
    # NXDOMAIN on the apex means the domain is not registered/delegated at all.
    # Reporting "no SPF record published, anyone can send as this domain" for a
    # name that does not exist is false in a way a client would act on, so this
    # case short-circuits and says the one true thing instead.
    if mx["probe"]["status"] == 3:
        return {
            "domain": domain,
            "fetched_at": fetched_at.isoformat().replace("+00:00", "Z"),
            "elapsed_ms": int((time.time() - t0) * 1000),
            "resolvers_used": [mx["probe"]["resolver"]],
            "dnssec_validated": mx["probe"]["ad"],
            "resolves": False,
            "mx": mx, "spf": spf, "dmarc": dmarc, "dkim": dkim, "mta_sts": sts,
            "findings": [("nxdomain", "The resolver returned NXDOMAIN for this name: "
                                      "the domain is not registered or not delegated. "
                                      "No mail-authentication conclusion can be drawn.")],
            "queries": 4 + dkim["selectors_tried"],
        }
    if not mx["hosts"]:
        findings.append(("no-mx", "No MX record: this domain does not receive mail."))
    if spf.get("multiple"):
        findings.append(("spf-multiple", "%d SPF records are published. RFC 7208 s4.5 makes "
                                         "more than one a permanent error, so SPF fails for "
                                         "every message regardless of what either record says."
                         % len(spf["records"])))
    elif not spf["published"]:
        findings.append(("spf-missing", "No SPF record published. Any host on the "
                                        "internet can claim to send as this domain."))
    else:
        if spf["bad_terms"]:
            findings.append(("spf-syntax", "The SPF record contains a term no receiver can "
                                           "evaluate: %s. RFC 7208 s4.6 makes an unrecognised "
                                           "term a permanent error, which fails SPF for every "
                                           "message." % ", ".join("'%s'" % t for t in spf["bad_terms"])))
        if spf["qualifier"] is None and not spf.get("redirect"):
            findings.append(("spf-no-all", "The SPF record has no 'all' mechanism and no "
                                           "redirect, so a sender that matches nothing in it "
                                           "gets a neutral result - the same outcome as no "
                                           "SPF record at all."))
        elif spf["qualifier"] is not None and spf["qualifier"] != "-":
            findings.append(("spf-soft", "SPF ends in '%sall', which asks receivers not to "
                                         "reject unlisted senders." % spf["qualifier"]))
    if spf["lookups"] is not None and spf["lookups"] > 10:
        findings.append(("spf-lookups", "SPF uses %d DNS-querying mechanisms; the limit "
                                        "is 10." % spf["lookups"]))
    if not dmarc["published"]:
        findings.append(("dmarc-missing", "No DMARC record. Nothing tells receivers what "
                                          "to do with mail that fails authentication."))
    elif dmarc["policy"] == "none":
        findings.append(("dmarc-none", "DMARC is published at p=none: it reports, it does "
                                       "not act."))
    elif dmarc["pct"] and dmarc["pct"] < 100:
        findings.append(("dmarc-pct", "DMARC policy applies to %d%% of mail." % dmarc["pct"]))
    if dmarc["published"] and not dmarc["rua"]:
        findings.append(("dmarc-no-rua", "DMARC publishes no rua address, so nobody "
                                         "receives the aggregate reports."))
    if not dkim["found"]:
        findings.append(("dkim-unknown", "No DKIM key found at %d common selectors. This "
                                         "is not proof that mail is unsigned - the selector "
                                         "is not discoverable from DNS."
                         % dkim["selectors_tried"]))

    return {
        "domain": domain,
        "fetched_at": fetched_at.isoformat().replace("+00:00", "Z"),
        "elapsed_ms": int((time.time() - t0) * 1000),
        "resolvers_used": sorted({p["resolver"] for p in
                                  [mx["probe"], spf["probe"], dmarc["probe"], sts["probe"]]}),
        "dnssec_validated": all(p["ad"] for p in
                                [mx["probe"], spf["probe"], dmarc["probe"]]),
        "resolves": True,
        "mx": mx, "spf": spf, "dmarc": dmarc, "dkim": dkim, "mta_sts": sts,
        "findings": findings,
        "queries": 4 + dkim["selectors_tried"],
    }
