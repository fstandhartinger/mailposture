#!/usr/bin/env python3
"""Lightweight route, metadata and structured-data checks for MailPosture.

Starts the real stdlib server on an ephemeral port and reads it over HTTP. It
does not touch DNS: the only /check request uses an input that is rejected
before any lookup, so the suite is offline and fast. Run:  python3 test_site.py
"""
import json
import re
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from unittest.mock import patch

import app
import pages

JSONLD_RE = re.compile(
    r'<script type="application/ld\+json">(.*?)</script>', re.DOTALL)


class SiteTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = ThreadingHTTPServer(("127.0.0.1", 0), app.H)
        cls.port = cls.srv.server_address[1]
        cls.thread = threading.Thread(target=cls.srv.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()

    def get(self, path):
        url = "http://127.0.0.1:%d%s" % (self.port, path)
        try:
            with urllib.request.urlopen(url, timeout=10) as r:
                return r.status, r.headers.get("Content-Type", ""), r.read().decode("utf-8")
        except urllib.error.HTTPError as e:
            return e.code, e.headers.get("Content-Type", ""), e.read().decode("utf-8")

    def jsonld(self, body):
        return [json.loads(m) for m in JSONLD_RE.findall(body)]

    # -- routes ------------------------------------------------------------

    def test_healthz(self):
        code, ctype, body = self.get("/healthz")
        self.assertEqual(code, 200)
        self.assertIn("text/plain", ctype)
        self.assertEqual(body, "ok")

    def test_home(self):
        code, _, body = self.get("/")
        self.assertEqual(code, 200)
        self.assertIn("/check", body)
        self.assertIn('name=domain', body)
        self.assertIn("SPF", body)

    def test_guide_routes(self):
        for g in pages.GUIDES:
            code, _, body = self.get("/" + g["slug"])
            self.assertEqual(code, 200, g["slug"])
            self.assertIn("<h1>%s</h1>" % g["h1"], body)
            self.assertIn(g["title"], body)
            self.assertIn('rel=canonical href="%s/%s"' % (app.SITE_URL, g["slug"]), body)

    def test_robots(self):
        code, _, body = self.get("/robots.txt")
        self.assertEqual(code, 200)
        self.assertIn("Sitemap: %s/sitemap.xml" % app.SITE_URL, body)

    def test_sitemap(self):
        code, ctype, body = self.get("/sitemap.xml")
        self.assertEqual(code, 200)
        self.assertIn("xml", ctype)
        self.assertIn("<loc>%s/</loc>" % app.SITE_URL, body)
        for g in pages.GUIDES:
            self.assertIn("<loc>%s/%s</loc>" % (app.SITE_URL, g["slug"]), body)

    def test_llms_txt(self):
        code, _, body = self.get("/llms.txt")
        self.assertEqual(code, 200)
        self.assertIn("# MailPosture", body)
        for g in pages.GUIDES:
            self.assertIn("%s/%s" % (app.SITE_URL, g["slug"]), body)

    def test_icons(self):
        for path in ("/favicon.svg", "/social-card.svg"):
            code, ctype, _ = self.get(path)
            self.assertEqual(code, 200, path)
            self.assertIn("image/svg+xml", ctype)

    def test_indexnow_key_file(self):
        key = "869c7049df43e0112f5e6b2ad9b195c0"
        code, ctype, body = self.get("/" + key + ".txt")
        self.assertEqual(code, 200)
        self.assertIn("text/plain", ctype)
        self.assertEqual(body.strip(), key)

    def test_404(self):
        code, _, body = self.get("/does-not-exist")
        self.assertEqual(code, 404)
        self.assertIn("Not found", body)

    def test_invalid_domain(self):
        code, _, body = self.get("/check?domain=this%20is%20not%20a%20domain")
        self.assertEqual(code, 400)
        self.assertIn("does not look like a domain", body)

    def test_invalid_check_page_is_noindex(self):
        code, _, body = self.get("/check?domain=this%20is%20not%20a%20domain")
        self.assertEqual(code, 400)
        self.assertRegex(body, r"<meta name=robots content=['\"]noindex,follow['\"]>")

    def test_dynamic_check_result_is_noindex(self):
        result = {
            "domain": "example.com", "resolves": True, "findings": [],
            "spf": {"multiple": False, "published": False, "records": [],
                    "bad_terms": [], "qualifier": None, "record": None},
            "dmarc": {"published": False, "policy": None, "record": None},
            "dkim": {"found": [], "selectors_tried": 4},
            "mta_sts": {"published": False, "record": None},
            "mx": {"provider": None, "hosts": []},
            "queries": 9, "elapsed_ms": 12, "fetched_at": "2026-09-30T00:00:00Z",
            "resolvers_used": ["Cloudflare"], "dnssec_validated": True,
        }
        with patch("app.posture", return_value=result):
            code, _, body = self.get("/check?domain=example.com")
        self.assertEqual(code, 200)
        self.assertRegex(body, r"<meta name=robots content=['\"]noindex,follow['\"]>")

    # -- metadata ----------------------------------------------------------

    def test_canonical_and_social_on_every_page(self):
        paths = ["/"] + ["/" + g["slug"] for g in pages.GUIDES]
        for p in paths:
            _, _, body = self.get(p)
            self.assertIn("<title>", body, p)
            self.assertIn("rel=canonical", body, p)
            self.assertIn("og:title", body, p)
            self.assertIn("og:description", body, p)
            self.assertIn("og:image", body, p)
            self.assertIn("twitter:card", body, p)
            self.assertIn(app.SITE_URL, body, p)

    def test_titles_and_descriptions_are_unique(self):
        seen_t = set()
        seen_d = set()
        for p in ["/"] + ["/" + g["slug"] for g in pages.GUIDES]:
            _, _, body = self.get(p)
            title = re.search(r"<title>(.*?)</title>", body, re.DOTALL).group(1)
            desc = re.search(r'name=description content="(.*?)"', body).group(1)
            self.assertTrue(desc.strip(), p)
            self.assertNotIn(title, seen_t, p)
            self.assertNotIn(desc, seen_d, p)
            seen_t.add(title)
            seen_d.add(desc)

    def test_home_structured_data(self):
        _, _, body = self.get("/")
        types = {d.get("@type") for d in self.jsonld(body)}
        self.assertIn("Organization", types)
        self.assertIn("SoftwareApplication", types)
        self.assertIn("FAQPage", types)
        org = next(d for d in self.jsonld(body) if d.get("@type") == "Organization")
        self.assertEqual(org["url"], app.SITE_URL)

    def test_faq_schema_matches_visible_faq(self):
        _, _, body = self.get("/")
        faq = next(d for d in self.jsonld(body) if d.get("@type") == "FAQPage")
        self.assertEqual(len(faq["mainEntity"]), len(pages.FAQ))
        for q, _ in pages.FAQ:
            self.assertIn(q, body)  # visible on the page
        names = {m["name"] for m in faq["mainEntity"]}
        self.assertEqual(names, {q for q, _ in pages.FAQ})

    def test_guide_article_schema(self):
        for g in pages.GUIDES:
            _, _, body = self.get("/" + g["slug"])
            articles = [d for d in self.jsonld(body) if d.get("@type") == "Article"]
            self.assertEqual(len(articles), 1, g["slug"])
            self.assertEqual(articles[0]["url"], "%s/%s" % (app.SITE_URL, g["slug"]))

    # -- safety / preserved behaviour --------------------------------------

    def test_no_secrets_or_tracking_expansion(self):
        _, _, body = self.get("/")
        self.assertIn("data-website-id", body)          # preserved Umami
        self.assertIn("data-exclude-search", body)
        self.assertNotIn("googletagmanager", body)
        self.assertNotIn("facebook.net", body)

    def test_checker_still_anonymous(self):
        _, _, body = self.get("/")
        self.assertNotIn("sign up", body.lower())
        self.assertNotIn("newsletter", body.lower())


if __name__ == "__main__":
    unittest.main(verbosity=2)
