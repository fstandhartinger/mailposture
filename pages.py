"""Editorial content for MailPosture: the home-page FAQ and the four guides.

Kept apart from app.py so the server code stays readable. Everything here is
static HTML fragments; the app wraps them in the shared layout. Claims in these
texts must stay true to what email_auth_dns.py actually checks - when the
checker is a lower bound or a probe list, the text says so.
"""

# ------------------------------------------------------------------ FAQ -----
# (question, answer-html). The same list feeds the visible FAQ and the
# FAQPage JSON-LD, so they can never drift apart.
FAQ = [
    ("Is MailPosture free?",
     "Yes. There is no sign-up, no price, no trial and no follow-up email. You type a "
     "domain and read the result."),
    ("Does it scan or touch my mail server?",
     "No. It only reads public DNS records over DNS-over-HTTPS, from Cloudflare and, as a "
     "fallback, Google. It never connects to your mail servers and never sends a message."),
    ("Do you store the domains I check?",
     "MailPosture has no database and does not record the domains you check. Like any "
     "website, the hosting infrastructure may keep standard server logs for operation "
     "and security."),
    ("Why does DKIM say “not found” when my mail is signed?",
     "A DKIM key lives at <code>&lt;selector&gt;._domainkey.&lt;domain&gt;</code>, and the "
     "selector cannot be listed from DNS. MailPosture probes eight common selectors (Microsoft "
     "365, Google Workspace, Mailchimp, SendGrid and generic ones). If yours uses another "
     "selector, the result is “not found here”, never “unsigned”. The "
     "<a href=\"/dkim-record-checker\">DKIM guide</a> shows how to find your selector."),
    ("Is an SPF record ending in ~all a failure?",
     "No. <code>~all</code> (softfail) asks receivers to accept but distrust unlisted senders. "
     "Many large domains, Google’s included, publish it. MailPosture shows it as a "
     "warning rather than a finding an insurer would flag. What matters more is that DMARC "
     "is enforcing."),
    ("How do I use this as evidence for a cyber-insurance questionnaire?",
     "Every result prints the records verbatim, the resolver that answered and the UTC time "
     "of the lookup, plus the <code>dig</code> command to re-run each query. Save or print "
     "the result page and anyone can verify what it showed."),
    ("Why might another checker show something different?",
     "DNS answers are cached, so a record you just changed can take until its TTL expires to "
     "show everywhere. Checkers also differ in depth: MailPosture counts the DNS-querying "
     "terms in your top-level SPF record, not in every nested include, so treat that number "
     "as a floor."),
]


# ------------------------------------------------------------- guides -------
# Each guide: slug, nav label, <title>, meta description, h1, lede, body html.
GUIDES = [
    {
        "slug": "spf-record-checker",
        "short": "SPF",
        "name": "SPF record checker",
        "title": "SPF Record Checker: validate your SPF TXT record | MailPosture",
        "desc": ("Free SPF record checker. See your domain's SPF record verbatim, whether it "
                 "ends in -all or ~all, syntax errors and duplicate records, and how to fix them."),
        "h1": "SPF record checker",
        "lede": ("Look up the SPF record a domain actually publishes, see whether it rejects "
                 "forgeries, and learn how to fix the mistakes that quietly break it."),
        "body": """
<h2 id="what">What an SPF record is</h2>
<p>SPF (Sender Policy Framework, RFC&nbsp;7208) is one TXT record, published at your domain,
that lists the servers allowed to send mail for it. When a receiving server accepts a message,
it looks up the SPF record of the domain in the <em>envelope sender</em> (the Return-Path, not
the From address people see) and checks whether the connecting IP address is on the list. The
answer is pass, fail, softfail, neutral, or an error.</p>
<p>SPF on its own does not protect the visible From address. That is DMARC&rsquo;s job: DMARC
only counts an SPF pass when the envelope domain matches the From domain. SPF is necessary,
but it is not enough on its own.</p>

<h2 id="syntax">What a working record looks like</h2>
<pre class="code"><code>v=spf1 include:_spf.google.com include:sendgrid.net ip4:203.0.113.10 -all</code></pre>
<ul>
<li><code>v=spf1</code> must come first, and there must be exactly one such record.</li>
<li><code>include:</code> pulls in the list a provider publishes for its own servers.</li>
<li><code>ip4:</code> and <code>ip6:</code> authorise addresses or ranges directly.</li>
<li><code>a</code> and <code>mx</code> authorise the hosts your A and MX records point to.</li>
<li>The final <code>all</code> decides what happens to everyone else: <code>-all</code> fails
them, <code>~all</code> softfails them, <code>?all</code> says nothing, and <code>+all</code>
lets anyone on the internet pass as you.</li>
</ul>
<p>A domain that never sends mail should still publish <code>v=spf1 -all</code>. Parked and
legacy domains are a favourite for spoofing because nobody watches them.</p>

<h2 id="all">-all or ~all?</h2>
<p><code>-all</code> is the strict choice: unlisted senders fail. <code>~all</code> asks
receivers to accept the message but treat it with suspicion, and many large senders publish
it, Google among them. In practice, once DMARC is at <code>p=quarantine</code> or
<code>p=reject</code>, DMARC decides what happens to forged mail and the difference between
the two shrinks. MailPosture therefore marks <code>~all</code> as a warning, not as a failure.
<code>+all</code> and <code>?all</code> are different: they authorise nothing useful and
should be replaced.</p>

<h2 id="mistakes">Common mistakes</h2>
<ul>
<li><strong>Two SPF records.</strong> Adding a second <code>v=spf1</code> record for a new
service instead of editing the existing one is the most common error. RFC&nbsp;7208 makes more
than one record a permanent error, so SPF fails for every message.</li>
<li><strong>More than 10 DNS lookups.</strong> <code>include</code>, <code>a</code>,
<code>mx</code>, <code>ptr</code>, <code>exists</code> and <code>redirect</code> each cost a
lookup, and so do the includes inside those includes. Above ten, SPF returns a permanent
error. MailPosture counts the terms in your top-level record, so treat its number as a floor:
four includes can still exceed ten once the providers&rsquo; own records are expanded.</li>
<li><strong>Forgotten senders.</strong> The CRM, the helpdesk, the invoicing tool and the
newsletter platform all send as your domain. Leave one out and tighten to <code>-all</code>,
and its mail starts failing.</li>
<li><strong>Typos and pasted characters.</strong> A space after the colon
(<code>include: _spf.google.com</code>), curly quotes copied from a document, or an impossible
range like <code>ip4:192.0.2.0/33</code>. Receivers cannot evaluate such a term, and the whole
record fails.</li>
<li><strong>Long records split badly.</strong> One TXT string holds at most 255 characters.
Longer records are published as several quoted strings that receivers join with no space.
Some DNS panels handle this for you; others insert a space or cut the record off.</li>
<li><strong>The <code>ptr</code> mechanism.</strong> RFC&nbsp;7208 advises against it: it is
slow, unreliable, and some receivers ignore it. Replace it with <code>ip4</code>/<code>ip6</code>
or an include.</li>
</ul>

<h2 id="fix">How to fix it</h2>
<ol>
<li>List every service that sends mail with your domain in the From or Return-Path, and look
up the include each provider documents.</li>
<li>Publish one record at the domain apex that combines them, e.g.
<code>v=spf1 include:spf.protection.outlook.com include:servers.mcsv.net ~all</code>.</li>
<li>Delete any second <code>v=spf1</code> record, including the one your DNS host may have
added by default.</li>
<li>Run the check above again after the TTL has passed, and read the record back to make sure
it arrived exactly as you typed it.</li>
<li>Watch DMARC aggregate reports for a couple of weeks before you switch <code>~all</code> to
<code>-all</code>.</li>
</ol>

<h2 id="insurance">What cyber-insurance questionnaires ask</h2>
<p>Cyber-insurance applications and renewal questionnaires commonly ask whether SPF, DKIM and
DMARC are configured for your email domains; the exact wording varies between carriers, and
some ask specifically whether DMARC is set to enforce. A yes is easier to stand behind when it
comes with evidence: the record text, the time it was read, and the resolver that answered.
MailPosture prints all three, plus the <code>dig</code> command to reproduce the lookup. Watch
the word <em>all</em> in such questions: it usually includes parked and secondary domains, which
should carry <code>v=spf1 -all</code> and a DMARC record of their own.</p>
""",
    },
    {
        "slug": "dmarc-record-checker",
        "short": "DMARC",
        "name": "DMARC record checker",
        "title": "DMARC Record Checker: is your DMARC policy enforcing? | MailPosture",
        "desc": ("Free DMARC checker. Read the _dmarc TXT record for any domain, see whether the "
                 "policy is p=none, quarantine or reject, and learn how to move to enforcement."),
        "h1": "DMARC record checker",
        "lede": ("See the DMARC policy a domain publishes, whether it actually acts on forged mail "
                 "or only reports on it, and how to get from p=none to p=reject safely."),
        "body": """
<h2 id="what">What a DMARC record is</h2>
<p>DMARC (Domain-based Message Authentication, Reporting and Conformance, RFC&nbsp;7489) ties SPF
and DKIM to the address people actually see: the From header. A message passes DMARC when it
passes SPF or DKIM <em>and</em> the domain that passed matches the From domain. This matching is
called alignment. The DMARC record then tells receivers what to do with mail that fails, and
where to send reports about it.</p>
<p>The record is a TXT record at <code>_dmarc.</code> in front of your domain, for example
<code>_dmarc.example.com</code>.</p>

<h2 id="syntax">Example syntax</h2>
<pre class="code"><code>v=DMARC1; p=reject; rua=mailto:dmarc-reports@example.com; adkim=r; aspf=r</code></pre>
<ul>
<li><code>v=DMARC1</code> must be the first tag.</li>
<li><code>p=</code> is the policy: <code>none</code> (monitor only), <code>quarantine</code>
(treat as spam) or <code>reject</code> (refuse the message).</li>
<li><code>rua=</code> is where daily aggregate reports go. Without it you are flying blind.</li>
<li><code>sp=</code> sets a separate policy for subdomains; without it they inherit
<code>p=</code>.</li>
<li><code>pct=</code> applies the policy to only a percentage of failing mail. It defaults to
100.</li>
<li><code>adkim=</code> and <code>aspf=</code> choose relaxed (<code>r</code>, the default) or
strict (<code>s</code>) alignment.</li>
</ul>

<h2 id="none">Why p=none is not protection</h2>
<p><code>p=none</code> publishes a policy and then asks receivers to do nothing about failures.
It is the right place to <em>start</em>, because the reports show you every service sending as
your domain. But a domain left at <code>p=none</code> can still be spoofed in the From header,
and that is why MailPosture shows it as a warning and counts it among the findings an insurer
would flag. Google and Yahoo have required bulk senders to publish at least <code>p=none</code>
since February 2024, which has left many domains with a DMARC record that does not enforce.</p>

<h2 id="mistakes">Common mistakes</h2>
<ul>
<li><strong>Staying at p=none forever.</strong> The monitoring phase was meant to last weeks,
not years.</li>
<li><strong>No rua address.</strong> Without reports you cannot tell a legitimate sender that is
failing from a forgery, so nobody dares to tighten the policy.</li>
<li><strong>Reports sent to another domain without authorisation.</strong> If
<code>rua</code> points to a different domain, that domain must publish a record such as
<code>example.com._report._dmarc.reports-vendor.net</code> agreeing to receive them. Hosted
DMARC services usually do this for you.</li>
<li><strong>pct below 100 left in place.</strong> <code>p=reject; pct=10</code> rejects only one
failing message in ten. It is a rollout step, not an end state.</li>
<li><strong>Two DMARC records.</strong> If more than one record is published at
<code>_dmarc</code>, receivers ignore DMARC for the domain altogether.</li>
<li><strong>Syntax slips.</strong> <code>v=DMARC1</code> not first, commas instead of semicolons
between tags, or <code>mailto:</code> missing from the report address.</li>
<li><strong>The wrong name.</strong> Publishing the record at the apex instead of at
<code>_dmarc.example.com</code>.</li>
</ul>

<h2 id="fix">How to move to enforcement</h2>
<ol>
<li>Publish <code>v=DMARC1; p=none; rua=mailto:&hellip;</code> and collect reports for two to
four weeks.</li>
<li>For every legitimate source in the reports, make sure SPF or DKIM passes <em>and aligns</em>
with your From domain. Usually this means enabling DKIM signing with your own domain in each
sending tool.</li>
<li>Move to <code>p=quarantine</code>. If you are nervous, step through <code>pct=25</code>,
<code>50</code> and <code>100</code>.</li>
<li>When the reports stay clean, move to <code>p=reject</code>.</li>
<li>Give parked domains <code>v=DMARC1; p=reject;</code> straight away, since they send
nothing.</li>
</ol>

<h2 id="insurance">What cyber-insurance questionnaires ask</h2>
<p>DMARC is the email control that cyber-insurance questionnaires ask about most often,
typically as &ldquo;Is DMARC implemented?&rdquo; and sometimes as &ldquo;Is DMARC set to
quarantine or reject?&rdquo;. Wording differs by carrier, so read the question closely: a
<code>p=none</code> record answers the first question with a yes and the second with a no.
MailPosture separates the two. It shows the policy verbatim, flags <code>p=none</code> and
<code>pct</code> below 100, and prints the resolver and UTC time so the answer you give can be
checked by anyone.</p>
""",
    },
    {
        "slug": "dkim-record-checker",
        "short": "DKIM",
        "name": "DKIM record checker",
        "title": "DKIM Record Checker: find your DKIM selector and key | MailPosture",
        "desc": ("Free DKIM checker. Probe common selectors for Microsoft 365, Google Workspace "
                 "and more, read the public key record, and learn how to find your own selector."),
        "h1": "DKIM record checker",
        "lede": ("Find a domain's DKIM public key at the selectors the big mail providers use, and "
                 "learn why &ldquo;not found&rdquo; is not the same as &ldquo;not signed&rdquo;."),
        "body": """
<h2 id="what">What DKIM is</h2>
<p>DKIM (DomainKeys Identified Mail, RFC&nbsp;6376) lets a sending server sign each message
with a private key. The signature travels in a <code>DKIM-Signature</code> header, and the
matching public key is published in DNS so any receiver can verify that the message was not
altered and really came from a server holding the key. Unlike SPF, a DKIM signature survives
forwarding, which makes it the more dependable half of DMARC.</p>
<p>The public key lives at <code>&lt;selector&gt;._domainkey.&lt;domain&gt;</code>. The selector
is a label the sender chooses, and it appears in the signature as the <code>s=</code> tag.</p>

<h2 id="syntax">Example record</h2>
<pre class="code"><code>selector1._domainkey.example.com  TXT
"v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA..."</code></pre>
<ul>
<li><code>v=DKIM1</code> identifies the record; it is recommended, though optional.</li>
<li><code>k=</code> is the key type, <code>rsa</code> by default; <code>ed25519</code> also
exists.</li>
<li><code>p=</code> is the base64 public key. An empty <code>p=</code> means the key has been
revoked.</li>
</ul>
<p>Microsoft 365 publishes the key through CNAME records (<code>selector1</code> and
<code>selector2</code> pointing into your <code>onmicrosoft.com</code> tenant); Google Workspace
uses the selector <code>google</code> by default.</p>

<h2 id="selector">Why a checker cannot always find your key</h2>
<p>DNS has no way to list every name under <code>_domainkey</code>, so no outside tool can
enumerate your selectors. MailPosture probes eight common ones: <code>selector1</code> and
<code>selector2</code> (Microsoft 365), <code>google</code> (Google Workspace), <code>k1</code>
(Mailchimp and Mandrill), <code>s1</code>, <code>default</code>, <code>dkim</code> and
<code>mail</code>. A miss means &ldquo;no key at these selectors&rdquo;, never &ldquo;this domain
does not sign&rdquo;. That is why DKIM is shown as information rather than a failure.</p>
<p>To find your real selector, open a message you sent in any mail client, view the original
headers, and find <code>DKIM-Signature</code>. The <code>d=</code> tag is the signing domain
and <code>s=</code> is the selector. Then run
<code>dig +short TXT &lt;s&gt;._domainkey.&lt;d&gt;</code>.</p>

<h2 id="mistakes">Common mistakes</h2>
<ul>
<li><strong>Key published, signing never switched on.</strong> Google Workspace needs
&ldquo;Start authentication&rdquo; in the admin console after the record is added, and Microsoft
365 needs DKIM enabled per domain in the Defender portal.</li>
<li><strong>Signing with the provider&rsquo;s domain.</strong> Many newsletter and CRM tools
sign with their own domain by default. The signature passes, but it does not align with your
From address, so it does not help DMARC. Set up the custom sending domain they offer.</li>
<li><strong>Keys that are too short.</strong> 1024-bit RSA keys are still common. Use 2048-bit
where the provider supports it.</li>
<li><strong>Broken copy and paste.</strong> Line breaks, stray quotes, or a key truncated by a DNS
panel that cannot store long TXT values. The record must be split into 255-character strings,
not cut.</li>
<li><strong>Keys never rotated.</strong> A key that has been in DNS since the domain was set up
has had years to leak. Rotate on a schedule, which is exactly what two selectors are for.</li>
<li><strong>Old keys left behind.</strong> When you leave a provider, remove its selector or
publish it with an empty <code>p=</code>.</li>
</ul>

<h2 id="fix">How to fix it</h2>
<ol>
<li>For each service that sends as your domain, find its DKIM setup page and generate a key for
your own domain.</li>
<li>Publish the TXT or CNAME records exactly as given, at the selector names given.</li>
<li>Switch signing on in the provider&rsquo;s console.</li>
<li>Send a test message and confirm the header shows <code>dkim=pass</code> with
<code>header.d=</code> equal to your domain.</li>
<li>Check here again. If your selector is not one of the eight probed, verify with
<code>dig</code> as shown above.</li>
</ol>

<h2 id="insurance">What cyber-insurance questionnaires ask</h2>
<p>DKIM usually appears alongside SPF and DMARC in the same question: &ldquo;Do you have SPF,
DKIM and DMARC configured?&rdquo;, with wording that varies by carrier. Because DKIM cannot be
proven absent from outside, the best evidence is a selector and its key record: MailPosture shows
the selector it found and the record text, with the resolver and UTC time of the lookup. If it
found none, attach a message header showing <code>dkim=pass</code> for your domain.</p>
""",
    },
    {
        "slug": "mta-sts-checker",
        "short": "MTA-STS",
        "name": "MTA-STS checker",
        "title": "MTA-STS Checker: check your _mta-sts record | MailPosture",
        "desc": ("Free MTA-STS checker. See whether a domain publishes the _mta-sts TXT record, what "
                 "the policy file must contain, and how to roll out TLS enforcement for inbound mail."),
        "h1": "MTA-STS checker",
        "lede": ("Check whether a domain asks senders to deliver its mail only over verified TLS, "
                 "and see what a complete MTA-STS setup needs beyond the DNS record."),
        "body": """
<h2 id="what">What MTA-STS is</h2>
<p>Mail between servers is encrypted with STARTTLS, but by default that encryption is
opportunistic: if an attacker in the network path strips the STARTTLS offer, or answers with a
fake certificate, most sending servers quietly fall back to plain text. MTA-STS (SMTP MTA Strict
Transport Security, RFC&nbsp;8461) lets a domain publish a policy that says: deliver mail to me
only over TLS, only to these MX hosts, and only with a valid certificate.</p>
<p>It protects mail <em>coming in</em> to your domain. Senders that support it, including Gmail
and Microsoft 365, fetch and cache your policy and refuse to deliver insecurely while the policy
is in enforce mode.</p>

<h2 id="syntax">The two parts of MTA-STS</h2>
<p>First, a TXT record at <code>_mta-sts.</code> in front of your domain announces that a policy
exists:</p>
<pre class="code"><code>_mta-sts.example.com  TXT  "v=STSv1; id=20260926T090000"</code></pre>
<p>The <code>id</code> is any string of up to 32 letters and digits; change it whenever the
policy changes so senders fetch the new version. Second, the policy itself is a plain-text file
served over HTTPS at a fixed address:</p>
<pre class="code"><code>https://mta-sts.example.com/.well-known/mta-sts.txt

version: STSv1
mode: enforce
mx: mail.example.com
mx: *.mail.protection.outlook.com
max_age: 604800</code></pre>
<ul>
<li><code>mode</code> is <code>testing</code> (report problems but deliver anyway),
<code>enforce</code>, or <code>none</code> (withdraw the policy).</li>
<li>Each <code>mx</code> line must match your real MX hosts; a leading <code>*.</code> matches
one label.</li>
<li><code>max_age</code> is how long senders cache the policy, in seconds. One week or more is
typical once you are confident.</li>
</ul>
<p>A companion TXT record, TLS-RPT (RFC&nbsp;8460) at <code>_smtp._tls.example.com</code> with
<code>v=TLSRPTv1; rua=mailto:&hellip;</code>, asks senders to report TLS failures to you daily.
Set it up at the same time; it is what makes testing mode useful.</p>

<h2 id="scope">What this checker looks at</h2>
<p>MailPosture reads the <code>_mta-sts</code> TXT record and prints it verbatim. It does not
fetch the policy file or test your MX certificates, so a &ldquo;published&rdquo; result means the
announcement exists, not that the whole setup works. MTA-STS is optional and many small domains
do not publish it, so its absence is shown as information, not as a failure.</p>

<h2 id="mistakes">Common mistakes</h2>
<ul>
<li><strong>TXT record without a policy file.</strong> The record promises a policy that returns
a 404, so senders ignore it and you get no protection.</li>
<li><strong>An invalid certificate on the mta-sts host.</strong> The policy host needs its own
valid HTTPS certificate for <code>mta-sts.yourdomain</code>.</li>
<li><strong>mx lines that do not match.</strong> After an email migration the MX changes but the
policy still lists the old host. In enforce mode, senders then refuse to deliver.</li>
<li><strong>Forgetting to change the id.</strong> Senders keep the cached policy until
<code>max_age</code> runs out.</li>
<li><strong>Starting in enforce mode.</strong> Run in <code>testing</code> with TLS-RPT for a few
weeks first.</li>
<li><strong>A tiny max_age in production.</strong> A policy cached for minutes gives an attacker a
window after every expiry.</li>
</ul>

<h2 id="fix">How to set it up</h2>
<ol>
<li>Publish TLS-RPT at <code>_smtp._tls</code> so you receive reports.</li>
<li>Host the policy file at <code>https://mta-sts.yourdomain/.well-known/mta-sts.txt</code> with
<code>mode: testing</code> and your current MX hosts.</li>
<li>Publish the <code>_mta-sts</code> TXT record with a fresh <code>id</code>.</li>
<li>Read the TLS reports for two to four weeks and fix any MX host that fails.</li>
<li>Switch to <code>mode: enforce</code>, raise <code>max_age</code>, and change the
<code>id</code>.</li>
</ol>

<h2 id="insurance">What cyber-insurance questionnaires ask</h2>
<p>MTA-STS is asked about far less often than SPF, DKIM and DMARC. Where it does come up, it is
usually as part of a broader question about encrypting email in transit or enforcing TLS. If a
questionnaire asks, answer precisely: a published <code>_mta-sts</code> record plus a policy in
<code>enforce</code> mode is enforcement; <code>testing</code> mode is monitoring. MailPosture
shows the record as it was read, with the resolver and UTC time, so the claim can be checked.</p>
""",
    },
]

GUIDE_BY_SLUG = {g["slug"]: g for g in GUIDES}
