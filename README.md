# mailposture

A free, self-serve **email-authentication posture check**. Enter a domain; it reads
what that domain's **public DNS** says about **SPF, DMARC, DKIM and MTA-STS** — the
records a cyber-insurance questionnaire asks an organisation to attest to.

- Reads **public DNS only**, over DNS-over-HTTPS (Cloudflare + Google). It runs no
  scan against anyone's servers, installs nothing, and stores nothing.
- Every result shows the **resolver that answered** and the **UTC instant** of the
  query, and prints records verbatim so you can re-run any lookup yourself.
- Stdlib-only Python, no framework, no database.

Built by Florian Standhartinger while developing a monthly security-and-compliance
report for small MSPs. Offered free and unconditionally.

## Run locally
    python3 app.py            # serves on :8080
    PORT=9000 python3 app.py

## Deploy
Container listens on `$PORT` (default 8080); health endpoint at `/healthz`.
