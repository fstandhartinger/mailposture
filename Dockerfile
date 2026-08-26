# Public, dependency-free email-authentication posture checker.
# Stdlib-only Python; curl is installed solely so Coolify's container
# health-check has a client (slim images ship without one).
FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY email_auth_dns.py app.py ./

ENV PORT=8080
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8080/healthz || exit 1

CMD ["python", "app.py"]
