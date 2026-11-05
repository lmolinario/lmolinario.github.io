# Security hardening (staged; do not deploy without validation)

This branch is a security change to the FastAPI backend and its deployment files.
It is **not** deployed automatically through GitHub Pages.

## Implemented in this branch

- Asynchronous scan dispatch to Celery (avoids blocking FastAPI workers).
- Redis hourly quota on scan creation. Behind a reverse proxy, the host IP may be
  the proxy: use an authenticated gateway or trusted proxy configuration before
  scaling public use.
- Rejects DNS names resolving to local/private/reserved addresses.
- HTTPS scanner connects to vetted IP addresses rather than resolving again.
- Administrative funnel statistics now require `X-Admin-Key` and `ADMIN_API_KEY`.
- Docker dev services bind to loopback; database password must be set externally.
- Image uses a non-root application user; image build excludes local .env files.

## New authorization model (staged)

- Each new scan creates a 256-bit random opaque access token.
- Only its SHA-256 digest is stored in a separate `scan_access` database table;
  deployment creates the new table through SQLAlchemy `create_all`. Verify
  production database permissions and backups before enabling.
- Every scan-status, finding, report, paid-PDF and checkout/confirmation/cancel
  endpoint requires the matching `X-Scan-Token` header.
- Legacy scans without tokens cannot be read through these routes (including
  already purchased historical scans). **Plan a controlled owner-verification
  migration or customer support procedure before deployment.**
- Shared completed-scan cache is intentionally disabled to avoid cross-user
  access via reused numeric IDs.
- The static frontend uses browser `sessionStorage`; tokens are neither placed
  in URL parameters nor persisted in the server as plaintext. Closing a browser
  session can make an unlocked report irrecoverable without a future
  account-based recovery process.
- Stripe webhooks remain independently authenticated by signed Stripe payloads.
- Protected API responses have `Cache-Control: no-store`.

## Mandatory follow-up before production promotion

**No production deployment or end-to-end checkout test has occurred.** The
new authorization code and frontend must be deployed together and tested with
the actual T340 API, Redis, Celery, reverse proxy and Stripe. Confirm generated
reports, multi-tab behavior, payment returns, PDF exports and backup recovery.
Consider an account/login-based design for durable paid customer entitlements
rather than relying solely on browser-tab tokens.

Also verify: Celery worker is deployed and health-checked; NGINX/Tailscale
forwarding trust; proxy IP handling and quota limits; Stripe live/test mode
separation; secure Postgres/Redis credentials; payment webhooks; log redaction;
secrets provisioned to the running service; volume ownership for UID 10001;
API smoke tests and rollback on staging.

Run: `python -m pytest tests/test_host_validation.py -q` from the backend root.
No penetration test or real-world production verification is claimed here.
