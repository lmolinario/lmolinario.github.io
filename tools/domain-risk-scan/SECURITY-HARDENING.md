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

## Mandatory follow-up before production promotion

**Access control is not solved by these changes.** The existing numeric scan IDs
allow retrieval of scan statuses, findings and purchased report artifacts without
proof of ownership. Implement authenticated accounts or opaque per-scan access
credentials with server-side authorization for **all** scan/report/PDF/billing
routes, and ensure cached scans are never made readable cross-user. Update the
public frontend in the same release. Do not claim paid report privacy until this
is addressed.

Also verify: Celery worker is deployed and health-checked; NGINX/Tailscale
forwarding trust; proxy IP handling and quota limits; Stripe live/test mode
separation; secure Postgres/Redis credentials; payment webhooks; log redaction;
secrets provisioned to the running service; volume ownership for UID 10001;
API smoke tests and rollback on staging.

Run: `python -m pytest tests/test_host_validation.py -q` from the backend root.
No penetration test or real-world production verification is claimed here.
