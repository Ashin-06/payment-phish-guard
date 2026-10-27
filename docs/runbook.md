# Runbook

How to deploy, configure and operate the scanner. Commands assume the repository root.

## Deploy

```bash
docker build -t payment-phish-guard:1.0.0 .
python -m phishguard.ops keygen          # one API key per client
docker run -d --name phishguard -p 8006:8006 \
  -e PHISHGUARD_KEYS_FILE=/run/secrets/phishguard-keys.json \
  payment-phish-guard:1.0.0
curl -fsS http://127.0.0.1:8006/readyz
```

The image runs in production mode as a non-root user. It keeps no state, so it needs no volume
and no database, and replicas can be added or removed freely. It refuses to start, and logs why,
when no hashed API keys are configured. Terminate TLS in front of it.

Server-side page fetching stays off unless you set `PHISHGUARD_FETCH=1`. If you turn it on, run
the container on a network with no route to internal services; the fetcher refuses non-public
addresses, but network isolation is the backstop.

Point the browser extension at the service on its Options page (API address and key), and add the
address to `host_permissions` in `extension/manifest.json` before packaging it.

Without Docker: `pip install -r requirements.lock && pip install -e .`, then `phishguard serve`.

## Configure

| Variable | Required in production | Meaning |
|---|---|---|
| `PHISHGUARD_ENV` | — | `development` (default) or `production` |
| `PHISHGUARD_API_KEYS` / `PHISHGUARD_KEYS_FILE` | yes | JSON `{"sha256:<hex>": {"user": "...", "role": "..."}}`. Roles: `scanner` (all `/v1/scan*`), `monitor` (`/metrics`), `admin` |
| `PHISHGUARD_HOST`, `PHISHGUARD_PORT` | — | default `127.0.0.1:8006`; any non-loopback address needs API keys |
| `PHISHGUARD_RATE_LIMIT` | — | requests per minute per client (default 120) |
| `PHISHGUARD_MAX_BODY_BYTES` | — | default 160,000,000 (one APK); per-file caps are 150 MB (APK) and 10 MB (image) |
| `PHISHGUARD_CORS_ORIGINS` | — | comma-separated web origins allowed to call from a browser; extension origins are always allowed |
| `PHISHGUARD_FETCH` | — | `1` lets `/v1/scan/page` fetch the page when no HTML is sent |
| `PHISHGUARD_LOG_LEVEL` | — | default `INFO` |
| `FORWARDED_ALLOW_IPS` | — | addresses of proxies whose `X-Forwarded-For` is trusted (uvicorn) |

The old `PHISHGUARD_API_KEY`, `PHISHGUARD_RATE` and `PHISHGUARD_ORIGINS` are replaced by the
variables above.

## Watch

- `GET /healthz`: the process is up (used by the container health check).
- `GET /readyz`: both models loaded; 503 otherwise.
- `GET /metrics` (role `monitor`): `http_requests_total`, `http_request_duration_seconds`,
  `errors_total`, `phishguard_decisions_total{decision="safe|suspicious|dangerous"}`.
- Logs are one JSON object per line on stdout, each with a `request_id` that is also returned in
  the `X-Request-ID` response header. Submitted content is never logged.

Suggested alerts: `/readyz` failing for 2 minutes; `errors_total{kind="unhandled"}` increasing
(a parser choking on a crafted file); 5xx share above 1% for 10 minutes; p95 latency of
`/v1/scan/apk` above your SLO; the `dangerous` share moving sharply (a campaign, or stale brand
data after a bank changes its domains).

## Rotate keys

Add the new hash to the key file, restart, give the client the new key, then remove the old hash
and restart again. Extension keys reach every installed browser: rotate them on a schedule.

## Update models and reference data

Brand domains, packages and UPI handles live in `phishguard/brands.py`; official signing
certificates in `phishguard/official_certs.json`. Models are retrained with
`python -m phishguard train` / `realdata --update-models` (see the README). Any of these changes
needs a new image: rebuild, run the tests, and compare the real-data numbers before rolling out.
Keep scikit-learn at the version the models were saved with (1.7, pinned in `pyproject.toml`).

## Back up and restore

Nothing to back up: the service has no state. Keep the image, the key file and any retrained
model files.

## Incidents

1. **A scam was rated safe and a customer lost money.** Reproduce it with
   `python -m phishguard check` (or `page` / `apk`), add the case to the tests, add a rule or
   retrain, and roll out. Check whether the brand data was stale.
2. **A genuine bank page or message was flagged.** Same steps; usually a missing official domain,
   package or handle in `brands.py`.
3. **Leaked API key.** Remove its hash from the key file and restart. Issue a new key.
4. **Worker crashes or hangs on an upload.** The request returns 500 with a request ID; find it in
   the logs, get the file from the reporter, add it as a test fixture and fix the parser.
5. **SSRF suspicion with fetching on.** Turn `PHISHGUARD_FETCH` off, check egress logs for
   internal destinations, and review the fetcher before turning it back on.
