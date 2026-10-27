# Changelog

All notable changes to this project. Versions follow [semantic versioning](https://semver.org/).

## 1.0.0 — 2026-10-27

### Added
- `pyproject.toml` with a `phishguard` console command, and pinned `requirements.lock` /
  `requirements-dev.lock` (generated with `uv pip compile --universal`). scikit-learn is held at
  1.7, the version the shipped models were saved with.
- Container image: slim Python 3.12 base, `opencv-python-headless`, non-root user, health check on
  `/healthz`. No volume: the scanner keeps no state.
- CI on every push: ruff, bandit, pip-audit, pytest with a coverage report.
- Settings from `PHISHGUARD_*` environment variables, checked at startup.
  `PHISHGUARD_ENV=production` refuses to start without hashed API keys.
- Roles on API keys: `scanner` scans, `monitor` scrapes metrics, `admin` does both. Keys can be
  stored as `sha256:<hex>`; `python -m phishguard.ops keygen` makes new ones.
- Request body cap sized for one APK, security headers, JSON logs with request IDs, `/readyz`
  (both models loaded) and Prometheus `/metrics` with a `phishguard_decisions_total` counter.
- `SECURITY.md`, `docs/threat-model.md`, `docs/runbook.md`, `docs/model-card.md`.

### Changed
- The single `PHISHGUARD_API_KEY` is replaced by `PHISHGUARD_API_KEYS` / `PHISHGUARD_KEYS_FILE`
  (several keys, hashed, with roles). The extension's `X-API-Key` header keeps working.
- `PHISHGUARD_RATE` is now `PHISHGUARD_RATE_LIMIT`, and `PHISHGUARD_ORIGINS` is now
  `PHISHGUARD_CORS_ORIGINS`; browser-extension origins are still allowed. Rate-limited replies now
  carry `Retry-After`.
- `/healthz` is a bare liveness check; which models are loaded moved to `/readyz`.
- Validation errors no longer echo the submitted input, and a failed page fetch no longer returns
  the network error text.
- The web scanner page sends an API key when the service has keys.
- Without API keys the service refuses to listen on anything but loopback.
- `requirements.txt` uses `opencv-python-headless`.

### Unchanged
- Every rule, both models and the scoring logic. The real-data numbers in `results/real_data.json`
  and the README were not re-run (the datasets are not on this machine) and are unchanged.
