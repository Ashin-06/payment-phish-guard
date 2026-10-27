"""Settings, auth, limits, headers, CORS, metrics and health."""
import hashlib
import importlib
import json
import os
import subprocess
import sys

import pytest
from fastapi.testclient import TestClient

from phishguard import ops

KEY = "phishguard_" + "x" * 40
HASHED = {f"sha256:{hashlib.sha256(KEY.encode()).hexdigest()}": {"user": "extension", "role": "scanner"}}


def prod_env(**over):
    env = {"PHISHGUARD_ENV": "production", "PHISHGUARD_API_KEYS": json.dumps(HASHED)}
    env.update(over)
    return {k: v for k, v in env.items() if v is not None}


def boot(monkeypatch, **env):
    for k in [k for k in os.environ if k.startswith("PHISHGUARD_")]:
        monkeypatch.delenv(k)
    for k, v in env.items():
        monkeypatch.setenv(f"PHISHGUARD_{k}", v)
    import phishguard.api as api

    return importlib.reload(api)


def test_production_settings_accepted():
    s = ops.load_settings(prod_env())
    assert s.production and not s.demo and not s.ephemeral


@pytest.mark.parametrize("change, message", [
    ({"PHISHGUARD_API_KEYS": None}, "API keys"),
    ({"PHISHGUARD_API_KEYS": json.dumps({KEY: {"user": "extension", "role": "scanner"}})}, "sha256"),
    ({"PHISHGUARD_API_KEYS": json.dumps({"sha256:" + "0" * 64: {"user": "x", "role": "root"}})}, "roles"),
    ({"PHISHGUARD_API_KEYS": "not json"}, "JSON"),
    ({"PHISHGUARD_CORS_ORIGINS": "*"}, "CORS"),
    ({"PHISHGUARD_ENV": "prod"}, "development or production"),
    ({"PHISHGUARD_RATE_LIMIT": "fast"}, "integers"),
])
def test_production_refuses_to_start(change, message):
    with pytest.raises(ops.ConfigError, match=message):
        ops.load_settings(prod_env(**change))


def test_no_public_bind_without_keys():
    with pytest.raises(ops.ConfigError, match="without API keys"):
        ops.load_settings({"PHISHGUARD_HOST": "0.0.0.0"})
    assert ops.load_settings({"PHISHGUARD_HOST": "0.0.0.0", "PHISHGUARD_API_KEYS": json.dumps(HASHED)}).host == "0.0.0.0"
    assert ops.load_settings({}).demo


def test_serve_exits_with_a_readable_error():
    env = {k: v for k, v in os.environ.items() if not k.startswith("PHISHGUARD_")}
    r = subprocess.run([sys.executable, "-m", "phishguard", "serve", "--host", "0.0.0.0"], env=env,
                       capture_output=True, text=True, timeout=60)
    assert r.returncode != 0 and "without API keys" in r.stderr


def test_roles_decide_what_a_key_may_do(monkeypatch):
    keys = {"k-scan": {"user": "extension", "role": "scanner"}, "k-mon": {"user": "prom", "role": "monitor"}}
    c = TestClient(boot(monkeypatch, API_KEYS=json.dumps(keys)).app)
    body = {"input": "sbi-kyc-update.xyz/login"}
    assert c.post("/v1/scan", json=body).status_code == 401
    assert c.post("/v1/scan", json=body, headers={"x-api-key": "wrong"}).status_code == 401
    assert c.post("/v1/scan", json=body, headers={"X-API-Key": "k-scan"}).status_code == 200  # the extension's header
    assert c.post("/v1/scan", json=body, headers={"authorization": "Bearer k-mon"}).status_code == 403
    assert c.get("/metrics", headers={"x-api-key": "k-scan"}).status_code == 403
    m = c.get("/metrics", headers={"x-api-key": "k-mon"})
    assert m.status_code == 200 and 'http_requests_total{method="POST",route="/v1/scan",status="200"}' in m.text
    assert "phishguard_decisions_total" in m.text and "http_request_duration_seconds_bucket" in m.text
    assert c.get("/").status_code == 200  # the scanner page itself is static


def test_rate_limit(monkeypatch):
    c = TestClient(boot(monkeypatch, RATE_LIMIT="3").app)
    codes = [c.post("/v1/scan/upi", json={"input": "x@ybl"}).status_code for _ in range(5)]
    assert codes[:3] == [200] * 3 and codes[3:] == [429, 429]
    assert int(c.post("/v1/scan/upi", json={"input": "x@ybl"}).headers["retry-after"]) >= 1
    assert c.get("/healthz").status_code == 200  # probes are never limited


def test_body_size_cap(monkeypatch):
    c = TestClient(boot(monkeypatch, MAX_BODY_BYTES="1000").app)
    assert c.post("/v1/scan/qr", files={"image": ("q.png", b"a" * 2000, "image/png")}).status_code == 413

    def chunks():  # no content-length: the cap still holds
        for _ in range(20):
            yield b"a" * 100

    assert c.post("/v1/scan", content=chunks(), headers={"content-type": "application/json"}).status_code == 413
    assert c.post("/v1/scan", json={"input": "hello"}).status_code == 200


def test_headers_and_request_ids(monkeypatch):
    c = TestClient(boot(monkeypatch).app)
    r = c.post("/v1/scan", json={"input": "hello"}, headers={"x-request-id": "abc-123"})
    assert r.headers["x-request-id"] == "abc-123"
    assert r.headers["x-content-type-options"] == "nosniff" and r.headers["x-frame-options"] == "DENY"
    assert r.headers["content-security-policy"] == ops.API_CSP and r.headers["cache-control"] == "no-store"
    assert "unsafe-inline" in c.get("/").headers["content-security-policy"]
    assert len(c.get("/healthz", headers={"x-request-id": "bad id\n"}).headers["x-request-id"]) == 32


def test_cors_for_extensions_and_listed_origins_only(monkeypatch):
    c = TestClient(boot(monkeypatch, CORS_ORIGINS="https://scan.bank.example").app)
    for origin in ("https://scan.bank.example", "chrome-extension://abcdefghijklmnop", "moz-extension://1b2c-3d4e"):
        assert c.get("/healthz", headers={"origin": origin}).headers["access-control-allow-origin"] == origin
    for origin in ("https://evil.example", "chrome-extension://x.evil.example"):
        assert "access-control-allow-origin" not in c.get("/healthz", headers={"origin": origin}).headers


def test_errors_do_not_leak(monkeypatch):
    api = boot(monkeypatch, FETCH="1")

    @api.app.get("/boom")
    def boom():
        raise RuntimeError("secret detail: vpa victim@okaxis")

    c = TestClient(api.app)
    r = c.get("/boom")
    assert r.status_code == 500 and "victim" not in r.text and r.json()["request_id"] == r.headers["x-request-id"]
    bad = c.post("/v1/scan", json={"input": ["victim@okaxis"]})
    assert bad.status_code == 422 and "victim" not in bad.text

    def down(url):
        raise OSError("connect to 10.1.2.3:443 refused")

    monkeypatch.setattr(api, "fetch", down)
    r = c.post("/v1/scan/page", json={"url": "https://example.com/login"})
    assert r.status_code == 502 and "10.1.2.3" not in r.text


def test_health_and_readiness(monkeypatch):
    api = boot(monkeypatch)
    c = TestClient(api.app)
    assert c.get("/healthz").json() == {"status": "ok"}
    r = c.get("/readyz")
    assert r.status_code == 200 and r.json()["checks"] == {"models": True}
    import phishguard.message as message

    monkeypatch.setattr(message, "_model", lambda: None)  # the text model failed to load
    r = c.get("/readyz")
    assert r.status_code == 503 and r.json()["checks"]["models"] is False


def test_json_logs_carry_request_ids(capsys):
    ops.setup_logging("INFO")
    token = ops.request_id.set("rid-1")
    ops.log.info("hello", extra={"fields": {"n": 1}})
    ops.request_id.reset(token)
    line = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert line["msg"] == "hello" and line["request_id"] == "rid-1" and line["n"] == 1 and line["level"] == "INFO"
