"""HTTP API used by the web scanner and the browser extension.

    uvicorn phishguard.api:app --port 8006

Environment:
    PHISHGUARD_API_KEY      require this value in the X-API-Key header (unset = open, for local use)
    PHISHGUARD_FETCH=1      allow /v1/scan/page to fetch pages server-side when no HTML is sent
    PHISHGUARD_RATE         requests per minute per client (default 120)
    PHISHGUARD_ORIGINS      extra allowed CORS origins, comma separated
"""
from __future__ import annotations

import os
import threading
import time
from pathlib import Path

from fastapi import Depends, FastAPI, File, Header, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from .apk import analyze_apk
from .engine import analyze_qr, analyze_text
from .message import analyze_message
from .page import UnsafeURL, analyze_page, fetch
from .upi import analyze_upi
from .url import analyze_url

ROOT = Path(__file__).resolve().parent.parent
API_KEY = os.environ.get("PHISHGUARD_API_KEY")
RATE = int(os.environ.get("PHISHGUARD_RATE", "120"))
MAX_APK = 150 * 1024 * 1024
MAX_IMAGE = 10 * 1024 * 1024

app = FastAPI(title="Payment Phish Guard", version="1.0")


def _warm() -> None:
    """Load both models at startup so the first request is not slow."""
    from .message import _model as text_model
    from .url import _model as url_model

    url_model(), text_model()


_warm()
app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"^(chrome-extension|moz-extension)://.*$",
    allow_origins=[o for o in os.environ.get("PHISHGUARD_ORIGINS", "").split(",") if o],
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "X-API-Key"],
)

_buckets: dict[str, tuple[float, float]] = {}
_lock = threading.Lock()


def guard(request: Request, x_api_key: str | None = Header(default=None)):
    if API_KEY and x_api_key != API_KEY:
        raise HTTPException(401, "missing or wrong X-API-Key")
    ip = request.client.host if request.client else "?"
    now = time.monotonic()
    with _lock:
        tokens, last = _buckets.get(ip, (RATE, now))
        tokens = min(RATE, tokens + (now - last) * RATE / 60)
        if tokens < 1:
            raise HTTPException(429, "rate limit exceeded")
        _buckets[ip] = (tokens - 1, now)


class TextIn(BaseModel):
    input: str = Field(..., min_length=1, max_length=20_000)


class PageIn(BaseModel):
    url: str = Field(..., min_length=4, max_length=4096)
    html: str | None = Field(default=None, max_length=3_000_000)


@app.get("/")
def index():
    return FileResponse(ROOT / "web" / "index.html")


@app.get("/healthz")
def health():
    from .message import _model as text_model
    from .url import _model as url_model

    return {"ok": True, "url_model": url_model() is not None, "text_model": text_model() is not None}


@app.post("/v1/scan", dependencies=[Depends(guard)])
def scan_any(body: TextIn):
    return analyze_text(body.input).as_dict()


@app.post("/v1/scan/url", dependencies=[Depends(guard)])
def scan_url(body: TextIn):
    return analyze_url(body.input).as_dict()


@app.post("/v1/scan/upi", dependencies=[Depends(guard)])
def scan_upi(body: TextIn):
    return analyze_upi(body.input).as_dict()


@app.post("/v1/scan/message", dependencies=[Depends(guard)])
def scan_message(body: TextIn):
    return analyze_message(body.input).as_dict()


@app.post("/v1/scan/page", dependencies=[Depends(guard)])
def scan_page(body: PageIn):
    url, html = body.url, body.html
    if html is None:
        if os.environ.get("PHISHGUARD_FETCH") != "1":
            raise HTTPException(400, "send the page HTML, or enable server-side fetching with PHISHGUARD_FETCH=1")
        try:
            url, html = fetch(url)
        except UnsafeURL as e:
            raise HTTPException(400, str(e)) from e
        except Exception as e:  # network errors of every kind
            raise HTTPException(502, f"could not fetch page: {e}") from e
    return analyze_page(html, url).as_dict()


async def _read(f: UploadFile, limit: int) -> bytes:
    data = await f.read(limit + 1)
    if len(data) > limit:
        raise HTTPException(413, "file too large")
    return data


@app.post("/v1/scan/qr", dependencies=[Depends(guard)])
async def scan_qr(image: UploadFile = File(...)):
    try:
        return analyze_qr(await _read(image, MAX_IMAGE)).as_dict()
    except ValueError as e:
        raise HTTPException(422, str(e)) from e


@app.post("/v1/scan/apk", dependencies=[Depends(guard)])
async def scan_apk(apk: UploadFile = File(...)):
    return analyze_apk(await _read(apk, MAX_APK), apk.filename or "app.apk").as_dict()
