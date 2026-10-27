"""HTTP API used by the web scanner and the browser extension.

    python -m phishguard serve            # settings: PHISHGUARD_* environment variables

PHISHGUARD_FETCH=1 lets /v1/scan/page fetch pages server-side when no HTML is sent.
"""
from __future__ import annotations

import logging
import os
from pathlib import Path

from fastapi import Depends, FastAPI, File, HTTPException, UploadFile
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from . import ops
from .apk import analyze_apk
from .engine import analyze_qr, analyze_text
from .message import analyze_message
from .page import UnsafeURL, analyze_page, fetch
from .upi import analyze_upi
from .url import analyze_url

ROOT = Path(__file__).resolve().parent.parent
MAX_APK = 150 * 1024 * 1024
MAX_IMAGE = 10 * 1024 * 1024
log = logging.getLogger("phishguard.api")

settings = ops.load_settings()
ops.setup_logging(settings.log_level)
app = FastAPI(title="Payment Phish Guard", version="1.0.0")


def _warm() -> None:
    """Load both models at startup so the first request is not slow."""
    from .message import _model as text_model
    from .url import _model as url_model

    url_model(), text_model()


_warm()


def _models_loaded() -> bool:
    from .message import _model as text_model
    from .url import _model as url_model

    return url_model() is not None and text_model() is not None


ops.install(app, settings, {"models": _models_loaded})
guard = ops.require("scan")


def _verdict(v) -> dict:
    ops.DECISIONS.labels(decision=v.level).inc()
    return v.as_dict()


class TextIn(BaseModel):
    input: str = Field(..., min_length=1, max_length=20_000)


class PageIn(BaseModel):
    url: str = Field(..., min_length=4, max_length=4096)
    html: str | None = Field(default=None, max_length=3_000_000)


@app.get("/")
def index():
    return FileResponse(ROOT / "web" / "index.html")


@app.post("/v1/scan", dependencies=[Depends(guard)])
def scan_any(body: TextIn):
    return _verdict(analyze_text(body.input))


@app.post("/v1/scan/url", dependencies=[Depends(guard)])
def scan_url(body: TextIn):
    return _verdict(analyze_url(body.input))


@app.post("/v1/scan/upi", dependencies=[Depends(guard)])
def scan_upi(body: TextIn):
    return _verdict(analyze_upi(body.input))


@app.post("/v1/scan/message", dependencies=[Depends(guard)])
def scan_message(body: TextIn):
    return _verdict(analyze_message(body.input))


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
            log.warning("page fetch failed", exc_info=True)
            raise HTTPException(502, "could not fetch page") from e
    return _verdict(analyze_page(html, url))


async def _read(f: UploadFile, limit: int) -> bytes:
    data = await f.read(limit + 1)
    if len(data) > limit:
        raise HTTPException(413, "file too large")
    return data


@app.post("/v1/scan/qr", dependencies=[Depends(guard)])
async def scan_qr(image: UploadFile = File(...)):
    try:
        return _verdict(analyze_qr(await _read(image, MAX_IMAGE)))
    except ValueError as e:
        raise HTTPException(422, str(e)) from e


@app.post("/v1/scan/apk", dependencies=[Depends(guard)])
async def scan_apk(apk: UploadFile = File(...)):
    return _verdict(analyze_apk(await _read(apk, MAX_APK), apk.filename or "app.apk"))
