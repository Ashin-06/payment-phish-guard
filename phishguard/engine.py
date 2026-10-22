"""One entry point that works out what it was given and routes it."""
from __future__ import annotations

import re

from .message import analyze_message
from .upi import VPA_RE, analyze_upi, analyze_vpa
from .url import analyze_url
from .verdict import Verdict


def decode_qr(image_bytes: bytes) -> list[str]:
    import cv2
    import numpy as np

    img = cv2.imdecode(np.frombuffer(image_bytes, np.uint8), cv2.IMREAD_COLOR)
    if img is None:
        raise ValueError("not an image")
    det = cv2.QRCodeDetector()
    ok, texts, _, _ = det.detectAndDecodeMulti(img)
    found = [t for t in (texts if ok else []) if t]
    if not found:
        t, _, _ = det.detectAndDecode(cv2.cvtColor(img, cv2.COLOR_BGR2GRAY))
        found = [t] if t else []
    return found


def analyze_text(text: str) -> Verdict:
    t = text.strip()
    if t.lower().startswith("upi://"):
        return analyze_upi(t)
    if VPA_RE.match(t) and " " not in t:
        return analyze_vpa(t)
    if " " not in t and (re.match(r"^https?://", t, re.I) or re.match(r"^[\w.-]+\.[a-z]{2,}(/|$)", t, re.I)):
        return analyze_url(t)
    return analyze_message(t)


def analyze_qr(image_bytes: bytes) -> Verdict:
    payloads = decode_qr(image_bytes)
    if not payloads:
        v = Verdict("qr", "image")
        v.add(0, "no QR code found in the image")
        return v
    worst = max((analyze_text(p) for p in payloads), key=lambda r: r.risk)
    worst.entities["qr_payloads"] = payloads
    worst.kind = f"qr/{worst.kind}"
    return worst
