"""SMS / WhatsApp / email text: scam-pattern rules, a text classifier, and every link,
UPI ID and phone number inside it analysed on its own."""
from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path

from .upi import VPA_RE, analyze_upi, analyze_vpa
from .url import analyze_url
from .verdict import Verdict

URL_RE = re.compile(r"\b((?:https?://|www\.)[^\s<>\"']+|[a-z0-9][a-z0-9\-]{1,62}\.(?:[a-z]{2,10}|co\.in|org\.in|gov\.in)(?:/[^\s<>\"']*)?)", re.I)
UPI_LINK_RE = re.compile(r"upi://[^\s<>\"']+", re.I)
VPA_TEXT_RE = re.compile(r"\b[a-z0-9.\-_]{2,64}@[a-z][a-z0-9]{1,30}\b", re.I)
PHONE_RE = re.compile(r"(?<!\d)(?:\+91[\s-]?)?[6-9]\d{4}[\s-]?\d{5}(?!\d)")

PATTERNS = [
    (3.0, "asks you to share an OTP, PIN, CVV or password", re.compile(r"\b(share|send|tell|provide|forward|reply with)\b.{0,30}\b(otp|pin|cvv|password|code)\b", re.I | re.S)),
    (2.5, "threatens to block, suspend or disconnect", re.compile(r"\b(will be|has been|is)\b.{0,15}\b(blocked|suspended|deactivated|disconnected|closed|frozen)\b", re.I | re.S)),
    (2.0, "KYC / PAN / Aadhaar update demand", re.compile(r"\b(kyc|pan|aadhaa?r)\b.{0,40}\b(update|expire|expired|pending|verify|link)\b", re.I | re.S)),
    (2.0, "promises a prize, refund or cashback", re.compile(r"\b(won|winner|lottery|prize|refund|cash ?back|reward|bonus|gift)\b", re.I)),
    (2.0, "electricity disconnection scare", re.compile(r"\belectricity\b.{0,60}\b(disconnect|cut|tonight|9\.?30)\b", re.I | re.S)),
    (2.0, "parcel / customs / courier pretext", re.compile(r"\b(parcel|courier|customs|fedex|consignment)\b.{0,60}\b(held|seized|pay|fee|drugs|illegal)\b", re.I | re.S)),
    (2.0, "work-from-home / task job lure", re.compile(r"\b(part[- ]time|work from home|daily income|earn)\b.{0,40}\b(₹|rs\.?|inr|per day|daily|tasks?|likes?)\b", re.I | re.S)),
    (2.0, "instant loan / credit limit lure", re.compile(r"\b(instant|pre-?approved)\b.{0,20}\b(loan|credit limit)\b", re.I | re.S)),
    (2.5, "asks you to install an app or APK", re.compile(r"\b(install|download)\b.{0,30}\b(app|apk|anydesk|teamviewer|quick ?support)\b", re.I | re.S)),
    (2.0, "impersonates police, court, RBI or customs", re.compile(r"\b(cbi|police|cyber cell|narcotics|court|rbi|enforcement directorate|digital arrest)\b", re.I)),
    (2.5, "someone claiming to be family or a friend on a new number", re.compile(r"\b(new number|changed my number|my (phone|mobile) (is )?(broken|lost|not working|damaged))\b", re.I)),
    (0.8, "asks you to send money", re.compile(r"\b(send|transfer|pay)\b.{0,25}(₹|rs\.?|inr)\s?[\d,]+", re.I | re.S)),
    (1.5, "urgency", re.compile(r"\b(urgent|immediately|within \d+ ?(hrs?|hours|minutes)|today|tonight|last date)\b", re.I)),
    (1.0, "asks you to call a number", re.compile(r"\b(call|contact|whatsapp)\b.{0,20}(\+91|\b[6-9]\d{9}\b)", re.I | re.S)),
]

# genuine bank alerts tend to say this
REASSURING = re.compile(r"\b(do not share|never share|don't share)\b.{0,30}\b(otp|pin|password)\b|\bnot you\?|\bif not done by you\b", re.I | re.S)

MODEL_PATH = Path(__file__).resolve().parent / "models" / "text_model.joblib"


@lru_cache(maxsize=1)
def _model():
    if MODEL_PATH.exists():
        import joblib

        return joblib.load(MODEL_PATH)
    return None


def extract(text: str) -> dict:
    upi_links = UPI_LINK_RE.findall(text)
    rest = UPI_LINK_RE.sub(" ", text)
    vpas = [m for m in VPA_TEXT_RE.findall(rest) if VPA_RE.match(m) and "." not in m.split("@")[1]]
    rest_no_vpa = VPA_TEXT_RE.sub(" ", rest)
    urls = [u.rstrip(".,);") for u in URL_RE.findall(rest_no_vpa)]
    phones = [re.sub(r"\D", "", p)[-10:] for p in PHONE_RE.findall(rest_no_vpa)]
    return {"urls": urls, "upi_links": upi_links, "vpas": vpas, "phones": sorted(set(phones))}


def analyze_message(text: str) -> Verdict:
    v = Verdict("message", text[:280])
    ents = extract(text)
    v.entities = ents
    for w, msg, rx in PATTERNS:
        if rx.search(text):
            v.add(w, msg, "pattern")
    if REASSURING.search(text) and not any(f.weight >= 2.5 for f in v.findings):
        v.add(-1.5, "contains the standard 'never share your OTP' warning", "pattern")
    sub = []
    for u in ents["urls"][:5]:
        r = analyze_url(u)
        sub.append(r.as_dict())
        if r.risk >= 40:
            v.add(r.risk / 25, f"link {r.entities.get('registered_domain', u)} looks {r.level} ({r.risk}/100)", "link")
    for u in ents["upi_links"][:3]:
        r = analyze_upi(u)
        sub.append(r.as_dict())
        if r.risk >= 40:
            v.add(r.risk / 25, f"UPI link looks {r.level} ({r.risk}/100)", "upi")
    for p in ents["vpas"][:3]:
        r = analyze_vpa(p)
        sub.append(r.as_dict())
        if r.risk >= 40:
            v.add(r.risk / 30, f"UPI ID {p} looks {r.level}", "upi")
    if ents["urls"] and any(f.category == "pattern" and f.weight >= 2 for f in v.findings):
        v.add(1.0, "combines a pressure story with a link", "pattern")
    v.entities["analysed"] = sub
    m = _model()
    if m is not None:
        v.model_score = float(m.predict_proba([text])[0, 1])
    v.advice = ("This matches known scam patterns. Do not click, call or pay. Banks never ask for OTP/PIN by SMS or call. "
                "Report it at cybercrime.gov.in or call 1930." if v.risk >= 40 else "No strong scam signals found.")
    return v
