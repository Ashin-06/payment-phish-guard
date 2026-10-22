"""Link analysis: rules that explain, plus a gradient-boosted model that generalises."""
from __future__ import annotations

import ipaddress
import math
import re
import unicodedata
from collections import Counter
from functools import lru_cache
from pathlib import Path
from urllib.parse import parse_qsl, unquote, urlsplit

import numpy as np

from .brands import (BRANDS, COMMON_SAFE, FREE_HOSTING, LOOKALIKE_TABLE, MULTI_PART_SUFFIXES, RISKY_TLDS, SHORTENERS,
                     official_domains)
from .verdict import Verdict

LURE_WORDS = ["kyc", "update", "verify", "verification", "refund", "reward", "cashback", "login", "signin", "secure",
              "account", "blocked", "suspend", "pan", "aadhaar", "aadhar", "upi", "otp", "bonus", "claim", "prize", "gift",
              "lottery", "free", "offer", "electricity", "bill", "unlock", "reactivate", "netbanking", "credit-card", "limit"]


def normalise(url: str) -> str:
    url = url.strip().strip("<>\"'")
    if not re.match(r"^[a-z][a-z0-9+.-]*:", url, re.I):
        url = "http://" + url
    return url


def split_host(host: str) -> tuple[str, str, str]:
    """(subdomain, registered domain, suffix) using a small built-in suffix list."""
    host = host.lower().rstrip(".")
    labels = host.split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in MULTI_PART_SUFFIXES:
        suffix, reg = ".".join(labels[-2:]), ".".join(labels[-3:])
        sub = ".".join(labels[:-3])
    else:
        suffix, reg = labels[-1], ".".join(labels[-2:])
        sub = ".".join(labels[:-2])
    return sub, reg, suffix


def skeleton(s: str) -> str:
    s = unicodedata.normalize("NFKC", s).lower().translate(LOOKALIKE_TABLE)
    return s.replace("rn", "m").replace("vv", "w")


def damerau(a: str, b: str) -> int:
    d = {(i, -1): i + 1 for i in range(-1, len(a) + 1)}
    d.update({(-1, j): j + 1 for j in range(-1, len(b) + 1)})
    for i, ca in enumerate(a):
        for j, cb in enumerate(b):
            cost = ca != cb
            d[i, j] = min(d[i - 1, j] + 1, d[i, j - 1] + 1, d[i - 1, j - 1] + cost)
            if i and j and ca == b[j - 1] and a[i - 1] == cb:
                d[i, j] = min(d[i, j], d[i - 2, j - 2] + 1)
    return d[len(a) - 1, len(b) - 1]


def entropy(s: str) -> float:
    if not s:
        return 0.0
    c = Counter(s)
    return -sum(v / len(s) * math.log2(v / len(s)) for v in c.values())


def _brand_word(word: str, name: str) -> bool:
    """Short brand names (sbi, hdfc) must start a label; longer ones may appear anywhere."""
    return word.startswith(name) if len(name) <= 4 else name in word


def _host_is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return bool(re.fullmatch(r"\d+", host)) or bool(re.fullmatch(r"0x[0-9a-f]+", host, re.I))


FEATURE_NAMES = [
    "len_url", "len_host", "n_dots", "n_hyphens", "n_digits_host", "sub_depth", "is_ip", "punycode", "non_ascii",
    "at_sign", "double_slash_path", "https", "odd_port", "risky_tld", "shortener", "free_hosting", "lure_words",
    "brand_in_host_not_owner", "brand_in_path", "typosquat", "host_entropy", "path_depth", "n_params", "apk_link",
    "official",
]


def features(url: str) -> dict:
    url = normalise(url)
    p = urlsplit(url)
    host = (p.hostname or "").lower()
    try:
        host_uni = host.encode("ascii").decode("idna") if "xn--" in host else host
    except UnicodeError:
        host_uni = host
    sub, reg, suffix = split_host(host_uni)
    official = official_domains() | set(COMMON_SAFE)
    owner = reg in official or host_uni in official or any(host_uni.endswith("." + d) for d in official)
    reg_skel = skeleton(reg.split(".")[0])
    typo = 0
    if not owner and len(reg_skel) >= 4:
        for d in official_domains():
            base = skeleton(d.split(".")[0])
            if reg_skel == base or (len(base) >= 5 and damerau(reg_skel, base) <= 2):
                typo = 1
                break
    host_words = re.split(r"[.\-_]", skeleton(host_uni))
    brand_host = any(_brand_word(w, n.replace(" ", "")) for b in BRANDS.values() for n in b["names"] for w in host_words)
    path = unquote(p.path + "?" + p.query).lower()
    brand_path = any(n.replace(" ", "") in path.replace("-", "").replace("_", "") for b in BRANDS.values() for n in b["names"])
    lure = sum(1 for w in LURE_WORDS if w in skeleton(host_uni) or w in path)
    return {
        "len_url": len(url), "len_host": len(host), "n_dots": host.count("."), "n_hyphens": host.count("-"),
        "n_digits_host": sum(c.isdigit() for c in host), "sub_depth": len(sub.split(".")) if sub else 0,
        "is_ip": int(_host_is_ip(host)), "punycode": int("xn--" in host), "non_ascii": int(any(ord(c) > 127 for c in host_uni)),
        "at_sign": int("@" in p.netloc), "double_slash_path": int("//" in p.path), "https": int(p.scheme == "https"),
        "odd_port": int(p.port not in (None, 80, 443)), "risky_tld": int(suffix in RISKY_TLDS),
        "shortener": int(reg in SHORTENERS or host in SHORTENERS),
        "free_hosting": int(any(host.endswith(h) for h in FREE_HOSTING)), "lure_words": lure,
        "brand_in_host_not_owner": int(brand_host and not owner), "brand_in_path": int(brand_path and not owner),
        "typosquat": typo, "host_entropy": entropy(host), "path_depth": p.path.count("/"),
        "n_params": len(parse_qsl(p.query)), "apk_link": int(p.path.lower().endswith(".apk")), "official": int(owner),
        "_host": host_uni, "_reg": reg, "_sub": sub,
    }


def vector(f: dict) -> np.ndarray:
    return np.array([f[k] for k in FEATURE_NAMES], dtype=float)


MODEL_PATH = Path(__file__).resolve().parent / "models" / "url_model.joblib"


@lru_cache(maxsize=1)
def _model():
    if MODEL_PATH.exists():
        import joblib

        return joblib.load(MODEL_PATH)
    return None


def analyze_url(url: str, f: dict | None = None, model=None) -> Verdict:
    """`f` and `model` let an evaluation reuse computed features or score a candidate model."""
    f = f or features(url)
    v = Verdict("url", url, entities={"host": f["_host"], "registered_domain": f["_reg"]})
    if f["official"]:
        v.add(-3, f"{f['_reg']} is an official domain", "reputation")
    if f["typosquat"]:
        v.add(4, f"'{f['_reg']}' imitates a bank or payment brand domain (look-alike spelling)", "impersonation")
    if f["brand_in_host_not_owner"]:
        v.add(3.5, f"brand name in the address, but the site is {f['_reg']}, not the brand's domain", "impersonation")
    elif f["brand_in_path"]:
        v.add(1.5, "brand name appears in the link path on an unrelated site", "impersonation")
    if f["punycode"] or f["non_ascii"]:
        v.add(3, "internationalised domain (can hide look-alike characters)", "obfuscation")
    if f["is_ip"]:
        v.add(3, "link points to a raw IP address instead of a domain", "obfuscation")
    if f["at_sign"]:
        v.add(4, "'@' in the address hides the real destination (everything before it is ignored)", "obfuscation")
    if f["shortener"]:
        v.add(1.5, "shortened link hides where it goes", "obfuscation")
    if f["free_hosting"]:
        v.add(2, "hosted on a free site builder / tunnel often used for phishing kits", "hosting")
    if f["risky_tld"]:
        v.add(1.2, f"top-level domain .{f['_reg'].split('.')[-1]} is heavily abused", "hosting")
    if f["apk_link"]:
        v.add(3, "link downloads an Android app (APK) outside the Play Store", "malware")
    if f["lure_words"] >= 2:
        v.add(1.0 + 0.4 * min(f["lure_words"], 5), f"{f['lure_words']} lure words (KYC, refund, reward, verify...)", "lure")
    if f["odd_port"]:
        v.add(1, "unusual network port", "obfuscation")
    if f["sub_depth"] >= 3:
        v.add(1, "deeply nested subdomains", "obfuscation")
    if not f["https"] and not f["official"]:
        v.add(0.5, "not using HTTPS", "transport")
    m = model if model is not None else _model()
    if m is not None and not f["official"]:
        v.model_score = float(m.predict_proba(vector(f)[None, :])[0, 1])
    v.advice = ("Do not enter card, UPI PIN, OTP or login details here. Open your bank's app directly instead."
                if v.risk >= 40 else "No strong warning signs. Still never share OTP or UPI PIN.")
    return v
