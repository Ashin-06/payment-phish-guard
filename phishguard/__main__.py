"""Command line.

    python -m phishguard check "Dear customer your SBI account will be blocked..."
    python -m phishguard check "upi://pay?pa=9876543210@ybl&pn=SBI%20Refund&am=4999"
    python -m phishguard qr photo_of_qr.jpg
    python -m phishguard apk suspicious.apk
    python -m phishguard page https://example.com/login [--html saved.html]
    python -m phishguard train
    python -m phishguard realdata --phiusiil PhiUSIIL_Phishing_URL_Dataset.csv --uci-sms SMSSpamCollection
    python -m phishguard serve                       # web scanner + API (settings: PHISHGUARD_* env)
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from .apk import analyze_apk
from .engine import analyze_qr, analyze_text
from .page import analyze_page, fetch

COLORS = {"safe": "\033[32m", "suspicious": "\033[33m", "dangerous": "\033[31m"}


def show(v, as_json: bool) -> None:
    if as_json:
        print(json.dumps(v.as_dict(), indent=2, ensure_ascii=False, default=str))
        return
    tty = sys.stdout.isatty()
    lvl = f"{COLORS[v.level]}{v.level.upper()}\033[0m" if tty else v.level.upper()
    print(f"{lvl}  risk {v.risk}/100  ({v.kind})")
    for f in sorted(v.findings, key=lambda f: -f.weight):
        print(f"  {f.weight:+.1f}  {f.message}")
    print(f"\n{v.advice}")


def main(argv=None):
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    ap = argparse.ArgumentParser(prog="phishguard")
    ap.add_argument("--json", action="store_true")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("check").add_argument("input", nargs="+")
    sub.add_parser("qr").add_argument("image")
    sub.add_parser("apk").add_argument("file")
    p = sub.add_parser("page")
    p.add_argument("url")
    p.add_argument("--html", help="saved page source instead of fetching")
    sub.add_parser("train", add_help=False)
    sub.add_parser("realdata", add_help=False)
    s = sub.add_parser("serve")
    s.add_argument("--port", type=int, help="default PHISHGUARD_PORT or 8006")
    s.add_argument("--host", help="default PHISHGUARD_HOST or 127.0.0.1; any other address needs API keys")
    a, rest = ap.parse_known_args(argv)

    if a.cmd == "check":
        show(analyze_text(" ".join(a.input)), a.json)
    elif a.cmd == "qr":
        show(analyze_qr(Path(a.image).read_bytes()), a.json)
    elif a.cmd == "apk":
        show(analyze_apk(Path(a.file).read_bytes(), Path(a.file).name), a.json)
    elif a.cmd == "page":
        url, html = (a.url, Path(a.html).read_text(encoding="utf-8", errors="replace")) if a.html else fetch(a.url)
        show(analyze_page(html, url), a.json)
    elif a.cmd == "train":
        from .train import main as train

        train(rest)
    elif a.cmd == "realdata":
        from .realdata import main as realdata

        realdata(rest)
    elif a.cmd == "serve":
        import uvicorn

        from . import ops

        for name, val in (("HOST", a.host), ("PORT", a.port)):
            if val is not None:
                os.environ[f"PHISHGUARD_{name}"] = str(val)
        try:
            settings = ops.load_settings()  # fail here, before uvicorn, with a readable message
        except ops.ConfigError as e:
            sys.exit(f"configuration error: {e}")
        ops.setup_logging(settings.log_level)
        uvicorn.run("phishguard.api:app", host=settings.host, port=settings.port, log_config=None, access_log=False)


if __name__ == "__main__":
    main()
