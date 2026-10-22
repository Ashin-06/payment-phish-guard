"""Phishing page analysis from HTML (fetched server-side or sent by the extension).

Looks for what phishing kits need: a form that collects credentials or card/UPI
details, a brand they borrow, somewhere to send the loot (often a Telegram bot), and
tricks to stop the victim from inspecting the page.
"""
from __future__ import annotations

import re
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

from .brands import BRANDS
from .url import analyze_url, split_host
from .verdict import Verdict

SENSITIVE_FIELDS = {
    "password": re.compile(r"pass(word)?|pwd|mpin|login ?pin", re.I),
    "otp": re.compile(r"\botp\b|one.?time|verification code", re.I),
    "card": re.compile(r"card ?(number|no)|ccnum|cvv|cvc|expiry|exp ?date", re.I),
    "upi_pin": re.compile(r"upi ?pin|\bupin\b", re.I),
    "aadhaar_pan": re.compile(r"aadhaa?r|\bpan\b|pan ?card", re.I),
    "dob_mother": re.compile(r"date of birth|\bdob\b|mother'?s? maiden", re.I),
}
EXFIL = re.compile(r"api\.telegram\.org/bot|discord(app)?\.com/api/webhooks|formspree\.io|getform\.io|"
                   r"script\.google\.com/macros|webhook\.site|pipedream\.net|requestbin", re.I)
OBFUSCATION = re.compile(r"eval\s*\(\s*(atob|unescape|decodeURIComponent)|String\.fromCharCode\s*\((\s*\d+\s*,){20,}|"
                         r"document\.write\s*\(\s*unescape|\\x[0-9a-f]{2}(\\x[0-9a-f]{2}){30,}", re.I)
ANTI_INSPECT = re.compile(r"(contextmenu|oncontextmenu)[^;]{0,40}(preventDefault|return false)|keyCode\s*==\s*123|"
                          r"devtools|debugger;", re.I)


class _Collector(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.title, self._in_title = "", False
        self.forms, self.inputs, self.links, self.scripts, self.iframes, self.resources = [], [], [], [], [], []
        self.text, self.meta_refresh, self._in_script = [], None, False

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "title":
            self._in_title = True
        elif tag == "form":
            self.forms.append(a.get("action", ""))
        elif tag in ("input", "textarea", "select"):
            self.inputs.append(" ".join([a.get("name", ""), a.get("id", ""), a.get("placeholder", ""), a.get("type", ""),
                                         a.get("aria-label", ""), a.get("autocomplete", "")]))
        elif tag == "a" and a.get("href"):
            self.links.append(a["href"])
        elif tag == "script":
            self._in_script = True
            if a.get("src"):
                self.resources.append(a["src"])
        elif tag == "iframe":
            hidden = a.get("width") in ("0", "1") or a.get("height") in ("0", "1") or "display:none" in a.get("style", "").replace(" ", "")
            self.iframes.append((a.get("src", ""), hidden))
        elif tag in ("img", "link") and (a.get("src") or a.get("href")):
            self.resources.append(a.get("src") or a.get("href"))
        elif tag == "meta" and a.get("http-equiv", "").lower() == "refresh":
            self.meta_refresh = a.get("content", "")

    def handle_endtag(self, tag):
        if tag == "title":
            self._in_title = False
        elif tag == "script":
            self._in_script = False

    def handle_data(self, data):
        if self._in_title:
            self.title += data
        if self._in_script:
            self.scripts.append(data)
        elif data.strip():
            self.text.append(data.strip())


def analyze_page(html: str, page_url: str) -> Verdict:
    v = Verdict("page", page_url)
    c = _Collector()
    c.feed(html[:2_000_000])
    host = (urlsplit(page_url).hostname or "").lower()
    _, reg, _ = split_host(host) if host else ("", "", "")
    u = analyze_url(page_url)
    official = any(f.weight < 0 for f in u.findings)
    for f in u.findings:
        v.findings.append(f)

    asks = sorted({k for k, rx in SENSITIVE_FIELDS.items() if any(rx.search(i) for i in c.inputs)})
    v.entities.update(title=c.title.strip()[:120], collects=asks, forms=len(c.forms))
    body = (c.title + " " + " ".join(c.text[:400])).lower()
    brands = sorted({k for k, b in BRANDS.items() if any(n in body for n in b["names"] if len(n) > 3 or f" {n} " in f" {body} ")})
    v.entities["brands_mentioned"] = brands

    if asks and not official:
        weight = 1.0 + sum({"password": 1, "otp": 1.5, "card": 1.5, "upi_pin": 3, "aadhaar_pan": 1, "dob_mother": 0.5}[k] for k in asks)
        v.add(weight, f"page collects {', '.join(asks).replace('_', ' ')}", "credentials")
    if "upi_pin" in asks:
        v.add(2, "asks for a UPI PIN in a web page: legitimate UPI apps never do this", "credentials")
    if brands and asks and not official:
        v.add(3, f"uses {', '.join(b.upper() for b in brands)} branding and asks for credentials on {reg}", "impersonation")
    for action in c.forms:
        dest = urlsplit(urljoin(page_url, action)).hostname or ""
        if dest and split_host(dest)[1] != reg:
            v.add(2, f"form sends data to another site ({dest})", "exfiltration")
            break
    blob = html if len(html) < 2_000_000 else html[:2_000_000]
    if EXFIL.search(blob):
        v.add(4, f"sends data to {EXFIL.search(blob).group(0)} (typical of phishing kits)", "exfiltration")
    if OBFUSCATION.search(" ".join(c.scripts)):
        v.add(2, "heavily obfuscated JavaScript", "obfuscation")
    if ANTI_INSPECT.search(" ".join(c.scripts) + blob[:20000]):
        v.add(1.5, "blocks right-click / developer tools", "obfuscation")
    if any(hidden for _, hidden in c.iframes):
        v.add(1.5, "hidden iframe", "obfuscation")
    brand_domains = {d for b in BRANDS.values() for d in b["domains"]}
    hotlinked = [r for r in c.resources if (urlsplit(urljoin(page_url, r)).hostname or "").endswith(tuple(brand_domains))]
    if hotlinked and not official:
        v.add(2, "loads logos/styles straight from a bank's site (cloned page)", "impersonation")
    if c.meta_refresh and "url=" in c.meta_refresh.lower():
        target = c.meta_refresh.lower().split("url=", 1)[1].strip("'\" ")
        if split_host(urlsplit(urljoin(page_url, target)).hostname or "x")[1] != reg:
            v.add(1.5, f"auto-redirects to another site ({target[:60]})", "redirect")
    v.advice = ("Close this page. Do not type passwords, OTP, card or UPI details. Use your bank's official app."
                if v.risk >= 40 else "No phishing-kit traits found.")
    return v


class UnsafeURL(ValueError):
    """The URL points somewhere a server-side fetch must never go."""


def _require_public(url: str) -> None:
    """Block server-side request forgery: only http(s) to hosts that resolve to public
    addresses (no localhost, private ranges, link-local cloud metadata, multicast)."""
    import ipaddress
    import socket

    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise UnsafeURL("only http and https URLs can be fetched")
    port = parts.port or (443 if parts.scheme == "https" else 80)
    try:
        infos = socket.getaddrinfo(parts.hostname, port, type=socket.SOCK_STREAM)
    except socket.gaierror as e:
        raise UnsafeURL(f"cannot resolve {parts.hostname}") from e
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if not ip.is_global or ip.is_multicast:
            raise UnsafeURL(f"{parts.hostname} resolves to a non-public address ({ip})")


def fetch(url: str, timeout: float = 8.0, max_bytes: int = 2_000_000, max_redirects: int = 5) -> tuple[str, str]:
    """Fetch a page without running scripts. Every hop, redirects included, must be a
    public http(s) address. Returns (final_url, html)."""
    import httpx

    headers = {"User-Agent": "Mozilla/5.0 (PhishGuard scanner)"}
    with httpx.Client(follow_redirects=False, timeout=timeout, headers=headers) as cl:
        for _ in range(max_redirects + 1):
            _require_public(url)
            with cl.stream("GET", url) as r:
                if r.is_redirect:
                    url = urljoin(url, r.headers.get("location", ""))
                    continue
                chunks, total = [], 0
                for chunk in r.iter_bytes():
                    chunks.append(chunk)
                    total += len(chunk)
                    if total > max_bytes:
                        break
                return str(r.url), b"".join(chunks).decode(r.encoding or "utf-8", "replace")
    raise UnsafeURL("too many redirects")
