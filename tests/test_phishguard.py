import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).parent))
from fixtures import apk, qr_png  # noqa: E402

from phishguard.apk import analyze_apk, read_manifest  # noqa: E402
from phishguard.engine import analyze_qr, analyze_text  # noqa: E402
from phishguard.message import extract  # noqa: E402
from phishguard.page import analyze_page  # noqa: E402
from phishguard.url import analyze_url, split_host  # noqa: E402

PHISHY = ["sbi-kyc-update.xyz/login", "https://hdfcbank.secure-verify.top/netbanking", "https://hdfcbnak.com/login",
          "https://xn--pytm-5na.com", "https://sbi-yono-reward.web.app", "http://paytm.com@evil.example/claim"]
GOOD = ["https://www.onlinesbi.sbi/", "https://www.icicibank.com/personal-banking", "https://github.com/a/b", "https://www.amazon.in/gp/cart"]


@pytest.mark.parametrize("u", PHISHY)
def test_phishing_urls_flagged(u):
    assert analyze_url(u).level != "safe"


@pytest.mark.parametrize("u", GOOD)
def test_official_urls_safe(u):
    assert analyze_url(u).level == "safe"


def test_suffix_handling():
    assert split_host("netbanking.sbi.co.in") == ("netbanking", "sbi.co.in", "co.in")
    assert split_host("a.b.example.com")[1] == "example.com"


def test_upi_refund_scam_vs_merchant():
    scam = analyze_text("upi://pay?pa=9876543210@ybl&pn=SBI%20Refund%20Desk&am=4999&tn=Refund%20receive%20now")
    shop = analyze_text("upi://pay?pa=bigbasket@icici&pn=BigBasket&mc=5411&am=820&tr=ORD123&cu=INR")
    assert scam.level == "dangerous" and shop.level == "safe"
    assert any("never enter a UPI PIN to receive" in f.message for f in scam.findings)


def test_message_scam_and_genuine_alert():
    scam = analyze_text("Dear customer your SBI account will be blocked today. Update KYC immediately https://sbi-kyc-update.xyz/login")
    alert = analyze_text("INR 2,340 debited from A/c XX4412 on 21-Oct to SWIGGY. Avl Bal INR 45,120. Not you? Call HDFC Bank customer care.")
    assert scam.level == "dangerous" and alert.level == "safe"


def test_entity_extraction():
    e = extract("pay 500 to rahul99@ybl or visit sbi-help.top/kyc, call +91 98765 43210, upi://pay?pa=a@ybl")
    assert e["vpas"] == ["rahul99@ybl"] and e["upi_links"] == ["upi://pay?pa=a@ybl"]
    assert "sbi-help.top/kyc" in e["urls"] and e["phones"] == ["9876543210"]


def test_qr_code_decoded_and_scored():
    v = analyze_qr(qr_png("upi://pay?pa=9876543210@ybl&pn=Electricity%20Board%20Refund&am=9999&tn=refund"))
    assert v.kind.startswith("qr/upi") and v.level == "dangerous"


def test_fake_bank_apk():
    data = apk("com.sbi.yono.kyc.update",
               ["android.permission.INTERNET", "android.permission.RECEIVE_SMS", "android.permission.READ_SMS",
                "android.permission.SYSTEM_ALERT_WINDOW"],
               services=[(".Acc", "android.permission.BIND_ACCESSIBILITY_SERVICE")], sms_receiver=True)
    v = analyze_apk(data, "SBI_KYC.apk")
    assert v.entities["package"] == "com.sbi.yono.kyc.update"
    assert "android.permission.READ_SMS" in v.entities["permissions"]
    assert v.entities["certificates"] and "Android Debug" in v.entities["certificates"][0]["subject"]
    assert v.level == "dangerous"
    msgs = " ".join(f.message for f in v.findings)
    assert "imitates SBI" in msgs and "banking-trojan" in msgs


def test_plain_apk_is_not_flagged():
    v = analyze_apk(apk("org.example.notes", ["android.permission.INTERNET"], cn="Example Dev"), "notes.apk")
    assert v.level == "safe"


def test_manifest_parser_reads_components():
    import io
    import zipfile

    raw = apk("x.y", ["android.permission.SEND_SMS"], services=[(".N", "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE")], sms_receiver=True)
    m = read_manifest(zipfile.ZipFile(io.BytesIO(raw)).read("AndroidManifest.xml"))
    assert m.package == "x.y" and m.permissions == ["android.permission.SEND_SMS"]
    assert m.services[0]["permission"].endswith("NOTIFICATION_LISTENER_SERVICE")
    assert m.receivers[0]["actions"] == ["android.provider.Telephony.SMS_RECEIVED"]


def test_phishing_kit_page():
    html = """<html><head><title>SBI Online KYC</title><link href="https://www.onlinesbi.sbi/css/x.css"></head>
    <body><form action="https://api.telegram.org/bot1:A/sendMessage"><input name=user><input type=password name=pwd>
    <input name=otp placeholder="Enter OTP"></form></body></html>"""
    v = analyze_page(html, "https://sbi-kyc-online.web.app/login")
    assert v.level == "dangerous" and "otp" in v.entities["collects"]
    real = analyze_page("<html><title>SBI</title><form><input type=password></form></html>", "https://retail.onlinesbi.sbi/login")
    assert real.risk < v.risk


def test_api_endpoints():
    from phishguard.api import app

    c = TestClient(app)
    assert c.get("/healthz").json()["ok"]
    r = c.post("/v1/scan", json={"input": "sbi-kyc-update.xyz/login"}).json()
    assert r["level"] != "safe" and r["kind"] == "url"
    r = c.post("/v1/scan/qr", files={"image": ("q.png", qr_png("https://www.icicibank.com"), "image/png")}).json()
    assert r["level"] == "safe"
    r = c.post("/v1/scan/apk", files={"apk": ("a.apk", b"not a zip", "application/octet-stream")}).json()
    assert "not a readable APK" in r["findings"][0]["message"]
    assert c.post("/v1/scan/page", json={"url": "https://x.example"}).status_code == 400


def test_v2_signing_block_certificate_is_read():
    import struct

    from cryptography.hazmat.primitives.serialization import Encoding
    from fixtures import self_signed

    from phishguard.apk import v2_certificates

    _, cert = self_signed("CN=V2 Signer")
    der = cert.public_bytes(Encoding.DER)
    lp = lambda b: struct.pack("<I", len(b)) + b
    signed_data = lp(b"") + lp(lp(der)) + lp(b"")
    signer = lp(signed_data) + lp(b"") + lp(b"")
    value = lp(lp(signer))
    pair = struct.pack("<QI", len(value) + 4, 0x7109871A) + value
    size = len(pair) + 8 + 16
    block = struct.pack("<Q", size) + pair + struct.pack("<Q", size) + b"APK Sig Block 42"

    raw = apk("org.example.v2", ["android.permission.INTERNET"], cn="Example")
    eocd = raw.rfind(b"PK\x05\x06")
    cd = struct.unpack_from("<I", raw, eocd + 16)[0]
    patched = raw[:cd] + block + raw[cd:eocd + 16] + struct.pack("<I", cd + len(block)) + raw[eocd + 20:]
    certs, schemes = v2_certificates(patched)
    assert schemes == ["v2"] and certs == [der]
    v = analyze_apk(patched, "v2.apk")
    assert "v2" in v.entities["signing_schemes"] and len(v.entities["certificates"]) == 2


@pytest.mark.parametrize("url", ["http://127.0.0.1:8006/healthz", "http://169.254.169.254/latest/meta-data/",
                                 "http://localhost/", "file:///etc/passwd", "http://10.0.0.5/admin", "ftp://example.com/x"])
def test_fetch_refuses_internal_targets(url):
    from phishguard.page import UnsafeURL, fetch

    with pytest.raises(UnsafeURL):
        fetch(url)


def test_api_page_fetch_blocks_ssrf(monkeypatch):
    monkeypatch.setenv("PHISHGUARD_FETCH", "1")
    from phishguard.api import app

    r = TestClient(app).post("/v1/scan/page", json={"url": "http://169.254.169.254/latest/meta-data/"})
    assert r.status_code == 400 and "non-public" in r.json()["detail"]


def test_malformed_signing_block_does_not_crash():
    import struct

    raw = apk("org.example.bad", ["android.permission.INTERNET"], cn="Example")
    lp = lambda b: struct.pack("<I", len(b)) + b
    value = lp(lp(lp(b"")))  # signer with no signed data inside
    pair = struct.pack("<QI", len(value) + 4, 0x7109871A) + value
    size = len(pair) + 8 + 16
    block = struct.pack("<Q", size) + pair + struct.pack("<Q", size) + b"APK Sig Block 42"
    eocd = raw.rfind(b"PK\x05\x06")
    cd = struct.unpack_from("<I", raw, eocd + 16)[0]
    patched = raw[:cd] + block + raw[cd:eocd + 16] + struct.pack("<I", cd + len(block)) + raw[eocd + 20:]
    v = analyze_apk(patched, "bad.apk")
    assert any("could not be parsed" in f.message for f in v.findings)
