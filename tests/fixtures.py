"""Builds test artifacts: a binary AndroidManifest (AXML), a signed APK and QR images."""
from __future__ import annotations

import datetime as dt
import io
import struct
import zipfile

ANDROID_NS = "http://schemas.android.com/apk/res/android"


def axml(elements: list[tuple[str, dict]]) -> bytes:
    """elements: ('tag', {attr: value}) for start tags and ('/tag', {}) for end tags.
    String values are typed as strings, ints as decimal ints, bools as booleans."""
    strings: list[str] = []

    def sid(s: str) -> int:
        if s not in strings:
            strings.append(s)
        return strings.index(s)

    for name, attrs in elements:
        sid(name.lstrip("/"))
        for k, val in attrs.items():
            sid(k)
            if isinstance(val, str):
                sid(val)
    sid(ANDROID_NS)

    # UTF-16 string pool
    offsets, blob = [], b""
    for s in strings:
        offsets.append(len(blob))
        blob += struct.pack("<H", len(s)) + s.encode("utf-16-le") + b"\x00\x00"
    while len(blob) % 4:
        blob += b"\x00"
    pool_header = 28
    pool = struct.pack("<HHIIIIII", 0x0001, pool_header, pool_header + 4 * len(strings) + len(blob), len(strings), 0, 0,
                       pool_header + 4 * len(strings), 0) + struct.pack(f"<{len(strings)}I", *offsets) + blob

    nodes = b""
    for name, attrs in elements:
        if name.startswith("/"):
            nodes += struct.pack("<HHIIIII", 0x0103, 16, 24, 1, 0xFFFFFFFF, 0xFFFFFFFF, sid(name[1:]))
            continue
        body = b""
        for k, val in attrs.items():
            if isinstance(val, bool):
                raw, dtype, data = 0xFFFFFFFF, 0x12, 0xFFFFFFFF if val else 0
            elif isinstance(val, int):
                raw, dtype, data = 0xFFFFFFFF, 0x10, val
            else:
                raw, dtype, data = sid(val), 0x03, sid(val)
            ns = sid(ANDROID_NS) if k != "package" else 0xFFFFFFFF
            body += struct.pack("<IIIHBBI", ns, sid(k), raw, 8, 0, dtype, data)
        ext = struct.pack("<IIHHHHHH", 0xFFFFFFFF, sid(name), 20, 20, len(attrs), 0, 0, 0)
        size = 16 + len(ext) + len(body)
        nodes += struct.pack("<HHIII", 0x0102, 16, size, 1, 0xFFFFFFFF) + ext + body
    total = 8 + len(pool) + len(nodes)
    return struct.pack("<HHI", 0x0003, 8, total) + pool + nodes


def self_signed(cn: str):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now).not_valid_after(now + dt.timedelta(days=3650))
            .sign(key, hashes.SHA256()))
    return key, cert


def apk(package: str, permissions: list[str], services: list[tuple[str, str]] = (), sms_receiver: bool = False,
        cn: str = "Android Debug") -> bytes:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.serialization import pkcs7

    els = [("manifest", {"package": package, "versionName": "1.0"})]
    els += [x for p in permissions for x in (("uses-permission", {"name": p}), ("/uses-permission", {}))]
    els.append(("application", {"label": "App"}))
    els += [("activity", {"name": ".Main"}), ("/activity", {})]
    for name, perm in services:
        els += [("service", {"name": name, "permission": perm}), ("/service", {})]
    if sms_receiver:
        els += [("receiver", {"name": ".SmsReceiver", "exported": True}), ("intent-filter", {}),
                ("action", {"name": "android.provider.Telephony.SMS_RECEIVED"}), ("/action", {}),
                ("/intent-filter", {}), ("/receiver", {})]
    els += [("/application", {}), ("/manifest", {})]

    key, cert = self_signed(cn)
    sig = (pkcs7.PKCS7SignatureBuilder().set_data(b"Signature-Version: 1.0\r\n").add_signer(cert, key, hashes.SHA256())
           .sign(serialization.Encoding.DER, [pkcs7.PKCS7Options.DetachedSignature]))
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("AndroidManifest.xml", axml(els))
        z.writestr("classes.dex", b"dex\n035\x00" + b"\x00" * 64)
        z.writestr("META-INF/CERT.RSA", sig)
    return buf.getvalue()


def qr_png(text: str) -> bytes:
    import cv2
    import numpy as np

    img = cv2.QRCodeEncoder.create().encode(text)
    img = cv2.resize(img, None, fx=8, fy=8, interpolation=cv2.INTER_NEAREST)
    img = cv2.copyMakeBorder(img, 40, 40, 40, 40, cv2.BORDER_CONSTANT, value=255)
    ok, png = cv2.imencode(".png", img.astype(np.uint8))
    return png.tobytes()
