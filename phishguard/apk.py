"""Android APK triage without the Android SDK.

Parses the binary AndroidManifest.xml (AXML) directly, reads the signing certificate
from the v1 (META-INF PKCS#7) or v2/v3 (APK Signing Block) scheme, and scores the app
against the profile of Indian banking trojans and fake bank/KYC apps: SMS interception
for OTPs, accessibility abuse for remote control, overlays, notification snooping,
call forwarding and a package name dressed up as a bank.
"""
from __future__ import annotations

import hashlib
import io
import json
import struct
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

from .brands import BRANDS, official_packages
from .verdict import Verdict

ANDROID_ATTR_IDS = {0x01010003: "name", 0x01010001: "label", 0x01010006: "permission", 0x0101021B: "versionCode",
                    0x0101021C: "versionName", 0x0101020C: "minSdkVersion", 0x01010270: "targetSdkVersion",
                    0x01010010: "exported", 0x0101000E: "enabled"}

PERMISSION_RISK = {
    "android.permission.RECEIVE_SMS": (3.0, "reads incoming SMS (OTP interception)"),
    "android.permission.READ_SMS": (3.0, "reads your SMS inbox (OTPs, bank alerts)"),
    "android.permission.SEND_SMS": (2.0, "sends SMS silently (can hijack UPI device binding)"),
    "android.permission.SYSTEM_ALERT_WINDOW": (1.5, "draws over other apps (fake login overlays)"),
    "android.permission.REQUEST_INSTALL_PACKAGES": (1.0, "can install other apps"),
    "android.permission.CALL_PHONE": (1.0, "places calls (call-forwarding codes)"),
    "android.permission.PROCESS_OUTGOING_CALLS": (1.5, "intercepts outgoing calls"),
    "android.permission.READ_CONTACTS": (0.5, "reads contacts"),
    "android.permission.READ_PHONE_STATE": (0.5, "reads phone identity"),
    "android.permission.QUERY_ALL_PACKAGES": (0.5, "lists every installed app (looks for banking apps)"),
    "android.permission.RECEIVE_BOOT_COMPLETED": (0.3, "starts itself at boot"),
    "android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS": (0.5, "keeps itself running in the background"),
}
SERVICE_RISK = {
    "android.permission.BIND_ACCESSIBILITY_SERVICE": (3.0, "registers an accessibility service (can read the screen and tap for you)"),
    "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE": (2.0, "reads all notifications (OTPs from other apps)"),
    "android.permission.BIND_DEVICE_ADMIN": (2.0, "asks to become device administrator (hard to uninstall)"),
}


MAX_MANIFEST_BYTES = 8 * 1024 * 1024
MAX_ZIP_ENTRIES = 60_000
MAX_SIG_FILE_BYTES = 1024 * 1024


class AxmlError(ValueError):
    pass


def _string_pool(data: bytes, off: int) -> list[str]:
    _, hsize, _size, count, _styles, flags, start, _ = struct.unpack_from("<HHIIIIII", data, off)
    utf8 = bool(flags & (1 << 8))
    offsets = struct.unpack_from(f"<{count}I", data, off + hsize)
    base = off + start
    out = []
    for o in offsets:
        p = base + o
        if utf8:
            n = data[p]
            p += 2 if n & 0x80 else 1
            n = data[p]
            if n & 0x80:
                n = ((n & 0x7F) << 8) | data[p + 1]
                p += 2
            else:
                p += 1
            out.append(data[p : p + n].decode("utf-8", "replace"))
        else:
            n = struct.unpack_from("<H", data, p)[0]
            p += 2
            if n & 0x8000:
                n = ((n & 0x7FFF) << 16) | struct.unpack_from("<H", data, p)[0]
                p += 2
            out.append(data[p : p + 2 * n].decode("utf-16-le", "replace"))
    return out


def parse_axml(data: bytes) -> list[tuple[str, dict]]:
    """Return a flat list of (element name, attributes) in document order. End tags
    are represented as ('/name', {})."""
    if len(data) < 8 or struct.unpack_from("<H", data, 0)[0] != 0x0003:
        raise AxmlError("not a binary XML document")
    strings, resmap, out = [], [], []
    off = 8
    while off + 8 <= len(data):
        ctype, hsize, csize = struct.unpack_from("<HHI", data, off)
        if csize < 8 or off + csize > len(data):
            break  # truncated or obfuscated tail
        if ctype == 0x0001:
            strings = _string_pool(data, off)
        elif ctype == 0x0180:
            resmap = list(struct.unpack_from(f"<{(csize - hsize) // 4}I", data, off + hsize))
        elif ctype == 0x0102:
            _ns, name, astart, asize, acount = struct.unpack_from("<IIHHH", data, off + 16)
            attrs = {}
            for i in range(acount):
                a = off + 16 + astart + i * asize
                _ans, aname, raw, _vsize, _r0, dtype, val = struct.unpack_from("<IIIHBBI", data, a)
                key = strings[aname] if aname < len(strings) and strings[aname] else ANDROID_ATTR_IDS.get(resmap[aname] if aname < len(resmap) else -1, f"attr{aname}")
                if raw != 0xFFFFFFFF and raw < len(strings):
                    value = strings[raw]
                elif dtype == 0x03 and val < len(strings):
                    value = strings[val]
                elif dtype == 0x12:
                    value = val != 0
                elif dtype in (0x10, 0x11):
                    value = val
                elif dtype == 0x01:
                    value = f"@0x{val:08x}"
                else:
                    value = val
                attrs[key] = value
            out.append((strings[name] if name < len(strings) else "?", attrs))
        elif ctype == 0x0103:
            name = struct.unpack_from("<I", data, off + 20)[0]
            out.append(("/" + (strings[name] if name < len(strings) else "?"), {}))
        off += csize
    return out


@dataclass
class Manifest:
    package: str = ""
    version: str = ""
    permissions: list[str] = field(default_factory=list)
    services: list[dict] = field(default_factory=list)
    receivers: list[dict] = field(default_factory=list)
    activities: int = 0
    min_sdk: int | None = None
    target_sdk: int | None = None


def read_manifest(data: bytes) -> Manifest:
    m = Manifest()
    stack, current = [], None
    for name, attrs in parse_axml(data):
        if name.startswith("/"):
            if stack:
                stack.pop()
            continue
        stack.append(name)
        if name == "manifest":
            m.package, m.version = str(attrs.get("package", "")), str(attrs.get("versionName", ""))
        elif name in ("uses-permission", "uses-permission-sdk-23"):
            m.permissions.append(str(attrs.get("name", "")))
        elif name == "uses-sdk":
            m.min_sdk, m.target_sdk = attrs.get("minSdkVersion"), attrs.get("targetSdkVersion")
        elif name in ("service", "receiver"):
            current = {"name": str(attrs.get("name", "")), "permission": str(attrs.get("permission", "")), "actions": []}
            (m.services if name == "service" else m.receivers).append(current)
        elif name == "activity":
            m.activities += 1
        elif name == "action" and current is not None and "intent-filter" in stack:
            current["actions"].append(str(attrs.get("name", "")))
    return m


# ------------------------------------------------------------------ signatures

def _u32_blocks(buf: bytes):
    p = 0
    while p + 4 <= len(buf):
        n = struct.unpack_from("<I", buf, p)[0]
        yield buf[p + 4 : p + 4 + n]
        p += 4 + n


def v2_certificates(apk: bytes) -> tuple[list[bytes], list[str]]:
    eocd = apk.rfind(b"PK\x05\x06")
    if eocd < 0:
        return [], []
    cd_off = struct.unpack_from("<I", apk, eocd + 16)[0]
    if cd_off < 32 or apk[cd_off - 16 : cd_off] != b"APK Sig Block 42":
        return [], []
    size = struct.unpack_from("<Q", apk, cd_off - 24)[0]
    start = cd_off - size - 8
    p, end, certs, schemes = start + 8, cd_off - 24, [], []
    while p + 12 <= end:
        length, pid = struct.unpack_from("<QI", apk, p)
        value = apk[p + 12 : p + 8 + length]
        if pid in (0x7109871A, 0xF05368C0):
            schemes.append("v2" if pid == 0x7109871A else "v3")
            for signers in _u32_blocks(value):
                for signer in _u32_blocks(signers):
                    signed_data = next(_u32_blocks(signer))
                    blocks = _u32_blocks(signed_data)
                    next(blocks)  # digests
                    for cert in _u32_blocks(next(blocks)):
                        certs.append(cert)
        p += 8 + length
    return certs, schemes


def certificate_info(der: bytes) -> dict:
    from cryptography import x509

    c = x509.load_der_x509_certificate(der)
    return {"subject": c.subject.rfc4514_string(), "issuer": c.issuer.rfc4514_string(),
            "sha256": hashlib.sha256(der).hexdigest(), "not_before": c.not_valid_before_utc.date().isoformat(),
            "not_after": c.not_valid_after_utc.date().isoformat(), "self_signed": c.subject == c.issuer}


def signing_certificates(z: zipfile.ZipFile, raw: bytes) -> tuple[list[dict], list[str]]:
    from cryptography.hazmat.primitives.serialization import Encoding, pkcs7

    infos, schemes = [], []
    for n in z.namelist():
        if n.upper().startswith("META-INF/") and n.upper().endswith((".RSA", ".DSA", ".EC")):
            if z.getinfo(n).file_size > MAX_SIG_FILE_BYTES:
                continue
            try:
                for c in pkcs7.load_der_pkcs7_certificates(z.read(n)):
                    infos.append(certificate_info(c.public_bytes(Encoding.DER)))
                schemes.append("v1")
            except ValueError:
                pass
    v2, s2 = v2_certificates(raw)
    schemes += s2
    for der in v2:
        info = certificate_info(der)
        if info["sha256"] not in {i["sha256"] for i in infos}:
            infos.append(info)
    return infos, sorted(set(schemes))


OFFICIAL_CERTS = Path(__file__).resolve().parent / "official_certs.json"


def _official_fingerprints() -> dict[str, list[str]]:
    return json.loads(OFFICIAL_CERTS.read_text()) if OFFICIAL_CERTS.exists() else {}


def analyze_apk(data: bytes, filename: str = "app.apk") -> Verdict:
    v = Verdict("apk", filename, entities={"sha256": hashlib.sha256(data).hexdigest()})
    try:
        z = zipfile.ZipFile(io.BytesIO(data))
        info = z.getinfo("AndroidManifest.xml")
        if info.file_size > MAX_MANIFEST_BYTES or len(z.infolist()) > MAX_ZIP_ENTRIES:
            raise AxmlError("archive or manifest is implausibly large (possible zip bomb)")
        man = read_manifest(z.read(info))
    except (zipfile.BadZipFile, KeyError, AxmlError, struct.error, IndexError, UnicodeDecodeError) as e:
        v.add(3, f"not a readable APK ({e.__class__.__name__}): may be corrupted or deliberately malformed", "format")
        return v
    try:
        certs, schemes = signing_certificates(z, data)
    except (ValueError, struct.error, StopIteration, IndexError, zipfile.BadZipFile) as e:
        certs, schemes = [], []
        v.add(1.5, f"signing data could not be parsed ({e.__class__.__name__}): malformed or tampered", "signature")
    v.entities.update(package=man.package, version=man.version, permissions=man.permissions,
                      services=[s["name"] for s in man.services], signing_schemes=schemes, certificates=certs)

    official = official_packages()
    pkg = man.package.lower()
    if man.package in official:
        fps = _official_fingerprints().get(man.package)
        if fps and certs and not any(c["sha256"] in fps for c in certs):
            v.add(6, f"uses the official package name {man.package} but is signed with a different key: a repackaged fake", "impersonation")
        elif fps and certs:
            v.add(-4, "signed with the brand's official certificate", "reputation")
    else:
        for key, b in BRANDS.items():
            if any(n.replace(" ", "") in pkg.replace(".", "").replace("_", "") for n in b["names"] if len(n) >= 3):
                v.add(4, f"package '{man.package}' imitates {key.upper()} but is not its official app", "impersonation")
                break
        if any(w in pkg for w in ("kyc", "rewards", "reward", "refund", "pointsredeem", "cashback", "update", "aadhar", "aadhaar", "pmkisan", "rto", "challan")):
            v.add(2, f"package name '{man.package}' uses a lure word", "lure")

    for perm in man.permissions:
        if perm in PERMISSION_RISK:
            w, msg = PERMISSION_RISK[perm]
            v.add(w, msg, "permission")
    for s in man.services:
        if s["permission"] in SERVICE_RISK:
            w, msg = SERVICE_RISK[s["permission"]]
            v.add(w, msg, "component")
    for r in man.receivers:
        if r["permission"] == "android.permission.BIND_DEVICE_ADMIN":
            w, msg = SERVICE_RISK["android.permission.BIND_DEVICE_ADMIN"]
            v.add(w, msg, "component")
        if "android.provider.Telephony.SMS_RECEIVED" in r["actions"]:
            v.add(1.5, "listens for every incoming SMS in the background", "component")
    perms = set(man.permissions)
    has_access = any(s["permission"] == "android.permission.BIND_ACCESSIBILITY_SERVICE" for s in man.services)
    if (perms & {"android.permission.RECEIVE_SMS", "android.permission.READ_SMS"}) and "android.permission.INTERNET" in perms and has_access:
        v.add(2, "classic banking-trojan combination: reads SMS + remote screen control + internet", "profile")

    if not certs:
        v.add(3, "no signing certificate found", "signature")
    for c in certs:
        if "Android Debug" in c["subject"]:
            v.add(2, "signed with an Android debug key (never used for store releases)", "signature")
    v.advice = ("Do not install. Delete the file and, if installed, uninstall it, change net-banking passwords from "
                "another device and call your bank." if v.risk >= 40 else
                "No banking-trojan traits found. Prefer installing banking apps only from the Play Store.")
    return v
