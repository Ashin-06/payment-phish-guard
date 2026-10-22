"""UPI payment links, QR payloads and VPAs.

The most common UPI scam is a 'receive money' story that ends with the victim
entering their UPI PIN on a prefilled pay request. These checks look for the tells.
"""
from __future__ import annotations

import re
from urllib.parse import parse_qsl, unquote, urlsplit

from .brands import BRANDS, UPI_HANDLES
from .verdict import Verdict

VPA_RE = re.compile(r"^[a-z0-9.\-_]{2,256}@[a-z][a-z0-9.\-]{1,63}$", re.I)
RECEIVE_WORDS = re.compile(r"\b(refund|cash ?back|prize|reward|lottery|won|winner|receive|credit(ed)?|bonus|gift|kyc|"
                           r"verification|verify|unlock|claim|return|reversal|compensation|subsidy|scholarship)\b", re.I)
URGENT_WORDS = re.compile(r"\b(urgent|immediately|today only|last chance|blocked|suspend|penalty|expire)\b", re.I)
GOV_WORDS = re.compile(r"\b(rbi|income tax|govt|government|police|cyber cell|customs|court|npci|trai)\b", re.I)


def parse_upi(payload: str) -> dict:
    p = urlsplit(payload.strip())
    params = {k.lower(): unquote(v) for k, v in parse_qsl(p.query, keep_blank_values=True)}
    return {"scheme": p.scheme.lower(), "action": (p.netloc or p.path).lower().strip("/"), **params}


def analyze_vpa(vpa: str, claimed_name: str = "", v: Verdict | None = None) -> Verdict:
    v = v or Verdict("vpa", vpa)
    vpa = vpa.strip().lower()
    if not VPA_RE.match(vpa):
        v.add(3, f"'{vpa}' is not a valid UPI ID", "format")
        return v
    user, handle = vpa.split("@", 1)
    if handle not in UPI_HANDLES:
        v.add(1.5, f"'@{handle}' is not a known bank/PSP UPI handle", "format")
    if re.fullmatch(r"[6-9]\d{9}", user):
        v.entities["phone_in_vpa"] = user
        if claimed_name and _claims_institution(claimed_name):
            v.add(3, f"payee claims to be '{claimed_name}' but the UPI ID is a personal mobile number", "impersonation")
    for key, b in BRANDS.items():
        if any(n.replace(" ", "") in user.replace(".", "") for n in b["names"] if len(n) > 3):
            v.add(2, f"UPI ID '{vpa}' uses the name of {key.upper()} in a personal handle", "impersonation")
            break
    if re.search(r"(refund|cashback|reward|kyc|support|care|help|helpdesk|customer)", user):
        v.add(2, f"UPI ID contains '{re.search(r'(refund|cashback|reward|kyc|support|care|help|helpdesk|customer)', user).group(1)}' - "
                 "banks do not collect money through such IDs", "lure")
    return v


def _claims_institution(name: str) -> bool:
    low = name.lower()
    return bool(GOV_WORDS.search(low) or re.search(r"\b(bank|refund|support|care|helpdesk|customer|official|desk|"
                                                    r"department|electricity|kyc)\b", low)
                or any(n in low for b in BRANDS.values() for n in b["names"] if len(n) > 3))


def analyze_upi(payload: str) -> Verdict:
    v = Verdict("upi", payload)
    q = parse_upi(payload)
    v.entities = {k: q.get(k) for k in ("pa", "pn", "am", "tn", "mc", "tr", "cu") if q.get(k)}
    if q["scheme"] != "upi":
        v.add(2, "not a UPI link", "format")
        return v
    if q["action"] == "collect":
        v.add(3, "this is a collect (request money) link: approving it sends YOUR money", "lure")
    elif q["action"] not in ("pay", "mandate"):
        v.add(1, f"unusual UPI action '{q['action']}'", "format")
    if q["action"] == "mandate":
        v.add(2.5, "sets up a recurring auto-debit mandate", "lure")
    pa, pn, tn = q.get("pa", ""), q.get("pn", ""), q.get("tn", "")
    if not pa:
        v.add(3, "no payee address (pa) in the link", "format")
    else:
        analyze_vpa(pa, pn, v)
    text = f"{pn} {tn}"
    if RECEIVE_WORDS.search(text):
        v.add(3.5, f"the note promises money ('{RECEIVE_WORDS.search(text).group(0)}'), but this link takes money: "
                   "you never enter a UPI PIN to receive", "lure")
    if URGENT_WORDS.search(text):
        v.add(1, "pressure language in the payment note", "lure")
    if pn and _claims_institution(pn) and not q.get("mc"):
        v.add(2, f"payee name '{pn}' claims to be an institution but the link has no merchant code", "impersonation")
    if q.get("mc") == "0000" or (q.get("mc") and not re.fullmatch(r"\d{4}", q["mc"])):
        v.add(1, f"invalid merchant category code '{q.get('mc')}'", "format")
    if q.get("am"):
        try:
            amt = float(q["am"])
            v.entities["amount"] = amt
            if amt <= 0:
                v.add(2, "non-positive amount", "format")
            elif amt >= 10_000:
                v.add(1, f"large prefilled amount ₹{amt:,.0f}", "amount")
        except ValueError:
            v.add(2, f"malformed amount '{q['am']}'", "format")
    if q.get("cu") and q["cu"].upper() != "INR":
        v.add(2, f"currency '{q['cu']}' is not INR", "format")
    v.advice = ("Entering your UPI PIN always sends money out of your account. Nobody needs your PIN to pay you."
                if v.risk >= 40 else "Check the payee name shown in your UPI app before entering the PIN.")
    return v
