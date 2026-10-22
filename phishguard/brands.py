"""Reference data: brands that phishing in Indian payments impersonates, their real
domains and Android package names, and the UPI handles that belong to PSP banks.

Keep this list current for production; it is the ground truth the detectors compare
against. Fingerprints of official signing certificates can be added per brand to turn
the APK check from "suspicious" into "proven fake".
"""
from __future__ import annotations

BRANDS: dict[str, dict] = {
    "sbi": {"names": ["sbi", "state bank", "yono", "onlinesbi"], "domains": ["sbi.co.in", "onlinesbi.sbi", "sbi.bank.in", "sbicard.com"],
            "packages": ["com.sbi.lotusintouch", "com.sbi.SBIFreedomPlus", "com.sbi.upi"]},
    "hdfc": {"names": ["hdfc"], "domains": ["hdfcbank.com", "hdfc.bank.in", "hdfcbank.net"], "packages": ["com.snapwork.hdfc", "com.hdfcbank.payzapp"]},
    "icici": {"names": ["icici", "imobile"], "domains": ["icicibank.com", "icici.bank.in"], "packages": ["com.csam.icici.bank.imobile"]},
    "axis": {"names": ["axis bank", "axisbank"], "domains": ["axisbank.com", "axis.bank.in"], "packages": ["com.axis.mobile"]},
    "kotak": {"names": ["kotak"], "domains": ["kotak.com", "kotak.bank.in"], "packages": ["com.msf.kbank.mobile"]},
    "pnb": {"names": ["pnb", "punjab national"], "domains": ["pnbindia.in", "pnb.bank.in"], "packages": ["com.Version1"]},
    "bob": {"names": ["bank of baroda", "bob world", "bankofbaroda"], "domains": ["bankofbaroda.in", "bankofbaroda.bank.in"], "packages": ["com.bankofbaroda.mconnect"]},
    "paytm": {"names": ["paytm"], "domains": ["paytm.com", "paytmbank.com", "paytm.in"], "packages": ["net.one97.paytm"]},
    "phonepe": {"names": ["phonepe", "phone pe"], "domains": ["phonepe.com"], "packages": ["com.phonepe.app"]},
    "gpay": {"names": ["google pay", "gpay"], "domains": ["google.com", "pay.google.com"], "packages": ["com.google.android.apps.nbu.paisa.user"]},
    "bhim": {"names": ["bhim", "npci"], "domains": ["npci.org.in", "bhimupi.org.in"], "packages": ["in.org.npci.upiapp"]},
    "amazonpay": {"names": ["amazon pay", "amazon"], "domains": ["amazon.in", "amazon.com"], "packages": ["in.amazon.mShop.android.shopping"]},
    "rbi": {"names": ["rbi", "reserve bank"], "domains": ["rbi.org.in"], "packages": []},
    "incometax": {"names": ["income tax", "incometax", "itr refund"], "domains": ["incometax.gov.in"], "packages": []},
    "indiapost": {"names": ["india post", "indiapost", "speed post"], "domains": ["indiapost.gov.in"], "packages": ["com.indiapost.ippb"]},
    "epfo": {"names": ["epfo", "epfindia"], "domains": ["epfindia.gov.in"], "packages": []},
    "electricity": {"names": ["electricity board", "bescom", "msedcl", "tneb", "bses"], "domains": ["bescom.co.in", "mahadiscom.in", "tnebltd.gov.in", "bsesdelhi.com"], "packages": []},
}

# well-known sites that are not payment brands but appear in normal links
COMMON_SAFE = ["google.com", "youtube.com", "wikipedia.org", "github.com", "microsoft.com", "apple.com", "flipkart.com",
               "irctc.co.in", "gov.in", "nic.in", "linkedin.com", "zomato.com", "swiggy.com", "myntra.com", "makemytrip.com"]

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rb.gy", "shorturl.at", "tiny.cc", "ow.ly", "s.id", "rebrand.ly", "v.gd"}

# free hosting / tunnels: legitimate services, heavily abused for phishing kits
FREE_HOSTING = {"web.app", "firebaseapp.com", "vercel.app", "netlify.app", "github.io", "pages.dev", "glitch.me",
                "000webhostapp.com", "weebly.com", "wixsite.com", "blogspot.com", "ngrok-free.app", "ngrok.io",
                "trycloudflare.com", "herokuapp.com", "onrender.com", "repl.co", "duckdns.org", "sites.google.com"}

RISKY_TLDS = {"xyz", "top", "click", "link", "buzz", "rest", "icu", "monster", "cyou", "cfd", "sbs", "online", "site",
              "live", "shop", "support", "help", "info", "work", "loan", "win", "bid", "gq", "tk", "ml", "cf", "ga"}

MULTI_PART_SUFFIXES = {"co.in", "org.in", "net.in", "gov.in", "ac.in", "res.in", "nic.in", "bank.in", "edu.in", "firm.in",
                       "gen.in", "ind.in", "co.uk", "org.uk", "com.au", "co.jp", "com.br", "com.sg"}

# UPI handles (the part after @) issued by PSP banks / apps. Unknown handles are not
# necessarily fake (new PSPs appear) but are worth a warning.
UPI_HANDLES = {
    "okaxis", "oksbi", "okhdfcbank", "okicici", "ybl", "ibl", "axl", "paytm", "ptsbi", "pthdfc", "ptaxis", "ptyes",
    "upi", "apl", "yapl", "rapl", "ikwik", "freecharge", "airtel", "jio", "kotak", "kmbl", "hdfcbank", "icici",
    "sbi", "axisbank", "axisb", "yesbank", "yesbankltd", "idfcbank", "idfcfirst", "indus", "federal", "fbl", "pnb",
    "barodampay", "boi", "cnrb", "unionbankofindia", "uboi", "aubank", "rbl", "dbs", "hsbc", "sc", "citi",
    "waaxis", "wahdfcbank", "wasbi", "waicici", "naviaxis", "mbk", "timecosmos", "abfspay", "jupiteraxis", "fam", "slc",
    "superyes", "tapicici", "pingpay", "nsdl", "postbank", "ippb", "equitas", "jsb", "kbl", "kvb", "tmb", "csbpay", "dlb",
}

LOOKALIKE_TABLE = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "@": "a", "$": "s",
                                 "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j",
                                 "ѕ": "s", "ԁ": "d", "ɡ": "g", "ո": "n", "ս": "u", "ν": "v", "ο": "o", "α": "a"})


def official_domains() -> set[str]:
    return {d for b in BRANDS.values() for d in b["domains"]}


def official_packages() -> dict[str, str]:
    return {p: k for k, b in BRANDS.items() for p in b["packages"]}
