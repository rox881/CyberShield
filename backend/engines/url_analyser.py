"""
URL analyser — structural and visual-deception signals.
v2 improvements:
  - Full Unicode confusables map (Cyrillic, Greek, Armenian, fullwidth,
    digit substitutions, mixed-script detection)
  - Punycode / IDN domain decoding for detected xn-- labels
  - Raised lookalike score (95) for higher precision
  - Richer detail messages with listed confusable chars
"""

import re
import unicodedata
import httpx
from urllib.parse import urlparse
from models.scan_models import SignalResult

# ---------------------------------------------------------------------------
# Static detection sets
# ---------------------------------------------------------------------------

SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".click", ".loan", ".work", ".gq", ".tk",
    ".ml", ".cf", ".ga", ".monster", ".zip", ".mov", ".icu",
    ".pw", ".cc", ".su", ".ru", ".cn",
}

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "buff.ly", "short.io", "rebrand.ly", "cutt.ly", "is.gd",
    "rb.gy", "tiny.cc", "shorte.st",
}

IP_PATTERN = re.compile(r"https?://(\d{1,3}\.){3}\d{1,3}")
ENCODED_PATTERN = re.compile(r"%[0-9a-fA-F]{2}")

# ---------------------------------------------------------------------------
# Unicode Confusables Map
# Maps visually deceptive characters → their ASCII equivalent
# Sources: Unicode confusables.txt (condensed to high-impact subset)
# ---------------------------------------------------------------------------

CONFUSABLE_MAP: dict[str, str] = {
    # ── Cyrillic lookalikes ────────────────────────────────────────────────
    "\u0430": "a",  # а (Cyrillic)   → a
    "\u0435": "e",  # е               → e
    "\u043e": "o",  # о               → o
    "\u0440": "r",  # р               → r
    "\u0441": "c",  # с               → c
    "\u0445": "x",  # х               → x
    "\u0443": "y",  # у               → y
    "\u0456": "i",  # і               → i
    "\u0410": "A",  # А               → A
    "\u0412": "B",  # В               → B
    "\u0415": "E",  # Е               → E
    "\u041a": "K",  # К               → K
    "\u041c": "M",  # М               → M
    "\u041d": "H",  # Н               → H
    "\u041e": "O",  # О               → O
    "\u0420": "P",  # Р               → P
    "\u0421": "C",  # С               → C
    "\u0422": "T",  # Т               → T
    "\u0425": "X",  # Х               → X
    # ── Greek lookalikes ──────────────────────────────────────────────────
    "\u03bf": "o",  # ο (Greek omicron)
    "\u03c1": "p",  # ρ               → p
    "\u03b1": "a",  # α               → a
    "\u03b5": "e",  # ε               → e
    "\u03bd": "v",  # ν               → v
    "\u039f": "O",  # Ο               → O
    "\u0391": "A",  # Α               → A
    "\u0392": "B",  # Β               → B
    "\u0395": "E",  # Ε               → E
    "\u0396": "Z",  # Ζ               → Z
    "\u0397": "H",  # Η               → H
    "\u0399": "I",  # Ι               → I
    "\u039a": "K",  # Κ               → K
    "\u039c": "M",  # Μ               → M
    "\u039d": "N",  # Ν               → N
    "\u03a1": "P",  # Ρ               → P
    "\u03a4": "T",  # Τ               → T
    "\u03a5": "Y",  # Υ               → Y
    "\u03a7": "X",  # Χ               → X
    # ── Armenian lookalikes ───────────────────────────────────────────────
    "\u0578": "o",  # օ               → o
    "\u0570": "h",  # հ               → h
    # ── Latin diacritics (common in IDN homoglyph domains) ───────────────────
    "\u00e0": "a",  # à  → a
    "\u00e1": "a",  # á  → a
    "\u00e2": "a",  # â  → a
    "\u00e3": "a",  # ã  → a
    "\u00e5": "a",  # å  → a  (also ring-above a)
    "\u00e8": "e",  # è  → e
    "\u00e9": "e",  # é  → e
    "\u00ea": "e",  # ê  → e
    "\u00eb": "e",  # ë  → e
    "\u00ec": "i",  # ì  → i
    "\u00ed": "i",  # í  → i
    "\u00ee": "i",  # î  → i
    "\u00ef": "i",  # ï  → i
    "\u00f2": "o",  # ò  → o
    "\u00f3": "o",  # ó  → o
    "\u00f4": "o",  # ô  → o
    "\u00f5": "o",  # õ  → o
    "\u00f9": "u",  # ù  → u
    "\u00fa": "u",  # ú  → u
    "\u00fb": "u",  # û  → u
    "\u00fd": "y",  # ý  → y (y-acute — appears in some IDN decodes)
    "\u00ff": "y",  # ÿ  → y
    "\u00f1": "n",  # ñ  → n
    "\u00e7": "c",  # ç  → c
    # ── Fullwidth Latin ───────────────────────────────────────────────────
    **{chr(0xFF01 + i): chr(0x21 + i) for i in range(94)},  # ！～ → !~
    # ── Digit substitutions (common phishing tricks) ──────────────────────
    "0": "o",   # zero → o
    "1": "l",   # one  → l / I
    "3": "e",   # 3    → e
    "4": "a",   # 4    → a
    "5": "s",   # 5    → s
    "6": "b",   # 6    → b (or g)
    "8": "b",   # 8    → b
    # ── Common ASCII homoglyphs ───────────────────────────────────────────
    "|": "l",
    "!": "i",
    "\u00f8": "o",  # ø               → o
    "\u00f6": "o",  # ö               → o
    "\u00fc": "u",  # ü               → u
    "\u00e4": "a",  # ä               → a
    "\u0131": "i",  # ı (dotless i)   → i
    "\u017f": "s",  # ſ (long s)      → s
    "\u1d0f": "o",  # ᴏ (small cap)   → o
    "\u1d00": "a",  # ᴀ               → a
}

# Known brand tokens that should trigger brand-mismatch bonus when confusables present
KNOWN_BRANDS = {
    "paypal", "google", "amazon", "microsoft", "apple", "facebook",
    "netflix", "instagram", "linkedin", "twitter", "dropbox", "github",
    "adobe", "docusign", "coinbase", "binance", "chase", "wellsfargo",
    "bankofamerica", "hdfc", "sbi", "icici",
}

# ---------------------------------------------------------------------------
# Confusable detection helpers
# ---------------------------------------------------------------------------

def _normalise_to_ascii(text: str) -> tuple[str, list[str]]:
    """
    Return the ASCII-equivalent string and a list of (original→ascii) pairs
    for every confusable character found.
    """
    result = []
    found: list[str] = []
    for ch in text:
        if ch in CONFUSABLE_MAP:
            replacement = CONFUSABLE_MAP[ch]
            result.append(replacement)
            if ch != replacement and not ch.isascii():
                found.append(f"U+{ord(ch):04X}({ch}→{replacement})")
        else:
            result.append(ch)
    return "".join(result), found


def _has_mixed_scripts(text: str) -> bool:
    """Return True if the text mixes Latin with another script (e.g. Cyrillic)."""
    scripts: set[str] = set()
    for ch in text:
        if ch.isalpha():
            name = unicodedata.name(ch, "")
            if "LATIN" in name:
                scripts.add("LATIN")
            elif "CYRILLIC" in name:
                scripts.add("CYRILLIC")
            elif "GREEK" in name:
                scripts.add("GREEK")
            elif "ARMENIAN" in name:
                scripts.add("ARMENIAN")
    # Mixed if Latin coexists with a non-Latin script
    return "LATIN" in scripts and len(scripts) > 1


def _decode_punycode_label(label: str) -> str | None:
    """Decode a single xn-- Punycode label to Unicode, return None on failure."""
    try:
        if label.startswith("xn--"):
            return label.encode("ascii").decode("idna")
    except (UnicodeError, UnicodeDecodeError):
        pass
    return None


def detect_homoglyphs(text: str) -> tuple[bool, list[str], str]:
    """
    Check a string (domain / email address) for visual homoglyph deception.

    Returns:
        (detected: bool, confusables: list[str], normalised: str)
    """
    text_lower = text.lower()
    _, found = _normalise_to_ascii(text_lower)
    mixed = _has_mixed_scripts(text_lower)
    if mixed:
        found.append("mixed-script")
    return bool(found), found, text_lower


def analyse_domain_homoglyphs(domain: str) -> tuple[bool, list[str]]:
    """
    Full domain-level homoglyph analysis including Punycode decoding.
    Returns (detected, confusable_descriptions).
    """
    all_found: list[str] = []
    labels = domain.split(".")

    for label in labels:
        # Punycode decode
        decoded = _decode_punycode_label(label)
        target = decoded if decoded else label

        _, found = _normalise_to_ascii(target)
        if found:
            all_found.extend(found)

        if _has_mixed_scripts(target):
            all_found.append(f"mixed-script in '{label}'")

        # Digit substitution check: normalised version matches a known brand
        normalised, _ = _normalise_to_ascii(target)
        # Remove non-alpha for brand comparison
        brand_candidate = re.sub(r"[^a-z]", "", normalised)
        if brand_candidate in KNOWN_BRANDS and brand_candidate != re.sub(r"[^a-z]", "", label):
            all_found.append(f"brand-spoof: '{label}' normalises to '{brand_candidate}'")

    return bool(all_found), all_found


# ---------------------------------------------------------------------------
# URL extraction & redirect following
# ---------------------------------------------------------------------------

def extract_urls(text: str) -> list[str]:
    return re.findall(r"https?://[^\s\"'<>]+", text)


async def follow_redirects(url: str, max_hops: int = 5) -> list[str]:
    chain = [url]
    try:
        async with httpx.AsyncClient(timeout=10, follow_redirects=False) as client:
            current = url
            for _ in range(max_hops):
                r = await client.head(current)
                if r.status_code in (301, 302, 303, 307, 308) and "location" in r.headers:
                    current = r.headers["location"]
                    chain.append(current)
                else:
                    break
    except Exception:
        pass
    return chain


# ---------------------------------------------------------------------------
# Per-URL signal analysis
# ---------------------------------------------------------------------------

def analyse_url(url: str) -> list[SignalResult]:
    signals = []
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        path = parsed.path.lower()
    except Exception:
        return [SignalResult(name="URL parse", score=50, severity="yellow", detail="Could not parse URL")]

    # ── IP as host ────────────────────────────────────────────────────────
    ip_score = 85 if IP_PATTERN.match(url) else 0
    signals.append(SignalResult(
        name="IP as hostname",
        score=ip_score,
        severity="red" if ip_score else "green",
        detail="Direct IP address used instead of domain name" if ip_score else "Uses domain name",
    ))

    # ── Suspicious TLD ────────────────────────────────────────────────────
    tld_score = 0
    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            tld_score = 65
            break
    signals.append(SignalResult(
        name="Domain TLD",
        score=tld_score,
        severity="yellow" if tld_score else "green",
        detail="TLD flagged as high-risk" if tld_score else "TLD appears normal",
    ))

    # ── Subdomain depth ───────────────────────────────────────────────────
    subdomain_count = domain.count(".")
    subdomain_score = min((subdomain_count - 1) * 20, 70) if subdomain_count > 2 else 0
    signals.append(SignalResult(
        name="Subdomain depth",
        score=subdomain_score,
        severity="yellow" if subdomain_score > 30 else "green",
        detail=f"{subdomain_count} subdomain level(s)",
    ))

    # ── Homoglyph / Lookalike domain ──────────────────────────────────────
    detected, confusables = analyse_domain_homoglyphs(domain)
    lookalike_score = 95 if detected else 0
    detail_str = (
        f"Visual deception detected — {len(confusables)} confusable(s): "
        + ", ".join(confusables[:5])
        + ("…" if len(confusables) > 5 else "")
        if detected
        else "No homoglyph or lookalike characters found"
    )
    signals.append(SignalResult(
        name="Lookalike domain",
        score=lookalike_score,
        severity="red" if lookalike_score else "green",
        detail=detail_str,
    ))

    # ── URL shortener ─────────────────────────────────────────────────────
    shortener_score = 55 if any(s in domain for s in SHORTENERS) else 0
    signals.append(SignalResult(
        name="URL shortener",
        score=shortener_score,
        severity="yellow" if shortener_score else "green",
        detail="URL shortened — true destination hidden" if shortener_score else "Direct URL",
    ))

    # ── Excessive encoding ────────────────────────────────────────────────
    encoded_matches = ENCODED_PATTERN.findall(url)
    encode_score = min(len(encoded_matches) * 10, 65)
    signals.append(SignalResult(
        name="URL encoding",
        score=encode_score,
        severity="yellow" if encode_score > 20 else "green",
        detail=f"{len(encoded_matches)} encoded segment(s) detected",
    ))

    # ── Login/credential path keywords ────────────────────────────────────
    path_keywords = [
        "login", "signin", "verify", "account", "secure", "update",
        "confirm", "auth", "credential", "password", "reset", "token",
    ]
    path_hits = [k for k in path_keywords if k in path]
    path_score = min(len(path_hits) * 15, 65)
    signals.append(SignalResult(
        name="Path keywords",
        score=path_score,
        severity="yellow" if path_score > 20 else "green",
        detail=f"Sensitive path keywords: {', '.join(path_hits) or 'none'}",
    ))

    return signals


# ---------------------------------------------------------------------------
# Aggregate over multiple URLs
# ---------------------------------------------------------------------------

def analyse_urls_in_text(text: str) -> list[SignalResult]:
    urls = extract_urls(text)
    if not urls:
        return [SignalResult(name="URL presence", score=0, severity="green", detail="No URLs found in content")]

    all_signals = []
    for url in urls[:5]:  # analyse top 5 URLs (was 3)
        all_signals.extend(analyse_url(url))

    # Aggregate: take max score per signal type
    aggregated: dict[str, SignalResult] = {}
    for s in all_signals:
        if s.name not in aggregated or s.score > aggregated[s.name].score:
            aggregated[s.name] = s

    return list(aggregated.values())
