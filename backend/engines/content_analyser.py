"""
Content analyser — NLP heuristics for email phishing detection.
Optimizations over v1:
  - Reply-to / display-name spoofing detection
  - HTML-only / invisible text detection
  - Extended urgency + credential patterns
  - Sender domain age proxy via pattern matching
  - Reduced false positives on legitimate transactional emails
Optimizations over v2:
  - Homoglyph / Unicode confusable detection in sender email address
"""
import re
from models.scan_models import SignalResult
from engines.url_analyser import detect_homoglyphs

URGENCY_PATTERNS = [
    r"urgent", r"immediately", r"within \d+ hours?", r"account.*suspended",
    r"verify.*now", r"click here", r"final warning", r"act now",
    r"limited time", r"expire[sd]?", r"unusual activity", r"unauthorized",
    r"will be (closed|terminated|suspended|deleted)",
    r"last (chance|warning|notice)",
    r"action required", r"response (required|needed)",
    r"your account (will|has been|is)",
]

CREDENTIAL_PATTERNS = [
    r"enter.*password", r"confirm.*account", r"update.*payment",
    r"verify.*identity", r"login.*details", r"bank.*details",
    r"social security", r"credit card", r"otp|one.time.pass",
    r"sign in to", r"re-?enter.*credentials",
    r"provide.*account (number|details|info)",
    r"billing (information|details|update)",
]

BRAND_IMPERSONATION = [
    "paypal", "amazon", "apple", "microsoft", "google", "facebook",
    "netflix", "hdfc", "sbi", "icici", "chase", "wells fargo",
    "instagram", "whatsapp", "linkedin", "dropbox", "docusign",
    "coinbase", "binance", "crypto", "dhl", "fedex", "ups",
    "irs", "hmrc", "income tax", "twitter", "x.com",
]

SUSPICIOUS_SENDER_PATTERNS = [
    r"noreply@(?!.*\.(com|org|net)$)",
    r"support@.*\d{4,}",
    r"security.*alert@",
    r"no-reply@.*\.xyz",
    r"verify@",
    r"@.*-secure\.",
    r"@.*secure-.*\.",
    r"@.*-login\.",
    r"@.*login-.*\.",
    r"@.*-alert\.",
]

# Patterns that strongly indicate legitimate transactional email
LEGIT_INDICATORS = [
    r"unsubscribe",
    r"view.*in.*browser",
    r"you.*subscribed",
    r"your (order|receipt|invoice) (number|#)",
    r"tracking number",
]


def analyse_content(text: str, sender: str = "", subject: str = "") -> list[SignalResult]:
    signals = []
    text_lower = text.lower()

    # ── Legitimacy pre-check ──────────────────────────────────────────────
    # Reduce scores if strong legit indicators are present
    legit_hits = sum(1 for p in LEGIT_INDICATORS if re.search(p, text_lower))
    legit_dampener = min(legit_hits * 0.15, 0.4)  # max 40% reduction

    def dampen(score: int) -> int:
        return max(0, int(score * (1 - legit_dampener)))

    # ── Urgency score ─────────────────────────────────────────────────────
    urgency_hits = [p for p in URGENCY_PATTERNS if re.search(p, text_lower)]
    urgency_score = dampen(min(len(urgency_hits) * 12, 88))
    signals.append(SignalResult(
        name="Urgency language",
        score=urgency_score,
        severity="red" if urgency_score > 40 else "yellow" if urgency_score > 0 else "green",
        detail=f"{len(urgency_hits)} urgency trigger(s): {', '.join(urgency_hits[:3]) or 'none'}",
    ))

    # ── Credential harvesting ─────────────────────────────────────────────
    cred_hits = [p for p in CREDENTIAL_PATTERNS if re.search(p, text_lower)]
    cred_score = dampen(min(len(cred_hits) * 20, 95))
    signals.append(SignalResult(
        name="Credential request",
        score=cred_score,
        severity="red" if cred_score > 30 else "green",
        detail=f"{len(cred_hits)} credential pattern(s) detected",
    ))

    # ── Brand impersonation ───────────────────────────────────────────────
    brands_found = [b for b in BRAND_IMPERSONATION if b in text_lower or b in subject.lower()]
    brand_score = 60 if brands_found else 0
    if brands_found and sender:
        for brand in brands_found:
            if brand.replace(" ", "") in sender.lower().replace("-", ""):
                brand_score = 0
                break
    brand_score = dampen(brand_score)
    signals.append(SignalResult(
        name="Brand impersonation",
        score=brand_score,
        severity="red" if brand_score > 0 else "green",
        detail=f"Brand(s) referenced: {', '.join(brands_found) or 'none'}",
    ))

    # ── Sender authenticity ───────────────────────────────────────────────
    sender_score = 0
    sender_detail = "Sender pattern looks normal"

    if sender:
        # Pattern-based suspicious sender
        for p in SUSPICIOUS_SENDER_PATTERNS:
            if re.search(p, sender.lower()):
                sender_score = 72
                sender_detail = f"Suspicious sender pattern: {sender}"
                break

        # Domain mismatch with referenced brand
        if not sender_score and "@" in sender:
            domain = sender.split("@")[-1].lower()
            mismatched = [
                b for b in brands_found
                if b.replace(" ", "") not in domain.replace("-", "")
            ]
            if mismatched:
                sender_score = 80
                sender_detail = f"Sender '{domain}' doesn't match referenced brand(s): {', '.join(mismatched)}"

    signals.append(SignalResult(
        name="Sender authenticity",
        score=sender_score,
        severity="red" if sender_score > 50 else "yellow" if sender_score > 0 else "green",
        detail=sender_detail,
    ))

    # ── Homoglyph in sender email ─────────────────────────────────────────
    # Detects Unicode confusable characters used in the sender address to
    # visually impersonate a brand (e.g. suppоrt@paypal.com with Cyrillic о)
    homoglyph_score = 0
    homoglyph_detail = "No homoglyph characters detected in sender address"
    if sender and "@" in sender:
        sender_domain = sender.split("@")[-1]
        hg_detected, hg_chars, _ = detect_homoglyphs(sender_domain)
        if not hg_detected:
            # Also check full address (username may contain confusables)
            hg_detected, hg_chars, _ = detect_homoglyphs(sender)
        if hg_detected:
            homoglyph_score = 90
            homoglyph_detail = (
                f"Homoglyph character(s) in sender '{sender}': "
                + ", ".join(hg_chars[:5])
                + ("…" if len(hg_chars) > 5 else "")
            )
    signals.append(SignalResult(
        name="Homoglyph in sender",
        score=homoglyph_score,
        severity="red" if homoglyph_score else "green",
        detail=homoglyph_detail,
    ))

    # ── Display-name spoofing ─────────────────────────────────────────────
    # e.g. "PayPal Security <evil@random.ru>" — display name mentions brand
    # but email address domain doesn't
    display_score = 0
    display_detail = "No display-name spoofing detected"
    # Look for "Brand Name <email@domain>" pattern
    header_match = re.search(r"From:\s*(.+?)\s*<([^>]+)>", text, re.IGNORECASE)
    if header_match:
        display_name = header_match.group(1).lower().strip()
        email_addr   = header_match.group(2).lower()
        email_domain = email_addr.split("@")[-1] if "@" in email_addr else ""
        for brand in BRAND_IMPERSONATION:
            if brand in display_name and brand.replace(" ", "") not in email_domain.replace("-", ""):
                display_score = 88
                display_detail = f'Display name "{header_match.group(1).strip()}" impersonates {brand.title()} but sends from {email_domain}'
                break
    signals.append(SignalResult(
        name="Display-name spoof",
        score=display_score,
        severity="red" if display_score >= 70 else "green",
        detail=display_detail,
    ))

    # ── Text quality ──────────────────────────────────────────────────────
    caps_ratio = sum(1 for c in text if c.isupper()) / max(len(text), 1)
    grammar_score = int(caps_ratio * 200) if caps_ratio > 0.15 else 0
    grammar_score = min(grammar_score, 60)
    signals.append(SignalResult(
        name="Text quality",
        score=grammar_score,
        severity="yellow" if grammar_score > 20 else "green",
        detail=f"Caps ratio {caps_ratio:.1%} — {'excessive' if grammar_score > 20 else 'normal'}",
    ))

    # ── HTML-only / cloaking ──────────────────────────────────────────────
    # Emails with almost no plain text but lots of links are suspicious
    word_count  = len(text.split())
    link_count  = len(re.findall(r"https?://", text))
    cloak_score = 0
    cloak_detail = "Normal text-to-link ratio"
    if word_count < 30 and link_count >= 2:
        cloak_score = 45
        cloak_detail = f"Very short email ({word_count} words) with {link_count} links — possible cloaking"
    elif link_count > 0 and word_count / max(link_count, 1) < 10:
        cloak_score = 30
        cloak_detail = f"High link density: {link_count} links in {word_count} words"
    signals.append(SignalResult(
        name="Link density",
        score=cloak_score,
        severity="yellow" if cloak_score > 0 else "green",
        detail=cloak_detail,
    ))

    return signals
