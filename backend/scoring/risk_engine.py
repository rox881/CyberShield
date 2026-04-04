"""
Risk engine — weighted multi-signal scoring with input-type awareness.
Optimizations over v1:
  - Input-type specific weight profiles (email vs URL vs attachment)
  - Confidence decay: low-confidence signals weighted down
  - Hard floor raised for critical signal combinations
  - Explainability: returns contributing signals sorted by impact
"""
from models.scan_models import SignalResult
from config import settings

# Weight profiles per input type
WEIGHTS_EMAIL = {
    "Urgency language":     0.11,
    "Credential request":   0.16,
    "Brand impersonation":  0.13,
    "Sender authenticity":  0.16,
    "Display-name spoof":   0.20,  # high-weight signal
    "Text quality":         0.04,
    "Link density":         0.08,
    "IP as hostname":       0.14,
    "Domain TLD":           0.07,
    "Subdomain depth":      0.05,
    "Lookalike domain":     0.22,  # raised from 0.18
    "Homoglyph in sender":  0.24,  # new — Unicode confusable in sender addr
    "URL shortener":        0.07,
    "URL encoding":         0.04,
    "Path keywords":        0.06,
}

WEIGHTS_URL = {
    "IP as hostname":    0.25,
    "Lookalike domain":  0.35,  # raised from 0.25 — strongest single URL signal
    "Domain TLD":        0.15,
    "URL shortener":     0.12,
    "Subdomain depth":   0.10,
    "URL encoding":      0.08,
    "Path keywords":     0.10,
}

WEIGHTS_ATTACHMENT = {
    "File extension":         0.20,
    "Magic bytes / file type": 0.25,
    "Double extension":        0.25,
    "Filename suspicion":      0.12,
    "Office macros":           0.20,
    "PDF embedded JS":         0.18,
    "File size":               0.05,
}

DEFAULT_WEIGHT = 0.08

# Signal combinations that should hard-floor the score
CRITICAL_COMBOS = [
    # Display-name spoof + any credential request → always at least 75
    ({"Display-name spoof", "Credential request"}, 75),
    # IP host + path keywords → at least 70
    ({"IP as hostname", "Path keywords"}, 70),
    # Lookalike + brand impersonation → at least 72
    ({"Lookalike domain", "Brand impersonation"}, 72),
    # Double extension + macros → at least 80
    ({"Double extension", "Office macros"}, 80),
    # Lookalike domain + credential request → clear phishing attempt, at least 80
    ({"Lookalike domain", "Credential request"}, 80),
    # Homoglyph sender + brand impersonation → highly targeted attack, at least 85
    ({"Homoglyph in sender", "Brand impersonation"}, 85),
]


def _get_weights(signals: list[SignalResult]) -> dict:
    names = {s.name for s in signals}
    # Detect input type by signal presence
    if "File extension" in names or "Magic bytes / file type" in names:
        return WEIGHTS_ATTACHMENT
    if len(names & set(WEIGHTS_URL.keys())) >= 3 and "Urgency language" not in names:
        return WEIGHTS_URL
    return WEIGHTS_EMAIL


def compute_score(signals: list[SignalResult]) -> int:
    if not signals:
        return 0

    weights = _get_weights(signals)
    weighted_sum = 0.0
    total_weight = 0.0

    for signal in signals:
        w = weights.get(signal.name, DEFAULT_WEIGHT)
        # Confidence decay: signals with score 1-15 contribute less
        if 0 < signal.score < 15:
            w *= 0.5
        weighted_sum += signal.score * w
        total_weight += w

    if total_weight == 0:
        return 0

    raw = weighted_sum / total_weight

    # Single critical signal floor (score ≥ 85 → at least 65)
    max_signal = max(s.score for s in signals)
    if max_signal >= 85:
        raw = max(raw, 65)

    # Combination floors
    triggered = {s.name for s in signals if s.score >= 40}
    for combo, floor in CRITICAL_COMBOS:
        if combo.issubset(triggered):
            raw = max(raw, floor)

    return min(int(raw), 100)


def get_verdict(score: int) -> str:
    if score >= settings.threshold_suspicious:
        return "threat"
    if score >= settings.threshold_safe:
        return "suspicious"
    return "safe"


def top_reasons(signals: list[SignalResult], n: int = 3) -> list[str]:
    flagged = [s for s in signals if s.score > 25]
    flagged.sort(key=lambda s: s.score, reverse=True)
    return [f"{s.name}: {s.detail}" for s in flagged[:n]] or ["No significant threat indicators detected"]


def contributing_signals(signals: list[SignalResult]) -> list[SignalResult]:
    """Return signals sorted by score descending, for explainability."""
    return sorted([s for s in signals if s.score > 0], key=lambda s: s.score, reverse=True)
