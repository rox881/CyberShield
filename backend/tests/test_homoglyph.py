"""
Standalone test script for homoglyph detection in url_analyser.py
Run from: d:\\Ritesh\\Projects\\hackathons\\HackUp\\phishguard-v1.1\\backend

Usage:
    cd d:\\Ritesh\\Projects\\hackathons\\HackUp\\phishguard-v1.1\\backend
    python tests\\test_homoglyph.py
"""

import sys
import os

# Ensure backend root is in path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engines.url_analyser import (
    detect_homoglyphs,
    analyse_domain_homoglyphs,
    analyse_url,
    _normalise_to_ascii,
)

PASS_LABEL = "[PASS]"
FAIL_LABEL = "[FAIL]"


def check(condition: bool, label: str) -> bool:
    status = PASS_LABEL if condition else FAIL_LABEL
    print(f"  {status}  {label}")
    return condition


def run_all() -> int:
    """Return count of failures."""
    failures = 0

    print("\n-- 1. Digit substitution: paypa1 -> paypal ----------------------")
    detected, chars = analyse_domain_homoglyphs("paypa1")
    failures += 0 if check(detected, "paypa1 detected (digit sub '1'->l)") else 1
    norm, _ = _normalise_to_ascii("paypa1")
    failures += 0 if check(norm == "paypal", f"paypa1 normalises to 'paypal' (got '{norm}')") else 1

    print("\n-- 2. Cyrillic confusable: a->a (U+0430) ------------------------")
    # Cyrillic a (U+0430) is visually identical to Latin 'a'
    cyrillic_amazon = "\u0430m\u0430zon"
    detected, chars = analyse_domain_homoglyphs(cyrillic_amazon)
    failures += 0 if check(detected, "Cyrillic-a amazon domain detected") else 1
    failures += 0 if check(
        any("U+0430" in c for c in chars),
        f"U+0430 listed in confusables: {chars}"
    ) else 1

    print("\n-- 3. Mixed-script: Cyrillic+Latin in same word -----------------")
    # g + Cyrillic-o (U+043E) + gle
    mixed = "g\u043egle"
    detected, chars = analyse_domain_homoglyphs(mixed)
    failures += 0 if check(detected, "g(Cyrillic-o)gle mixed-script detected") else 1

    print("\n-- 4. ASCII-only rn: NO false positive --------------------------")
    # 'rnicrosoft' has only ASCII; new detector does not flag rn->m (render-only)
    detected_rn, _ = analyse_domain_homoglyphs("rnicrosoft")
    failures += 0 if check(not detected_rn, "rnicrosoft not flagged (avoids ASCII false positive)") else 1

    print("\n-- 5. Punycode/IDN: xn-- label with diacritic -------------------")
    # xn--mzon-7ra decodes to 'mzoyn' (y-acute = U+00FD, now in confusable map)
    # This exercises the IDN decode path + diacritic confusable detection
    detected_idn, chars_idn = analyse_domain_homoglyphs("xn--mzon-7ra.com")
    failures += 0 if check(detected_idn, "xn--mzon-7ra.com IDN domain detected") else 1
    failures += 0 if check(len(chars_idn) > 0, f"Confusables listed: {chars_idn}") else 1

    print("\n-- 6. Brand-spoof normalisation ---------------------------------")
    detected_bs, chars_bs = analyse_domain_homoglyphs("paypa1.com")
    failures += 0 if check(detected_bs, "paypa1.com flagged") else 1
    failures += 0 if check(
        any("paypal" in c for c in chars_bs),
        f"brand-spoof detail present: {chars_bs}"
    ) else 1

    print("\n-- 7. Clean domains: no false positives -------------------------")
    for clean in ["google.com", "microsoft.com", "amazon.com", "github.com"]:
        det, _ = analyse_domain_homoglyphs(clean)
        failures += 0 if check(not det, f"{clean} is clean") else 1

    print("\n-- 8. analyse_url: score and severity for lookalike URL ---------")
    # Use Cyrillic-a in amazon domain
    url_hg = "https://\u0430mazon.com/login/verify"
    signals = analyse_url(url_hg)
    sig = next((s for s in signals if s.name == "Lookalike domain"), None)
    failures += 0 if check(sig is not None, "Lookalike domain signal emitted") else 1
    if sig:
        failures += 0 if check(sig.score >= 90, f"Score >= 90 (got {sig.score})") else 1
        failures += 0 if check(sig.severity == "red", f"Severity='red' (got '{sig.severity}')") else 1
        failures += 0 if check(
            "confusable" in sig.detail.lower() or "U+" in sig.detail,
            f"Detail mentions confusable: {repr(sig.detail)}"
        ) else 1

    print("\n-- 9. detect_homoglyphs: Cyrillic-o in email sender -------------")
    # Cyrillic-o (U+043E) in username
    spoof = "supp\u043ert@paypal.com"
    hg_det, hg_chars, _ = detect_homoglyphs(spoof)
    failures += 0 if check(hg_det, f"Homoglyph detected in '{repr(spoof)}'") else 1
    failures += 0 if check(len(hg_chars) > 0, f"Confusable chars: {hg_chars}") else 1

    print("\n" + "-" * 60)
    if failures == 0:
        print("[ALL TESTS PASSED]")
    else:
        print(f"[{failures} TEST(S) FAILED]")
    return failures


if __name__ == "__main__":
    sys.exit(run_all())
