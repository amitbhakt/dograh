import re
from typing import Optional, Tuple

try:
    from fastapi import HTTPException
except ImportError:
    class HTTPException(Exception):  # type: ignore
        def __init__(self, status_code: int = 400, detail: str = ""):
            self.status_code = status_code
            self.detail = detail
            super().__init__(detail)

# Meta officially restricts Business-Initiated Calls (BIC) in:
# United States (+1), Canada (+1), Egypt (+20), Vietnam (+84), Nigeria (+234)
RESTRICTED_BIC_COUNTRIES = {
    "US": "United States",
    "CA": "Canada",
    "EG": "Egypt",
    "VN": "Vietnam",
    "NG": "Nigeria",
}

RESTRICTED_BIC_PREFIXES = {
    "+1": "United States and Canada (+1)",
    "+20": "Egypt (+20)",
    "+84": "Vietnam (+84)",
    "+234": "Nigeria (+234)",
}


_NON_DIAL_CHARS_RE = re.compile(r"[^\d+]")


def _restricted_reason(name: str) -> str:
    return (
        f"Business-Initiated WhatsApp Calls are not permitted in {name} "
        "due to Meta platform regulations. Inbound calling remains supported."
    )


def is_restricted_country(phone_number: str) -> Tuple[bool, Optional[str]]:
    """Check whether a number is in one of Meta's restricted BIC countries.

    Classifies only numbers that state their country, i.e. E.164 with a leading
    "+". Every path that reaches an outbound call now guarantees that:
    campaign leads are rejected at ingest without one (``validate_source_data``),
    and the test-call and public API routes enforce ``is_e164`` on the resolved
    number. So a bare number never arrives here, and this does not try to infer
    a country from one.

    That inference used to live here and could not be made correct. A bare
    11-digit number starting with "1" is either a US number carrying its country
    code or a Chinese mobile without one, and nothing in the digits separates
    them - so the rule either blocked legitimate Chinese calls or let US calls
    through. Requiring the country code upstream removes the ambiguity instead
    of choosing which way to be wrong.

    A "+" anywhere in the input (``"++20..."``, ``"+ +20..."``) still counts:
    all "+" are dropped and one canonical leading "+" is re-added before
    matching. This mirrors the dial path, which strips every non-digit and
    redials ``f"+{digits}"`` - so a malformed extra "+" cannot smuggle a
    restricted destination past this gate.

    Returns:
        Tuple of (is_restricted: bool, reason: Optional[str])
    """
    stripped = _NON_DIAL_CHARS_RE.sub("", phone_number.strip())
    if "+" not in stripped:
        # No country code: not classifiable, and by the invariant above this
        # should not reach a dial path. Nothing to assert about it here.
        return False, None

    digits_only = stripped.replace("+", "")
    if not digits_only:
        # "+" or "++" alone.
        return False, None

    canonical = "+" + digits_only
    for prefix, name in RESTRICTED_BIC_PREFIXES.items():
        if canonical.startswith(prefix):
            return True, _restricted_reason(name)
    return False, None


def validate_destination_country(phone_number: str) -> None:
    """Validate that the destination phone number is not in Meta's restricted countries.

    Raises:
        HTTPException: 400 if the destination is in a restricted country.
    """
    restricted, reason = is_restricted_country(phone_number)
    if restricted:
        raise HTTPException(status_code=400, detail=reason)
