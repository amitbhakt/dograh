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


# Numbers stripped down to only digits (and a leading "+" if present) shorter
# than this can't carry an explicit country code on top of a plausible
# national number, so their leading digits are never checked against a
# restricted dial code when there is no "+". This is exactly the length of a
# bare NANP number (area code + local number, no country code) -- the case
# that was previously misread as Egypt (+20) or Nigeria (+234) for numbers
# such as "2015551234" or "2345551234".
_MIN_BARE_INTERNATIONAL_LENGTH = 11

_NON_DIAL_CHARS_RE = re.compile(r"[^\d+]")


def _restricted_reason(name: str) -> str:
    return (
        f"Business-Initiated WhatsApp Calls are not permitted in {name} "
        "due to Meta platform regulations. Inbound calling remains supported."
    )


def is_restricted_country(phone_number: str) -> Tuple[bool, Optional[str]]:
    """Check if the given phone number falls into Meta's restricted BIC countries.

    Only numbers that genuinely carry an explicit country code are matched:
    either an E.164 "+" prefix, or -- absent a "+" -- a bare digit string long
    enough that it could not plausibly be a domestic number in an unrelated,
    shorter numbering plan (see `_MIN_BARE_INTERNATIONAL_LENGTH`).

    A bare number that is too short to disambiguate (e.g. a 10-digit NANP
    local number) is deliberately treated as NOT restricted (fail-open for
    that ambiguous case) rather than blocked outright: failing closed would
    reject legitimate domestic calls to non-restricted countries whenever a
    lead's number happens to be stored without a country code, which is the
    common case for US-only data. The tradeoff is that a genuinely restricted
    number entered without its country code slips through this check; that
    residual risk is a Meta BIC compliance exposure, not a correctness bug in
    the numbers this function *can* classify.

    Returns:
        Tuple of (is_restricted: bool, reason: Optional[str])
    """
    clean = phone_number.strip()
    if not clean:
        return False, None

    normalized = _NON_DIAL_CHARS_RE.sub("", clean)
    if not normalized:
        return False, None

    for prefix, name in RESTRICTED_BIC_PREFIXES.items():
        if normalized.startswith(prefix):
            return True, _restricted_reason(name)

    if normalized.startswith("+"):
        # Explicit country code present but it didn't match a restricted one.
        return False, None

    if len(normalized) > _MIN_BARE_INTERNATIONAL_LENGTH - 1:
        for prefix, name in RESTRICTED_BIC_PREFIXES.items():
            if normalized.startswith(prefix.lstrip("+")):
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
