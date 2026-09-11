from typing import Optional, Tuple

try:
    from fastapi import HTTPException
except ImportError:
    class HTTPException(Exception):  # type: ignore
        def __init__(self, status_code: int = 400, detail: str = ""):
            self.status_code = status_code
            self.detail = detail
            super().__init__(detail)

from api.utils.telephony_address import normalize_telephony_address

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


def is_restricted_country(phone_number: str) -> Tuple[bool, Optional[str]]:
    """Check if the given phone number falls into Meta's restricted BIC countries.

    Returns:
        Tuple of (is_restricted: bool, reason: Optional[str])
    """
    clean = phone_number.strip()
    if not clean:
        return False, None

    for prefix, name in RESTRICTED_BIC_PREFIXES.items():
        if clean.startswith(prefix) or clean.lstrip("+").startswith(prefix.lstrip("+")):
            return (
                True,
                f"Business-Initiated WhatsApp Calls are not permitted in {name} "
                "due to Meta platform regulations. Inbound calling remains supported.",
            )

    try:
        norm = normalize_telephony_address(clean)
        for prefix, name in RESTRICTED_BIC_PREFIXES.items():
            if norm.canonical.startswith(prefix):
                return (
                    True,
                    f"Business-Initiated WhatsApp Calls are not permitted in {name} "
                    "due to Meta platform regulations. Inbound calling remains supported.",
                )
    except Exception:
        pass

    return False, None


def validate_destination_country(phone_number: str) -> None:
    """Validate that the destination phone number is not in Meta's restricted countries.

    Raises:
        HTTPException: 400 if the destination is in a restricted country.
    """
    restricted, reason = is_restricted_country(phone_number)
    if restricted:
        raise HTTPException(status_code=400, detail=reason)
