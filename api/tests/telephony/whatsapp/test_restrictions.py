import importlib.util
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import MagicMock

if "fastapi" not in sys.modules:
    fastapi_mock = MagicMock()
    class HTTPException(Exception):
        def __init__(self, status_code: int = 400, detail: str = ""):
            self.status_code = status_code
            self.detail = detail
            super().__init__(detail)
    fastapi_mock.HTTPException = HTTPException
    sys.modules["fastapi"] = fastapi_mock

if "starlette" not in sys.modules:
    sys.modules["starlette"] = MagicMock()
    sys.modules["starlette.responses"] = MagicMock()

if "api.constants" not in sys.modules:
    const_mock = MagicMock()
    const_mock.COUNTRY_CODES = {}
    sys.modules["api.constants"] = const_mock

# Load restrictions.py directly
RESTRICTIONS_PATH = Path(__file__).resolve().parents[3] / "services" / "telephony" / "providers" / "whatsapp" / "restrictions.py"
spec = importlib.util.spec_from_file_location("restrictions", RESTRICTIONS_PATH)
restrictions = importlib.util.module_from_spec(spec)
spec.loader.exec_module(restrictions)

RESTRICTED_BIC_COUNTRIES = restrictions.RESTRICTED_BIC_COUNTRIES
RESTRICTED_BIC_PREFIXES = restrictions.RESTRICTED_BIC_PREFIXES
is_restricted_country = restrictions.is_restricted_country
validate_destination_country = restrictions.validate_destination_country
HTTPException = getattr(restrictions, "HTTPException", Exception)


class TestWhatsAppRestrictions(unittest.TestCase):
    """Test suite for WhatsApp destination country restrictions."""

    def test_restricted_prefixes_defined(self):
        """Ensure all required restricted country prefixes are configured."""
        self.assertIn("+1", RESTRICTED_BIC_PREFIXES)
        self.assertIn("+20", RESTRICTED_BIC_PREFIXES)
        self.assertIn("+84", RESTRICTED_BIC_PREFIXES)
        self.assertIn("+234", RESTRICTED_BIC_PREFIXES)

    def test_us_and_canada_are_restricted(self):
        """Test +1 numbers (US and Canada) are flagged as restricted."""
        is_restr, reason = is_restricted_country("+16502530000")
        self.assertTrue(is_restr)
        self.assertIn("United States and Canada", reason)

        is_restr_no_plus, _ = is_restricted_country("16502530000")
        self.assertTrue(is_restr_no_plus)

        with self.assertRaises(HTTPException) as ctx:
            validate_destination_country("+14155552671")
        self.assertEqual(ctx.exception.status_code, 400)
        self.assertIn("not permitted", ctx.exception.detail)

    def test_egypt_is_restricted(self):
        """Test +20 numbers (Egypt) are flagged as restricted."""
        is_restr, reason = is_restricted_country("+201012345678")
        self.assertTrue(is_restr)
        self.assertIn("Egypt", reason)

        with self.assertRaises(HTTPException) as ctx:
            validate_destination_country("+201012345678")
        self.assertEqual(ctx.exception.status_code, 400)

    def test_vietnam_is_restricted(self):
        """Test +84 numbers (Vietnam) are flagged as restricted."""
        is_restr, reason = is_restricted_country("+84912345678")
        self.assertTrue(is_restr)
        self.assertIn("Vietnam", reason)

        with self.assertRaises(HTTPException) as ctx:
            validate_destination_country("+84912345678")
        self.assertEqual(ctx.exception.status_code, 400)

    def test_nigeria_is_restricted(self):
        """Test +234 numbers (Nigeria) are flagged as restricted."""
        is_restr, reason = is_restricted_country("+2348012345678")
        self.assertTrue(is_restr)
        self.assertIn("Nigeria", reason)

        with self.assertRaises(HTTPException) as ctx:
            validate_destination_country("+2348012345678")
        self.assertEqual(ctx.exception.status_code, 400)

    def test_allowed_countries(self):
        """Test non-restricted countries pass validation without error."""
        allowed = [
            "+447911123456",  # UK
            "+919876543210",  # India
            "+4915123456789", # Germany
            "+5511999999999", # Brazil
            "+819012345678",  # Japan
            "+61412345678",   # Australia
        ]
        for number in allowed:
            is_restr, reason = is_restricted_country(number)
            self.assertFalse(is_restr, f"{number} should not be restricted")
            self.assertIsNone(reason)
            # Should not raise
            validate_destination_country(number)


if __name__ == "__main__":
    unittest.main()
