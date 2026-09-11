"""Tests for matching a WhatsApp recipient number against parked campaign leads.

The SQL prefilter in get_queued_runs_awaiting_whatsapp_permission is deliberately
wide (it ILIKEs digit runs against the serialized context_variables) so that
punctuated numbers still get loaded. is_same_recipient_number is what decides
which of those rows actually belong to the recipient, so the false-positive
boundary lives here.
"""

import re
from unittest import TestCase

from api.db.campaign_client import is_same_recipient_number
from api.utils.telephony_address import normalize_telephony_address


def _matches(candidate: str, target: str) -> bool:
    target_digits = re.sub(r"\D", "", target)
    try:
        target_canonical = normalize_telephony_address(target).canonical
    except Exception:
        target_canonical = f"+{target_digits}"
    return is_same_recipient_number(
        candidate,
        target_digits=target_digits,
        target_canonical=target_canonical,
        target_no_plus=target_canonical.lstrip("+"),
    )


class TestIsSameRecipientNumber(TestCase):
    def test_matches_formatting_variants(self):
        for candidate in ("+1 (555) 123-4567", "1-555-123-4567", "15551234567", "+15551234567"):
            with self.subTest(candidate=candidate):
                self.assertTrue(_matches(candidate, "+15551234567"))

    def test_matches_across_missing_country_code(self):
        self.assertTrue(_matches("5551234567", "+15551234567"))
        self.assertTrue(_matches("+919876543210", "9876543210"))

    def test_rejects_different_subscriber(self):
        self.assertFalse(_matches("+15559994567", "+15551234567"))

    def test_rejects_unrelated_number_sharing_a_long_suffix(self):
        """A shared tail longer than any country code is coincidence, not the same lead."""
        self.assertFalse(_matches("+442079461234567", "1234567"))
        self.assertFalse(_matches("+8613800001234567", "5551234567"))

    def test_rejects_local_fragment_shorter_than_a_real_number(self):
        """A 7-digit local number has no area code, so any longer number ends the same way."""
        # 415-123-4567 and 555-123-4567 share their last 7 digits but are
        # different subscribers; neither may match the bare local part.
        self.assertFalse(_matches("4151234567", "1234567"))
        self.assertFalse(_matches("1234567", "5551234567"))

    def test_rejects_trunk_prefix_masquerading_as_country_code(self):
        """A leading 0 is a national trunk prefix; no country dials with one."""
        self.assertFalse(_matches("012345678", "12345678"))

    def test_rejects_short_and_empty_candidates(self):
        self.assertFalse(_matches("", "+15551234567"))
        self.assertFalse(_matches("123456", "0123456"))
