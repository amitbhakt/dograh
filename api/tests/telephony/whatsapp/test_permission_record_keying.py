"""Tests for the format a WhatsApp permission row is keyed by.

uq_whatsapp_perm_config_recipient constrains the stored recipient string, so it
only prevents duplicates if every writer stores one agreed spelling. These pin
that spelling down, and that lookups still find it.
"""

from unittest import IsolatedAsyncioTestCase, TestCase
from unittest.mock import AsyncMock, MagicMock

from api.db.telephony_configuration_client import (
    _canonical_recipient_number,
    _get_recipient_number_candidates,
    _select_permission_row,
)

EQUIVALENT_SPELLINGS = [
    "+447123456789",
    "447123456789",
    "+44 7123 456789",
    "+44-7123-456789",
    " +447123456789 ",
]


class TestCanonicalRecipientNumber(TestCase):
    def test_equivalent_spellings_collapse_to_one_key(self):
        keys = {_canonical_recipient_number(s) for s in EQUIVALENT_SPELLINGS}
        self.assertEqual(
            len(keys), 1, f"equivalent numbers must share one stored key, got {keys}"
        )

    def test_stored_key_is_reachable_from_every_spelling(self):
        """A row written from one spelling has to be found by a lookup from any other."""
        stored = _canonical_recipient_number("+44 7123 456789")
        for spelling in EQUIVALENT_SPELLINGS:
            with self.subTest(lookup=spelling):
                self.assertIn(stored, _get_recipient_number_candidates(spelling))

    def test_distinct_numbers_do_not_collapse(self):
        self.assertNotEqual(
            _canonical_recipient_number("+447123456789"),
            _canonical_recipient_number("+447123456780"),
        )

    def test_unparseable_input_still_yields_a_stable_key(self):
        self.assertEqual(
            _canonical_recipient_number("44 (7123) 456789"),
            _canonical_recipient_number("447123456789"),
        )


class TestSelectPermissionRow(IsolatedAsyncioTestCase):
    """Rows predating canonical storage can still collide; readers must agree on one."""

    @staticmethod
    def _session_returning(rows):
        session = MagicMock()
        result = MagicMock()
        result.scalars.return_value.all.return_value = rows
        session.execute = AsyncMock(return_value=result)
        return session

    async def test_returns_none_when_no_rows(self):
        session = self._session_returning([])
        self.assertIsNone(
            await _select_permission_row(session, MagicMock(), "+447123456789")
        )

    async def test_duplicates_resolve_to_the_same_row_for_every_reader(self):
        rows = [MagicMock(id=7), MagicMock(id=3), MagicMock(id=11)]
        session = self._session_returning(rows)

        picked = await _select_permission_row(session, MagicMock(), "+447123456789")

        # The query is ordered by id, so whatever the DB returns first is the
        # row every caller gets - the point is that it is not arbitrary.
        self.assertIs(picked, rows[0])
        session.execute.return_value.scalars.assert_called_once()

    async def test_orders_the_query_by_id(self):
        query = MagicMock()
        session = self._session_returning([MagicMock(id=1)])

        await _select_permission_row(session, query, "+447123456789")

        query.order_by.assert_called_once()
        session.execute.assert_awaited_once_with(query.order_by.return_value)
