"""Regression tests for WhatsApp webhook verification."""

from unittest import IsolatedAsyncioTestCase
from unittest.mock import AsyncMock, MagicMock, patch

from fastapi import HTTPException
from fastapi.responses import PlainTextResponse

from api.services.telephony.providers.whatsapp.routes import (
    handle_webhook_verification,
    router,
)


class TestWhatsAppRoutes(IsolatedAsyncioTestCase):
    def test_whatsapp_webhook_route_path_is_webhook(self):
        paths = [route.path for route in router.routes if getattr(route, "path", None)]
        self.assertIn("/whatsapp/webhook", paths)

    async def test_whatsapp_webhook_verification_returns_plain_text_challenge(self):
        with patch(
            "api.services.telephony.providers.whatsapp.routes.WHATSAPP_WEBHOOK_VERIFY_TOKEN",
            "verify-me",
        ):
            response = await handle_webhook_verification(
                hub_mode="subscribe",
                hub_verify_token="verify-me",
                hub_challenge="123456789",
            )

        self.assertIsInstance(response, PlainTextResponse)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.body, b"123456789")

    async def test_whatsapp_webhook_verification_rejects_bad_token(self):
        with patch(
            "api.services.telephony.providers.whatsapp.routes.WHATSAPP_WEBHOOK_VERIFY_TOKEN",
            "verify-me",
        ), patch(
            "api.services.telephony.providers.whatsapp.routes.db_client.get_whatsapp_configuration_by_verify_token",
            AsyncMock(return_value=None),
        ):
            with self.assertRaises(HTTPException) as ctx:
                await handle_webhook_verification(
                    hub_mode="subscribe",
                    hub_verify_token="wrong-token",
                    hub_challenge="123456789",
                )

        self.assertEqual(ctx.exception.status_code, 403)
        self.assertEqual(ctx.exception.detail, "Invalid verification token")

    async def test_whatsapp_webhook_verification_matches_db_token(self):
        mock_config = MagicMock()
        mock_config.id = 42
        with patch(
            "api.services.telephony.providers.whatsapp.routes.WHATSAPP_WEBHOOK_VERIFY_TOKEN",
            "",
        ), patch(
            "api.services.telephony.providers.whatsapp.routes.db_client.get_whatsapp_configuration_by_verify_token",
            AsyncMock(return_value=mock_config),
        ):
            response = await handle_webhook_verification(
                hub_mode="subscribe",
                hub_verify_token="db-verify-token",
                hub_challenge="challenge-from-db",
            )

        self.assertIsInstance(response, PlainTextResponse)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.body, b"challenge-from-db")

    def test_whatsapp_permission_routes_are_registered(self):
        paths = [route.path for route in router.routes if getattr(route, "path", None)]
        self.assertIn("/whatsapp/permissions/check", paths)
        self.assertIn("/whatsapp/permissions/request", paths)

    async def test_check_permission_restricted_country(self):
        from api.services.telephony.providers.whatsapp.routes import check_whatsapp_permission
        mock_user = MagicMock(selected_organization_id=1)
        res = await check_whatsapp_permission(
            telephony_configuration_id=10,
            recipient_phone_number="+16502530000",
            current_user=mock_user,
        )
        self.assertFalse(res.can_call)
        self.assertTrue(res.restricted_country)
        self.assertEqual(res.status, "restricted_country")
        self.assertIn("United States and Canada", res.restriction_reason)

    async def test_check_permission_granted_db(self):
        from api.services.telephony.providers.whatsapp.routes import check_whatsapp_permission
        from datetime import datetime, timezone, timedelta
        mock_user = MagicMock(selected_organization_id=1)
        mock_config = MagicMock(
            id=10,
            organization_id=1,
            provider="whatsapp",
            credentials={"phone_number_id": "test_phone_id", "access_token": "test_token"},
        )
        mock_perm = MagicMock(
            status="granted_temporary",
            permission_type="temporary",
            expires_at=datetime.now(timezone.utc) + timedelta(days=3),
            recipient_phone_number="+447123456789",
        )
        mock_client = MagicMock()
        mock_client.check_call_permission = AsyncMock(
            return_value={
                "permission": {
                    "status": "granted_temporary",
                    "expiration_time": int((datetime.now(timezone.utc) + timedelta(days=3)).timestamp()),
                },
                "actions": [{"action_name": "start_call", "can_perform_action": True}],
            }
        )
        with patch("api.services.telephony.providers.whatsapp.routes.db_client.get_telephony_configuration_for_org", AsyncMock(return_value=mock_config)), \
             patch("api.services.telephony.providers.whatsapp.routes.db_client.get_whatsapp_call_permission", AsyncMock(return_value=mock_perm)), \
             patch("api.services.telephony.providers.whatsapp.routes.db_client.upsert_whatsapp_call_permission", AsyncMock()), \
             patch("api.services.telephony.providers.whatsapp.routes._get_or_create_whatsapp_client", return_value=mock_client):
            res = await check_whatsapp_permission(
                telephony_configuration_id=10,
                recipient_phone_number="+447123456789",
                current_user=mock_user,
            )
            self.assertTrue(res.can_call)
            self.assertEqual(res.status, "granted_temporary")
            self.assertFalse(res.restricted_country)
            self.assertIsNotNone(res.hours_remaining)

    async def test_send_permission_request_success(self):
        from api.services.telephony.providers.whatsapp.routes import (
            WhatsAppPermissionRequestPayload,
            send_whatsapp_permission_request,
        )
        mock_user = MagicMock(selected_organization_id=1)
        mock_config = MagicMock(
            id=10,
            organization_id=1,
            provider="whatsapp",
            credentials={
                "phone_number_id": "test_phone_id",
                "access_token": "test_token",
                "business_initiated_calls_enabled": True,
            },
        )
        payload = WhatsAppPermissionRequestPayload(
            telephony_configuration_id=10,
            recipient_phone_number="+447123456789",
            body_text="May we call you?",
        )
        with patch("api.services.telephony.providers.whatsapp.routes.db_client.get_telephony_configuration_for_org", AsyncMock(return_value=mock_config)), \
             patch("api.services.telephony.providers.whatsapp.routes._get_or_create_whatsapp_client") as mock_get_client, \
             patch("api.services.telephony.providers.whatsapp.routes.db_client.upsert_whatsapp_call_permission", AsyncMock()):
            mock_client = MagicMock()
            mock_client.send_call_permission_request = AsyncMock(
                return_value={"messages": [{"id": "wamid.12345"}]}
            )
            mock_get_client.return_value = mock_client

            res = await send_whatsapp_permission_request(
                payload=payload,
                current_user=mock_user,
            )
            self.assertTrue(res["success"])
            self.assertEqual(res["status"], "pending")
            self.assertEqual(res["message_id"], "wamid.12345")
            self.assertEqual(res["hours_remaining"], 168.0)
            mock_client.send_call_permission_request.assert_called_once_with(
                to="447123456789",
                body_text="May we call you?",
            )

    async def test_send_permission_request_uses_config_default_message(self):
        from api.services.telephony.providers.whatsapp.routes import (
            WhatsAppPermissionRequestPayload,
            send_whatsapp_permission_request,
        )
        mock_user = MagicMock(selected_organization_id=1)
        mock_config = MagicMock(
            id=10,
            organization_id=1,
            provider="whatsapp",
            credentials={
                "phone_number_id": "test_phone_id",
                "access_token": "test_token",
                "business_initiated_calls_enabled": True,
                "default_permission_message": "Custom configured permission message from org",
            },
        )
        payload = WhatsAppPermissionRequestPayload(
            telephony_configuration_id=10,
            recipient_phone_number="+447123456789",
            body_text=None,
        )
        with patch("api.services.telephony.providers.whatsapp.routes.db_client.get_telephony_configuration_for_org", AsyncMock(return_value=mock_config)), \
             patch("api.services.telephony.providers.whatsapp.routes._get_or_create_whatsapp_client") as mock_get_client, \
             patch("api.services.telephony.providers.whatsapp.routes.db_client.upsert_whatsapp_call_permission", AsyncMock()):
            mock_client = MagicMock()
            mock_client.send_call_permission_request = AsyncMock(
                return_value={"messages": [{"id": "wamid.12345"}]}
            )
            mock_get_client.return_value = mock_client

            res = await send_whatsapp_permission_request(
                payload=payload,
                current_user=mock_user,
            )
            self.assertTrue(res["success"])
            mock_client.send_call_permission_request.assert_called_once_with(
                to="447123456789",
                body_text="Custom configured permission message from org",
            )

    async def test_send_permission_request_uses_global_crisp_default_message(self):
        from api.services.telephony.providers.whatsapp.config import (
            DEFAULT_WHATSAPP_PERMISSION_MESSAGE,
        )
        from api.services.telephony.providers.whatsapp.routes import (
            WhatsAppPermissionRequestPayload,
            send_whatsapp_permission_request,
        )
        mock_user = MagicMock(selected_organization_id=1)
        mock_config = MagicMock(
            id=10,
            organization_id=1,
            provider="whatsapp",
            credentials={
                "phone_number_id": "test_phone_id",
                "access_token": "test_token",
                "business_initiated_calls_enabled": True,
            },
        )
        payload = WhatsAppPermissionRequestPayload(
            telephony_configuration_id=10,
            recipient_phone_number="+447123456789",
            body_text=None,
        )
        with patch("api.services.telephony.providers.whatsapp.routes.db_client.get_telephony_configuration_for_org", AsyncMock(return_value=mock_config)), \
             patch("api.services.telephony.providers.whatsapp.routes._get_or_create_whatsapp_client") as mock_get_client, \
             patch("api.services.telephony.providers.whatsapp.routes.db_client.upsert_whatsapp_call_permission", AsyncMock()):
            mock_client = MagicMock()
            mock_client.send_call_permission_request = AsyncMock(
                return_value={"messages": [{"id": "wamid.12345"}]}
            )
            mock_get_client.return_value = mock_client

            res = await send_whatsapp_permission_request(
                payload=payload,
                current_user=mock_user,
            )
            self.assertTrue(res["success"])
            mock_client.send_call_permission_request.assert_called_once_with(
                to="447123456789",
                body_text=DEFAULT_WHATSAPP_PERMISSION_MESSAGE,
            )

    async def test_check_permission_token_expired(self):
        from api.services.telephony.providers.whatsapp.routes import check_whatsapp_permission
        mock_user = MagicMock(selected_organization_id=1)
        mock_config = MagicMock(
            id=10,
            organization_id=1,
            provider="whatsapp",
            credentials={"phone_number_id": "test_phone_id", "access_token": "expired_token"},
        )
        mock_client = MagicMock()
        mock_client.check_call_permission = AsyncMock(
            side_effect=HTTPException(
                status_code=401,
                detail="Meta API Error (190): Error validating access token: Session has expired. The WhatsApp access token has expired or is invalid. Please generate a fresh token in Meta Business Manager and update your Telephony Configuration.",
            )
        )
        with patch("api.services.telephony.providers.whatsapp.routes.db_client.get_telephony_configuration_for_org", AsyncMock(return_value=mock_config)), \
             patch("api.services.telephony.providers.whatsapp.routes.db_client.get_whatsapp_call_permission", AsyncMock(return_value=None)), \
             patch("api.services.telephony.providers.whatsapp.routes._get_or_create_whatsapp_client", return_value=mock_client):
            res = await check_whatsapp_permission(
                telephony_configuration_id=10,
                recipient_phone_number="+447123456789",
                current_user=mock_user,
            )
            self.assertFalse(res.can_call)
            self.assertEqual(res.status, "token_expired")
            self.assertIn("The WhatsApp access token has expired or is invalid", res.delivery_error)

    async def test_send_permission_request_token_expired(self):
        from api.services.telephony.providers.whatsapp.routes import (
            WhatsAppPermissionRequestPayload,
            send_whatsapp_permission_request,
        )
        mock_user = MagicMock(selected_organization_id=1)
        mock_config = MagicMock(
            id=10,
            organization_id=1,
            provider="whatsapp",
            credentials={
                "phone_number_id": "test_phone_id",
                "access_token": "expired_token",
                "business_initiated_calls_enabled": True,
            },
        )
        payload = WhatsAppPermissionRequestPayload(
            telephony_configuration_id=10,
            recipient_phone_number="+447123456789",
            body_text="May we call you?",
        )
        mock_client = MagicMock()
        mock_client.send_call_permission_request = AsyncMock(
            side_effect=HTTPException(
                status_code=401,
                detail="Meta API Error (190): Error validating access token. The WhatsApp access token has expired or is invalid.",
            )
        )
        with patch("api.services.telephony.providers.whatsapp.routes.db_client.get_telephony_configuration_for_org", AsyncMock(return_value=mock_config)), \
             patch("api.services.telephony.providers.whatsapp.routes._get_or_create_whatsapp_client", return_value=mock_client):
            with self.assertRaises(HTTPException) as ctx:
                await send_whatsapp_permission_request(
                    payload=payload,
                    current_user=mock_user,
                )
            self.assertEqual(ctx.exception.status_code, 401)
            self.assertIn("access token has expired", ctx.exception.detail)

