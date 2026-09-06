"""Unit tests for WhatsApp inbound calling webhook and WebRTC integration."""

import hashlib
import hmac
import json
from unittest import IsolatedAsyncioTestCase
from unittest.mock import AsyncMock, MagicMock, patch

from fastapi import HTTPException
from fastapi.responses import PlainTextResponse
from starlette.requests import Request

from api.db import db_client
from api.services.telephony.providers.whatsapp.routes import (
    _active_connections,
    handle_webhook_verification,
    handle_whatsapp_webhook,
)


class TestWhatsAppInboundCalling(IsolatedAsyncioTestCase):
    def setUp(self):
        _active_connections.clear()

    async def test_webhook_verification_via_db_fallback(self):
        """Verify GET /webhook falls back to DB telephony configuration if env var not set."""
        mock_config = MagicMock()
        mock_config.id = 42

        with patch(
            "api.services.telephony.providers.whatsapp.routes.WHATSAPP_WEBHOOK_VERIFY_TOKEN",
            None,
        ):
            with patch.object(db_client, "async_session") as mock_session_ctx:
                mock_session = AsyncMock()
                mock_session_ctx.return_value.__aenter__.return_value = mock_session
                mock_result = MagicMock()
                mock_result.scalars.return_value.first.return_value = mock_config
                mock_session.execute.return_value = mock_result

                response = await handle_webhook_verification(
                    hub_mode="subscribe",
                    hub_verify_token="custom_org_token",
                    hub_challenge="challenge_777",
                )

                self.assertIsInstance(response, PlainTextResponse)
                self.assertEqual(response.body, b"challenge_777")

    async def test_webhook_connect_creates_workflow_run_and_answers_call(self):
        """Verify POST /webhook handles connect event, creates workflow_run, and answers call."""
        phone_number_id = "106540352242922"
        call_id = "call_abc123"
        app_secret = "test_app_secret"

        payload = {
            "object": "whatsapp_business_account",
            "entry": [
                {
                    "id": "waba_123",
                    "changes": [
                        {
                            "field": "calls",
                            "value": {
                                "messaging_product": "whatsapp",
                                "metadata": {
                                    "display_phone_number": "+15551234567",
                                    "phone_number_id": phone_number_id,
                                },
                                "calls": [
                                    {
                                        "id": call_id,
                                        "from": "+15559876543",
                                        "to": "+15551234567",
                                        "event": "connect",
                                        "timestamp": "1725619200",
                                        "direction": "inbound",
                                        "session": {
                                            "sdp_type": "offer",
                                            "sdp": "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\nm=audio 50000 UDP/TLS/RTP/SAVPF 111\r\n",
                                        },
                                    }
                                ],
                            },
                        }
                    ],
                }
            ],
        }

        body_bytes = json.dumps(payload).encode("utf-8")
        signature = hmac.new(
            app_secret.encode("utf-8"), body_bytes, hashlib.sha256
        ).hexdigest()

        # Mock DB records
        mock_config = MagicMock()
        mock_config.id = 1
        mock_config.organization_id = 10
        mock_config.credentials = {
            "phone_number_id": phone_number_id,
            "access_token": "valid_token",
            "app_secret": app_secret,
        }

        mock_phone = MagicMock()
        mock_phone.id = 2
        mock_phone.address_normalized = "+15551234567"
        mock_phone.inbound_workflow_id = 99

        mock_workflow = MagicMock()
        mock_workflow.id = 99
        mock_workflow.user_id = 5
        mock_workflow.organization_id = 10

        mock_workflow_run = MagicMock()
        mock_workflow_run.id = 101

        mock_client = AsyncMock()

        # Build mock request
        async def mock_receive():
            return {"type": "http.request", "body": body_bytes}

        scope = {
            "type": "http",
            "method": "POST",
            "headers": [
                (b"content-type", b"application/json"),
                (b"x-hub-signature-256", f"sha256={signature}".encode("utf-8")),
            ],
        }
        request = Request(scope, receive=mock_receive)

        with patch.object(db_client, "async_session") as mock_session_ctx, \
             patch.object(db_client, "get_workflow", AsyncMock(return_value=mock_workflow)), \
             patch.object(db_client, "create_workflow_run", AsyncMock(return_value=mock_workflow_run)), \
             patch("api.services.call_concurrency.call_concurrency.acquire_org_slot", AsyncMock(return_value="slot1")), \
             patch("api.services.call_concurrency.call_concurrency.bind_workflow_run", AsyncMock()), \
             patch("api.services.telephony.providers.whatsapp.routes.prepare_workflow_run_inputs", AsyncMock(return_value=MagicMock(definition_id=1))), \
             patch("api.services.telephony.providers.whatsapp.routes.authorize_workflow_run_start", AsyncMock(return_value=MagicMock(has_quota=True))), \
             patch("api.services.telephony.providers.whatsapp.routes._get_or_create_whatsapp_client", return_value=mock_client), \
             patch("api.services.telephony.providers.whatsapp.routes._run_whatsapp_pipeline", AsyncMock()):

            mock_session = AsyncMock()
            mock_session_ctx.return_value.__aenter__.return_value = mock_session

            # First query: TelephonyConfigurationModel
            # Second query: TelephonyPhoneNumberModel
            config_result = MagicMock()
            config_result.scalars.return_value.first.return_value = mock_config

            phone_result = MagicMock()
            phone_result.scalars.return_value.all.return_value = [mock_phone]

            mock_session.execute.side_effect = [config_result, phone_result]

            response = await handle_whatsapp_webhook(request)

            self.assertEqual(response, {"status": "success"})
            mock_client.handle_webhook_request.assert_called_once()

    async def test_webhook_connect_rejects_invalid_signature(self):
        """Verify POST /webhook raises 403 when signature does not match app_secret."""
        phone_number_id = "106540352242922"
        app_secret = "secret123"

        payload = {
            "object": "whatsapp_business_account",
            "entry": [
                {
                    "changes": [
                        {
                            "field": "calls",
                            "value": {
                                "metadata": {"phone_number_id": phone_number_id},
                                "calls": [{"id": "c1", "event": "connect", "session": {"sdp_type": "offer"}}],
                            },
                        }
                    ]
                }
            ],
        }

        body_bytes = json.dumps(payload).encode("utf-8")

        mock_config = MagicMock()
        mock_config.credentials = {
            "phone_number_id": phone_number_id,
            "app_secret": app_secret,
        }

        async def mock_receive():
            return {"type": "http.request", "body": body_bytes}

        scope = {
            "type": "http",
            "method": "POST",
            "headers": [
                (b"content-type", b"application/json"),
                (b"x-hub-signature-256", b"sha256=wrong_signature"),
            ],
        }
        request = Request(scope, receive=mock_receive)

        with patch.object(db_client, "async_session") as mock_session_ctx:
            mock_session = AsyncMock()
            mock_session_ctx.return_value.__aenter__.return_value = mock_session
            config_result = MagicMock()
            config_result.scalars.return_value.first.return_value = mock_config
            mock_session.execute.return_value = config_result

            with self.assertRaises(HTTPException) as ctx:
                await handle_whatsapp_webhook(request)

            self.assertEqual(ctx.exception.status_code, 403)
            self.assertEqual(ctx.exception.detail, "Invalid webhook signature")

    async def test_webhook_connect_rejects_missing_signature(self):
        """Verify POST /webhook raises 403 when x-hub-signature-256 is omitted on connect."""
        phone_number_id = "106540352242922"
        payload = {
            "object": "whatsapp_business_account",
            "entry": [
                {
                    "changes": [
                        {
                            "field": "calls",
                            "value": {
                                "metadata": {"phone_number_id": phone_number_id},
                                "calls": [{"id": "c1", "event": "connect", "session": {"sdp_type": "offer"}}],
                            },
                        }
                    ]
                }
            ],
        }

        body_bytes = json.dumps(payload).encode("utf-8")
        mock_config = MagicMock()
        mock_config.credentials = {
            "phone_number_id": phone_number_id,
            "app_secret": "secret123",
        }

        async def mock_receive():
            return {"type": "http.request", "body": body_bytes}

        scope = {
            "type": "http",
            "method": "POST",
            "headers": [(b"content-type", b"application/json")],
        }
        request = Request(scope, receive=mock_receive)

        with patch.object(db_client, "async_session") as mock_session_ctx:
            mock_session = AsyncMock()
            mock_session_ctx.return_value.__aenter__.return_value = mock_session
            config_result = MagicMock()
            config_result.scalars.return_value.first.return_value = mock_config
            mock_session.execute.return_value = config_result

            with self.assertRaises(HTTPException) as ctx:
                await handle_whatsapp_webhook(request)

            self.assertEqual(ctx.exception.status_code, 403)
            self.assertEqual(ctx.exception.detail, "Missing webhook signature")

    async def test_webhook_calling_rejects_missing_app_secret(self):
        """Verify POST /webhook raises 403 when app_secret is not configured."""
        phone_number_id = "106540352242922"
        payload = {
            "object": "whatsapp_business_account",
            "entry": [
                {
                    "changes": [
                        {
                            "field": "calls",
                            "value": {
                                "metadata": {"phone_number_id": phone_number_id},
                                "calls": [{"id": "c1", "event": "connect", "session": {"sdp_type": "offer"}}],
                            },
                        }
                    ]
                }
            ],
        }

        body_bytes = json.dumps(payload).encode("utf-8")
        mock_config = MagicMock()
        mock_config.credentials = {
            "phone_number_id": phone_number_id,
            "app_secret": None,
        }

        async def mock_receive():
            return {"type": "http.request", "body": body_bytes}

        scope = {
            "type": "http",
            "method": "POST",
            "headers": [
                (b"content-type", b"application/json"),
                (b"x-hub-signature-256", b"sha256=some_sig"),
            ],
        }
        request = Request(scope, receive=mock_receive)

        with patch.object(db_client, "async_session") as mock_session_ctx:
            mock_session = AsyncMock()
            mock_session_ctx.return_value.__aenter__.return_value = mock_session
            config_result = MagicMock()
            config_result.scalars.return_value.first.return_value = mock_config
            mock_session.execute.return_value = config_result

            with self.assertRaises(HTTPException) as ctx:
                await handle_whatsapp_webhook(request)

            self.assertEqual(ctx.exception.status_code, 403)
            self.assertEqual(
                ctx.exception.detail,
                "Webhook signature verification failed: app_secret not configured",
            )

    async def test_webhook_terminate_disconnects_peer_connection(self):
        """Verify POST /webhook with valid signature handles terminate event and disconnects."""
        call_id = "call_to_terminate"
        phone_number_id = "123"
        app_secret = "test_app_secret"
        mock_connection = AsyncMock()
        _active_connections[call_id] = (mock_connection, 101, 10, phone_number_id)

        payload = {
            "object": "whatsapp_business_account",
            "entry": [
                {
                    "changes": [
                        {
                            "field": "calls",
                            "value": {
                                "metadata": {"phone_number_id": phone_number_id},
                                "calls": [{"id": call_id, "event": "terminate"}],
                            },
                        }
                    ]
                }
            ],
        }

        body_bytes = json.dumps(payload).encode("utf-8")
        signature = hmac.new(
            app_secret.encode("utf-8"), body_bytes, hashlib.sha256
        ).hexdigest()

        mock_config = MagicMock()
        mock_config.credentials = {
            "phone_number_id": phone_number_id,
            "app_secret": app_secret,
        }

        async def mock_receive():
            return {"type": "http.request", "body": body_bytes}

        scope = {
            "type": "http",
            "method": "POST",
            "headers": [
                (b"content-type", b"application/json"),
                (b"x-hub-signature-256", f"sha256={signature}".encode("utf-8")),
            ],
        }
        request = Request(scope, receive=mock_receive)

        with patch.object(db_client, "async_session") as mock_session_ctx, \
             patch.object(db_client, "update_workflow_run", AsyncMock()):
            mock_session = AsyncMock()
            mock_session_ctx.return_value.__aenter__.return_value = mock_session
            config_result = MagicMock()
            config_result.scalars.return_value.first.return_value = mock_config
            mock_session.execute.return_value = config_result

            response = await handle_whatsapp_webhook(request)

            self.assertEqual(response, {"status": "success"})
            mock_connection.disconnect.assert_called_once()
            self.assertNotIn(call_id, _active_connections)

    async def test_webhook_terminate_rejects_missing_signature(self):
        """Verify POST /webhook raises 403 and does NOT disconnect when signature is omitted on terminate."""
        call_id = "call_to_terminate"
        phone_number_id = "123"
        mock_connection = AsyncMock()
        _active_connections[call_id] = (mock_connection, 101, 10, phone_number_id)

        payload = {
            "object": "whatsapp_business_account",
            "entry": [
                {
                    "changes": [
                        {
                            "field": "calls",
                            "value": {
                                "metadata": {"phone_number_id": phone_number_id},
                                "calls": [{"id": call_id, "event": "terminate"}],
                            },
                        }
                    ]
                }
            ],
        }

        body_bytes = json.dumps(payload).encode("utf-8")
        mock_config = MagicMock()
        mock_config.credentials = {
            "phone_number_id": phone_number_id,
            "app_secret": "test_app_secret",
        }

        async def mock_receive():
            return {"type": "http.request", "body": body_bytes}

        scope = {
            "type": "http",
            "method": "POST",
            "headers": [(b"content-type", b"application/json")],
        }
        request = Request(scope, receive=mock_receive)

        with patch.object(db_client, "async_session") as mock_session_ctx:
            mock_session = AsyncMock()
            mock_session_ctx.return_value.__aenter__.return_value = mock_session
            config_result = MagicMock()
            config_result.scalars.return_value.first.return_value = mock_config
            mock_session.execute.return_value = config_result

            with self.assertRaises(HTTPException) as ctx:
                await handle_whatsapp_webhook(request)

            self.assertEqual(ctx.exception.status_code, 403)
            self.assertEqual(ctx.exception.detail, "Missing webhook signature")
            mock_connection.disconnect.assert_not_called()
            self.assertIn(call_id, _active_connections)

    async def test_webhook_terminate_rejects_invalid_signature(self):
        """Verify POST /webhook raises 403 and does NOT disconnect when signature is forged on terminate."""
        call_id = "call_to_terminate"
        phone_number_id = "123"
        mock_connection = AsyncMock()
        _active_connections[call_id] = (mock_connection, 101, 10, phone_number_id)

        payload = {
            "object": "whatsapp_business_account",
            "entry": [
                {
                    "changes": [
                        {
                            "field": "calls",
                            "value": {
                                "metadata": {"phone_number_id": phone_number_id},
                                "calls": [{"id": call_id, "event": "terminate"}],
                            },
                        }
                    ]
                }
            ],
        }

        body_bytes = json.dumps(payload).encode("utf-8")
        mock_config = MagicMock()
        mock_config.credentials = {
            "phone_number_id": phone_number_id,
            "app_secret": "test_app_secret",
        }

        async def mock_receive():
            return {"type": "http.request", "body": body_bytes}

        scope = {
            "type": "http",
            "method": "POST",
            "headers": [
                (b"content-type", b"application/json"),
                (b"x-hub-signature-256", b"sha256=forged_signature_digest"),
            ],
        }
        request = Request(scope, receive=mock_receive)

        with patch.object(db_client, "async_session") as mock_session_ctx:
            mock_session = AsyncMock()
            mock_session_ctx.return_value.__aenter__.return_value = mock_session
            config_result = MagicMock()
            config_result.scalars.return_value.first.return_value = mock_config
            mock_session.execute.return_value = config_result

            with self.assertRaises(HTTPException) as ctx:
                await handle_whatsapp_webhook(request)

            self.assertEqual(ctx.exception.status_code, 403)
            self.assertEqual(ctx.exception.detail, "Invalid webhook signature")
            mock_connection.disconnect.assert_not_called()
            self.assertIn(call_id, _active_connections)
