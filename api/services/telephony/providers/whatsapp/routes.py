"""WhatsApp webhook routes.

This module handles incoming webhooks from Meta's WhatsApp Business Calling API,
including call lifecycle events (connect, terminate), permission callbacks, and
webhook verification, connecting incoming WhatsApp calls directly to Dograh's
WebRTC AI voice pipeline.
"""

from datetime import datetime, timedelta, timezone

try:
    from datetime import UTC
except ImportError:
    UTC = timezone.utc

import asyncio
import hashlib
import hmac
import json
from typing import Any, Dict, Optional, Tuple

import aiohttp
import redis.asyncio as aioredis
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from loguru import logger
from pydantic import BaseModel
from starlette.responses import PlainTextResponse

from api.constants import (
    ENABLE_COTURN,
    FORCE_TURN_RELAY,
    REDIS_URL,
    WHATSAPP_WEBHOOK_VERIFY_TOKEN,
)
from api.db import db_client
from api.db.models import (
    TelephonyConfigurationModel,
    TelephonyPhoneNumberModel,
    UserModel,
    WhatsAppCallPermissionModel,
    WorkflowRunModel,
)
from api.enums import CallType, TelephonyCallStatus, WorkflowRunState
from api.routes.turn_credentials import (
    TURN_HOST,
    TURN_PORT,
    TURN_SECRET,
    generate_turn_credentials,
)
from api.services.auth.depends import get_user
from api.services.call_concurrency import (
    CallConcurrencyLimitError,
    call_concurrency,
)
from api.services.pipecat.run_pipeline import run_pipeline_smallwebrtc
from api.services.quota_service import authorize_workflow_run_start
from api.services.telephony.providers.whatsapp.config import (
    DEFAULT_WHATSAPP_PERMISSION_MESSAGE,
    GRANTED_PERMISSION_STATUSES,
    normalize_whatsapp_permission_status,
    parse_whatsapp_expiration,
)
from api.services.telephony.providers.whatsapp.restrictions import (
    is_restricted_country,
    validate_destination_country,
)
from api.services.workflow.run_creation import prepare_workflow_run_inputs
from api.services.workflow_run_failure import mark_workflow_run_failed
from api.utils.telephony_address import normalize_telephony_address
from pipecat.transports.smallwebrtc.connection import IceServer, SmallWebRTCConnection
from pipecat.transports.whatsapp.api import (
    WhatsAppConnectCall,
    WhatsAppWebhookRequest,
)
from pipecat.transports.whatsapp.client import WhatsAppClient

router = APIRouter(prefix="/whatsapp")

from api.services.telephony.providers.whatsapp.service import (
    REDIS_CALL_EVENTS_CHANNEL,
    REDIS_PERMISSION_CHANNEL,
    REDIS_TERMINATE_CHANNEL,
    WHATSAPP_CALL_KEY_PREFIX,
    _active_connections,
    _background_tasks,
    _build_whatsapp_ice_servers,
    _clients,
    _ensure_redis_subscriber,
    _get_http_session,
    _get_or_create_whatsapp_client,
    _get_redis,
    _http_session,
    _listen_for_remote_events,
    _outbound_answered_events,
    _redis_client,
    _redis_subscriber_task,
    build_whatsapp_ice_servers,
    ensure_redis_subscriber,
    get_http_session,
    get_or_create_whatsapp_client,
    get_whatsapp_redis,
    listen_for_remote_events,
    register_outbound_active_connection,
    set_pipeline_runner,
)


async def _reject_whatsapp_call(
    phone_number_id: str,
    call_id: str,
    access_token: Optional[str],
) -> None:
    """Send a call rejection signal to Meta Graph API."""
    if not access_token or not phone_number_id or not call_id:
        return
    try:
        url = f"https://graph.facebook.com/v21.0/{phone_number_id}/calls"
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
        }
        payload = {
            "messaging_product": "whatsapp",
            "call_id": call_id,
            "action": "reject",
        }
        session = _get_http_session()
        async with session.post(url, headers=headers, json=payload) as resp:
            logger.info(
                f"[WhatsApp] Call {call_id} rejected via Graph API, status={resp.status}"
            )
    except Exception as e:
        logger.error(f"[WhatsApp] Failed to send call reject to Meta: {e}")


@router.get("/webhook")
async def handle_webhook_verification(
    hub_mode: str = Query(alias="hub.mode"),
    hub_verify_token: str = Query(alias="hub.verify_token"),
    hub_challenge: str = Query(alias="hub.challenge"),
):
    """Handle Meta's webhook verification handshake (hub.challenge)."""
    if hub_mode != "subscribe":
        raise HTTPException(status_code=400, detail="Invalid hub.mode")

    # 1. Match against the global environment variable
    if WHATSAPP_WEBHOOK_VERIFY_TOKEN and hub_verify_token == WHATSAPP_WEBHOOK_VERIFY_TOKEN:
        logger.info("[WhatsApp] Webhook verification succeeded via environment verify token")
        return PlainTextResponse(hub_challenge, status_code=200)

    # 2. Fallback: Match against active WhatsApp telephony configurations in the DB
    try:
        matching_config = await db_client.get_whatsapp_configuration_by_verify_token(
            hub_verify_token
        )
        if matching_config:
            logger.info(
                f"[WhatsApp] Webhook verification succeeded for config {matching_config.id}"
            )
            return PlainTextResponse(hub_challenge, status_code=200)
    except Exception as e:
        logger.warning(f"[WhatsApp] Error during DB verify token lookup: {e}")

    logger.warning("[WhatsApp] Webhook verification failed: token mismatch")
    raise HTTPException(status_code=403, detail="Invalid verification token")


def _verify_whatsapp_signature(
    app_secret: Optional[str],
    raw_body: bytes,
    signature_header: Optional[str],
    phone_number_id: Optional[str] = None,
) -> None:
    """Validate Meta's X-Hub-Signature-256 HMAC for incoming webhook payloads.

    Raises:
        HTTPException: 403 if signature is missing, invalid format, app_secret is not configured, or signature mismatch.
    """
    if not app_secret:
        logger.error(
            f"[WhatsApp] Webhook signature verification failed: app_secret not configured "
            f"for phone_number_id={phone_number_id}"
        )
        raise HTTPException(
            status_code=403,
            detail="Webhook signature verification failed: app_secret not configured",
        )

    if not signature_header:
        logger.error(
            f"[WhatsApp] Missing x-hub-signature-256 header for phone_number_id={phone_number_id}"
        )
        raise HTTPException(status_code=403, detail="Missing webhook signature")

    if not signature_header.startswith("sha256="):
        logger.error(f"[WhatsApp] Invalid signature header format: {signature_header}")
        raise HTTPException(status_code=403, detail="Invalid webhook signature")

    expected_sig = hmac.new(
        key=app_secret.encode("utf-8"),
        msg=raw_body,
        digestmod=hashlib.sha256,
    ).hexdigest()
    received_sig = signature_header[7:]

    if not hmac.compare_digest(expected_sig, received_sig):
        logger.error(
            f"[WhatsApp] Webhook signature verification failed for phone_number_id={phone_number_id}"
        )
        raise HTTPException(status_code=403, detail="Invalid webhook signature")


@router.post("/webhook")
async def handle_whatsapp_webhook(request: Request):
    """Handle incoming WhatsApp Cloud API webhooks (including calling events)."""
    try:
        raw_body = await request.body()
        signature_header = request.headers.get("x-hub-signature-256")

        if not signature_header:
            logger.error("[WhatsApp] Missing x-hub-signature-256 header")
            raise HTTPException(status_code=403, detail="Missing webhook signature")

        if not signature_header.startswith("sha256="):
            logger.error(f"[WhatsApp] Invalid signature header format: {signature_header}")
            raise HTTPException(status_code=403, detail="Invalid webhook signature")

        try:
            payload = json.loads(raw_body.decode("utf-8"))
        except Exception as e:
            logger.error(f"[WhatsApp] Webhook JSON parse error: {e}")
            raise HTTPException(status_code=400, detail="Invalid JSON payload")

        entry_list = payload.get("entry") or []
        if not entry_list:
            all_configs = await db_client.get_active_whatsapp_configurations()
            verified = False
            for cfg in all_configs:
                sec = (cfg.credentials or {}).get("app_secret")
                if sec:
                    expected_sig = hmac.new(
                        key=sec.encode("utf-8"),
                        msg=raw_body,
                        digestmod=hashlib.sha256,
                    ).hexdigest()
                    if hmac.compare_digest(expected_sig, signature_header[7:]):
                        verified = True
                        break
            if not verified:
                raise HTTPException(status_code=403, detail="Invalid webhook signature")
            return {"status": "success"}

        verified_configs: dict[str, Any] = {}

        async def _get_verified_config(p_id: str) -> Any:
            if not p_id:
                logger.error("[WhatsApp] Webhook change missing phone_number_id")
                raise HTTPException(
                    status_code=400,
                    detail="Missing phone_number_id in webhook metadata",
                )
            if p_id in verified_configs:
                return verified_configs[p_id]

            cfg = await db_client.get_whatsapp_configuration_by_phone_number_id(p_id)
            if not cfg:
                logger.error(
                    f"[WhatsApp] No active configuration found for phone_number_id {p_id}"
                )
                raise HTTPException(
                    status_code=404,
                    detail=f"No active configuration for phone_number_id {p_id}",
                )

            sec = (cfg.credentials or {}).get("app_secret")
            _verify_whatsapp_signature(
                app_secret=sec,
                raw_body=raw_body,
                signature_header=signature_header,
                phone_number_id=p_id,
            )
            verified_configs[p_id] = cfg
            return cfg

        for entry in entry_list:
            changes = entry.get("changes") or []
            for change in changes:
                field = change.get("field")
                value = change.get("value") or {}
                metadata = value.get("metadata") or {}
                phone_number_id = str(metadata.get("phone_number_id") or "")

                if field == "user_call_permissions":
                    await _get_verified_config(phone_number_id)
                    await _handle_user_call_permissions_change(
                        change_value=value,
                        metadata=metadata,
                    )
                    continue

                if field == "messages":
                    await _get_verified_config(phone_number_id)
                    # 1. Handle incoming user replies (interactive call_permission_reply)
                    incoming_messages = value.get("messages") or []
                    for msg in incoming_messages:
                        msg_type = msg.get("type")
                        from_wa_id = msg.get("from") or ""
                        if msg_type == "interactive":
                            interactive_data = msg.get("interactive") or {}
                            if interactive_data.get("type") == "call_permission_reply":
                                reply = interactive_data.get("call_permission_reply") or {}
                                response_choice = reply.get("response")  # "accept" or "decline"
                                is_perm = reply.get("is_permanent", False)
                                exp_ts = reply.get("expiration_timestamp")
                                expires_at = parse_whatsapp_expiration(exp_ts)
                                granted_at = (
                                    datetime.now(UTC)
                                    if response_choice == "accept"
                                    else None
                                )
                                status = (
                                    ("granted_permanent" if is_perm else "granted_temporary")
                                    if response_choice == "accept"
                                    else "denied"
                                )
                                perm_type = (
                                    ("permanent" if is_perm else "temporary")
                                    if response_choice == "accept"
                                    else None
                                )

                                logger.info(
                                    f"[WhatsApp] Call permission reply from {from_wa_id}: "
                                    f"response={response_choice}, status={status}, expires_at={expires_at}"
                                )

                                context_wamid = (msg.get("context") or {}).get("id")
                                updated_row = None
                                if context_wamid:
                                    updated_row = await db_client.update_whatsapp_call_permission_status_by_message_id(
                                        meta_message_id=context_wamid,
                                        status=status,
                                        permission_type=perm_type,
                                        expires_at=expires_at,
                                        granted_at=granted_at,
                                    )
                                if not updated_row and from_wa_id and phone_number_id:
                                    updated_row = await db_client.update_whatsapp_call_permission_status_by_wa_id(
                                        phone_number_id=phone_number_id,
                                        recipient_phone_number=from_wa_id,
                                        status=status,
                                        permission_type=perm_type,
                                        expires_at=expires_at,
                                        granted_at=granted_at,
                                    )

                                redis = await _get_redis()
                                if redis:
                                    try:
                                        await redis.publish(
                                            REDIS_PERMISSION_CHANNEL,
                                            json.dumps({
                                                "phone_number_id": phone_number_id,
                                                "recipient_phone_number": from_wa_id,
                                                "status": status,
                                                "expires_at": (
                                                    expires_at.isoformat()
                                                    if expires_at
                                                    else None
                                                ),
                                            }),
                                        )
                                    except Exception as e:
                                        logger.warning(f"[WhatsApp] Redis publish error: {e}")

                                # Reactivate parked campaign runs for this contact
                                await reactivate_campaign_runs_for_recipient(
                                    from_wa_id, status, phone_number_id=phone_number_id
                                )

                    # 2. Handle outbound message delivery status callbacks
                    statuses = value.get("statuses") or []
                    for st in statuses:
                        wamid = st.get("id")
                        st_name = st.get("status")
                        if not wamid:
                            continue
                        logger.info(f"[WhatsApp] Message status update: wamid={wamid}, status={st_name}")
                        if st_name == "failed":
                            err_list = st.get("errors") or []
                            first_err = err_list[0] if err_list else {}
                            err_code = first_err.get("code")
                            err_msg = (
                                first_err.get("error_data", {}).get("details")
                                or first_err.get("message")
                                or "Message delivery failed"
                            )
                            logger.warning(
                                f"[WhatsApp] Outbound message {wamid} failed ({err_code}): {err_msg}"
                            )
                            new_status = f"delivery_failed:{err_code}" if err_code else "delivery_failed"
                            updated = await db_client.update_whatsapp_call_permission_status_by_message_id(
                                meta_message_id=wamid,
                                status=new_status,
                            )
                            if updated:
                                redis = await _get_redis()
                                if redis:
                                    try:
                                        await redis.publish(
                                            REDIS_PERMISSION_CHANNEL,
                                            json.dumps({
                                                "phone_number_id": phone_number_id,
                                                "recipient_phone_number": updated.recipient_phone_number,
                                                "status": "delivery_failed",
                                                "error_code": err_code,
                                                "error_message": err_msg,
                                            }),
                                        )
                                    except Exception as e:
                                        logger.warning(f"[WhatsApp] Redis publish error: {e}")
                    continue

                if field != "calls":
                    logger.debug(f"[WhatsApp] Skipping non-calling webhook field: {field}")
                    continue

                calls = value.get("calls") or []
                call_statuses = value.get("statuses") or []
                if not calls and not call_statuses:
                    continue

                # Fallback to active connection if phone_number_id is omitted from metadata
                if not phone_number_id:
                    for item in calls + call_statuses:
                        cid = item.get("id")
                        if (
                            cid
                            and cid in _active_connections
                            and len(_active_connections[cid]) > 3
                        ):
                            phone_number_id = str(_active_connections[cid][3])
                            break

                config = await _get_verified_config(phone_number_id)

                # 1. Process call status callbacks (RINGING, ACCEPTED, etc.)
                if call_statuses:
                    for st in call_statuses:
                        cid = st.get("id") or ""
                        st_status = (st.get("status") or "").upper()
                        st_type = st.get("type")
                        opaque = st.get("biz_opaque_callback_data")
                        logger.info(
                            f"[WhatsApp] Call status callback: call_id={cid}, status={st_status}, "
                            f"type={st_type}, opaque={opaque}"
                        )
                        run_id = None
                        if opaque and str(opaque).isdigit():
                            run_id = int(opaque)
                        elif cid in _active_connections:
                            run_id = _active_connections[cid][1]

                        if run_id:
                            try:
                                run = await db_client.get_workflow_run(run_id)
                                if run:
                                    ctx = dict(run.gathered_context or {})
                                    if st_status == "RINGING":
                                        if ctx.get("call_status") != "in-progress":
                                            ctx["call_status"] = "ringing"
                                            await db_client.update_workflow_run(
                                                run_id, gathered_context=ctx
                                            )
                                    elif st_status in ("ACCEPTED", "CONNECTED"):
                                        await _handle_call_accepted(
                                            call_data={"id": cid},
                                            payload=payload,
                                        )
                            except Exception as e:
                                logger.warning(
                                    f"[WhatsApp] Failed to update workflow run {run_id} on call status {st_status}: {e}"
                                )

                # 2. Process call events (connect, terminate, accepted)
                for call_data in calls:
                    event = call_data.get("event")
                    call_id = call_data.get("id") or ""
                    session_data = call_data.get("session") or {}
                    sdp_type = session_data.get("sdp_type")

                    if event == "connect":
                        if sdp_type == "answer" or call_id in _active_connections:
                            logger.info(
                                f"[WhatsApp] Outbound call connect (sdp_type={sdp_type}) for call {call_id}; applying SDP answer"
                            )
                            await _handle_outbound_sdp_answer(
                                call_data=call_data,
                                payload=payload,
                            )
                        else:
                            await _handle_inbound_call_connect(
                                call_data=call_data,
                                metadata=metadata,
                                phone_number_id=phone_number_id,
                                raw_body=raw_body,
                                signature_header=signature_header,
                                payload=payload,
                                config=config,
                            )
                    elif event == "terminate":
                        await _handle_call_terminate(
                            call_data=call_data,
                            payload=payload,
                        )
                    elif event == "accepted":
                        await _handle_call_accepted(
                            call_data=call_data,
                            payload=payload,
                        )
                    else:
                        logger.info(
                            f"[WhatsApp] Received call event {event!r} for call {call_id}"
                        )

        return {"status": "success"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"[WhatsApp] Error processing webhook: {e}", exc_info=True)
        raise HTTPException(
            status_code=500, detail=f"Webhook processing failed: {str(e)}"
        )


async def _handle_inbound_call_connect(
    call_data: Dict[str, Any],
    metadata: Dict[str, Any],
    phone_number_id: str,
    raw_body: bytes,
    signature_header: Optional[str],
    payload: Dict[str, Any],
    config: Optional[TelephonyConfigurationModel] = None,
) -> None:
    """Process an incoming WhatsApp call connect event (SDP offer)."""
    call_id = call_data.get("id") or ""
    from_number = call_data.get("from") or ""
    to_number = call_data.get("to") or metadata.get("display_phone_number") or ""
    session_data = call_data.get("session") or {}
    sdp_type = session_data.get("sdp_type")

    logger.info(
        f"[WhatsApp] Incoming call {call_id} from {from_number} to {to_number}, "
        f"sdp_type={sdp_type}"
    )

    if sdp_type != "offer":
        if sdp_type == "answer" or call_id in _active_connections:
            logger.info(
                f"[WhatsApp] Inbound connect called with sdp_type={sdp_type} for outbound call {call_id}; delegating to _handle_call_accepted"
            )
            await _handle_call_accepted(call_data=call_data, payload=payload)
            return
        logger.warning(
            f"[WhatsApp] Unexpected sdp_type {sdp_type!r} for inbound call {call_id}"
        )
        return

    # 1. Check for duplicate or active call
    if not call_id:
        logger.warning("[WhatsApp] Missing call_id in connect event")
        return

    if call_id in _active_connections:
        logger.warning(
            f"[WhatsApp] Call {call_id} already active in-memory, ignoring duplicate connect"
        )
        return

    existing_run = await db_client.get_workflow_run_by_call_id(call_id)
    if existing_run:
        logger.warning(
            f"[WhatsApp] Call {call_id} already has workflow_run {existing_run.id}, ignoring duplicate connect"
        )
        return

    # 2. Lookup the TelephonyConfiguration for this phone_number_id if not supplied
    if config is None:
        config = await db_client.get_whatsapp_configuration_by_phone_number_id(
            phone_number_id
        )
        if not config:
            logger.error(
                f"[WhatsApp] No active configuration found for phone_number_id {phone_number_id}"
            )
            return

        app_secret = (config.credentials or {}).get("app_secret")
        _verify_whatsapp_signature(
            app_secret=app_secret,
            raw_body=raw_body,
            signature_header=signature_header,
            phone_number_id=phone_number_id,
        )

    access_token = (config.credentials or {}).get("access_token")

    # 3. Resolve destination phone number & assigned inbound workflow
    normalized_to = (
        normalize_telephony_address(to_number).canonical if to_number else ""
    )
    normalized_from = (
        normalize_telephony_address(from_number).canonical if from_number else ""
    )

    phones = await db_client.list_phone_numbers_for_config(config.id)
    phone_row: Optional[TelephonyPhoneNumberModel] = None
    for p in phones:
        if p.is_active and p.address_normalized == normalized_to:
            phone_row = p
            break

    # Fallback: only when destination to_number was omitted/empty in the incoming webhook,
    # resolve by matching phone_number_id in extra_metadata or single active phone row
    if not phone_row and not normalized_to:
        if phone_number_id:
            for p in phones:
                if not getattr(p, "is_active", True):
                    continue
                meta = getattr(p, "extra_metadata", {}) or {}
                if str(meta.get("phone_number_id") or meta.get("meta_phone_number_id") or "") == str(phone_number_id):
                    phone_row = p
                    break

        if not phone_row:
            active_phones = [p for p in phones if getattr(p, "is_active", True)]
            if len(active_phones) == 1:
                phone_row = active_phones[0]

        if phone_row:
            normalized_to = phone_row.address_normalized

    if not phone_row:
        logger.warning(
            f"[WhatsApp] No active configured phone number found matching destination "
            f"{normalized_to} (or phone_number_id {phone_number_id}) for config {config.id}. "
            f"Rejecting call {call_id}."
        )
        await _reject_whatsapp_call(phone_number_id, call_id, access_token)
        return

    if not phone_row.inbound_workflow_id:
        logger.warning(
            f"[WhatsApp] No inbound workflow assigned for number {to_number} "
            f"(phone_number_id {phone_number_id}). Rejecting call."
        )
        await _reject_whatsapp_call(phone_number_id, call_id, access_token)
        return

    workflow_id = phone_row.inbound_workflow_id
    workflow = await db_client.get_workflow(
        workflow_id, organization_id=config.organization_id
    )
    if not workflow:
        logger.error(
            f"[WhatsApp] Inbound workflow {workflow_id} not found in org {config.organization_id}. Rejecting."
        )
        await _reject_whatsapp_call(phone_number_id, call_id, access_token)
        return

    # 4. Concurrency slot & workflow run creation
    try:
        concurrency_slot = await call_concurrency.acquire_org_slot(
            config.organization_id,
            source="inbound:whatsapp",
            timeout=0,
        )
    except CallConcurrencyLimitError:
        logger.warning(
            f"[WhatsApp] Concurrency limit exceeded for org {config.organization_id}"
        )
        await _reject_whatsapp_call(phone_number_id, call_id, access_token)
        return

    workflow_run = None
    slot_bound = False
    try:
        run_inputs = await prepare_workflow_run_inputs(db_client, workflow)
        workflow_run_name = f"Inbound WhatsApp call from {normalized_from}"

        workflow_run = await db_client.create_workflow_run(
            workflow_run_name,
            workflow_id,
            "whatsapp",
            user_id=workflow.user_id,
            call_type=CallType.INBOUND,
            initial_context={
                "caller_number": normalized_from,
                "called_number": normalized_to,
                "direction": "inbound",
                "provider": "whatsapp",
                "telephony_configuration_id": config.id,
            },
            gathered_context={
                "call_id": call_id,
            },
            logs={
                "inbound_webhook": {
                    "account_id": phone_number_id,
                    "from_number": normalized_from,
                    "to_number": normalized_to,
                    "from_phone_number_id": phone_row.id,
                },
            },
            organization_id=config.organization_id,
            definition_id=run_inputs.definition_id,
        )
        await call_concurrency.bind_workflow_run(concurrency_slot, workflow_run.id)
        slot_bound = True

        quota_result = await authorize_workflow_run_start(
            workflow_id=workflow_id,
            organization_id=config.organization_id,
            workflow_run_id=workflow_run.id,
        )
        if not quota_result.has_quota:
            logger.warning(
                f"[WhatsApp] Org {config.organization_id} has exceeded quota: "
                f"{quota_result.error_message}"
            )
            await mark_workflow_run_failed(
                workflow_run.id, quota_result.error_message or "Quota exceeded"
            )
            await call_concurrency.release_workflow_run_slot(workflow_run.id)
            await _reject_whatsapp_call(phone_number_id, call_id, access_token)
            return

    except Exception as e:
        logger.error(f"[WhatsApp] Failed to initialize workflow run: {e}")
        if workflow_run:
            await mark_workflow_run_failed(workflow_run.id, str(e))
        if slot_bound:
            await call_concurrency.release_workflow_run_slot(workflow_run.id)
        else:
            await call_concurrency.release_slot(concurrency_slot)
        await _reject_whatsapp_call(phone_number_id, call_id, access_token)
        return

    # 5. Connect WebRTC via Pipecat's WhatsAppClient
    # Signature is already verified above in routes.py, so we pass app_secret=None
    # to avoid redundant double-verification in WhatsAppClient.
    client = _get_or_create_whatsapp_client(
        phone_number_id=phone_number_id,
        access_token=access_token,
        app_secret=None,
    )

    async def on_call_connected(
        connection: SmallWebRTCConnection, call: WhatsAppConnectCall
    ) -> None:
        logger.info(
            f"[WhatsApp] Call {call.id} connected! Starting voice pipeline for "
            f"workflow_run {workflow_run.id} in background"
        )
        _active_connections[call.id] = (
            connection,
            workflow_run.id,
            config.organization_id,
            phone_number_id,
        )

        # Store call lifecycle state in shared Redis
        try:
            redis = await _get_redis()
            if redis:
                await redis.setex(
                    f"{WHATSAPP_CALL_KEY_PREFIX}{call.id}",
                    3600,
                    json.dumps({
                        "workflow_run_id": workflow_run.id,
                        "organization_id": config.organization_id,
                        "phone_number_id": phone_number_id,
                    }),
                )
        except Exception as e:
            logger.warning(f"[WhatsApp] Failed to store call state in Redis: {e}")

        # Ensure this worker is subscribed to cross-worker shutdown events
        _ensure_redis_subscriber()

        # Launch the voice pipeline asynchronously so the webhook responds immediately
        pipeline_task = asyncio.create_task(
            _run_whatsapp_pipeline(
                connection=connection,
                workflow_id=workflow_id,
                workflow_run_id=workflow_run.id,
                user_id=workflow.user_id,
                organization_id=config.organization_id,
                call_id=call.id,
            )
        )
        _background_tasks.add(pipeline_task)
        pipeline_task.add_done_callback(_background_tasks.discard)

    try:
        parsed_request = WhatsAppWebhookRequest.model_validate(payload)
        await client.handle_webhook_request(
            request=parsed_request,
            connection_callback=on_call_connected,
            raw_body=raw_body,
            sha256_signature=signature_header,
        )
        logger.info(
            f"[WhatsApp] Successfully accepted call {call_id} and dispatched pipeline"
        )
    except Exception as e:
        logger.error(f"[WhatsApp] Failed to establish WebRTC connection for call {call_id}: {e}")
        await mark_workflow_run_failed(
            workflow_run.id, f"WebRTC connection failed: {e}"
        )
        await call_concurrency.release_workflow_run_slot(workflow_run.id)
        await _reject_whatsapp_call(phone_number_id, call_id, access_token)


async def _run_whatsapp_pipeline(
    connection: SmallWebRTCConnection,
    workflow_id: int,
    workflow_run_id: int,
    user_id: int,
    organization_id: int,
    call_id: str,
    call_answered_event: Optional[asyncio.Event] = None,
) -> None:
    """Execute Dograh's WebRTC AI pipeline over the active peer connection."""
    try:
        logger.info(
            f"[WhatsApp] Pipeline started for workflow_run {workflow_run_id}, call_id={call_id}"
        )
        await run_pipeline_smallwebrtc(
            webrtc_connection=connection,
            workflow_id=workflow_id,
            workflow_run_id=workflow_run_id,
            user_id=user_id,
            organization_id=organization_id,
            call_answered_event=call_answered_event,
        )
        logger.info(
            f"[WhatsApp] Pipeline finished cleanly for workflow_run {workflow_run_id}"
        )
    except Exception as e:
        logger.error(
            f"[WhatsApp] Pipeline error for workflow_run {workflow_run_id}: {e}",
            exc_info=True,
        )
        try:
            await mark_workflow_run_failed(
                workflow_run_id, str(e), only_if_incomplete=True
            )
        except Exception as mark_err:
            logger.warning(
                f"[WhatsApp] Failed to mark workflow run {workflow_run_id} failed: {mark_err}"
            )
    finally:
        answered_evt = _outbound_answered_events.pop(call_id, None)
        if answered_evt and not answered_evt.is_set():
            answered_evt.set()
        try:
            await terminate_whatsapp_call_by_id(
                call_id=call_id,
                workflow_run_id=workflow_run_id,
                organization_id=organization_id,
            )
        except Exception as term_err:
            logger.warning(
                f"[WhatsApp] Failed to send terminate in pipeline cleanup for call {call_id}: {term_err}"
            )
        _active_connections.pop(call_id, None)
        try:
            redis = await _get_redis()
            if redis:
                await redis.delete(f"{WHATSAPP_CALL_KEY_PREFIX}{call_id}")
        except Exception:
            pass
        try:
            await call_concurrency.release_workflow_run_slot(workflow_run_id)
        except Exception as e:
            logger.warning(
                f"[WhatsApp] Failed to release concurrency slot for workflow_run {workflow_run_id}: {e}"
            )


async def _handle_call_terminate(
    call_data: Dict[str, Any], payload: Dict[str, Any]
) -> None:
    """Handle a WhatsApp call termination event from Meta."""
    call_id = call_data.get("id") or ""
    if not call_id:
        return
    logger.info(f"[WhatsApp] Processing terminate event for call {call_id}")

    # Broadcast terminate to owning worker via Redis pub/sub and delete call key
    try:
        redis = await _get_redis()
        if redis:
            await redis.delete(f"{WHATSAPP_CALL_KEY_PREFIX}{call_id}")
            await redis.publish(
                REDIS_TERMINATE_CHANNEL,
                json.dumps({"call_id": call_id}),
            )
    except Exception as e:
        logger.warning(f"[WhatsApp] Failed to publish terminate to Redis: {e}")

    answered_evt = _outbound_answered_events.pop(call_id, None)
    if answered_evt and not answered_evt.is_set():
        answered_evt.set()

    entry = _active_connections.pop(call_id, None)
    if entry:
        connection, workflow_run_id, org_id = entry[:3]
        try:
            await connection.disconnect()
            logger.info(f"[WhatsApp] Peer connection closed for call {call_id}")
        except Exception as e:
            logger.warning(f"[WhatsApp] Error during peer connection disconnect: {e}")

        # Mark workflow run state if still running
        try:
            errors = call_data.get("errors") or []
            err_msg = None
            if errors and isinstance(errors, list) and len(errors) > 0:
                err_msg = errors[0].get("title") or errors[0].get("message")
            run = await db_client.get_workflow_run(workflow_run_id)
            ctx = dict(run.gathered_context or {}) if run else {}
            ctx["call_status"] = "failed" if err_msg else "completed"
            ctx["ended_at"] = datetime.now(timezone.utc).isoformat()
            if err_msg:
                ctx["error"] = err_msg
            await db_client.update_workflow_run(
                workflow_run_id,
                is_completed=True,
                state=WorkflowRunState.COMPLETED.value,
                gathered_context=ctx,
            )
        except Exception as e:
            logger.warning(f"[WhatsApp] Failed to update workflow run on termination: {e}")

        try:
            await call_concurrency.release_workflow_run_slot(workflow_run_id)
        except Exception as e:
            logger.warning(
                f"[WhatsApp] Failed to release concurrency slot on terminate for {workflow_run_id}: {e}"
            )
    else:
        # Cross-worker termination cleanup: when webhook hits a different worker instance
        try:
            run = await db_client.get_workflow_run_by_call_id(call_id)
            if run and not run.is_completed:
                logger.info(
                    f"[WhatsApp] Cleaning up cross-worker workflow run {run.id} for terminated call {call_id}"
                )
                errors = call_data.get("errors") or []
                err_msg = None
                if errors and isinstance(errors, list) and len(errors) > 0:
                    err_msg = errors[0].get("title") or errors[0].get("message")
                ctx = dict(run.gathered_context or {})
                ctx["call_status"] = "failed" if err_msg else "completed"
                ctx["ended_at"] = datetime.now(timezone.utc).isoformat()
                if err_msg:
                    ctx["error"] = err_msg
                await db_client.update_workflow_run(
                    run.id,
                    is_completed=True,
                    state=WorkflowRunState.COMPLETED.value,
                    gathered_context=ctx,
                )
                await call_concurrency.release_workflow_run_slot(run.id)
        except Exception as e:
            logger.warning(
                f"[WhatsApp] Failed cross-worker terminate cleanup for call {call_id}: {e}"
            )


async def _handle_outbound_sdp_answer(
    call_data: Dict[str, Any], payload: Dict[str, Any]
) -> None:
    """Handle WebRTC SDP answer for an outbound call (sets remote description during dialing)."""
    call_id = call_data.get("id") or ""
    if not call_id:
        return
    logger.info(f"[WhatsApp] Processing WebRTC SDP answer for outbound call {call_id}")
    session_data = call_data.get("session") or {}
    sdp = session_data.get("sdp")
    sdp_type = session_data.get("sdp_type", "answer")

    if call_id in _active_connections and sdp:
        conn, workflow_run_id, org_id, phone_number_id = _active_connections[call_id]
        try:
            await conn.set_answer(sdp, type=sdp_type)
            logger.info(f"[WhatsApp] WebRTC SDP answer set locally for call {call_id}")
            if not getattr(conn, "_connect_invoked", False) or conn.is_connected():
                await conn.connect()
        except Exception as e:
            logger.warning(
                f"[WhatsApp] Failed setting local SDP answer for call {call_id}: {e}"
            )

    # Broadcast to other workers via Redis
    try:
        redis = await _get_redis()
        if redis:
            await redis.publish(
                REDIS_CALL_EVENTS_CHANNEL,
                json.dumps({
                    "event": "sdp_answer",
                    "call_id": call_id,
                    "sdp": sdp,
                    "sdp_type": sdp_type,
                }),
            )
    except Exception as e:
        logger.warning(f"[WhatsApp] Failed publishing call sdp_answer event: {e}")


async def _handle_call_accepted(
    call_data: Dict[str, Any], payload: Dict[str, Any]
) -> None:
    """Handle an accepted event for business-initiated or outbound call (user answered)."""
    call_id = call_data.get("id") or ""
    if not call_id:
        return
    logger.info(f"[WhatsApp] Processing accepted event (user answered) for call {call_id}")
    session_data = call_data.get("session") or {}
    sdp = session_data.get("sdp")
    sdp_type = session_data.get("sdp_type", "answer")

    # If SDP was included with accepted, apply it
    if call_id in _active_connections and sdp:
        conn = _active_connections[call_id][0]
        try:
            await conn.set_answer(sdp, type=sdp_type)
            if not getattr(conn, "_connect_invoked", False) or conn.is_connected():
                await conn.connect()
        except Exception as e:
            logger.warning(f"[WhatsApp] Failed applying SDP answer in accepted for call {call_id}: {e}")

    # Unblock voice pipeline locally if waiting for call answer
    answered_evt = _outbound_answered_events.get(call_id)
    if answered_evt and not answered_evt.is_set():
        logger.info(f"[WhatsApp] Unblocking pipeline for answered call {call_id}")
        answered_evt.set()

    # Update DB state and active connection to running and in-progress
    if call_id in _active_connections:
        conn, workflow_run_id, org_id, phone_number_id = _active_connections[call_id]
        if hasattr(conn, "call_status"):
            conn.call_status = "in-progress"
        now_iso = datetime.now(timezone.utc).isoformat()
        if hasattr(conn, "connected_at") and not conn.connected_at:
            conn.connected_at = now_iso
        try:
            run = await db_client.get_workflow_run(workflow_run_id)
            if run:
                ctx = dict(run.gathered_context or {})
                ctx["call_status"] = "in-progress"
                if not ctx.get("connected_at"):
                    ctx["connected_at"] = now_iso
                await db_client.update_workflow_run(
                    workflow_run_id,
                    state=WorkflowRunState.RUNNING.value,
                    gathered_context=ctx,
                )
        except Exception as e:
            logger.warning(f"[WhatsApp] Failed to update workflow run on accepted: {e}")

    # Broadcast to other workers via Redis
    try:
        redis = await _get_redis()
        if redis:
            await redis.publish(
                REDIS_CALL_EVENTS_CHANNEL,
                json.dumps({
                    "event": "accepted",
                    "call_id": call_id,
                    "sdp": sdp,
                    "sdp_type": sdp_type,
                }),
            )
    except Exception as e:
        logger.warning(f"[WhatsApp] Failed publishing call accepted event: {e}")


# Register the WhatsApp pipeline runner with the service layer
set_pipeline_runner(_run_whatsapp_pipeline)


def get_active_whatsapp_connection_by_call_id(
    call_id: str,
) -> Optional[Tuple[SmallWebRTCConnection, int, int, str]]:
    """Retrieve active connection tuple for call_id if present on this worker."""
    return _active_connections.get(call_id)


def get_active_whatsapp_connection_by_run_id(
    workflow_run_id: int,
) -> Optional[Tuple[str, SmallWebRTCConnection]]:
    """Find active connection tuple by workflow_run_id on this worker."""
    for cid, entry in _active_connections.items():
        if entry[1] == workflow_run_id:
            return cid, entry[0]
    return None


async def terminate_whatsapp_call_by_id(
    call_id: str,
    workflow_run_id: Optional[int] = None,
    organization_id: Optional[int] = None,
) -> bool:
    """Terminate an active WhatsApp call locally and via Meta Graph API."""
    answered_evt = _outbound_answered_events.pop(call_id, None)
    if answered_evt and not answered_evt.is_set():
        answered_evt.set()

    phone_number_id = None
    entry = _active_connections.get(call_id)
    if entry:
        phone_number_id = entry[3]
        if not workflow_run_id:
            workflow_run_id = entry[1]
    elif call_id:
        try:
            redis = await _get_redis()
            if redis:
                raw_data = await redis.get(f"{WHATSAPP_CALL_KEY_PREFIX}{call_id}")
                if raw_data:
                    data = json.loads(raw_data)
                    phone_number_id = data.get("phone_number_id")
                    if not workflow_run_id:
                        workflow_run_id = data.get("workflow_run_id")
        except Exception as e:
            logger.warning(f"[WhatsApp] Redis lookup error during termination: {e}")

    # Fallback to workflow run gathered_context
    if not phone_number_id and workflow_run_id:
        try:
            run = await db_client.get_workflow_run(workflow_run_id)
            if run:
                ctx = run.gathered_context or {}
                phone_number_id = ctx.get("from_phone_number_id") or ctx.get("phone_number_id")
                if not organization_id:
                    organization_id = run.organization_id
        except Exception:
            pass

    # 1. Ask Meta Graph API to terminate the call on user device
    try:
        config = None
        if phone_number_id:
            config = await db_client.get_whatsapp_configuration_by_phone_number_id(
                str(phone_number_id)
            )
        if not config and organization_id:
            configs = await db_client.list_active_telephony_configurations_by_provider(
                organization_id, "whatsapp"
            )
            config = configs[0] if configs else None

        if config:
            creds = config.credentials or {}
            access_token = creds.get("access_token") or creds.get("api_key")
            app_secret = creds.get("app_secret")
            config_phone_number_id = str(creds.get("phone_number_id") or phone_number_id or "")
            if access_token and config_phone_number_id:
                client = _get_or_create_whatsapp_client(
                    config_phone_number_id, access_token, app_secret
                )
                if client and client._whatsapp_api:
                    resp = await client._whatsapp_api.terminate_call_to_whatsapp(call_id)
                    logger.info(
                        f"[WhatsApp] Sent terminate request to Meta API for call {call_id}: resp={resp}"
                    )
            else:
                logger.warning(
                    f"[WhatsApp] Cannot terminate call {call_id}: missing access_token or phone_number_id"
                )
        else:
            logger.warning(
                f"[WhatsApp] Cannot terminate call {call_id}: no active WhatsApp configuration found"
            )
    except Exception as e:
        logger.warning(f"[WhatsApp] Meta Graph API termination failed: {e}")

    # 2. Terminate connection and clean up workflow run locally
    await _handle_call_terminate({"id": call_id}, {})
    return True


async def _handle_user_call_permissions_change(
    change_value: Dict[str, Any],
    metadata: Dict[str, Any],
) -> None:
    """Process user_call_permissions webhook events from Meta."""
    phone_number_id = str(metadata.get("phone_number_id") or "")
    raw_perms = change_value.get("user_call_permissions")
    if raw_perms is None:
        raw_perms = change_value.get("user_call_permission")
    if raw_perms is None and ("user_wa_id" in change_value or "wa_id" in change_value):
        user_permissions = [change_value]
    elif isinstance(raw_perms, list):
        user_permissions = raw_perms
    elif isinstance(raw_perms, dict):
        user_permissions = [raw_perms]
    else:
        user_permissions = []

    for perm in user_permissions:
        user_wa_id = str(perm.get("user_wa_id") or perm.get("wa_id") or perm.get("recipient_id") or "")
        raw_status = perm.get("status")
        # Only canonical states may reach the permission record; a malformed or
        # future webhook value must not overwrite a valid grant with a placeholder.
        status = normalize_whatsapp_permission_status(raw_status)
        if not user_wa_id or not status:
            logger.warning(
                f"[WhatsApp] Ignoring call permission update for phone_number_id={phone_number_id}: "
                f"user_wa_id={user_wa_id!r}, unsupported status={raw_status!r}"
            )
            continue

        expiration = perm.get("expiration") or perm.get("expiration_time")
        expires_at = None
        if expiration and status in GRANTED_PERMISSION_STATUSES:
            expires_at = parse_whatsapp_expiration(expiration)

        perm_type = "permanent" if status == "granted_permanent" else "temporary"
        granted_at = datetime.now(UTC) if status in GRANTED_PERMISSION_STATUSES else None

        logger.info(
            f"[WhatsApp] Call permission update for phone_number_id={phone_number_id}, "
            f"user_wa_id={user_wa_id}, status={status}, expires_at={expires_at}"
        )

        try:
            await db_client.update_whatsapp_call_permission_status_by_wa_id(
                phone_number_id=phone_number_id,
                recipient_phone_number=user_wa_id,
                status=status,
                permission_type=perm_type,
                expires_at=expires_at,
                granted_at=granted_at,
            )
        except Exception as e:
            logger.warning(f"[WhatsApp] Failed to update call permission in DB: {e}")

        try:
            redis = await _get_redis()
            if redis:
                await redis.publish(
                    REDIS_PERMISSION_CHANNEL,
                    json.dumps({
                        "phone_number_id": phone_number_id,
                        "user_wa_id": user_wa_id,
                        "status": status,
                    }),
                )
        except Exception as e:
            logger.warning(f"[WhatsApp] Failed to publish permission update to Redis: {e}")

        # Check for active campaign runs parked waiting for this recipient's permission
        await reactivate_campaign_runs_for_recipient(
            user_wa_id, status, phone_number_id=phone_number_id
        )


async def reactivate_campaign_runs_for_recipient(
    phone_number: str,
    status: str,
    phone_number_id: Optional[str] = None,
    telephony_configuration_id: Optional[int] = None,
    campaign_id: Optional[int] = None,
) -> int:
    """Reactivate parked campaign runs when a recipient grants call permission, or fail them if denied."""
    if not phone_number:
        return 0

    clean_phone = phone_number.strip().lstrip("+")
    try:
        from api.tasks.arq import enqueue_job
        from api.tasks.function_names import FunctionNames

        # Resolve target configuration id if phone_number_id is supplied
        target_config_id = telephony_configuration_id
        if target_config_id is None and phone_number_id:
            cfg = await db_client.get_whatsapp_configuration_by_phone_number_id(phone_number_id)
            if cfg:
                target_config_id = cfg.id

        waiting_runs = await db_client.get_queued_runs_awaiting_whatsapp_permission(clean_phone)
        if not waiting_runs:
            waiting_runs = await db_client.get_queued_runs_awaiting_whatsapp_permission("+" + clean_phone)

        if not waiting_runs:
            return 0

        # Filter waiting runs by campaign_id or telephony_configuration_id if provided
        filtered_runs = []
        for q_run in waiting_runs:
            if campaign_id is not None and q_run.campaign_id != campaign_id:
                continue
            if target_config_id is not None:
                camp = await db_client.get_campaign_by_id(q_run.campaign_id)
                if not camp or camp.telephony_configuration_id != target_config_id:
                    continue
            filtered_runs.append(q_run)

        if not filtered_runs:
            return 0

        if status in ("granted", "temporary", "permanent", "granted_temporary", "granted_permanent"):
            logger.info(
                f"[WhatsApp] Found {len(filtered_runs)} queued run(s) awaiting permission for {clean_phone}. "
                "Activating for immediate dialing."
            )
            triggered_campaign_ids = set()
            for q_run in filtered_runs:
                await db_client.activate_queued_run_for_immediate_dial(q_run.id)
                triggered_campaign_ids.add(q_run.campaign_id)

            for camp_id in triggered_campaign_ids:
                campaign = await db_client.get_campaign_by_id(camp_id)
                if campaign and campaign.state == "running":
                    await enqueue_job(
                        FunctionNames.PROCESS_CAMPAIGN_BATCH,
                        camp_id,
                        10,
                    )
                    logger.info(
                        f"[WhatsApp] Enqueued immediate batch for campaign {camp_id} "
                        f"after recipient {clean_phone} granted call permission."
                    )
            return len(filtered_runs)

        elif status in ("denied", "revoked"):
            for q_run in filtered_runs:
                await db_client.fail_queued_run_permission_denied(q_run.id)
                logger.info(
                    f"[WhatsApp] Marked queued run {q_run.id} as failed (permission_denied) "
                    f"for recipient {clean_phone}."
                )
            return len(filtered_runs)
    except Exception as e:
        logger.warning(
            f"[WhatsApp] Error reactivating queued runs on permission change for {clean_phone}: {e}"
        )
    return 0


async def sync_whatsapp_permissions_for_campaign(
    campaign_id: int, force: bool = False
) -> int:
    """
    Syncs WhatsApp call permission status from Meta Graph API for any leads parked
    in awaiting_whatsapp_permission for this campaign.
    
    If permission has been granted, activates the queued run for immediate dialing.
    If force is False, enforces a 30s cooldown per campaign via Redis to avoid spamming Meta.
    Returns the count of reactivated runs.
    """
    if not campaign_id:
        return 0

    redis_client = await _get_redis()
    cooldown_key = f"wa_perm_sync_cooldown:{campaign_id}"
    if not force and redis_client:
        try:
            if await redis_client.get(cooldown_key):
                return 0
        except Exception:
            pass

    try:
        parked_runs = await db_client.get_all_queued_runs_awaiting_whatsapp_permission(
            campaign_id=campaign_id
        )
        if not parked_runs:
            return 0

        campaign = await db_client.get_campaign_by_id(campaign_id)
        if not campaign or campaign.state != "running":
            return 0

        if not campaign.telephony_configuration_id:
            return 0

        config = await db_client.get_telephony_configuration(
            campaign.telephony_configuration_id
        )
        if not config or config.provider != "whatsapp":
            return 0

        creds = config.credentials or {}
        phone_number_id = creds.get("phone_number_id")
        access_token = creds.get("access_token")
        if not phone_number_id or not access_token:
            return 0

        client = _get_or_create_whatsapp_client(
            phone_number_id=phone_number_id,
            access_token=access_token,
            app_secret=creds.get("app_secret"),
        )

        # Set 30s cooldown in Redis
        if redis_client:
            try:
                await redis_client.set(cooldown_key, "1", ex=30)
            except Exception:
                pass

        recipients = set()
        for r in parked_runs:
            pn = str((r.context_variables or {}).get("phone_number") or "").strip()
            if pn:
                recipients.add(pn)

        reactivated_total = 0
        now = datetime.now(UTC)

        for recipient in recipients:
            clean_recipient = recipient.lstrip("+")
            try:
                meta_res = await client.check_call_permission(clean_recipient)
                if not meta_res or "error" in meta_res:
                    continue

                meta_perm = meta_res.get("permission") or {}
                meta_status = meta_perm.get("status") or meta_res.get("status")
                can_start_call = False
                for act in meta_res.get("actions") or []:
                    if act.get("action_name") == "start_call" and act.get("can_perform_action", False):
                        can_start_call = True

                normalized_status = normalize_whatsapp_permission_status(meta_status)

                if can_start_call or normalized_status in GRANTED_PERMISSION_STATUSES:
                    actual_status = (
                        normalized_status
                        if normalized_status in GRANTED_PERMISSION_STATUSES
                        else "granted_temporary"
                    )
                    perm_type = (
                        "permanent" if actual_status == "granted_permanent" else "temporary"
                    )
                    # Persist Meta's expiry: a temporary grant stored without one
                    # would later read as a permission that never lapses.
                    meta_expires_at = parse_whatsapp_expiration(
                        meta_perm.get("expiration_time") or meta_res.get("expiration")
                    )
                    await db_client.upsert_whatsapp_call_permission(
                        organization_id=config.organization_id,
                        telephony_configuration_id=config.id,
                        phone_number_id=phone_number_id,
                        recipient_phone_number=recipient,
                        status=actual_status,
                        permission_type=perm_type,
                        expires_at=meta_expires_at,
                        granted_at=now,
                    )
                    count = await reactivate_campaign_runs_for_recipient(
                        recipient,
                        actual_status,
                        phone_number_id=phone_number_id,
                        telephony_configuration_id=config.id,
                        campaign_id=campaign_id,
                    )
                    reactivated_total += count
                elif normalized_status in ("denied", "revoked"):
                    await db_client.upsert_whatsapp_call_permission(
                        organization_id=config.organization_id,
                        telephony_configuration_id=config.id,
                        phone_number_id=phone_number_id,
                        recipient_phone_number=recipient,
                        status=normalized_status,
                        expires_at=None,
                    )
                    await reactivate_campaign_runs_for_recipient(
                        recipient,
                        normalized_status,
                        phone_number_id=phone_number_id,
                        telephony_configuration_id=config.id,
                        campaign_id=campaign_id,
                    )
            except Exception as e:
                logger.warning(
                    f"[WhatsApp] Failed checking call permission for {recipient} in campaign {campaign_id}: {e}"
                )

        return reactivated_total
    except Exception as e:
        logger.warning(f"[WhatsApp] Error in sync_whatsapp_permissions_for_campaign: {e}")
        return 0


async def sync_all_parked_whatsapp_permissions() -> int:
    """Check and sync WhatsApp call permissions across all running campaigns with parked runs."""
    try:
        parked = await db_client.get_all_queued_runs_awaiting_whatsapp_permission()
        if not parked:
            return 0
        campaign_ids = {r.campaign_id for r in parked}
        total = 0
        for cid in campaign_ids:
            total += await sync_whatsapp_permissions_for_campaign(cid, force=False)
        return total
    except Exception as e:
        logger.warning(f"[WhatsApp] Error in sync_all_parked_whatsapp_permissions: {e}")
        return 0


@router.get("/permissions/check", response_model=WhatsAppPermissionCheckResponse)
async def check_whatsapp_permission(
    telephony_configuration_id: int,
    recipient_phone_number: str,
    current_user: UserModel = Depends(get_user),
):
    """Check WhatsApp call permission status for a recipient."""
    recipient = recipient_phone_number.strip()
    is_restricted, reason = is_restricted_country(recipient)
    if is_restricted:
        return WhatsAppPermissionCheckResponse(
            can_call=False,
            status="restricted_country",
            restricted_country=True,
            restriction_reason=reason,
        )

    config = await db_client.get_telephony_configuration_for_org(
        telephony_configuration_id, current_user.selected_organization_id
    )
    if not config or config.provider != "whatsapp":
        raise HTTPException(
            status_code=404,
            detail="WhatsApp telephony configuration not found",
        )

    phone_number_id = (config.credentials or {}).get("phone_number_id")
    if not phone_number_id:
        raise HTTPException(
            status_code=400,
            detail="Configuration is missing phone_number_id",
        )

    clean_wa_id = recipient.lstrip("+")
    # Check database record
    perm = await db_client.get_whatsapp_call_permission(
        telephony_configuration_id=config.id,
        recipient_phone_number=recipient,
    )
    if not perm:
        perm = await db_client.get_whatsapp_call_permission(
            telephony_configuration_id=config.id,
            recipient_phone_number=clean_wa_id,
        )

    now = datetime.now(UTC)

    # 1. Query Meta API for latest ground truth (e.g. if user granted or revoked in WhatsApp)
    access_token = (config.credentials or {}).get("access_token")
    can_start_call = False
    can_request_permission = True
    request_limit_reason: Optional[str] = None
    meta_status: Optional[str] = None
    meta_expires_at: Optional[datetime] = None
    meta_api_success = False

    if access_token and phone_number_id:
        try:
            client = _get_or_create_whatsapp_client(
                phone_number_id=phone_number_id,
                access_token=access_token,
                app_secret=(config.credentials or {}).get("app_secret"),
            )
            meta_res = await client.check_call_permission(user_wa_id=clean_wa_id)
            if "error" in meta_res:
                err_data = meta_res.get("error") or {}
                err_msg = err_data.get("message") or "Unknown Meta API error"
                err_code = err_data.get("code")
                logger.warning(
                    f"[WhatsApp] check_call_permission returned Meta API error: code={err_code}, {err_msg}"
                )
                is_token_err = (
                    err_code in (190, 102)
                    or str(err_code) in ("190", "102")
                    or err_data.get("type") == "OAuthException"
                    or "token" in err_msg.lower()
                    or "session" in err_msg.lower()
                )
                if is_token_err:
                    return WhatsAppPermissionCheckResponse(
                        can_call=False,
                        status="token_expired",
                        delivery_error=(
                            f"Meta API Error ({err_code}): {err_msg}. "
                            "The WhatsApp access token has expired or is invalid. "
                            "Please generate a fresh token in Meta Business Manager and update Telephony Configuration."
                        ),
                        can_request_permission=False,
                    )
                meta_api_success = False
            else:
                meta_api_success = True
                meta_perm = meta_res.get("permission") or {}
                meta_status = meta_perm.get("status") or meta_res.get("status")
                expiration = meta_perm.get("expiration_time") or meta_res.get("expiration")
                meta_expires_at = parse_whatsapp_expiration(expiration)

                actions = meta_res.get("actions") or []
                for act in actions:
                    act_name = act.get("action_name")
                    if act_name == "start_call":
                        can_start_call = bool(act.get("can_perform_action", False))
                    elif act_name == "send_call_permission_request":
                        can_request_permission = bool(act.get("can_perform_action", True))
                        if not can_request_permission:
                            limits = act.get("limits") or []
                            limit_texts = []
                            for lim in limits:
                                cur = lim.get("current_usage", 0)
                                mx = lim.get("max_allowed", 0)
                                period = lim.get("time_period", "")
                                if cur >= mx and mx > 0:
                                    limit_texts.append(f"{cur}/{mx} sent in {period}")
                            if limit_texts:
                                request_limit_reason = (
                                    f"Meta request limit reached ({', '.join(limit_texts)})."
                                )
                            else:
                                request_limit_reason = (
                                    "Meta allows at most 1 permission request per 24 hours (max 2 per 7 days)."
                                )

            # If Meta granted permission (either via start_call action or permission.status)
            if can_start_call or meta_status in ("granted", "temporary", "permanent", "granted_temporary", "granted_permanent"):
                perm_type = "permanent" if meta_status in ("permanent", "granted_permanent") else "temporary"
                actual_status = "granted_permanent" if perm_type == "permanent" else "granted_temporary"
                await db_client.upsert_whatsapp_call_permission(
                    organization_id=config.organization_id,
                    telephony_configuration_id=config.id,
                    phone_number_id=phone_number_id,
                    recipient_phone_number=recipient,
                    status=actual_status,
                    permission_type=perm_type,
                    expires_at=meta_expires_at,
                    granted_at=now,
                )
                hours_left = (
                    max(0.0, (meta_expires_at - now).total_seconds() / 3600.0)
                    if meta_expires_at
                    else None
                )
                # Reactivate any parked campaign runs awaiting permission for this recipient
                await reactivate_campaign_runs_for_recipient(
                    recipient,
                    actual_status,
                    phone_number_id=phone_number_id,
                    telephony_configuration_id=config.id,
                )

                return WhatsAppPermissionCheckResponse(
                    can_call=True,
                    status=actual_status,
                    permission_type=perm_type,
                    expires_at=meta_expires_at.isoformat() if meta_expires_at else None,
                    hours_remaining=hours_left,
                    can_request_permission=False,
                )
            else:
                # Meta explicitly says no permission or revoked
                if meta_status in ("no_permission", "revoked", "denied", "expired"):
                    normalized_st = "denied" if meta_status == "no_permission" else meta_status
                    await db_client.upsert_whatsapp_call_permission(
                        organization_id=config.organization_id,
                        telephony_configuration_id=config.id,
                        phone_number_id=phone_number_id,
                        recipient_phone_number=recipient,
                        status=normalized_st,
                        expires_at=None,
                    )
                    if meta_status in ("revoked", "denied"):
                        await reactivate_campaign_runs_for_recipient(
                            recipient,
                            meta_status,
                            phone_number_id=phone_number_id,
                            telephony_configuration_id=config.id,
                        )
        except HTTPException as he:
            if he.status_code == 401 or "token" in str(he.detail).lower():
                return WhatsAppPermissionCheckResponse(
                    can_call=False,
                    status="token_expired",
                    delivery_error=str(he.detail),
                    hours_remaining=None,
                    can_request_permission=False,
                    request_limit_reason="WhatsApp access token has expired or is invalid.",
                )
            logger.warning(f"[WhatsApp] Failed querying call permission from Meta API: {he.detail}")
        except Exception as e:
            err_str = str(e).lower()
            if "190" in err_str or "102" in err_str or "token" in err_str or "oauthexception" in err_str:
                return WhatsAppPermissionCheckResponse(
                    can_call=False,
                    status="token_expired",
                    delivery_error=(
                        "The WhatsApp access token has expired or is invalid. "
                        "Please generate a fresh token in Meta Business Manager and update your Telephony Configuration."
                    ),
                    hours_remaining=None,
                    can_request_permission=False,
                    request_limit_reason="WhatsApp access token has expired or is invalid.",
                )
            logger.warning(f"[WhatsApp] Failed querying call permission from Meta API: {e}")

    # 2. Fallback to DB record if Meta API was not reachable
    if not meta_api_success and perm and perm.status in ("granted_temporary", "granted_permanent"):
        if perm.expires_at and now > perm.expires_at:
            await db_client.update_whatsapp_call_permission_status_by_wa_id(
                phone_number_id=phone_number_id,
                recipient_phone_number=perm.recipient_phone_number,
                status="expired",
            )
        else:
            hours_left = (
                max(0.0, (perm.expires_at - now).total_seconds() / 3600.0)
                if perm.expires_at
                else None
            )
            return WhatsAppPermissionCheckResponse(
                can_call=True,
                status=perm.status,
                permission_type=perm.permission_type,
                expires_at=perm.expires_at.isoformat() if perm.expires_at else None,
                hours_remaining=hours_left,
                can_request_permission=False,
            )

    # 3. If not granted, determine current state from DB or Meta
    effective_status = meta_status or (perm.status if perm else "not_requested")
    delivery_err = None
    hours_left = None

    if perm and (perm.status.startswith("delivery_failed") or perm.status in ("failed", "undelivered")):
        effective_status = "delivery_failed"
        is_24h_window = "131047" in perm.status
        delivery_err = (
            "Permission request message failed to deliver because the 24-hour customer service window is closed. "
            "The recipient must send any message (e.g. 'Hi') to your WhatsApp business number first to open the 24-hour window."
            if is_24h_window
            else "Permission request message delivery failed on WhatsApp."
        )
    elif perm and perm.status == "pending" and not meta_api_success:
        if perm.expires_at and now > perm.expires_at:
            effective_status = "expired"
        else:
            effective_status = "pending"
            if perm.expires_at:
                hours_left = max(0.0, (perm.expires_at - now).total_seconds() / 3600.0)
    elif meta_status in ("pending", "denied", "expired", "no_permission", "revoked"):
        effective_status = meta_status
        if meta_expires_at and meta_expires_at > now:
            hours_left = max(0.0, (meta_expires_at - now).total_seconds() / 3600.0)

    return WhatsAppPermissionCheckResponse(
        can_call=False,
        status=effective_status,
        delivery_error=delivery_err,
        hours_remaining=hours_left,
        can_request_permission=can_request_permission,
        request_limit_reason=request_limit_reason,
    )


@router.post("/permissions/request")
async def send_whatsapp_permission_request(
    payload: WhatsAppPermissionRequestPayload,
    current_user: UserModel = Depends(get_user),
):
    """Send an interactive call permission request to a WhatsApp user."""
    recipient = payload.recipient_phone_number.strip()
    is_restricted, reason = is_restricted_country(recipient)
    if is_restricted:
        raise HTTPException(
            status_code=400,
            detail=reason,
        )

    config = await db_client.get_telephony_configuration_for_org(
        payload.telephony_configuration_id, current_user.selected_organization_id
    )
    if not config or config.provider != "whatsapp":
        raise HTTPException(
            status_code=404,
            detail="WhatsApp telephony configuration not found",
        )

    creds = config.credentials or {}
    if not creds.get("business_initiated_calls_enabled", False):
        raise HTTPException(
            status_code=400,
            detail="Business-initiated calls are not enabled in this configuration settings.",
        )

    phone_number_id = creds.get("phone_number_id")
    access_token = creds.get("access_token")
    if not phone_number_id or not access_token:
        raise HTTPException(
            status_code=400,
            detail="Configuration is missing phone_number_id or access_token",
        )

    client = _get_or_create_whatsapp_client(
        phone_number_id=phone_number_id,
        access_token=access_token,
        app_secret=creds.get("app_secret"),
    )

    clean_to = recipient.lstrip("+")
    body_text = (
        (payload.body_text or "").strip()
        or (creds.get("default_permission_message") or "").strip()
        or DEFAULT_WHATSAPP_PERMISSION_MESSAGE
    )
    try:
        res = await client.send_call_permission_request(
            to=clean_to,
            body_text=body_text,
        )
    except HTTPException:
        raise
    except Exception as e:
        err_str = str(e).lower()
        if "190" in err_str or "102" in err_str or "token" in err_str or "oauthexception" in err_str:
            raise HTTPException(
                status_code=401,
                detail=(
                    "Meta API Error (190): The WhatsApp access token has expired or is invalid. "
                    "Please generate a fresh token in Meta Business Manager and update your Telephony Configuration."
                ),
            )
        logger.error(f"[WhatsApp] Failed sending permission request: {e}")
        raise HTTPException(
            status_code=400,
            detail=f"Failed to send permission request via Meta: {str(e)}",
        )

    if "error" in res:
        err = res.get("error", {})
        code = err.get("code")
        msg = err.get("message")
        if code in (190, 102) or err.get("type") == "OAuthException" or "token" in str(msg).lower():
            detail_msg = (
                "Meta API Error (190): The WhatsApp access token has expired or is invalid. "
                "Please generate a fresh access token (System User token recommended) in Meta Business Manager "
                "and update your WhatsApp configuration under Telephony Configurations."
            )
            raise HTTPException(
                status_code=401,
                detail=detail_msg,
            )
        else:
            detail_msg = f"Meta API Error ({code}): {msg}"
            raise HTTPException(
                status_code=400,
                detail=detail_msg,
            )


    messages = res.get("messages") or []
    message_id = messages[0].get("id") if messages else None

    now = datetime.now(UTC)
    expires_at = now + timedelta(days=7)  # 168 hours Meta timeout

    await db_client.upsert_whatsapp_call_permission(
        organization_id=config.organization_id,
        telephony_configuration_id=config.id,
        phone_number_id=phone_number_id,
        recipient_phone_number=recipient,
        status="pending",
        meta_message_id=message_id,
        expires_at=expires_at,
    )

    return {
        "success": True,
        "status": "pending",
        "message_id": message_id,
        "expires_at": expires_at.isoformat(),
        "hours_remaining": 168.0,
    }


@router.post("/permissions")
async def handle_permission_callback(request: Request):
    """Handle permission callback webhooks from Meta for business-initiated calls."""
    return await handle_whatsapp_webhook(request)
