"""WhatsApp telephony service layer.

Manages active WebRTC connections, client caches, Redis pub/sub for
cross-worker events, and ICE/TURN credentials. Decouples core provider logic
from HTTP router handlers.
"""

import asyncio
import json
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

import aiohttp
from loguru import logger
import redis.asyncio as aioredis

from api.constants import (
    ENABLE_COTURN,
    FORCE_TURN_RELAY,
    REDIS_URL,
    TURN_HOST,
    TURN_PORT,
    TURN_SECRET,
)
from api.services.turn import generate_turn_credentials
from pipecat.transports.smallwebrtc.connection import IceServer, SmallWebRTCConnection
from pipecat.transports.whatsapp.client import WhatsAppClient

# Redis Channels & Key Prefixes
REDIS_TERMINATE_CHANNEL = "whatsapp:call:terminate"
REDIS_CALL_EVENTS_CHANNEL = "whatsapp:call:events"
REDIS_PERMISSION_CHANNEL = "whatsapp:permission:updated"
WHATSAPP_CALL_KEY_PREFIX = "whatsapp:call:"

# Active in-memory registry of ongoing WhatsApp WebRTC calls on this worker:
# call_id -> (SmallWebRTCConnection, workflow_run_id, organization_id, phone_number_id)
_active_connections: Dict[str, Tuple[SmallWebRTCConnection, int, int, str]] = {}
_outbound_answered_events: Dict[str, asyncio.Event] = {}
_background_tasks: Set[asyncio.Task] = set()

# Reusable aiohttp session and cached clients per phone_number_id
_http_session: Optional[aiohttp.ClientSession] = None
_clients: Dict[str, WhatsAppClient] = {}

# Redis client and subscriber
_redis_client: Optional[aioredis.Redis] = None
_redis_subscriber_task: Optional[asyncio.Task] = None

# Pipeline runner hook set by routes or runner runtime
_pipeline_runner: Optional[Callable[..., Any]] = None


def set_pipeline_runner(runner: Callable[..., Any]) -> None:
    """Register the voice pipeline runner callable."""
    global _pipeline_runner
    _pipeline_runner = runner


def get_pipeline_runner() -> Optional[Callable[..., Any]]:
    """Retrieve the registered voice pipeline runner callable."""
    return _pipeline_runner


def get_http_session() -> aiohttp.ClientSession:
    """Retrieve or create an aiohttp ClientSession bound to the running event loop."""
    global _http_session, _clients
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    session_loop = getattr(_http_session, "_loop", None) if _http_session else None
    if (
        _http_session is None
        or _http_session.closed
        or (loop and session_loop and session_loop != loop)
    ):
        if _http_session and not _http_session.closed:
            try:
                if session_loop and session_loop.is_running():
                    session_loop.create_task(_http_session.close())
                elif loop and loop.is_running():
                    loop.create_task(_http_session.close())
            except Exception:
                pass
        _clients.clear()
        _http_session = aiohttp.ClientSession()
    return _http_session


def build_whatsapp_ice_servers() -> List[IceServer]:
    """Configure STUN / TURN servers for WhatsApp WebRTC connections.

    The TURN credentials this mints are time-limited (TURN_CREDENTIAL_TTL), so
    the result is only good for as long as that TTL - call it per client fetch
    rather than once per process.
    """
    servers: List[IceServer] = []
    if not FORCE_TURN_RELAY:
        servers.append(IceServer(urls="stun:stun.l.google.com:19302"))

    if ENABLE_COTURN and TURN_HOST and TURN_SECRET:
        creds = generate_turn_credentials("whatsapp", TURN_SECRET)
        turn_udp = f"turn:{TURN_HOST}:{TURN_PORT}?transport=udp"
        turn_tcp = f"turn:{TURN_HOST}:{TURN_PORT}?transport=tcp"
        servers.append(
            IceServer(
                urls=[turn_udp, turn_tcp],
                username=creds["username"],
                credential=creds["password"],
            )
        )

    return servers


def get_or_create_whatsapp_client(
    phone_number_id: str,
    access_token: str,
    app_secret: Optional[str] = None,
) -> WhatsAppClient:
    """Get or instantiate a WhatsAppClient for the given business phone number."""
    client = _clients.get(phone_number_id)
    if not client:
        session = get_http_session()
        client = WhatsAppClient(
            whatsapp_token=access_token,
            phone_number_id=phone_number_id,
            session=session,
            ice_servers=build_whatsapp_ice_servers(),
            whatsapp_secret=app_secret,
        )
        _clients[phone_number_id] = client
    else:
        client.update_whatsapp_token(access_token)
        if app_secret:
            client.update_whatsapp_secret(app_secret)
        # Every new call builds its peer connection from the client's stored ICE
        # list, and the TURN credentials in it expire. A worker outliving
        # TURN_CREDENTIAL_TTL would otherwise hand every subsequent call the same
        # dead credentials and lose TURN relay.
        client.update_ice_servers(build_whatsapp_ice_servers())

    return client


async def get_whatsapp_redis() -> Optional[aioredis.Redis]:
    """Get or instantiate the Redis client for WhatsApp state and pub/sub."""
    global _redis_client
    if _redis_client is None:
        try:
            _redis_client = aioredis.from_url(REDIS_URL, decode_responses=True)
        except Exception as e:
            logger.warning(f"[WhatsApp] Failed to connect to Redis: {e}")
            return None
    return _redis_client


def ensure_redis_subscriber() -> None:
    """Ensure background listener for cross-worker events is running."""
    global _redis_subscriber_task
    if _redis_subscriber_task is None or _redis_subscriber_task.done():
        _redis_subscriber_task = asyncio.create_task(listen_for_remote_events())


async def listen_for_remote_events() -> None:
    """Listen for cross-worker events (terminate, accepted SDP) on Redis pub/sub."""
    while True:
        redis = None
        pubsub = None
        try:
            redis = aioredis.from_url(REDIS_URL, decode_responses=True)
            pubsub = redis.pubsub()
            await pubsub.subscribe(REDIS_TERMINATE_CHANNEL, REDIS_CALL_EVENTS_CHANNEL)
            async for message in pubsub.listen():
                if message.get("type") != "message":
                    continue
                try:
                    channel = message.get("channel")
                    data = json.loads(message["data"])
                    target_call_id = data.get("call_id")
                    if not target_call_id or target_call_id not in _active_connections:
                        continue

                    if channel == REDIS_TERMINATE_CHANNEL:
                        answered_evt = _outbound_answered_events.pop(target_call_id, None)
                        if answered_evt and not answered_evt.is_set():
                            answered_evt.set()
                        entry = _active_connections.pop(target_call_id, None)
                        if entry:
                            conn = entry[0]
                            try:
                                await conn.disconnect()
                                logger.info(
                                    f"[WhatsApp] Peer connection closed via cross-worker terminate for {target_call_id}"
                                )
                            except Exception as e:
                                logger.warning(
                                    f"[WhatsApp] Error during cross-worker peer disconnect: {e}"
                                )
                    elif channel == REDIS_CALL_EVENTS_CHANNEL:
                        event_type = data.get("event")
                        if event_type in ("sdp_answer", "accepted"):
                            sdp = data.get("sdp")
                            sdp_type = data.get("sdp_type", "answer")
                            if sdp and target_call_id in _active_connections:
                                conn = _active_connections[target_call_id][0]
                                try:
                                    logger.info(
                                        f"[WhatsApp] Applying cross-worker SDP answer for call {target_call_id}"
                                    )
                                    await conn.set_answer(sdp, type=sdp_type)
                                except Exception as e:
                                    logger.warning(
                                        f"[WhatsApp] Failed to set cross-worker answer: {e}"
                                    )
                except Exception as parse_err:
                    logger.warning(f"[WhatsApp] Error handling cross-worker message: {parse_err}")
        except asyncio.CancelledError:
            break
        except Exception as conn_err:
            logger.warning(f"[WhatsApp] Redis subscriber connection error: {conn_err}")
        finally:
            if pubsub:
                try:
                    await pubsub.unsubscribe()
                    await pubsub.close()
                except Exception:
                    pass
            if redis:
                try:
                    await redis.close()
                except Exception:
                    pass
        await asyncio.sleep(5)


def register_outbound_active_connection(
    call_id: str,
    connection: SmallWebRTCConnection,
    workflow_run_id: int,
    organization_id: int,
    phone_number_id: str,
    workflow_id: int,
    user_id: int,
) -> None:
    """Register an active outbound WebRTC connection and run its voice pipeline."""
    answered_event = asyncio.Event()
    _outbound_answered_events[call_id] = answered_event

    _active_connections[call_id] = (
        connection,
        workflow_run_id,
        organization_id,
        phone_number_id,
    )
    ensure_redis_subscriber()

    if _pipeline_runner:
        pipeline_task = asyncio.create_task(
            _pipeline_runner(
                connection=connection,
                workflow_id=workflow_id,
                workflow_run_id=workflow_run_id,
                user_id=user_id,
                organization_id=organization_id,
                call_id=call_id,
                call_answered_event=answered_event,
            )
        )
        _background_tasks.add(pipeline_task)
        pipeline_task.add_done_callback(_background_tasks.discard)
    else:
        logger.warning(
            f"[WhatsApp] No pipeline runner configured; active connection {call_id} registered without pipeline task"
        )


# Aliases for backwards compatibility with existing private names
_get_http_session = get_http_session
_build_whatsapp_ice_servers = build_whatsapp_ice_servers
_get_or_create_whatsapp_client = get_or_create_whatsapp_client
_get_redis = get_whatsapp_redis
_ensure_redis_subscriber = ensure_redis_subscriber
_listen_for_remote_events = listen_for_remote_events
