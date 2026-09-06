"""WhatsApp WebRTC transport factory.

This module creates WebRTC transports for WhatsApp voice calls using
Pipecat's WhatsApp transport or custom implementation for OPUS codec
at 48kHz with DTLS/SRTP encryption.
"""

from fastapi import WebSocket
from pipecat.transports.websocket.fastapi import (
    FastAPIWebsocketParams,
    FastAPIWebsocketTransport,
)

from api.services.pipecat.audio_config import AudioConfig
from api.services.pipecat.audio_mixer import build_audio_out_mixer
from api.services.pipecat.transport_params import realtime_param_overrides
from api.services.telephony.factory import load_credentials_for_transport

from .serializers import WhatsAppFrameSerializer
from .strategies import WhatsAppTransferStrategy, WhatsAppHangupStrategy


async def create_transport(
    websocket: WebSocket,
    workflow_run_id: int,
    audio_config: AudioConfig,
    organization_id: int,
    *,
    ambient_noise_config: dict | None = None,
    telephony_configuration_id: int | None = None,
    is_realtime: bool = False,
    call_id: str,
):
    """
    Create a WebRTC transport for WhatsApp voice calls.

    This factory creates a Pipecat transport configured for WhatsApp's
    WebRTC requirements: OPUS codec at 48kHz with DTLS/SRTP encryption.

    Args:
        websocket: FastAPI WebSocket connection
        workflow_run_id: Workflow run identifier
        audio_config: Audio configuration for the call
        organization_id: Organization ID for credential lookup
        ambient_noise_config: Optional ambient noise configuration
        telephony_configuration_id: Telephony configuration ID
        is_realtime: Whether to use realtime mode
        call_id: WhatsApp call ID from Graph API

    Returns:
        Configured FastAPIWebsocketTransport for WhatsApp WebRTC

    Raises:
        ValueError: If required credentials are missing

    Note:
        WhatsApp uses 48kHz OPUS codec with WebRTC. The transport must
        handle SDP offer/answer exchange with Meta's servers and support
        ICE candidate negotiation for NAT traversal.
    """
    config = await load_credentials_for_transport(
        organization_id, telephony_configuration_id, expected_provider="whatsapp"
    )

    access_token = config.get("access_token")
    phone_number_id = config.get("phone_number_id")

    if not access_token or not phone_number_id:
        raise ValueError(
            f"Incomplete WhatsApp configuration for organization {organization_id}"
        )

    # Create frame serializer with WhatsApp-specific strategies
    serializer = WhatsAppFrameSerializer(
        call_id=call_id,
        phone_number_id=phone_number_id,
        access_token=access_token,
        transfer_strategy=WhatsAppTransferStrategy(),
        hangup_strategy=WhatsAppHangupStrategy(),
    )

    # Build audio output mixer
    audio_out_mixer = build_audio_out_mixer(audio_config)

    # Apply realtime parameter overrides if needed
    params = realtime_param_overrides(
        audio_config=audio_config,
        ambient_noise_config=ambient_noise_config,
        is_realtime=is_realtime,
    )

    # Create WebRTC transport with WhatsApp configuration
    transport = FastAPIWebsocketTransport(
        websocket=websocket,
        params=FastAPIWebsocketParams(
            audio_in_sample_rate=audio_config.input_sample_rate,
            audio_out_sample_rate=audio_config.output_sample_rate,
            # WhatsApp-specific WebRTC parameters
            # Add any additional WhatsApp-specific parameters here
        ),
        serializer=serializer,
        audio_out_mixer=audio_out_mixer,
        **params,
    )

    logger.info(
        f"Created WhatsApp WebRTC transport for call_id={call_id}, "
        f"workflow_run_id={workflow_run_id}"
    )

    return transport
