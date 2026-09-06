"""WhatsApp frame serializer for WebRTC media transport.

This module implements frame serialization for WhatsApp WebRTC connections,
following the pattern from other telephony providers.
"""

from pipecat.frames.frames import AudioRawFrame, EndFrame, InputAudioRawFrame
from pipecat.serializers.base_serializer import FrameSerializer


class WhatsAppFrameSerializer(FrameSerializer):
    """Frame serializer for WhatsApp WebRTC connections.

    Handles serialization/deserialization of audio frames for WhatsApp's
    WebRTC media transport with OPUS codec at 48kHz.
    """

    def __init__(
        self,
        call_id: str,
        phone_number_id: str,
        access_token: str,
        transfer_strategy=None,
        hangup_strategy=None,
    ):
        """Initialize WhatsApp frame serializer.

        Args:
            call_id: WhatsApp call ID from Graph API
            phone_number_id: Business phone number ID
            access_token: WhatsApp API access token
            transfer_strategy: Strategy for handling call transfers
            hangup_strategy: Strategy for handling call hangups
        """
        self.call_id = call_id
        self.phone_number_id = phone_number_id
        self.access_token = access_token
        self.transfer_strategy = transfer_strategy
        self.hangup_strategy = hangup_strategy

    async def serialize(self, frame: AudioRawFrame) -> bytes:
        """Serialize audio frame to bytes for transmission."""
        # WhatsApp transports raw audio bytes through the WebRTC layer.
        return frame.audio

    async def deserialize(self, data: bytes) -> InputAudioRawFrame:
        """Deserialize bytes to an input audio frame."""
        # WhatsApp audio is transported as mono PCM at 48 kHz.
        return InputAudioRawFrame(audio=data, sample_rate=48000, num_channels=1)
