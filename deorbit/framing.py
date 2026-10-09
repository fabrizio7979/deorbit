"""Wire framing: a 4-byte big-endian payload size, then the payload."""

import asyncio
import struct

# One-byte control payloads; everything else is a UTF-8 JSON object.
HEARTBEAT = b"\x06"
CLOSE = b"\x00"

_HEADER = struct.Struct(">I")


class FrameTooLarge(Exception):
    pass


def encode_frame(payload: bytes) -> bytes:
    if not payload:
        raise ValueError("zero-length frames are not allowed")
    # Header and payload go out in one write: the robot expects the whole
    # header to arrive in a single socket read.
    return _HEADER.pack(len(payload)) + payload


async def read_frame(reader: asyncio.StreamReader, max_size: int) -> bytes:
    """Read one payload. Raises ``IncompleteReadError`` if the stream ends first."""
    (size,) = _HEADER.unpack(await reader.readexactly(_HEADER.size))
    if size > max_size:
        raise FrameTooLarge(f"{size} byte frame exceeds the {max_size} byte limit")
    return await reader.readexactly(size)
