"""
WHAT:   The tracekeep wire protocol: a small binary header in front of
        every message sent over TCP, and a decoder that splits a TCP byte
        stream back into whole messages.
WHY:    TCP delivers a stream of bytes, not messages: one recv() can return
        half a message, or two at once. A length field in a fixed-size
        header tells the receiver exactly where each message ends.

Frame layout (big-endian, 8-byte header):

    +-------+---------+------+----------------+-----------------+
    | magic | version | type | payload length | payload         |
    | "TK"  | 1 byte  | 1 B  | 4 bytes        | 0 to 64 KiB     |
    +-------+---------+------+----------------+-----------------+
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from enum import IntEnum

MAGIC = b"TK"
"""WHAT: the first two bytes of every frame. WHY: lets a receiver reject random or misdirected traffic at once."""

VERSION = 1
"""WHAT: the protocol version. WHY: a future version 2 can be refused cleanly instead of misread."""

HEADER = struct.Struct(">2sBBI")
"""WHAT: magic (2 bytes), version (1), type (1), payload length (4), big-endian. WHY: network byte order."""

MAX_PAYLOAD = 64 * 1024
"""WHAT: the largest payload accepted (64 KiB).
WHY: the length field could claim 4 GiB; checking it before reading stops a
hostile sender from making the receiver allocate huge buffers."""


class MessageType(IntEnum):
    """
    WHAT:   The kinds of frame.
    WHY:    One byte in the header says how to read the payload.
    """

    HELLO = 1
    """WHAT: shipper to collector, first frame: the stream name. WHY: says which log the records belong to."""

    RECORD = 2
    """WHAT: shipper to collector: one sealed log record. WHY: the actual log data."""

    ACK = 3
    """WHAT: collector to shipper: next expected sequence number and last hash. WHY: confirms storage and lets a shipper resume."""

    ERROR = 4
    """WHAT: collector to shipper: why it is closing the connection. WHY: a clear reason instead of a silent disconnect."""


class ProtocolError(Exception):
    """
    WHAT:   A frame broke the protocol: bad magic, wrong version, unknown
            type, or a payload too large or malformed.
    WHY:    The receiver closes the connection on any of these; continuing
            after garbage would mean guessing where the next frame starts.
    """


@dataclass(frozen=True)
class Frame:
    """
    WHAT:   One decoded message: its type and payload.
    WHY:    Immutable, so a frame cannot be changed after it was checked.
    """

    type: MessageType
    """WHAT: what kind of frame this is."""

    payload: bytes
    """WHAT: the bytes after the header."""


def encode(frame_type: MessageType, payload: bytes) -> bytes:
    """
    WHAT:   Builds a frame: header plus payload.
    WHY:    The length field is computed from the payload, so the header
            always matches whatever is sent, whatever its size.
    PRE:    payload is at most MAX_PAYLOAD bytes
    RETURN: the bytes to send
    RAISES: ProtocolError if the payload is too large
    """
    if len(payload) > MAX_PAYLOAD:
        raise ProtocolError(f"payload of {len(payload)} bytes is over the {MAX_PAYLOAD}-byte limit")
    return HEADER.pack(MAGIC, VERSION, frame_type, len(payload)) + payload


def parse_header(header: bytes) -> tuple[MessageType, int]:
    """
    WHAT:   Checks and reads an 8-byte header.
    WHY:    Every field is checked before any payload is read, so a bad
            frame is refused after 8 bytes, not after 4 GiB.
    PRE:    header is exactly HEADER.size bytes
    RETURN: the frame type and the payload length
    RAISES: ProtocolError for a bad magic, version, type or length
    """
    magic, version, raw_type, length = HEADER.unpack(header)
    if magic != MAGIC:
        raise ProtocolError(f"bad magic {magic!r}: not a tracekeep frame")
    if version != VERSION:
        raise ProtocolError(f"unsupported protocol version {version}")
    try:
        frame_type = MessageType(raw_type)
    except ValueError:
        raise ProtocolError(f"unknown frame type {raw_type}") from None
    if length > MAX_PAYLOAD:
        raise ProtocolError(f"frame claims {length} bytes, over the {MAX_PAYLOAD}-byte limit")
    return frame_type, length


class FrameDecoder:
    """
    WHAT:   Turns a stream of received bytes into whole frames.
    WHY:    "Sans-I/O": it never touches a socket, it only receives bytes
            through feed(). That makes the hardest part of TCP framing (a
            frame split across reads, or several in one read) testable byte
            by byte, without a network.
    """

    def __init__(self) -> None:
        """
        WHAT:   Starts with an empty buffer.
        POST:   no bytes are pending
        """
        self._buffer = bytearray()

    @property
    def pending(self) -> int:
        """
        WHAT:   How many received bytes are not yet part of a whole frame.
        WHY:    A connection that closes with pending bytes ended mid-frame.
        RETURN: the number of buffered bytes
        """
        return len(self._buffer)

    def feed(self, data: bytes) -> list[Frame]:
        """
        WHAT:   Adds received bytes and returns every frame now complete.
        WHY:    Called with whatever recv() returned, however it was split.
        PRE:    data is the next bytes of the stream, in order
        POST:   complete frames are removed from the buffer; a partial frame stays
        RETURN: the complete frames, in order (possibly none)
        RAISES: ProtocolError as soon as a header is invalid
        """
        self._buffer.extend(data)
        frames: list[Frame] = []

        while True:
            # 1. not even a whole header yet: wait for more bytes
            if len(self._buffer) < HEADER.size:
                return frames

            # 2. check the header first; a bad one fails here, before its payload arrives
            frame_type, length = parse_header(bytes(self._buffer[:HEADER.size]))

            # 3. the payload has not fully arrived: wait for more bytes
            end = HEADER.size + length
            if len(self._buffer) < end:
                return frames

            # 4. a whole frame: cut it off the front of the buffer and look for the next one
            frames.append(Frame(frame_type, bytes(self._buffer[HEADER.size:end])))
            del self._buffer[:end]
