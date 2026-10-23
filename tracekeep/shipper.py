"""
WHAT:   The shipper: connects to a collector, names its stream, and sends
        log lines as sealed records, one at a time.
WHY:    Logs sent off the machine as they are written cannot be quietly
        edited later by an attacker on that machine; the chain proves it.
"""

from __future__ import annotations

import socket
import time

from tracekeep.chain import ChainWriter
from tracekeep.collector import ACK_PAYLOAD
from tracekeep.protocol import Frame, FrameDecoder, MessageType, ProtocolError, encode


class ShipError(Exception):
    """
    WHAT:   The collector refused something or the connection failed.
    WHY:    One exception type for the command line to report.
    """


class Shipper:
    """
    WHAT:   A connection to a collector for one stream.
    WHY:    A context manager ("with Shipper(...) as s:") so the socket is
            always closed.
    """

    def __init__(self, host: str, port: int, key: bytes, stream: str, timeout: float = 10.0) -> None:
        """
        WHAT:   Connects and says HELLO.
        WHY:    The collector answers with where the chain stands, so the
                shipper continues it instead of starting again.
        PRE:    key is at least 16 bytes; stream is a valid stream name
        POST:   connected; the next send() continues the stored chain
        RAISES: ShipError if the connection or HELLO fails
        """
        self._decoder = FrameDecoder()
        try:
            self._sock = socket.create_connection((host, port), timeout=timeout)
        except OSError as error:
            raise ShipError(f"could not connect to {host}:{port}: {error}") from error

        try:
            self._sock.sendall(encode(MessageType.HELLO, stream.encode("utf-8")))
            next_seq, prev = ACK_PAYLOAD.unpack(self._expect_ack().payload)
        except (OSError, ShipError):
            # do not leave a half-open socket behind if the handshake fails
            self._sock.close()
            raise
        self._writer = ChainWriter(key, next_seq, prev)

    def send(self, message: str, time_ms: int | None = None) -> int:
        """
        WHAT:   Seals a log line, sends it, and waits until it is stored.
        WHY:    Waiting for the ACK (stop-and-wait) means a line is only
                reported as sent once the collector has written it.
        PRE:    message is at most 8 KiB in UTF-8
        POST:   the record is stored by the collector
        RETURN: the record's sequence number
        RAISES: ShipError if the collector refuses it or the connection fails
        """
        record = self._writer.seal(message, time_ms if time_ms is not None else int(time.time() * 1000))
        self._sock.sendall(encode(MessageType.RECORD, record.to_payload()))
        self._expect_ack()
        return record.seq

    def close(self) -> None:
        """
        WHAT:   Closes the connection.
        RETURN: nothing
        """
        self._sock.close()

    def __enter__(self) -> Shipper:
        """
        WHAT:   Supports "with Shipper(...) as shipper:".
        RETURN: this shipper
        """
        return self

    def __exit__(self, *exc: object) -> None:
        """
        WHAT:   Closes the connection at the end of the "with" block, even after an error.
        RETURN: nothing
        """
        self.close()

    def _expect_ack(self) -> Frame:
        """
        WHAT:   Reads frames until an ACK arrives.
        WHY:    An ERROR from the collector becomes a ShipError with its reason.
        PRE:    a request was just sent
        RETURN: the ACK frame
        RAISES: ShipError for an ERROR frame, a closed connection or a bad frame
        """
        try:
            while True:
                data = self._sock.recv(4096)
                if not data:
                    raise ShipError("the collector closed the connection")
                for frame in self._decoder.feed(data):
                    if frame.type == MessageType.ACK:
                        return frame
                    if frame.type == MessageType.ERROR:
                        raise ShipError("collector refused: " + frame.payload.decode("utf-8", errors="replace"))
                    raise ShipError(f"unexpected {frame.type.name} frame from the collector")
        except (OSError, ProtocolError) as error:
            raise ShipError(f"connection failed: {error}") from error
