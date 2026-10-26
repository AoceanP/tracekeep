"""
WHAT:   The collector: a TCP server that receives sealed records, checks
        each one against its stream's chain, and appends the good ones to
        that stream's log file.
WHY:    Checking on arrival means the stored log only ever contains a valid
        chain; anything forged or out of order is refused with a reason.
"""

from __future__ import annotations

import socket
import socketserver
import struct
import threading
from pathlib import Path

from tracekeep.chain import ChainError, ChainVerifier, Record
from tracekeep.protocol import Frame, FrameDecoder, MessageType, ProtocolError, encode
from tracekeep.storage import append, chain_end, is_valid_stream, stream_path

ACK_PAYLOAD = struct.Struct(">Q32s")
"""WHAT: an ACK carries the next expected sequence number (8 bytes) and the last hash (32)."""

IDLE_TIMEOUT = 30.0
"""WHAT: seconds a connection may stay silent before it is closed.
WHY: a client that connects and sends nothing would otherwise hold a thread forever."""


class Collector(socketserver.ThreadingTCPServer):
    """
    WHAT:   The TCP server; each connection is handled on its own thread.
    WHY:    Several shippers can send at once. One lock per stream makes
            sure two connections never write the same file at the same time.
    """

    daemon_threads = True
    """WHAT: connection threads stop when the program stops. WHY: Ctrl+C never hangs on an open connection."""

    allow_reuse_address = True
    """WHAT: the port can be reused straight after a restart. WHY: no "address already in use" for a minute."""

    def __init__(self, folder: Path, key: bytes, host: str = "127.0.0.1", port: int = 5140) -> None:
        """
        WHAT:   Opens the listening socket.
        WHY:    Listens on 127.0.0.1 by default, so it is not reachable from
                the network unless you choose another address on purpose.
        PRE:    key is at least 16 bytes
        POST:   the socket is bound; call serve_forever() to start
        RAISES: OSError if the port is in use
        """
        self.folder = folder
        self.key = key
        self._locks: dict[str, threading.Lock] = {}
        self._locks_guard = threading.Lock()
        self._open: set[socket.socket] = set()
        super().__init__((host, port), _Connection)

    def stream_lock(self, name: str) -> threading.Lock:
        """
        WHAT:   The lock for one stream, created the first time it is needed.
        WHY:    Different streams can be written at the same time; the same
                stream only by one connection at a time.
        PRE:    name is a valid stream name
        RETURN: the stream's lock
        """
        with self._locks_guard:
            return self._locks.setdefault(name, threading.Lock())

    def track(self, sock: socket.socket, is_open: bool) -> None:
        """
        WHAT:   Adds or removes a shipper connection from the open set.
        WHY:    stop() needs them all, to close them like a real shutdown does.
        PRE:    none
        RETURN: nothing
        """
        with self._locks_guard:
            if is_open:
                self._open.add(sock)
            else:
                self._open.discard(sock)

    def stop(self) -> None:
        """
        WHAT:   Stops accepting, closes the listening socket, and drops every
                open shipper connection.
        WHY:    shutdown() alone only stops new connections; shippers already
                connected would keep being served. Dropping them is what a
                crash or a restart really does, which is what shippers must
                survive (and what the outage demo and tests show).
        PRE:    serve_forever() is running in another thread
        POST:   nothing is listening and no connection is open
        RETURN: nothing
        """
        self.shutdown()
        self.server_close()
        with self._locks_guard:
            connections = list(self._open)
        for sock in connections:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass  # already closed by the other side


class _Connection(socketserver.BaseRequestHandler):
    """
    WHAT:   Handles one shipper connection: HELLO first, then RECORDs.
    WHY:    The protocol is a small state machine: no records before the
            stream is named, and any error ends the connection.
    """

    server: Collector
    """WHAT: the collector that accepted this connection."""

    def handle(self) -> None:
        """
        WHAT:   Reads frames until the shipper disconnects or breaks the rules.
        WHY:    Every failure ends in an ERROR frame with the reason, then the
                connection closes; nothing bad is ever stored.
        PRE:    called by socketserver for a new connection
        POST:   the connection is closed
        RETURN: nothing
        """
        sock: socket.socket = self.request
        sock.settimeout(IDLE_TIMEOUT)
        self.server.track(sock, True)
        decoder = FrameDecoder()
        stream: str | None = None
        verifier: ChainVerifier | None = None

        try:
            while True:
                # 1. read whatever arrived; b"" means the shipper closed the connection
                data = sock.recv(4096)
                if not data:
                    return

                # 2. split the bytes into whole frames (raises on a bad header)
                for frame in decoder.feed(data):
                    if stream is None:
                        # 3. the first frame must be HELLO, naming the stream
                        stream, verifier = self._hello(sock, frame)
                    else:
                        # 4. after that, only RECORDs
                        self._record(sock, frame, stream, verifier)
        except (ProtocolError, ChainError, ValueError) as error:
            self._send_error(sock, str(error))
        except OSError:
            # an idle shipper (timeout), a vanished one, or a disk error: just close
            return

    def finish(self) -> None:
        """
        WHAT:   Removes the connection from the open set when it ends.
        WHY:    socketserver calls finish() after handle(), whatever happened.
        RETURN: nothing
        """
        self.server.track(self.request, False)

    def _hello(self, sock: socket.socket, frame: Frame) -> tuple[str, ChainVerifier]:
        """
        WHAT:   Handles the first frame: checks the stream name and tells the
                shipper where its chain stands.
        WHY:    Resuming from the stored chain lets a shipper reconnect after
                a restart without breaking the chain.
        PRE:    this is the connection's first frame
        RETURN: the stream name and a verifier positioned at the chain's end
        RAISES: ProtocolError if it is not a valid HELLO
        """
        if frame.type != MessageType.HELLO:
            raise ProtocolError("the first frame must be HELLO")
        name = frame.payload.decode("utf-8", errors="replace")
        if not is_valid_stream(name):
            raise ProtocolError("invalid stream name: use 1 to 64 letters, digits, '_' or '-'")

        with self.server.stream_lock(name):
            next_seq, prev = chain_end(stream_path(self.server.folder, name))
        sock.sendall(encode(MessageType.ACK, ACK_PAYLOAD.pack(next_seq, prev)))
        return name, ChainVerifier(self.server.key, next_seq, prev)

    def _record(self, sock: socket.socket, frame: Frame, stream: str, verifier: ChainVerifier) -> None:
        """
        WHAT:   Checks one record, stores it, and acknowledges it.
        WHY:    The ACK is only sent after the record is written, so a
                shipper never believes a lost record was saved.
        PRE:    HELLO was handled for this connection
        POST:   the record is appended to the stream's file
        RETURN: nothing
        RAISES: ProtocolError for a wrong frame type or bad payload;
                ChainError if the record does not fit the chain
        """
        if frame.type != MessageType.RECORD:
            raise ProtocolError(f"expected RECORD, got {frame.type.name}")
        record = Record.from_payload(frame.payload)

        with self.server.stream_lock(stream):
            verifier.accept(record)
            append(stream_path(self.server.folder, stream), record)
        sock.sendall(encode(MessageType.ACK, ACK_PAYLOAD.pack(verifier.next_seq, verifier.prev)))

    @staticmethod
    def _send_error(sock: socket.socket, reason: str) -> None:
        """
        WHAT:   Tells the shipper why the connection is closing.
        WHY:    Best effort: if the shipper is already gone, there is no one
                to tell, so send errors are ignored.
        PRE:    none
        RETURN: nothing
        """
        try:
            sock.sendall(encode(MessageType.ERROR, reason.encode("utf-8")[:1024]))
        except OSError:
            pass
