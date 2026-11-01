"""
WHAT:   The collector: a TCP server that receives sealed records, checks
        each one against its stream's chain, and appends the good ones to
        that stream's log file.
WHY:    Checking on arrival means the stored log only ever contains a valid
        chain; anything forged or out of order is refused with a reason.

Protocol version 2 hardening (see handshake.py and admission.py):
    - connections over the total or per-address cap are closed at once,
      without a reply;
    - every connection starts with a CHALLENGE; nothing about any stream is
      revealed until the shipper proves it holds the key, and the collector
      proves it holds the key back;
    - the handshake must finish within a few seconds;
    - failed handshakes make that address's next puzzle harder, and enough
      of them get it refused for a while;
    - optional TLS encrypts the whole connection.
"""

from __future__ import annotations

import socket
import socketserver
import ssl
import struct
import threading
import time
from pathlib import Path

from tracekeep.admission import Admission, Limits
from tracekeep.chain import ChainError, ChainVerifier, Record
from tracekeep.handshake import (HandshakeError, check_hello, decode_hello, encode_challenge, encode_welcome,
                                 new_nonce)
from tracekeep.protocol import Frame, FrameDecoder, MessageType, ProtocolError, encode
from tracekeep.storage import append, chain_end, is_valid_stream, stream_path

ACK_PAYLOAD = struct.Struct(">Q32s")
"""WHAT: a record ACK carries the next expected sequence number (8 bytes) and the last hash (32)."""

SLOW_HASH_RATE = 250_000
"""WHAT: puzzle hashes per second assumed for a slow shipper when setting the handshake deadline.
WHY: about 7 times slower than a normal PC running Python, so the hardest puzzle (22 bits) still
gets about 17 extra seconds; a deadline shorter than the puzzle would lock real shippers out."""

IDLE_TIMEOUT = 30.0
"""WHAT: seconds an authenticated connection may stay silent before it is closed.
WHY: a client that stops sending would otherwise hold a thread forever."""


class Collector(socketserver.ThreadingTCPServer):
    """
    WHAT:   The TCP server; each admitted connection is handled on its own thread.
    WHY:    Several shippers can send at once. One lock per stream makes
            sure two connections never write the same file at the same time.
    """

    daemon_threads = True
    """WHAT: connection threads stop when the program stops. WHY: Ctrl+C never hangs on an open connection."""

    allow_reuse_address = True
    """WHAT: the port can be reused straight after a restart. WHY: no "address already in use" for a minute."""

    def __init__(self, folder: Path, key: bytes, host: str = "127.0.0.1", port: int = 5140,
                 limits: Limits | None = None, tls: ssl.SSLContext | None = None) -> None:
        """
        WHAT:   Opens the listening socket.
        WHY:    Listens on 127.0.0.1 by default, so it is not reachable from
                the network unless you choose another address on purpose.
        PRE:    key is at least 16 bytes; tls, if given, is a server-side context
        POST:   the socket is bound; call serve_forever() to start
        RAISES: OSError if the port is in use
        """
        self.folder = folder
        self.key = key
        self.admission = Admission(limits or Limits())
        self.tls = tls
        self._locks: dict[str, threading.Lock] = {}
        self._locks_guard = threading.Lock()
        self._open: set[socket.socket] = set()
        super().__init__((host, port), _Connection)

    def verify_request(self, request: socket.socket, client_address: tuple) -> bool:
        """
        WHAT:   Admits or drops a new connection, before any thread is started for it.
        WHY:    socketserver calls this for every accepted connection; returning
                False closes it with no reply, so a flood never gets a thread.
        RETURN: True if the connection may proceed
        """
        return self.admission.admit(client_address[0])

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
    WHAT:   Handles one shipper connection: CHALLENGE, HELLO, WELCOME, then RECORDs.
    WHY:    The protocol is a small state machine: no records before both
            sides are authenticated, and any error ends the connection.
    """

    server: Collector
    """WHAT: the collector that accepted this connection."""

    def handle(self) -> None:
        """
        WHAT:   Runs the handshake, then reads records until the shipper
                disconnects or breaks the rules.
        WHY:    Every failure ends in an ERROR frame with the reason, then the
                connection closes; nothing bad is ever stored. Failures before
                authentication count against the address.
        PRE:    called by socketserver for an admitted connection
        POST:   the connection is closed
        RETURN: nothing
        """
        source = self.client_address[0]
        limits = self.server.admission.limits
        deadline = time.monotonic() + limits.handshake_timeout
        sock: socket.socket = self.request
        self._tracked = sock
        self.server.track(sock, True)
        stream: str | None = None

        try:
            # 1. TLS first, if configured; inside this thread, so a slow client cannot stall accepting
            sock.settimeout(limits.handshake_timeout)
            if self.server.tls is not None:
                # wrapping replaces the socket, so the open set must hold the wrapped one for stop()
                self.server.track(sock, False)
                sock = self.server.tls.wrap_socket(sock, server_side=True, do_handshake_on_connect=False)
                self._tracked = sock
                self.server.track(sock, True)
                sock.do_handshake()

            # 2. the challenge: a fresh nonce and this address's puzzle difficulty, nothing else.
            #    The deadline grows with the puzzle, so a real shipper on a slow machine can still
            #    finish the hardest one; a client that only stalls is still cut off.
            server_nonce = new_nonce()
            difficulty = self.server.admission.difficulty(source)
            deadline += 2 ** difficulty / SLOW_HASH_RATE
            sock.sendall(encode(MessageType.CHALLENGE, encode_challenge(server_nonce, difficulty)))

            decoder = FrameDecoder()
            verifier: ChainVerifier | None = None
            while True:
                # 3. before authentication the remaining handshake time is the limit; after, the idle timeout
                if stream is None:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise HandshakeError("handshake took too long")
                    sock.settimeout(remaining)
                data = sock.recv(4096)
                if not data:
                    if stream is None:
                        self.server.admission.fail(source)
                    return

                for frame in decoder.feed(data):
                    if stream is None:
                        stream, verifier = self._hello(sock, frame, server_nonce, difficulty)
                        sock.settimeout(IDLE_TIMEOUT)
                    else:
                        self._record(sock, frame, stream, verifier)
        except TimeoutError:
            # a client that stalls before authenticating is told why, and it counts as a failure
            if stream is None:
                self.server.admission.fail(source)
                self._send_error(sock, "handshake took too long")
        except (ProtocolError, HandshakeError, ChainError, ValueError) as error:
            if stream is None:
                self.server.admission.fail(source)
            self._send_error(sock, str(error))
        except OSError:
            # a timeout, a failed TLS handshake, a vanished client, or a disk error: just close.
            # Before authentication it counts as a failure: stalling is an attack too.
            if stream is None:
                self.server.admission.fail(source)
            return
        finally:
            if sock is not self.request:
                try:
                    sock.close()
                except OSError:
                    pass

    def finish(self) -> None:
        """
        WHAT:   Stops counting the connection when it ends.
        WHY:    socketserver calls finish() after handle(), whatever happened.
        RETURN: nothing
        """
        self.server.track(getattr(self, "_tracked", self.request), False)
        self.server.admission.release(self.client_address[0])

    def _hello(self, sock: socket.socket, frame: Frame, server_nonce: bytes,
               difficulty: int) -> tuple[str, ChainVerifier]:
        """
        WHAT:   Checks the shipper's HELLO and answers with a WELCOME.
        WHY:    The puzzle and the proof are checked before the stream name
                is even looked at, so an unauthenticated client cannot learn
                which streams exist or how long they are.
        PRE:    this is the first frame after the CHALLENGE
        RETURN: the stream name and a verifier positioned at the chain's end
        RAISES: ProtocolError if it is not a HELLO; HandshakeError if the
                puzzle or proof is wrong; ValueError for an invalid name
        """
        if frame.type != MessageType.HELLO:
            raise ProtocolError("the first frame must be HELLO")
        hello = decode_hello(frame.payload)
        check_hello(self.server.key, server_nonce, difficulty, hello)
        if not is_valid_stream(hello.stream):
            raise ValueError("invalid stream name: use 1 to 64 letters, digits, '_' or '-'")

        with self.server.stream_lock(hello.stream):
            next_seq, prev = chain_end(stream_path(self.server.folder, hello.stream))
        sock.sendall(encode(MessageType.WELCOME,
                            encode_welcome(self.server.key, server_nonce, hello.client_nonce, next_seq, prev)))
        return hello.stream, ChainVerifier(self.server.key, next_seq, prev)

    def _record(self, sock: socket.socket, frame: Frame, stream: str, verifier: ChainVerifier) -> None:
        """
        WHAT:   Checks one record, stores it, and acknowledges it.
        WHY:    The ACK is only sent after the record is written, so a
                shipper never believes a lost record was saved.
        PRE:    the handshake succeeded on this connection
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
