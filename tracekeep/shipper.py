"""
WHAT:   The shipper: connects to a collector, names its stream, and sends
        log lines as sealed records, one at a time.
WHY:    Logs sent off the machine as they are written cannot be quietly
        edited later by an attacker on that machine; the chain proves it.
"""

from __future__ import annotations

import socket
import time

from tracekeep.chain import ChainWriter, Record
from tracekeep.collector import ACK_PAYLOAD
from tracekeep.protocol import Frame, FrameDecoder, MessageType, ProtocolError, encode
from tracekeep.spool import Spool


class ShipError(Exception):
    """
    WHAT:   The collector refused something or the connection failed.
    WHY:    One exception type for the command line to report.
    """


class RefusedError(ShipError):
    """
    WHAT:   The collector answered with an ERROR: it will not store the record.
    WHY:    Unlike a dropped connection, trying again will not help (the
            record is forged, damaged or does not fit the chain), so the
            spooling shipper stops instead of retrying forever.
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
        self.collector_end = (next_seq, prev)
        """WHAT: where the collector's stored chain ended when we connected: (next seq, last hash)."""
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
        self.send_sealed(record)
        return record.seq

    def send_sealed(self, record: Record) -> None:
        """
        WHAT:   Sends a record that was sealed earlier, and waits until it is stored.
        WHY:    The spooling shipper seals records when the line is written,
                which may be long before the collector can be reached.
        PRE:    record continues the collector's chain
        POST:   the record is stored by the collector
        RETURN: nothing
        RAISES: RefusedError if the collector refuses it; ShipError if the connection fails
        """
        try:
            self._sock.sendall(encode(MessageType.RECORD, record.to_payload()))
        except OSError as error:
            raise ShipError(f"connection failed: {error}") from error
        self._expect_ack()

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
                        raise RefusedError("collector refused: " + frame.payload.decode("utf-8", errors="replace"))
                    raise ShipError(f"unexpected {frame.type.name} frame from the collector")
        except (OSError, ProtocolError) as error:
            raise ShipError(f"connection failed: {error}") from error


class SpoolingShipper:
    """
    WHAT:   A shipper that keeps working while the collector is down: every
            line is sealed and written to a spool on disk first, then sent;
            whatever could not be sent waits there and goes out, in order,
            as soon as the collector is back.
    WHY:    Logs from an outage are often the ones that matter most. Sealing
            before spooling means a waiting record cannot be changed
            unnoticed, and the chain continues across the outage, restarts
            of either side, and crashes.
    """

    def __init__(self, host: str, port: int, key: bytes, stream: str, spool: Spool, retry_seconds: float = 5.0,
                 timeout: float = 10.0) -> None:
        """
        WHAT:   Starts shipping a stream through a spool.
        WHY:    Tries the collector once straight away to send anything left
                from a previous run. The very first run of a stream needs the
                collector, to learn where its chain stands.
        PRE:    key is at least 16 bytes; spool is for this stream
        POST:   ready to send(); waiting records were sent if the collector answered
        RAISES: ShipError if this stream was never shipped and the collector
                cannot be reached; RefusedError if the collector refuses the
                spooled records; ValueError if the spool is damaged
        """
        self._host, self._port, self._key, self._stream = host, port, key, stream
        self._spool = spool
        self._retry = retry_seconds
        self._timeout = timeout
        self._link: Shipper | None = None
        self._last_try = float("-inf")

        end = spool.chain_end()
        if end is None:
            # first run: the collector must say where the stored chain ends (it may already hold records)
            self._link = Shipper(host, port, key, stream, timeout)
            end = self._link.collector_end
            spool.remember_end(*end)
        self._writer = ChainWriter(key, *end)
        self.flush(force=True)

    @property
    def waiting(self) -> int:
        """
        WHAT:   How many records are spooled but not yet confirmed stored.
        RETURN: the count
        """
        return len(self._spool)

    @property
    def connected(self) -> bool:
        """
        WHAT:   Whether there is an open connection to the collector right now.
        RETURN: True if connected
        """
        return self._link is not None

    def send(self, message: str, time_ms: int | None = None) -> bool:
        """
        WHAT:   Seals a log line, spools it, and sends everything waiting.
        WHY:    The time is taken now, when the line is written, not when it
                finally reaches the collector.
        PRE:    message is at most 8 KiB in UTF-8
        POST:   the record is on disk; if the collector answered, it is stored there too
        RETURN: True if nothing is left waiting, False if records are spooled
        RAISES: SpoolFull if the spool is full; RefusedError if the collector
                refuses a record
        """
        record = self._writer.seal(message, time_ms if time_ms is not None else int(time.time() * 1000))
        self._spool.add(record)
        self.flush()
        return self.waiting == 0

    def flush(self, force: bool = False) -> int:
        """
        WHAT:   Sends the waiting records, oldest first, if the collector can be reached.
        WHY:    While the collector is down, a new connection is only tried
                every retry_seconds, so a busy log does not hammer a dead
                address with one attempt per line.
        PRE:    none
        POST:   every record the collector acknowledged is no longer waiting
        RETURN: how many records are still waiting
        RAISES: RefusedError if the collector refuses a record or its chain
                does not continue the spool
        """
        if self.waiting == 0:
            return 0
        if self._link is None:
            if not force and time.monotonic() - self._last_try < self._retry:
                return self.waiting
            self._last_try = time.monotonic()
            try:
                self._link = Shipper(self._host, self._port, self._key, self._stream, self._timeout)
            except RefusedError:
                raise
            except ShipError:
                return self.waiting

        try:
            for record in self._unsent(self._link.collector_end):
                self._link.send_sealed(record)
                # the collector's chain now ends after this record; remember it for a reconnect
                self._link.collector_end = (record.seq + 1, record.digest)
        except RefusedError:
            self._disconnect()
            raise
        except ShipError:
            # the collector went away mid-way: keep everything, the next HELLO says what arrived
            self._disconnect()
            return self.waiting
        self._spool.clear()
        return 0

    def close(self) -> int:
        """
        WHAT:   Tries once more to send what is waiting, then disconnects.
        RETURN: how many records are still waiting (they are sent on the next run)
        RAISES: RefusedError if the collector refuses a record
        """
        try:
            return self.flush(force=True)
        finally:
            self._disconnect()

    def __enter__(self) -> SpoolingShipper:
        """
        WHAT:   Supports "with SpoolingShipper(...) as shipper:".
        RETURN: this shipper
        """
        return self

    def __exit__(self, *exc: object) -> None:
        """
        WHAT:   Disconnects at the end of the "with" block.
        WHY:    After an error the spool stays as it is; nothing is lost.
        RETURN: nothing
        """
        self._disconnect()

    def _unsent(self, collector_end: tuple[int, bytes]) -> list[Record]:
        """
        WHAT:   The waiting records the collector does not have yet.
        WHY:    If an ACK arrived but the shipper crashed before clearing the
                spool, the collector already holds the first few records.
                They are skipped, but only after checking that the
                collector's chain really ends at our record; anything else
                means two different chains, which must not be merged.
        PRE:    collector_end came from the collector
        RETURN: the records to send, in order
        RAISES: RefusedError if the collector's chain does not continue the spool
        """
        next_seq, prev = collector_end
        records = self._spool.waiting()
        sent = [record for record in records if record.seq < next_seq]
        unsent = records[len(sent):]
        if sent and (sent[-1].seq != next_seq - 1 or sent[-1].digest != prev):
            raise RefusedError(f"the collector's chain does not match the spool at record {next_seq - 1}; "
                               f"the spool is kept in {self._spool.path}")
        if unsent and (unsent[0].seq != next_seq or unsent[0].prev != prev):
            raise RefusedError(f"the spool starts at record {unsent[0].seq} but the collector expects record "
                               f"{next_seq} with a different link; the spool is kept in {self._spool.path}")
        return unsent

    def _disconnect(self) -> None:
        """
        WHAT:   Closes the connection, if there is one.
        RETURN: nothing
        """
        if self._link is not None:
            self._link.close()
            self._link = None
