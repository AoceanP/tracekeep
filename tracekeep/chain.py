"""
WHAT:   The hash chain that makes a log tamper-evident.
WHY:    Each record stores the hash of the record before it, and an HMAC
        made with a secret key. Changing, removing, reordering or adding a
        record breaks the chain at that point, and without the key nobody
        can rebuild it to hide the change.

    record 0          record 1          record 2
    prev = 000...  <- prev = hash(0) <- prev = hash(1)
    mac = HMAC(key, hash(record))
"""

from __future__ import annotations

import hashlib
import hmac
import struct
from dataclasses import dataclass

from tracekeep.protocol import ProtocolError

GENESIS = bytes(32)
"""WHAT: the "previous hash" of the very first record: 32 zero bytes. WHY: the chain needs a fixed starting point."""

MAX_MESSAGE_BYTES = 8 * 1024
"""WHAT: the longest log message, in UTF-8 bytes. WHY: one runaway line cannot fill the collector's disk."""

MIN_KEY_BYTES = 16
"""WHAT: the shortest key accepted. WHY: a short key could be guessed, and then the chain could be forged."""

MAX_TIME_MS = 253_402_300_799_999
"""WHAT: 9999-12-31 23:59:59.999 UTC in milliseconds. WHY: the latest time a date can show; the 8-byte field allows far more."""

RECORD_PREFIX = struct.Struct(">QQ32s32s")
"""WHAT: sequence (8 bytes), time in ms (8), previous hash (32), MAC (32). WHY: the fixed part of a RECORD payload."""


class ChainError(Exception):
    """
    WHAT:   A record does not fit the chain: wrong key, wrong position, or
            changed contents.
    WHY:    The collector refuses such a record instead of storing it.
    """


@dataclass(frozen=True)
class Record:
    """
    WHAT:   One sealed log record.
    WHY:    Immutable: once sealed, a record is never changed in memory.
    """

    seq: int
    """WHAT: position in the chain, starting at 0. WHY: shows gaps and reordering."""

    time_ms: int
    """WHAT: when the shipper sealed it, in milliseconds since 1970 (UTC)."""

    prev: bytes
    """WHAT: the hash of the record before, or GENESIS for the first. WHY: the link in the chain."""

    message: str
    """WHAT: the log line itself."""

    mac: bytes
    """WHAT: HMAC-SHA256 of this record's hash, with the shared key. WHY: proves the record came from someone with the key."""

    @property
    def digest(self) -> bytes:
        """
        WHAT:   This record's SHA-256 hash.
        WHY:    The next record stores it as its prev, and the MAC covers it.
        RETURN: 32 bytes
        """
        return record_hash(self.seq, self.time_ms, self.prev, self.message)

    def to_payload(self) -> bytes:
        """
        WHAT:   Encodes the record as a RECORD frame payload.
        WHY:    Fixed-size fields first and the message last, so no separator
                is needed and the message may contain any characters.
        RETURN: the payload bytes
        """
        return RECORD_PREFIX.pack(self.seq, self.time_ms, self.prev, self.mac) + self.message.encode("utf-8")

    @staticmethod
    def from_payload(payload: bytes) -> Record:
        """
        WHAT:   Decodes a RECORD frame payload.
        WHY:    The payload comes from the network, so its size and text are
                checked before anything else uses it.
        PRE:    payload came from a RECORD frame
        RETURN: the record (not yet checked against the chain)
        RAISES: ProtocolError if it is too short, too long or not UTF-8
        """
        if len(payload) < RECORD_PREFIX.size:
            raise ProtocolError(f"record payload of {len(payload)} bytes is shorter than its {RECORD_PREFIX.size}-byte header")
        seq, time_ms, prev, mac = RECORD_PREFIX.unpack(payload[:RECORD_PREFIX.size])
        # a time past the year 9999 cannot be written as a date and would crash storage later
        if time_ms > MAX_TIME_MS:
            raise ProtocolError(f"record time {time_ms} is after the year 9999")
        raw = payload[RECORD_PREFIX.size:]
        if len(raw) > MAX_MESSAGE_BYTES:
            raise ProtocolError(f"message of {len(raw)} bytes is over the {MAX_MESSAGE_BYTES}-byte limit")
        try:
            message = raw.decode("utf-8")
        except UnicodeDecodeError:
            raise ProtocolError("message is not valid UTF-8") from None
        return Record(seq, time_ms, prev, message, mac)


def record_hash(seq: int, time_ms: int, prev: bytes, message: str) -> bytes:
    """
    WHAT:   Hashes the parts of a record with SHA-256.
    WHY:    prev, seq and time have fixed sizes and the message comes last,
            so two different records can never produce the same input bytes.
    PRE:    prev is 32 bytes
    RETURN: the 32-byte hash
    """
    h = hashlib.sha256()
    h.update(prev)
    h.update(struct.pack(">QQ", seq, time_ms))
    h.update(message.encode("utf-8"))
    return h.digest()


def check_key(key: bytes) -> bytes:
    """
    WHAT:   Refuses keys that are too short.
    WHY:    The whole scheme is only as strong as the key.
    PRE:    none
    RETURN: the key, unchanged
    RAISES: ValueError if it is shorter than MIN_KEY_BYTES
    """
    if len(key) < MIN_KEY_BYTES:
        raise ValueError(f"the key must be at least {MIN_KEY_BYTES} bytes, got {len(key)}")
    return key


def make_mac(key: bytes, digest: bytes) -> bytes:
    """
    WHAT:   HMAC-SHA256 of a record hash.
    WHY:    A plain hash chain can be rebuilt by anyone who edits a record;
            the HMAC needs the secret key, so a forged chain fails.
    PRE:    key passed check_key
    RETURN: the 32-byte MAC
    """
    return hmac.new(key, digest, hashlib.sha256).digest()


class ChainWriter:
    """
    WHAT:   Seals new records one after another (used by the shipper).
    WHY:    Keeps the running sequence number and previous hash in one place.
    """

    def __init__(self, key: bytes, next_seq: int = 0, prev: bytes = GENESIS) -> None:
        """
        WHAT:   Starts a chain, or continues one after a reconnect.
        WHY:    The collector tells a reconnecting shipper where the chain
                stands, so the chain survives restarts.
        PRE:    prev is 32 bytes
        POST:   the next sealed record has sequence next_seq
        RAISES: ValueError if the key is too short
        """
        self._key = check_key(key)
        self.next_seq = next_seq
        self.prev = prev

    def seal(self, message: str, time_ms: int) -> Record:
        """
        WHAT:   Turns a log line into the next record of the chain.
        WHY:    Links it to the previous record and signs it.
        PRE:    message is at most MAX_MESSAGE_BYTES in UTF-8
        POST:   next_seq and prev move on to this record
        RETURN: the sealed record
        RAISES: ValueError if the message is too long
        """
        if len(message.encode("utf-8")) > MAX_MESSAGE_BYTES:
            raise ValueError(f"message is over the {MAX_MESSAGE_BYTES}-byte limit")
        digest = record_hash(self.next_seq, time_ms, self.prev, message)
        record = Record(self.next_seq, time_ms, self.prev, message, make_mac(self._key, digest))
        self.next_seq += 1
        self.prev = digest
        return record


class ChainVerifier:
    """
    WHAT:   Checks records one by one as they arrive (used by the collector).
    WHY:    A bad record is refused before it is stored, so the stored log
            only ever holds a valid chain.
    """

    def __init__(self, key: bytes, next_seq: int = 0, prev: bytes = GENESIS) -> None:
        """
        WHAT:   Starts at the beginning, or where a stored chain ends.
        PRE:    prev is 32 bytes
        POST:   the next accepted record must have sequence next_seq
        RAISES: ValueError if the key is too short
        """
        self._key = check_key(key)
        self.next_seq = next_seq
        self.prev = prev

    def accept(self, record: Record) -> None:
        """
        WHAT:   Accepts the record if it is the correct next link.
        WHY:    The MAC is checked first: a record without a valid MAC was
                not written by a key holder, whatever else it says.
        PRE:    none
        POST:   on success, next_seq and prev move on to this record
        RETURN: nothing
        RAISES: ChainError naming what is wrong
        """
        # 1. signed by someone with the key? compare_digest takes the same time for any
        #    mismatch, so an attacker cannot guess a valid MAC byte by byte from timing
        if not hmac.compare_digest(record.mac, make_mac(self._key, record.digest)):
            raise ChainError(f"record {record.seq} has an invalid MAC: wrong key, or changed in transit")

        # 2. the expected position? (stops replays, gaps and reordering)
        if record.seq != self.next_seq:
            raise ChainError(f"expected record {self.next_seq}, got {record.seq}")

        # 3. linked to the record before?
        if record.prev != self.prev:
            raise ChainError(f"record {record.seq} does not link to record {record.seq - 1}")

        # 4. all good: the chain moves on
        self.next_seq += 1
        self.prev = record.digest


@dataclass(frozen=True)
class Problem:
    """
    WHAT:   One problem found when verifying a stored log.
    WHY:    verify() keeps going after a problem and reports every one, with
            the line number to look at.
    """

    line: int
    """WHAT: the line in the log file, starting at 1."""

    seq: int | None
    """WHAT: the record's sequence number, if it could be read."""

    kind: str
    """WHAT: short label: "altered", "missing", "duplicate", "out of order", "broken link" or "unreadable"."""

    detail: str
    """WHAT: one sentence explaining what was found."""


def verify(records: list[tuple[int, Record | None]], key: bytes) -> list[Problem]:
    """
    WHAT:   Checks a whole stored chain and lists every problem.
    WHY:    Unlike ChainVerifier, it does not stop at the first problem: it
            re-synchronises on each record so one edit does not hide later
            ones, and it explains each problem only once.
    PRE:    records are (line number, record or None if unreadable), in file order
    RETURN: the problems, in file order; empty if the chain is intact
    RAISES: ValueError if the key is too short
    """
    check_key(key)
    problems: list[Problem] = []

    # every sequence number that appears somewhere in the file: a number that is only
    # out of place (moved) is not "missing", so gaps are checked against this set
    present = {record.seq for _, record in records if record is not None}

    expected_seq = 0
    prev = GENESIS
    explained = False  # True when the previous record's problem already explains a broken link here
    unreadable = 0     # unreadable lines since the last good record: each probably was one of the "missing" records

    for line, record in records:
        # 1. a line that is not a record at all
        if record is None:
            problems.append(Problem(line, None, "unreadable", "this line is not a valid record"))
            explained = True
            unreadable += 1
            continue

        link_explained = explained
        explained = False

        # 2. the MAC: was this record changed, or written without the key?
        if not hmac.compare_digest(record.mac, make_mac(key, record.digest)):
            problems.append(Problem(line, record.seq, "altered",
                                    f"record {record.seq} was changed or forged: its MAC does not match"))
            explained = True

        # 3. the position: a gap means records were removed (unless they only moved elsewhere
        #    in the file), going backwards means reordering or duplication
        if record.seq > expected_seq:
            # unreadable lines just before already account for that many of the absent numbers
            missing = sum(1 for seq in range(expected_seq, record.seq) if seq not in present) - unreadable
            if missing > 0:
                problems.append(Problem(line, record.seq, "missing",
                                        f"{missing} record{'s' if missing > 1 else ''} missing before record {record.seq}"))
            link_explained = True
        elif record.seq == expected_seq - 1:
            problems.append(Problem(line, record.seq, "duplicate",
                                    f"record {record.seq} appears twice: a copy was inserted"))
            link_explained = True
        elif record.seq < expected_seq:
            problems.append(Problem(line, record.seq, "out of order",
                                    f"record {record.seq} comes after record {expected_seq - 1}: it was moved"))
            link_explained = True

        # 4. the link: only reported when no problem above already explains it
        if record.prev != prev and not link_explained and not explained:
            problems.append(Problem(line, record.seq, "broken link",
                                    f"record {record.seq} does not link to the record before it"))

        # 5. continue from this record, so later problems are still found
        expected_seq = record.seq + 1
        prev = record.digest
        unreadable = 0

    return problems
