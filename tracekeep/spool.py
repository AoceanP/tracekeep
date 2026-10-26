"""
WHAT:   The spool: records sealed by the shipper but not yet confirmed
        stored by the collector, kept on the shipper's disk in order.
WHY:    A collector can be down for a minute or a day (a restart, a
        network outage). Without a spool, every line written meanwhile is
        lost, and a missing stretch of log is exactly what an attacker
        wants. Records are sealed before they are spooled, so a record
        changed on disk while it waits is refused by the collector.

Files, for a stream named web01 in the spool folder:
    web01.spool.jsonl  the waiting records, oldest first, one JSON line each
                       (the same format as the collector's log)
    web01.state.json   where the shipper's chain ends: the next sequence
                       number and the last hash, kept when the spool is empty
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from tracekeep.chain import Record
from tracekeep.storage import is_valid_stream, line_to_record, record_to_line

DEFAULT_LIMIT = 100_000
"""WHAT: the most records a spool holds by default.
WHY: a bound on disk use; at a typical 200 bytes a line it is about 20 MB."""


class SpoolFull(Exception):
    """
    WHAT:   The spool holds its limit of records and cannot take more.
    WHY:    The oldest records cannot be dropped to make room: that would cut
            the chain, and the collector would refuse everything after the
            gap. Stopping loudly is the only honest choice.
    """


class Spool:
    """
    WHAT:   One stream's waiting records and chain end, on disk.
    WHY:    Every change is flushed and synced to disk before the call
            returns, so a crash or power cut loses nothing that was spooled.
    """

    def __init__(self, folder: Path, stream: str, limit: int = DEFAULT_LIMIT) -> None:
        """
        WHAT:   Opens (or creates) the spool for a stream.
        PRE:    limit is 1 or more
        POST:   the folder exists; the waiting records are counted
        RAISES: ValueError for an invalid stream name or a damaged spool file;
                OSError if the folder cannot be created or read
        """
        if not is_valid_stream(stream):
            raise ValueError(f"invalid stream name {stream!r}")
        if limit < 1:
            raise ValueError("the spool limit must be at least 1")
        folder.mkdir(parents=True, exist_ok=True)
        self.path = folder / f"{stream}.spool.jsonl"
        self._state = folder / f"{stream}.state.json"
        self.limit = limit
        self._count = len(self.waiting())

    def __len__(self) -> int:
        """
        WHAT:   How many records are waiting.
        RETURN: the count
        """
        return self._count

    def waiting(self) -> list[Record]:
        """
        WHAT:   The waiting records, oldest first.
        WHY:    A line that does not parse means the file was damaged or
                edited; sending around it would break the chain, so it stops
                everything with a clear error instead.
        PRE:    none
        RETURN: the records
        RAISES: ValueError if a line is not a valid record
        """
        if not self.path.exists():
            return []
        records = []
        with self.path.open(encoding="utf-8") as file:
            for number, line in enumerate(file, start=1):
                if not line.strip():
                    continue
                record = line_to_record(line)
                if record is None:
                    raise ValueError(f"line {number} of {self.path} is not a valid record; the spool is damaged")
                records.append(record)
        return records

    def add(self, record: Record) -> None:
        """
        WHAT:   Appends a sealed record and remembers the chain's new end.
        WHY:    Written and synced before the record is sent, so it survives
                a crash at any moment after this returns.
        PRE:    record continues the chain (seal() made it from chain_end())
        POST:   the record is the last waiting one; chain_end() is after it
        RETURN: nothing
        RAISES: SpoolFull if the spool already holds `limit` records;
                OSError if the disk cannot be written
        """
        if self._count >= self.limit:
            raise SpoolFull(f"the spool {self.path} holds {self.limit} records and the collector has not "
                            "taken them; start the collector, or raise --spool-limit")
        with self.path.open("a", encoding="utf-8", newline="\n") as file:
            file.write(record_to_line(record) + "\n")
            file.flush()
            os.fsync(file.fileno())
        self._count += 1
        self._save_end(record.seq + 1, record.digest)

    def clear(self) -> None:
        """
        WHAT:   Empties the spool once the collector has stored every record.
        WHY:    The chain end stays in the state file, so the next record
                still links to the last one sent.
        PRE:    every waiting record is confirmed stored
        POST:   no records are waiting
        RETURN: nothing
        """
        if self.path.exists():
            with self.path.open("w", encoding="utf-8") as file:
                file.flush()
                os.fsync(file.fileno())
        self._count = 0

    def chain_end(self) -> tuple[int, bytes] | None:
        """
        WHAT:   Where this shipper's chain ends: the next sequence number and the last hash.
        WHY:    Lets the shipper keep sealing while the collector is down.
                The last waiting record wins over the state file, in case a
                crash came between writing the record and the state.
        PRE:    none
        RETURN: (next seq, last hash), or None if this stream has never been shipped
        RAISES: ValueError if the state file or the spool is damaged
        """
        records = self.waiting()
        if records:
            return records[-1].seq + 1, records[-1].digest
        if not self._state.exists():
            return None
        try:
            state = json.loads(self._state.read_text(encoding="utf-8"))
            prev = bytes.fromhex(state["prev"])
            if not isinstance(state["next_seq"], int) or state["next_seq"] < 0 or len(prev) != 32:
                raise ValueError("bad values")
            return state["next_seq"], prev
        except (ValueError, KeyError, TypeError) as error:
            raise ValueError(f"{self._state} is damaged: {error}") from error

    def remember_end(self, next_seq: int, prev: bytes) -> None:
        """
        WHAT:   Records where the chain ends, learned from the collector.
        WHY:    Used on the very first connection, before anything is spooled.
        PRE:    prev is 32 bytes
        POST:   chain_end() returns these values while the spool is empty
        RETURN: nothing
        """
        self._save_end(next_seq, prev)

    def _save_end(self, next_seq: int, prev: bytes) -> None:
        """
        WHAT:   Writes the state file atomically.
        WHY:    Writing a temporary file and renaming it over the old one
                means a crash leaves either the old state or the new one,
                never half of each.
        PRE:    prev is 32 bytes
        RETURN: nothing
        """
        temporary = self._state.with_suffix(".tmp")
        with temporary.open("w", encoding="utf-8") as file:
            json.dump({"next_seq": next_seq, "prev": prev.hex()}, file)
            file.flush()
            os.fsync(file.fileno())
        os.replace(temporary, self._state)
