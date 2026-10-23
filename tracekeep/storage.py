"""
WHAT:   Reads and writes stored logs: one JSON object per line.
WHY:    JSON lines are readable in any text editor, so you can open a log,
        change a line by hand, and watch `verify` catch it. The format is
        only storage; the hash chain inside is what protects it.

    {"seq": 0, "time": "2026-10-21T10:00:00.000Z", "message": "...", "prev": "00..", "mac": "9f.."}
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path

from tracekeep.chain import GENESIS, Record

STREAM_NAME = re.compile(r"[A-Za-z0-9_-]{1,64}")
"""WHAT: allowed stream names: letters, digits, "_" and "-", 1 to 64 characters.
WHY: the name becomes a file name; refusing "/", "\\" and ".." stops a sender
from writing outside the log folder (path traversal)."""


def is_valid_stream(name: str) -> bool:
    """
    WHAT:   Checks a stream name.
    WHY:    It comes from the network and becomes part of a file path.
    PRE:    none
    RETURN: True only for 1 to 64 letters, digits, "_" or "-"
    """
    return STREAM_NAME.fullmatch(name) is not None


def stream_path(folder: Path, name: str) -> Path:
    """
    WHAT:   The file a stream is stored in: FOLDER/NAME.jsonl.
    WHY:    One place builds paths, and it refuses invalid names itself, so
            no caller can forget the check.
    PRE:    none
    RETURN: the file path
    RAISES: ValueError for an invalid stream name
    """
    if not is_valid_stream(name):
        raise ValueError(f"invalid stream name {name!r}")
    return folder / f"{name}.jsonl"


def record_to_line(record: Record) -> str:
    """
    WHAT:   Turns a record into one JSON line (without the newline).
    WHY:    Hashes are stored as hex so the file stays plain text; the time
            is shown in UTC ISO 8601 for people reading the file.
    PRE:    none
    RETURN: the JSON text
    """
    time = datetime.fromtimestamp(record.time_ms / 1000, tz=timezone.utc)
    return json.dumps({
        "seq": record.seq,
        "time": time.strftime("%Y-%m-%dT%H:%M:%S.") + f"{record.time_ms % 1000:03d}Z",
        "message": record.message,
        "prev": record.prev.hex(),
        "mac": record.mac.hex(),
    }, ensure_ascii=False)


def line_to_record(line: str) -> Record | None:
    """
    WHAT:   Turns one stored JSON line back into a record.
    WHY:    Returns None instead of raising for a broken line, so verify can
            report it and keep checking the rest of the file.
    PRE:    none
    RETURN: the record, or None if the line is not a valid record
    """
    try:
        item = json.loads(line)
        time = datetime.strptime(item["time"], "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
        prev = bytes.fromhex(item["prev"])
        mac = bytes.fromhex(item["mac"])
        if not isinstance(item["seq"], int) or item["seq"] < 0 or not isinstance(item["message"], str) \
                or len(prev) != 32 or len(mac) != 32:
            return None
        return Record(item["seq"], round(time.timestamp() * 1000), prev, item["message"], mac)
    except (ValueError, KeyError, TypeError):
        # json.JSONDecodeError is a ValueError; a missing field is a KeyError; a wrong type a TypeError
        return None


def read_log(path: Path) -> list[tuple[int, Record | None]]:
    """
    WHAT:   Reads a stored log file.
    WHY:    Keeps line numbers, so problems can point at the exact line.
    PRE:    path exists
    RETURN: (line number, record or None) for each non-blank line
    RAISES: OSError if the file cannot be read
    """
    records = []
    with path.open(encoding="utf-8") as file:
        for number, line in enumerate(file, start=1):
            if line.strip():
                records.append((number, line_to_record(line)))
    return records


def chain_end(path: Path) -> tuple[int, bytes]:
    """
    WHAT:   Where a stored chain ends: the next sequence number and the last hash.
    WHY:    The collector continues an existing log after a restart instead
            of starting a second chain at 0.
    PRE:    none
    RETURN: (0, GENESIS) for a new or empty log, otherwise (last seq + 1, last hash)
    RAISES: ValueError if the last line is not a valid record
    """
    if not path.exists():
        return 0, GENESIS
    records = read_log(path)
    if not records:
        return 0, GENESIS
    last = records[-1][1]
    if last is None:
        raise ValueError(f"the last line of {path} is not a valid record; run verify on it")
    return last.seq + 1, last.digest


def append(path: Path, record: Record) -> None:
    """
    WHAT:   Adds one record to the end of a log file.
    WHY:    Append-only: existing lines are never rewritten. flush() makes
            sure the line is handed to the operating system before the
            shipper is told it was stored.
    PRE:    record was accepted by the stream's ChainVerifier
    POST:   the file ends with this record's line
    RETURN: nothing
    RAISES: OSError if the file cannot be written
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8", newline="\n") as file:
        file.write(record_to_line(record) + "\n")
        file.flush()
