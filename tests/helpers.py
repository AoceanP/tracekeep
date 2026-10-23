"""
WHAT:   Shared test helpers: a fixed fake key, a collector running in the
        background on a free port, and a builder for sealed chains.
WHY:    Every test uses the same fake data and never touches a real log
        or a fixed port that might be in use.
"""

from __future__ import annotations

import tempfile
import threading
import unittest
from pathlib import Path

from tracekeep.chain import ChainWriter, Record
from tracekeep.collector import Collector

KEY = b"test-key-0123456789abcdef"
"""WHAT: the fake key used by every test. WHY: tests never need a real secret."""

START_MS = 1_792_576_800_000
"""WHAT: 2026-10-21 10:00:00 UTC in milliseconds. WHY: a fixed time, so results never depend on the clock."""


def sealed_chain(messages: list[str], key: bytes = KEY) -> list[Record]:
    """
    WHAT:   Seals a list of messages into a valid chain, one second apart.
    WHY:    Most tests start from a good chain and then break it on purpose.
    PRE:    key is at least 16 bytes
    RETURN: the records, in order
    """
    writer = ChainWriter(key)
    return [writer.seal(message, START_MS + i * 1000) for i, message in enumerate(messages)]


class CollectorTestCase(unittest.TestCase):
    """
    WHAT:   A test case with a collector running on 127.0.0.1 and a fresh
            temporary log folder for every test.
    WHY:    Network tests get a real TCP server without fixed ports or
            leftover files from earlier tests.
    """

    def setUp(self) -> None:
        """
        WHAT:   Starts the collector on a free port (port 0 lets the system pick).
        POST:   self.port, self.folder and self.server are ready
        """
        self._temp = tempfile.TemporaryDirectory(prefix="tracekeep-test-")
        self.folder = Path(self._temp.name)
        self.server = Collector(self.folder, KEY, "127.0.0.1", 0)
        self.port = self.server.server_address[1]
        self._thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self._thread.start()

    def tearDown(self) -> None:
        """
        WHAT:   Stops the collector and deletes the temporary folder.
        POST:   nothing is left running or on disk
        """
        self.server.shutdown()
        self.server.server_close()
        self._thread.join(timeout=5)
        self._temp.cleanup()
