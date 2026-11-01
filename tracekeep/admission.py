"""
WHAT:   Admission control for the collector: who may connect, how many at
        once, and how hard each address's puzzle is.
WHY:    Without limits, anyone who can reach the port can open thousands of
        connections and hold a thread each (version 1 had no limit), or try
        handshakes as fast as the network allows. Automated attackers,
        including AI-driven ones, are cheap, patient and fast, so every
        attempt must cost them and repeated failure must cost more:
          - a cap on connections in total and per address;
          - a puzzle that gets harder with each recent failure from an
            address, and with overall load;
          - addresses with many recent failures are refused outright for a while.
        Everything is in memory and bounded, so the defence itself cannot be
        used to exhaust memory with many forged addresses.
"""

from __future__ import annotations

import threading
import time
from collections import OrderedDict, deque
from dataclasses import dataclass

from tracekeep.handshake import MAX_DIFFICULTY


@dataclass(frozen=True)
class Limits:
    """
    WHAT:   The admission settings.
    WHY:    One object, so tests and the command line can change any of them.
    """

    max_connections: int = 64
    """WHAT: open connections allowed in total. WHY: bounds threads and sockets."""

    per_source: int = 8
    """WHAT: open connections allowed from one address. WHY: one client cannot take every slot."""

    base_difficulty: int = 8
    """WHAT: the normal puzzle, in bits (about 256 hashes, unnoticeable)."""

    penalty_bits: int = 2
    """WHAT: extra bits per recent failure from the address. WHY: each failure makes the next attempt 4x harder."""

    load_bits: int = 4
    """WHAT: extra bits for everyone when over 3/4 of the connection slots are in use. WHY: sheds load under a flood."""

    failure_window: float = 600.0
    """WHAT: seconds a failure is remembered."""

    ban_after: int = 20
    """WHAT: failures within the window after which the address is refused outright."""

    handshake_timeout: float = 5.0
    """WHAT: seconds a new connection has to finish the handshake. WHY: a client that connects and stalls is cut off fast."""

    max_tracked_sources: int = 10_000
    """WHAT: the most addresses whose failures are remembered.
    WHY: a flood of forged addresses must not grow memory without limit; the least recent are forgotten first."""


class Admission:
    """
    WHAT:   Tracks open connections and recent failures per address.
    WHY:    Called from the accepting thread and from every connection
            thread, so all state is behind one lock.
    """

    def __init__(self, limits: Limits = Limits(), clock=time.monotonic) -> None:
        """
        WHAT:   Starts with no connections and no failures.
        PRE:    clock returns seconds and never goes backwards
        """
        self.limits = limits
        self._clock = clock
        self._lock = threading.Lock()
        self._open: dict[str, int] = {}
        self._total = 0
        self._failures: OrderedDict[str, deque[float]] = OrderedDict()

    def admit(self, source: str) -> bool:
        """
        WHAT:   Decides whether a new connection from `source` may proceed.
        WHY:    A refused connection is closed without a reply, so an
                attacker learns nothing about why.
        PRE:    none
        POST:   if admitted, the connection is counted until release() is called
        RETURN: True if admitted
        """
        with self._lock:
            if self._recent_failures(source) >= self.limits.ban_after:
                return False
            if self._total >= self.limits.max_connections or self._open.get(source, 0) >= self.limits.per_source:
                return False
            self._open[source] = self._open.get(source, 0) + 1
            self._total += 1
            return True

    def release(self, source: str) -> None:
        """
        WHAT:   Stops counting a connection that ended.
        PRE:    admit(source) returned True for it
        RETURN: nothing
        """
        with self._lock:
            remaining = self._open.get(source, 0) - 1
            if remaining > 0:
                self._open[source] = remaining
            else:
                self._open.pop(source, None)
            self._total = max(0, self._total - 1)

    def difficulty(self, source: str) -> int:
        """
        WHAT:   The puzzle difficulty for a new connection from `source`.
        WHY:    Normal shippers get the base puzzle; an address that keeps
                failing gets 4x harder puzzles per failure, and everyone gets
                harder ones while the collector is nearly full.
        PRE:    none
        RETURN: bits, at most MAX_DIFFICULTY
        """
        with self._lock:
            bits = self.limits.base_difficulty + self.limits.penalty_bits * self._recent_failures(source)
            if self._total * 4 > self.limits.max_connections * 3:
                bits += self.limits.load_bits
            return min(bits, MAX_DIFFICULTY)

    def fail(self, source: str) -> None:
        """
        WHAT:   Remembers a failed handshake (bad proof, unsolved puzzle,
                protocol error or timeout before authenticating).
        PRE:    none
        POST:   the address's next puzzle is harder; enough failures ban it
        RETURN: nothing
        """
        with self._lock:
            history = self._failures.pop(source, None) or deque(maxlen=self.limits.ban_after)
            history.append(self._clock())
            self._failures[source] = history  # re-inserted at the end: most recently failed
            while len(self._failures) > self.limits.max_tracked_sources:
                self._failures.popitem(last=False)

    def failures(self, source: str) -> int:
        """
        WHAT:   Recent failures from an address, for reports and tests.
        RETURN: the count within the failure window
        """
        with self._lock:
            return self._recent_failures(source)

    @property
    def open_connections(self) -> int:
        """
        WHAT:   Connections currently counted.
        RETURN: the count
        """
        with self._lock:
            return self._total

    def _recent_failures(self, source: str) -> int:
        """
        WHAT:   Failures from `source` within the window; forgets older ones.
        PRE:    the lock is held
        RETURN: the count
        """
        history = self._failures.get(source)
        if not history:
            return 0
        cutoff = self._clock() - self.limits.failure_window
        while history and history[0] < cutoff:
            history.popleft()
        if not history:
            del self._failures[source]
            return 0
        return len(history)
