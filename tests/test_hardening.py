"""
WHAT:   Tests for protocol version 2's defences: the authenticated
        handshake, the adaptive puzzle, admission limits and TLS.
WHY:    Each test plays an attacker against a real collector: a stalled
        connection, a connection flood, a wrong key guessed again and
        again, a replayed handshake, a fake collector, random garbage,
        and TLS without credentials. The defence has to hold, and the
        real shipper has to keep working afterwards.
"""

from __future__ import annotations

import os
import random
import socket
import socketserver
import ssl
import tempfile
import threading
import time
import unittest
from pathlib import Path

from tests.helpers import KEY
from tracekeep.admission import Admission, Limits
from tracekeep.collector import Collector
from tracekeep.handshake import (MAX_DIFFICULTY, HandshakeError, Hello, check_hello, decode_challenge,
                                 encode_challenge, hello_proof, new_nonce, solve, solved)
from tracekeep.protocol import FrameDecoder, MessageType, encode
from tracekeep.shipper import RefusedError, ShipError, Shipper
from tracekeep.storage import read_log
from tracekeep.tls import client_context, server_context

CERTS = Path(__file__).parent / "certs"
"""WHAT: the test-only certificates (see certs/README.txt)."""

WRONG_KEY = b"wrong-key-0123456789abcdef"
"""WHAT: a key the collector does not have."""


class FakeClock:
    """
    WHAT:   A clock the test moves by hand.
    WHY:    Tests the failure window without waiting ten minutes.
    """

    def __init__(self) -> None:
        """WHAT: starts at 1000 seconds."""
        self.now = 1000.0

    def __call__(self) -> float:
        """RETURN: the current fake time."""
        return self.now


class HandshakeTests(unittest.TestCase):
    """
    WHAT:   The handshake's pure functions.
    """

    def test_puzzle_solution_checks_out(self) -> None:
        """
        WHAT:   A solved 12-bit puzzle.
        WHY:    Solving and checking must agree.
        """
        server, client = new_nonce(), new_nonce()
        answer = solve(server, client, 12)
        self.assertTrue(solved(server, client, answer, 12))

    def test_puzzle_is_bound_to_its_nonces(self) -> None:
        """
        WHAT:   A solution reused with a different server nonce.
        WHY:    Solutions cannot be computed in advance or reused on another connection.
        """
        server, client = new_nonce(), new_nonce()
        answer = solve(server, client, 16)
        self.assertFalse(solved(new_nonce(), client, answer, 16))

    def test_proof_is_bound_to_its_stream(self) -> None:
        """
        WHAT:   A valid proof for web01 presented for db01.
        WHY:    A captured proof cannot open another stream.
        """
        server, client = new_nonce(), new_nonce()
        proof = hello_proof(KEY, server, client, "web01")
        with self.assertRaisesRegex(HandshakeError, "authentication failed"):
            check_hello(KEY, server, 0, Hello(client, 0, proof, "db01"))

    def test_unsolved_puzzle_is_refused_before_the_proof(self) -> None:
        """
        WHAT:   A correct proof with no puzzle work done.
        WHY:    The cheap check comes first, so junk costs the collector one hash.
        """
        server, client = new_nonce(), new_nonce()
        proof = hello_proof(KEY, server, client, "web01")
        wrong = next(n for n in range(1000) if not solved(server, client, n, 12))
        with self.assertRaisesRegex(HandshakeError, "puzzle"):
            check_hello(KEY, server, 12, Hello(client, wrong, proof, "web01"))

    def test_shipper_refuses_an_impossible_puzzle(self) -> None:
        """
        WHAT:   A collector asking for a 30-bit puzzle.
        WHY:    A hostile collector must not make the shipper spin for hours.
        """
        with self.assertRaisesRegex(HandshakeError, "limit"):
            decode_challenge(encode_challenge(new_nonce(), MAX_DIFFICULTY + 8))


class AdmissionTests(unittest.TestCase):
    """
    WHAT:   Admission control on its own, with a fake clock.
    """

    def test_per_source_and_total_caps(self) -> None:
        """
        WHAT:   More connections than allowed, from one address and from many.
        WHY:    One client cannot take every slot, and many cannot take more than the total.
        """
        admission = Admission(Limits(max_connections=3, per_source=2))
        self.assertTrue(admission.admit("a"))
        self.assertTrue(admission.admit("a"))
        self.assertFalse(admission.admit("a"))
        self.assertTrue(admission.admit("b"))
        self.assertFalse(admission.admit("c"))
        admission.release("a")
        self.assertTrue(admission.admit("c"))

    def test_each_failure_makes_the_puzzle_harder(self) -> None:
        """
        WHAT:   Three failures from one address.
        WHY:    2 bits each: every failure makes the next attempt 4x the work;
                other addresses are not affected.
        """
        admission = Admission(Limits(base_difficulty=8, penalty_bits=2))
        for _ in range(3):
            admission.fail("attacker")
        self.assertEqual(14, admission.difficulty("attacker"))
        self.assertEqual(8, admission.difficulty("someone else"))

    def test_difficulty_is_capped(self) -> None:
        """
        WHAT:   Many failures.
        WHY:    The puzzle never exceeds MAX_DIFFICULTY, which shippers would refuse.
        """
        admission = Admission(Limits(ban_after=100))
        for _ in range(50):
            admission.fail("attacker")
        self.assertEqual(MAX_DIFFICULTY, admission.difficulty("attacker"))

    def test_load_makes_everyone_work_harder(self) -> None:
        """
        WHAT:   Over three quarters of the slots in use.
        WHY:    Under a flood every new client pays more, which sheds load.
        """
        admission = Admission(Limits(max_connections=4, per_source=4, base_difficulty=8, load_bits=4))
        for _ in range(4):
            admission.admit("x")
        self.assertEqual(12, admission.difficulty("y"))

    def test_ban_and_its_expiry(self) -> None:
        """
        WHAT:   Enough failures to be banned, then the window passing.
        WHY:    A persistent attacker is refused outright; the ban lifts by itself.
        """
        clock = FakeClock()
        admission = Admission(Limits(ban_after=5, failure_window=600), clock)
        for _ in range(5):
            admission.fail("attacker")
        self.assertFalse(admission.admit("attacker"))
        clock.now += 601
        self.assertTrue(admission.admit("attacker"))
        self.assertEqual(0, admission.failures("attacker"))

    def test_forged_address_flood_is_bounded(self) -> None:
        """
        WHAT:   Failures from far more addresses than are tracked.
        WHY:    Forged source addresses must not grow memory without limit.
        """
        admission = Admission(Limits(max_tracked_sources=100))
        for i in range(10_000):
            admission.fail(f"10.0.{i // 256}.{i % 256}")
        tracked = sum(1 for i in range(10_000) if admission.failures(f"10.0.{i // 256}.{i % 256}"))
        self.assertEqual(100, tracked)


class LiveDefenceTests(unittest.TestCase):
    """
    WHAT:   The defences against a real collector on 127.0.0.1.
    """

    def start(self, limits: Limits | None = None, tls: ssl.SSLContext | None = None) -> int:
        """
        WHAT:   Starts a collector with these settings, stopped after the test.
        RETURN: its port
        """
        temp = tempfile.TemporaryDirectory(prefix="tracekeep-hard-")
        self.folder = Path(temp.name)
        self.server = Collector(self.folder, KEY, "127.0.0.1", 0, limits, tls)
        thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        thread.start()

        def stop() -> None:
            self.server.stop()
            thread.join(timeout=5)
            temp.cleanup()

        self.addCleanup(stop)
        return self.server.server_address[1]

    @staticmethod
    def read_all(sock: socket.socket) -> list:
        """
        WHAT:   Reads frames until the collector closes the connection.
        RETURN: the frames
        """
        decoder, frames = FrameDecoder(), []
        try:
            while chunk := sock.recv(4096):
                frames += decoder.feed(chunk)
        except (ConnectionResetError, ConnectionAbortedError):
            pass
        return frames

    def test_unauthenticated_client_learns_nothing(self) -> None:
        """
        WHAT:   A client that connects and says nothing.
        WHY:    It gets one CHALLENGE (a nonce and a number) and nothing about
                any stream; then it is cut off at the handshake deadline and
                the stall counts as a failure.
        """
        port = self.start(Limits(handshake_timeout=0.5))
        started = time.monotonic()
        with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
            frames = self.read_all(sock)
        self.assertEqual([MessageType.CHALLENGE, MessageType.ERROR], [f.type for f in frames])
        self.assertIn(b"too long", frames[-1].payload)
        self.assertLess(time.monotonic() - started, 3)
        self.assertEqual(1, self.server.admission.failures("127.0.0.1"))

    def test_connection_flood_is_capped(self) -> None:
        """
        WHAT:   One address opening more connections than allowed.
        WHY:    The extra connection is closed at once with no reply: no CHALLENGE, no thread.
        """
        port = self.start(Limits(per_source=2, handshake_timeout=5))
        held = [socket.create_connection(("127.0.0.1", port), timeout=5) for _ in range(2)]
        try:
            for sock in held:
                sock.recv(4096)  # each admitted one gets its CHALLENGE
            with socket.create_connection(("127.0.0.1", port), timeout=5) as extra:
                self.assertEqual([], self.read_all(extra))
        finally:
            for sock in held:
                sock.close()

    def test_wrong_keys_raise_the_puzzle_then_ban(self) -> None:
        """
        WHAT:   A key guessed wrongly again and again.
        WHY:    Each failure raises the puzzle by 2 bits; after ban_after
                failures the address is refused outright, even with the right
                key, until the window passes.
        """
        port = self.start(Limits(base_difficulty=4, penalty_bits=2, ban_after=4))
        for attempt in range(4):
            with self.assertRaises(RefusedError):
                Shipper("127.0.0.1", port, WRONG_KEY, "web01")
        self.assertEqual(4, self.server.admission.failures("127.0.0.1"))
        with self.assertRaises(ShipError):
            Shipper("127.0.0.1", port, KEY, "web01")
        self.assertFalse((self.folder / "web01.jsonl").exists())

    def test_puzzle_difficulty_grows_on_the_wire(self) -> None:
        """
        WHAT:   The CHALLENGE a real shipper receives after two failures.
        WHY:    The penalty is visible in the protocol, not just in memory.
        """
        port = self.start(Limits(base_difficulty=6, penalty_bits=2))
        for _ in range(2):
            with self.assertRaises(RefusedError):
                Shipper("127.0.0.1", port, WRONG_KEY, "web01")
        with Shipper("127.0.0.1", port, KEY, "web01") as shipper:
            self.assertEqual(10, shipper.puzzle_bits)

    def test_replayed_hello_is_refused(self) -> None:
        """
        WHAT:   A complete, valid HELLO captured from one connection and sent on another.
        WHY:    Each connection has a fresh server nonce, so a recording is worthless.
        """
        port = self.start(Limits(base_difficulty=4))
        with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
            decoder = FrameDecoder()
            challenge = decoder.feed(sock.recv(4096))[0]
            server_nonce, difficulty = decode_challenge(challenge.payload)
            client_nonce = new_nonce()
            from tracekeep.handshake import HELLO_HEAD
            captured = HELLO_HEAD.pack(client_nonce, solve(server_nonce, client_nonce, difficulty),
                                       hello_proof(KEY, server_nonce, client_nonce, "web01")) + b"web01"
            sock.sendall(encode(MessageType.HELLO, captured))
            self.assertEqual(MessageType.WELCOME, decoder.feed(sock.recv(4096))[0].type)

        with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
            sock.recv(4096)  # a new CHALLENGE, with a new nonce
            sock.sendall(encode(MessageType.HELLO, captured))
            frames = self.read_all(sock)
        self.assertEqual(MessageType.ERROR, frames[-1].type)

    def test_impostor_collector_is_detected(self) -> None:
        """
        WHAT:   A fake collector that does not have the key.
        WHY:    It cannot produce a valid WELCOME proof, so the shipper
                refuses it before sending a single record.
        """
        received: list[bytes] = []

        class Impostor(socketserver.BaseRequestHandler):
            def handle(self) -> None:
                self.request.sendall(encode(MessageType.CHALLENGE, encode_challenge(new_nonce(), 4)))
                received.append(self.request.recv(4096))
                self.request.sendall(encode(MessageType.WELCOME, bytes(72)))
                received.append(self.request.recv(4096))

        with socketserver.TCPServer(("127.0.0.1", 0), Impostor) as fake:
            threading.Thread(target=fake.handle_request, daemon=True).start()
            with self.assertRaisesRegex(ShipError, "could not prove"):
                Shipper("127.0.0.1", fake.server_address[1], KEY, "web01")
        self.assertEqual(b"", received[-1])  # the shipper hung up instead of sending records

    def test_random_garbage_does_not_break_the_collector(self) -> None:
        """
        WHAT:   200 connections sending random bytes of random lengths (a small fuzz test).
        WHY:    Automated tools find parser bugs by throwing junk; the
                collector must refuse it all and keep serving real shippers.
                The junk also maxes out this address's puzzle (22 bits), so
                the real shipper afterwards proves the handshake deadline
                leaves room to solve the hardest puzzle.
        """
        port = self.start(Limits(ban_after=10_000, max_tracked_sources=10, handshake_timeout=1))
        rng = random.Random(2026)
        for _ in range(200):
            junk = bytes(rng.getrandbits(8) for _ in range(rng.randint(0, 300)))
            if rng.random() < 0.3:
                junk = b"TK\x02" + junk  # a plausible header start, to get past the magic check
            with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
                sock.sendall(junk)
                sock.shutdown(socket.SHUT_WR)
                self.read_all(sock)
        with Shipper("127.0.0.1", port, KEY, "web01", timeout=30) as shipper:
            self.assertEqual(MAX_DIFFICULTY, shipper.puzzle_bits)
            self.assertEqual(0, shipper.send("still working"))
        self.assertEqual(1, len(read_log(self.folder / "web01.jsonl")))

    def test_tls_round_trip(self) -> None:
        """
        WHAT:   Shipping over TLS 1.3.
        WHY:    The whole conversation, handshake included, is encrypted, and it still works end to end.
        """
        port = self.start(tls=server_context(str(CERTS / "server.pem"), str(CERTS / "server.key")))
        with Shipper("127.0.0.1", port, KEY, "web01", tls=client_context(str(CERTS / "ca.pem")),
                     tls_name="localhost") as shipper:
            shipper.send("encrypted")
        self.assertEqual("encrypted", read_log(self.folder / "web01.jsonl")[0][1].message)

    def test_plain_client_cannot_talk_to_tls_collector(self) -> None:
        """
        WHAT:   A shipper without TLS against a TLS collector.
        WHY:    No plaintext fallback.
        """
        port = self.start(tls=server_context(str(CERTS / "server.pem"), str(CERTS / "server.key")))
        with self.assertRaises(ShipError):
            Shipper("127.0.0.1", port, KEY, "web01", timeout=3)

    def test_untrusted_collector_certificate_is_refused(self) -> None:
        """
        WHAT:   A shipper that trusts a different certificate authority.
        WHY:    A machine pretending to be the collector is stopped at TLS.
        """
        port = self.start(tls=server_context(str(CERTS / "server.pem"), str(CERTS / "server.key")))
        untrusted = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        untrusted.load_verify_locations(cadata=_other_ca())
        with self.assertRaisesRegex(ShipError, "CERTIFICATE_VERIFY_FAILED|certificate verify failed"):
            Shipper("127.0.0.1", port, KEY, "web01", tls=untrusted, tls_name="localhost")

    def test_mutual_tls_requires_a_client_certificate(self) -> None:
        """
        WHAT:   A collector requiring client certificates, with and without one.
        WHY:    Without a certificate a client never even sees the CHALLENGE.
        """
        tls = server_context(str(CERTS / "server.pem"), str(CERTS / "server.key"), client_ca=str(CERTS / "ca.pem"))
        port = self.start(tls=tls)
        with self.assertRaises(ShipError):
            Shipper("127.0.0.1", port, KEY, "web01", tls=client_context(str(CERTS / "ca.pem")), tls_name="localhost")
        with_cert = client_context(str(CERTS / "ca.pem"), str(CERTS / "client.pem"), str(CERTS / "client.key"))
        with Shipper("127.0.0.1", port, KEY, "web01", tls=with_cert, tls_name="localhost") as shipper:
            self.assertEqual(0, shipper.send("mutual"))


def _other_ca() -> str:
    """
    WHAT:   A self-signed certificate that did not sign the collector's certificate.
    WHY:    The server's own certificate stands in for "some other CA": it is
            valid PEM, but trusting it does not make the chain to ca.pem valid.
    RETURN: PEM text
    """
    return (CERTS / "client.pem").read_text(encoding="ascii")


if __name__ == "__main__":
    unittest.main()
