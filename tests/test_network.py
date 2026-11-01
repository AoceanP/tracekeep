"""
WHAT:   End-to-end tests: a real collector on 127.0.0.1 and real shippers,
        plus hand-made hostile clients.
WHY:    Checks the parts only a real connection exercises: the handshake,
        resuming after a reconnect, and refusing bad senders without
        storing anything.
"""

import socket
import unittest

from tests.helpers import KEY, CollectorTestCase
from tracekeep.chain import ChainWriter, verify
from tracekeep.handshake import HELLO_HEAD, decode_challenge, hello_proof, new_nonce, solve
from tracekeep.protocol import FrameDecoder, MessageType, encode
from tracekeep.shipper import RefusedError, ShipError, Shipper
from tracekeep.storage import read_log


class NetworkTests(CollectorTestCase):
    """
    WHAT:   Shipper and collector talking over TCP.
    WHY:    The parts unit tests cannot reach.
    """

    def raw_exchange(self, data: bytes) -> list:
        """
        WHAT:   Sends raw bytes as a hostile client would, and reads the reply.
        WHY:    Lets tests send things a well-behaved Shipper never would.
        PRE:    the collector is running
        RETURN: the frames the collector sent back before closing, starting with its CHALLENGE
        """
        with socket.create_connection(("127.0.0.1", self.port), timeout=10) as sock:
            sock.sendall(data)
            decoder, frames = FrameDecoder(), []
            while chunk := sock.recv(4096):
                frames += decoder.feed(chunk)
            return frames

    def authenticated_exchange(self, stream: bytes, after_hello: bytes = b"", key: bytes = KEY) -> list:
        """
        WHAT:   Runs a correct handshake by hand (solving the puzzle and
                proving the key), then sends raw bytes.
        WHY:    Lets tests send bad records or bad stream names as a client
                that does hold the key.
        PRE:    the collector is running
        RETURN: the frames the collector sent after the CHALLENGE
        """
        with socket.create_connection(("127.0.0.1", self.port), timeout=10) as sock:
            decoder = FrameDecoder()
            frames = []
            while not frames:
                frames = decoder.feed(sock.recv(4096))
            server_nonce, difficulty = decode_challenge(frames[0].payload)
            client_nonce = new_nonce()
            name = stream.decode("utf-8", errors="replace")
            hello = HELLO_HEAD.pack(client_nonce, solve(server_nonce, client_nonce, difficulty),
                                    hello_proof(key, server_nonce, client_nonce, name)) + stream
            sock.sendall(encode(MessageType.HELLO, hello) + after_hello)
            replies = []
            while chunk := sock.recv(4096):
                replies += decoder.feed(chunk)
            return replies

    def test_ship_and_store(self) -> None:
        """
        WHAT:   Five lines shipped and stored.
        WHY:    The normal path: every line arrives, in order, as a valid chain.
        PRE:    none
        RETURN: nothing; fails if the stored log is wrong or not intact
        """
        with Shipper("127.0.0.1", self.port, KEY, "web01") as shipper:
            sequences = [shipper.send(f"line {i}") for i in range(5)]
        self.assertEqual(sequences, [0, 1, 2, 3, 4])
        records = read_log(self.folder / "web01.jsonl")
        self.assertEqual([r.message for _, r in records], [f"line {i}" for i in range(5)])
        self.assertEqual(verify(records, KEY), [])

    def test_reconnect_continues_chain(self) -> None:
        """
        WHAT:   A shipper disconnects and a new one continues the same stream.
        WHY:    The collector tells it where the chain ends, so the log stays
                one valid chain across restarts.
        PRE:    none
        RETURN: nothing; fails if numbering restarts or the chain breaks
        """
        with Shipper("127.0.0.1", self.port, KEY, "web01") as shipper:
            shipper.send("first run")
        with Shipper("127.0.0.1", self.port, KEY, "web01") as shipper:
            self.assertEqual(shipper.send("second run"), 1)
        self.assertEqual(verify(read_log(self.folder / "web01.jsonl"), KEY), [])

    def test_streams_are_separate(self) -> None:
        """
        WHAT:   Two streams shipped at the same time.
        WHY:    Each has its own file and its own chain.
        PRE:    none
        RETURN: nothing; fails if records mix
        """
        with Shipper("127.0.0.1", self.port, KEY, "web01") as a, Shipper("127.0.0.1", self.port, KEY, "db01") as b:
            a.send("from web")
            b.send("from db")
            a.send("from web again")
        self.assertEqual(len(read_log(self.folder / "web01.jsonl")), 2)
        self.assertEqual(len(read_log(self.folder / "db01.jsonl")), 1)

    def test_wrong_key_refused_and_not_stored(self) -> None:
        """
        WHAT:   A shipper with the wrong key.
        WHY:    Since protocol version 2 it is refused at the handshake,
                before it can send a single record, and nothing is written.
        PRE:    none
        RETURN: nothing; fails if anything is stored
        """
        with self.assertRaisesRegex(RefusedError, "authentication failed"):
            Shipper("127.0.0.1", self.port, b"wrong-key-0123456789abcdef", "web01")
        self.assertFalse((self.folder / "web01.jsonl").exists())

    def test_replayed_record_refused(self) -> None:
        """
        WHAT:   A valid record sent twice.
        WHY:    A captured record replayed later must not be stored again.
        PRE:    none
        RETURN: nothing; fails unless the replay is refused
        """
        writer = ChainWriter(KEY)
        record = writer.seal("once", 1_792_576_800_000)
        frames = self.authenticated_exchange(
            b"web01",
            encode(MessageType.RECORD, record.to_payload()) + encode(MessageType.RECORD, record.to_payload()))
        self.assertEqual([f.type for f in frames], [MessageType.WELCOME, MessageType.ACK, MessageType.ERROR])
        self.assertIn(b"expected record 1, got 0", frames[-1].payload)
        self.assertEqual(len(read_log(self.folder / "web01.jsonl")), 1)

    def test_record_before_hello(self) -> None:
        """
        WHAT:   A record sent without naming a stream first.
        WHY:    The handshake order is enforced.
        PRE:    none
        RETURN: nothing; fails unless an ERROR comes back
        """
        frames = self.raw_exchange(encode(MessageType.RECORD, bytes(80)))
        self.assertEqual([f.type for f in frames], [MessageType.CHALLENGE, MessageType.ERROR])
        self.assertIn(b"HELLO", frames[-1].payload)

    def test_path_traversal_stream_name(self) -> None:
        """
        WHAT:   Stream names that try to escape the log folder.
        WHY:    The name becomes a file name; "../evil" must never be written,
                even by a client that holds the key.
        PRE:    none
        RETURN: nothing; fails if any is accepted or a file appears outside the folder
        """
        for name in (b"../evil", b"..\\evil", b"a/b", b"", b"x" * 65, b"web01.jsonl"):
            with self.subTest(name=name):
                frames = self.authenticated_exchange(name)
                self.assertEqual(frames[-1].type, MessageType.ERROR)
        self.assertFalse((self.folder.parent / "evil.jsonl").exists())

    def test_garbage_bytes(self) -> None:
        """
        WHAT:   Random text sent to the port (e.g. a web browser or a port scanner).
        WHY:    Refused at the header, with no crash.
        PRE:    none
        RETURN: nothing; fails unless an ERROR comes back
        """
        frames = self.raw_exchange(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        self.assertEqual(frames[-1].type, MessageType.ERROR)
        self.assertIn(b"bad magic", frames[-1].payload)

    def test_disconnect_mid_frame(self) -> None:
        """
        WHAT:   A client that sends half a frame and hangs up.
        WHY:    The collector must survive it and keep serving others.
        PRE:    none
        RETURN: nothing; fails if the next shipper cannot connect
        """
        with socket.create_connection(("127.0.0.1", self.port), timeout=5) as sock:
            sock.sendall(encode(MessageType.HELLO, b"web01")[:5])
        with Shipper("127.0.0.1", self.port, KEY, "web01") as shipper:
            self.assertEqual(shipper.send("still working"), 0)


if __name__ == "__main__":
    unittest.main()
