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
from tracekeep.protocol import FrameDecoder, MessageType, encode
from tracekeep.shipper import ShipError, Shipper
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
        RETURN: the frames the collector sent back before closing
        """
        with socket.create_connection(("127.0.0.1", self.port), timeout=5) as sock:
            sock.sendall(data)
            decoder, frames = FrameDecoder(), []
            while chunk := sock.recv(4096):
                frames += decoder.feed(chunk)
            return frames

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
        WHY:    Its record is refused with a reason, and nothing is written.
        PRE:    none
        RETURN: nothing; fails if anything is stored
        """
        with Shipper("127.0.0.1", self.port, b"wrong-key-0123456789abcdef", "web01") as shipper:
            with self.assertRaisesRegex(ShipError, "invalid MAC"):
                shipper.send("intruder")
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
        frames = self.raw_exchange(
            encode(MessageType.HELLO, b"web01")
            + encode(MessageType.RECORD, record.to_payload())
            + encode(MessageType.RECORD, record.to_payload()))
        self.assertEqual([f.type for f in frames], [MessageType.ACK, MessageType.ACK, MessageType.ERROR])
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
        self.assertEqual(frames[-1].type, MessageType.ERROR)
        self.assertIn(b"HELLO", frames[-1].payload)

    def test_path_traversal_stream_name(self) -> None:
        """
        WHAT:   Stream names that try to escape the log folder.
        WHY:    The name becomes a file name; "../evil" must never be written.
        PRE:    none
        RETURN: nothing; fails if any is accepted or a file appears outside the folder
        """
        for name in (b"../evil", b"..\\evil", b"a/b", b"", b"x" * 65, b"web01.jsonl"):
            with self.subTest(name=name):
                frames = self.raw_exchange(encode(MessageType.HELLO, name))
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
