"""
WHAT:   Tests for the frame header and the stream decoder.
WHY:    Framing is the classic TCP bug: messages split across reads or
        glued together. The decoder must handle every split, and refuse
        a bad header before reading its payload.
"""

import unittest

from tracekeep.protocol import HEADER, MAX_PAYLOAD, FrameDecoder, MessageType, ProtocolError, encode


class ProtocolTests(unittest.TestCase):
    """
    WHAT:   Header encoding, decoding, and every way a header can be wrong.
    WHY:    The header is the first thing a hostile sender controls.
    """

    def test_length_field_matches_payload(self) -> None:
        """
        WHAT:   Payloads of 0, 1, 1000 and the maximum size.
        WHY:    The header's size field must adapt to whatever is sent.
        PRE:    none
        RETURN: nothing; fails if the length field or round trip is wrong
        """
        for size in (0, 1, 1000, MAX_PAYLOAD):
            payload = bytes(size)
            frame = encode(MessageType.RECORD, payload)
            self.assertEqual(len(frame), HEADER.size + size)
            self.assertEqual(int.from_bytes(frame[4:8], "big"), size)
            [decoded] = FrameDecoder().feed(frame)
            self.assertEqual(decoded.payload, payload)

    def test_payload_too_large_to_send(self) -> None:
        """
        WHAT:   A payload one byte over the limit.
        WHY:    The sender refuses it instead of sending something the receiver will reject.
        PRE:    none
        RETURN: nothing; fails if no ProtocolError is raised
        """
        with self.assertRaises(ProtocolError):
            encode(MessageType.RECORD, bytes(MAX_PAYLOAD + 1))

    def test_frame_split_byte_by_byte(self) -> None:
        """
        WHAT:   Two frames delivered one byte at a time.
        WHY:    TCP may split data anywhere; the decoder must reassemble it.
        PRE:    none
        RETURN: nothing; fails if frames are lost, early or merged
        """
        data = encode(MessageType.HELLO, b"web01") + encode(MessageType.RECORD, b"hello world")
        decoder = FrameDecoder()
        frames = []
        for byte in data:
            frames += decoder.feed(bytes([byte]))
        self.assertEqual([f.payload for f in frames], [b"web01", b"hello world"])
        self.assertEqual(decoder.pending, 0)

    def test_several_frames_in_one_read(self) -> None:
        """
        WHAT:   Three frames arriving in a single recv().
        WHY:    TCP may also glue messages together.
        PRE:    none
        RETURN: nothing; fails unless all three come out in order
        """
        data = b"".join(encode(MessageType.RECORD, bytes([i])) for i in range(3))
        self.assertEqual([f.payload for f in FrameDecoder().feed(data)], [b"\x00", b"\x01", b"\x02"])

    def test_partial_frame_stays_pending(self) -> None:
        """
        WHAT:   Half a frame.
        WHY:    Nothing is returned until it is complete, and the decoder
                remembers it, so a connection closing here is detectable.
        PRE:    none
        RETURN: nothing; fails if a frame is returned early
        """
        decoder = FrameDecoder()
        self.assertEqual(decoder.feed(encode(MessageType.RECORD, b"abcdef")[:10]), [])
        self.assertEqual(decoder.pending, 10)

    def test_bad_headers(self) -> None:
        """
        WHAT:   Wrong magic, wrong version, unknown type, and a length over the limit.
        WHY:    Each must be refused from the 8-byte header alone.
        PRE:    none
        RETURN: nothing; fails if any is accepted
        """
        cases = {
            "bad magic": b"XX" + bytes([1, 2]) + (0).to_bytes(4, "big"),
            "version 2": b"TK" + bytes([2, 2]) + (0).to_bytes(4, "big"),
            "type 99": b"TK" + bytes([1, 99]) + (0).to_bytes(4, "big"),
            "4 GiB": b"TK" + bytes([1, 2]) + (2**32 - 1).to_bytes(4, "big"),
        }
        for name, header in cases.items():
            with self.subTest(name), self.assertRaises(ProtocolError):
                FrameDecoder().feed(header)

    def test_huge_length_refused_before_payload(self) -> None:
        """
        WHAT:   A header claiming 4 GiB, with no payload sent.
        WHY:    The receiver must refuse it immediately, not wait for (or
                allocate) 4 GiB that a hostile sender never intends to send.
        PRE:    none
        RETURN: nothing; fails if the decoder waits instead of raising
        """
        with self.assertRaises(ProtocolError):
            FrameDecoder().feed(b"TK\x01\x02\xff\xff\xff\xff")


if __name__ == "__main__":
    unittest.main()
