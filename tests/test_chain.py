"""
WHAT:   Tests for sealing, checking and verifying the hash chain.
WHY:    The chain is the whole point: every kind of tampering must be
        caught, at the right record, and reported once.
"""

import unittest
from dataclasses import replace

from tests.helpers import KEY, START_MS, sealed_chain
from tracekeep.chain import (GENESIS, MAX_MESSAGE_BYTES, ChainError, ChainVerifier, ChainWriter, Record,
                             verify)
from tracekeep.protocol import ProtocolError

MESSAGES = [f"line {i}" for i in range(6)]
"""WHAT: six fake log lines. WHY: enough room to break the chain in the middle."""


def numbered(records: list) -> list:
    """
    WHAT:   Pairs records with line numbers, the way read_log returns them.
    WHY:    verify() takes (line, record) pairs.
    PRE:    none
    RETURN: the pairs, numbered from 1
    """
    return list(enumerate(records, start=1))


class ChainTests(unittest.TestCase):
    """
    WHAT:   The chain's links, MACs and every tampering case.
    WHY:    Each test breaks a valid chain in exactly one way.
    """

    def test_valid_chain_verifies(self) -> None:
        """
        WHAT:   An untouched chain.
        WHY:    No false alarms.
        PRE:    none
        RETURN: nothing; fails if any problem is reported
        """
        self.assertEqual(verify(numbered(sealed_chain(MESSAGES)), KEY), [])

    def test_links(self) -> None:
        """
        WHAT:   The first record links to GENESIS, each later one to the hash before it.
        WHY:    The structure every other check relies on.
        PRE:    none
        RETURN: nothing; fails if a link is wrong
        """
        chain = sealed_chain(MESSAGES)
        self.assertEqual(chain[0].prev, GENESIS)
        for before, after in zip(chain, chain[1:]):
            self.assertEqual(after.prev, before.digest)

    def test_edited_message(self) -> None:
        """
        WHAT:   One message changed.
        WHY:    Reported once, at that record; the next record's broken link
                is explained by it and not reported again.
        PRE:    none
        RETURN: nothing; fails unless exactly one "altered" problem at line 3
        """
        chain = sealed_chain(MESSAGES)
        chain[2] = replace(chain[2], message="line 2 (edited)")
        problems = verify(numbered(chain), KEY)
        self.assertEqual([(p.line, p.kind) for p in problems], [(3, "altered")])

    def test_deleted_record(self) -> None:
        """
        WHAT:   One record removed from the middle.
        WHY:    The gap in sequence numbers shows exactly what is missing.
        PRE:    none
        RETURN: nothing; fails unless one "missing" problem names record 3
        """
        chain = sealed_chain(MESSAGES)
        del chain[2]
        problems = verify(numbered(chain), KEY)
        self.assertEqual([p.kind for p in problems], ["missing"])
        self.assertIn("before record 3", problems[0].detail)

    def test_swapped_records(self) -> None:
        """
        WHAT:   Two neighbouring records swapped.
        WHY:    Reordering hides when things happened; it must be visible.
                Nothing is missing, so the only problem is the move.
        PRE:    none
        RETURN: nothing; fails unless exactly one "out of order" problem
        """
        chain = sealed_chain(MESSAGES)
        chain[2], chain[3] = chain[3], chain[2]
        self.assertEqual([p.kind for p in verify(numbered(chain), KEY)], ["out of order"])

    def test_duplicated_record(self) -> None:
        """
        WHAT:   A record copied right after itself.
        WHY:    A replayed entry (e.g. a second "payment sent") must be caught.
        PRE:    none
        RETURN: nothing; fails unless one "duplicate" problem
        """
        chain = sealed_chain(MESSAGES)
        chain.insert(3, chain[2])
        self.assertEqual([p.kind for p in verify(numbered(chain), KEY)], ["duplicate"])

    def test_forged_record_with_wrong_key(self) -> None:
        """
        WHAT:   A new record added by someone without the key.
        WHY:    They can copy the format and the links exactly, but not the MAC.
        PRE:    none
        RETURN: nothing; fails unless the forged record is reported as altered
        """
        chain = sealed_chain(MESSAGES)
        forger = ChainWriter(b"attacker-guessed-key-1234", len(chain), chain[-1].digest)
        chain.append(forger.seal("forged line", START_MS + 99_000))
        self.assertEqual([(p.line, p.kind) for p in verify(numbered(chain), KEY)], [(7, "altered")])

    def test_rebuilt_chain_without_key(self) -> None:
        """
        WHAT:   An attacker rewrites the whole log and re-links every record.
        WHY:    A plain hash chain could be rebuilt like this; the HMAC stops it.
        PRE:    none
        RETURN: nothing; fails unless every record is reported as altered
        """
        rebuilt = sealed_chain(["all good"] * 3, key=b"attacker-guessed-key-1234")
        self.assertEqual([p.kind for p in verify(numbered(rebuilt), KEY)], ["altered"] * 3)

    def test_unreadable_line(self) -> None:
        """
        WHAT:   A line that is not a record, in the middle of a good chain.
        WHY:    It is reported as unreadable, and checking carries on so the
                records after it are still verified.
        PRE:    none
        RETURN: nothing; fails unless exactly one "unreadable" problem at line 3
        """
        pairs = numbered(sealed_chain(MESSAGES))
        pairs[2] = (3, None)
        self.assertEqual([(p.line, p.kind) for p in verify(pairs, KEY)], [(3, "unreadable")])

    def test_wrong_key_rejects_everything(self) -> None:
        """
        WHAT:   Verifying a good chain with the wrong key.
        WHY:    Verification means nothing without the right key.
        PRE:    none
        RETURN: nothing; fails unless every record is reported
        """
        self.assertEqual(len(verify(numbered(sealed_chain(MESSAGES)), b"some-other-key-0123456789")), len(MESSAGES))

    def test_live_verifier(self) -> None:
        """
        WHAT:   The collector's record-by-record check.
        WHY:    Good records move it on; a replayed or forged one is refused.
        PRE:    none
        RETURN: nothing; fails if a bad record is accepted
        """
        chain = sealed_chain(MESSAGES)
        verifier = ChainVerifier(KEY)
        for record in chain[:3]:
            verifier.accept(record)
        with self.assertRaises(ChainError):
            verifier.accept(chain[1])  # replay of an old record
        with self.assertRaises(ChainError):
            verifier.accept(replace(chain[3], message="changed"))
        verifier.accept(chain[3])
        self.assertEqual(verifier.next_seq, 4)

    def test_payload_round_trip(self) -> None:
        """
        WHAT:   A record encoded as a frame payload and decoded again, with non-English text.
        WHY:    The bytes on the wire must give back exactly the same record.
        PRE:    none
        RETURN: nothing; fails if anything changes
        """
        [record] = sealed_chain(["Ошибка входа: José Müller 🚫"])
        self.assertEqual(Record.from_payload(record.to_payload()), record)

    def test_bad_payloads(self) -> None:
        """
        WHAT:   Too short, too long, not UTF-8, and a time after the year 9999.
        WHY:    Payloads come from the network and must be checked before use.
        PRE:    none
        RETURN: nothing; fails if any is accepted
        """
        [record] = sealed_chain(["x"])
        good = record.to_payload()
        cases = {
            "short": good[:40],
            "too long": good[:80] + b"a" * (MAX_MESSAGE_BYTES + 1),
            "not UTF-8": good[:80] + b"\xff\xfe",
            "year 10000": bytes(8) + (2**63).to_bytes(8, "big") + good[16:],
        }
        for name, payload in cases.items():
            with self.subTest(name), self.assertRaises(ProtocolError):
                Record.from_payload(payload)

    def test_short_key_refused(self) -> None:
        """
        WHAT:   A 15-byte key.
        WHY:    A short key could be guessed, and then the chain forged.
        PRE:    none
        RETURN: nothing; fails if it is accepted
        """
        with self.assertRaises(ValueError):
            ChainWriter(b"too-short-key!!")


if __name__ == "__main__":
    unittest.main()
