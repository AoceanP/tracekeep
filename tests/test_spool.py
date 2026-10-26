"""
WHAT:   Tests for store and forward: the spool on disk and the spooling
        shipper, against a real collector that is stopped and restarted.
WHY:    The promise is "nothing is lost and the chain never breaks, even
        across outages and crashes", so every way of breaking that promise
        is tried here: outages, restarts on both sides, a crash between an
        ACK and clearing the spool, a full spool, a spool edited on disk,
        and two different chains for one stream.
"""

from __future__ import annotations

import json
import tempfile
import threading
import unittest
from pathlib import Path

from tests.helpers import KEY, START_MS, sealed_chain
from tracekeep.chain import ChainWriter, verify
from tracekeep.collector import Collector
from tracekeep.shipper import RefusedError, ShipError, Shipper, SpoolingShipper
from tracekeep.spool import Spool, SpoolFull
from tracekeep.storage import read_log, record_to_line

LINES = [f"line {i}" for i in range(10)]
"""WHAT: fake log lines. WHY: easy to check order and completeness."""


class SpoolTest(unittest.TestCase):
    """
    WHAT:   The spool on its own: files, limits and damage.
    """

    def setUp(self) -> None:
        """
        WHAT:   A fresh temporary spool folder.
        """
        self._temp = tempfile.TemporaryDirectory(prefix="tracekeep-spool-")
        self.folder = Path(self._temp.name)

    def tearDown(self) -> None:
        """
        WHAT:   Deletes the folder.
        """
        self._temp.cleanup()

    def test_records_survive_reopening(self) -> None:
        """
        WHAT:   Records added, then the spool reopened (as after a restart).
        WHY:    The spool's whole job is to survive the process ending.
        """
        spool = Spool(self.folder, "web01")
        records = sealed_chain(LINES[:3])
        for record in records:
            spool.add(record)

        reopened = Spool(self.folder, "web01")
        self.assertEqual(3, len(reopened))
        self.assertEqual(records, reopened.waiting())
        self.assertEqual((3, records[-1].digest), reopened.chain_end())

    def test_chain_end_survives_clear(self) -> None:
        """
        WHAT:   The spool is emptied after delivery.
        WHY:    The next record must still link to the last one sent.
        """
        spool = Spool(self.folder, "web01")
        records = sealed_chain(LINES[:2])
        for record in records:
            spool.add(record)
        spool.clear()
        self.assertEqual(0, len(Spool(self.folder, "web01")))
        self.assertEqual((2, records[-1].digest), Spool(self.folder, "web01").chain_end())

    def test_new_stream_has_no_chain_end(self) -> None:
        """
        WHAT:   A stream never shipped before.
        WHY:    None tells the shipper to ask the collector first.
        """
        self.assertIsNone(Spool(self.folder, "web01").chain_end())

    def test_full_spool_refuses(self) -> None:
        """
        WHAT:   One record more than the limit.
        WHY:    Dropping old records would cut the chain, so it must refuse loudly.
        """
        spool = Spool(self.folder, "web01", limit=2)
        records = sealed_chain(LINES[:3])
        spool.add(records[0])
        spool.add(records[1])
        with self.assertRaises(SpoolFull):
            spool.add(records[2])
        self.assertEqual(2, len(spool))

    def test_damaged_spool_line_is_reported(self) -> None:
        """
        WHAT:   A line in the spool that is not a record.
        WHY:    Sending around it would break the chain; it must stop with the line number.
        """
        spool = Spool(self.folder, "web01")
        spool.add(sealed_chain(LINES[:1])[0])
        with spool.path.open("a", encoding="utf-8") as file:
            file.write("not json\n")
        with self.assertRaisesRegex(ValueError, "line 2"):
            Spool(self.folder, "web01")

    def test_damaged_state_file_is_reported(self) -> None:
        """
        WHAT:   A state file with a wrong hash length.
        WHY:    Continuing from a wrong chain end would make every new record unacceptable.
        """
        (self.folder / "web01.state.json").write_text(json.dumps({"next_seq": 3, "prev": "abcd"}), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "damaged"):
            Spool(self.folder, "web01").chain_end()

    def test_invalid_stream_name(self) -> None:
        """
        WHAT:   A stream name with a path in it.
        WHY:    The name becomes a file name; "../x" must never escape the folder.
        """
        with self.assertRaises(ValueError):
            Spool(self.folder, "../outside")


class SpoolingShipperTest(unittest.TestCase):
    """
    WHAT:   The spooling shipper against a real collector that goes down and comes back.
    """

    def setUp(self) -> None:
        """
        WHAT:   Temporary folders for the collector's logs and the spool,
                and a collector on a free port.
        POST:   self.port is the collector's port; it is reused after restarts
        """
        self._temp = tempfile.TemporaryDirectory(prefix="tracekeep-forward-")
        self.logs = Path(self._temp.name) / "logs"
        self.spool_folder = Path(self._temp.name) / "spool"
        self.server: Collector | None = None
        self.port = 0
        self.start_collector()

    def tearDown(self) -> None:
        """
        WHAT:   Stops the collector if it is running, and deletes the folders.
        """
        self.stop_collector()
        self._temp.cleanup()

    def start_collector(self) -> None:
        """
        WHAT:   Starts a collector, on the same port as before after a restart.
        """
        self.server = Collector(self.logs, KEY, "127.0.0.1", self.port)
        self.port = self.server.server_address[1]
        self._thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self._thread.start()

    def stop_collector(self) -> None:
        """
        WHAT:   Stops the collector and drops its connections, like a crash.
        """
        if self.server is not None:
            self.server.stop()
            self._thread.join(timeout=5)
            self.server = None

    def shipper(self, retry: float = 0.0) -> SpoolingShipper:
        """
        WHAT:   A spooling shipper for stream web01.
        WHY:    retry 0 reconnects on every send, so tests do not wait.
        """
        return SpoolingShipper("127.0.0.1", self.port, KEY, "web01", Spool(self.spool_folder, "web01"), retry,
                               timeout=0.5)

    def stored(self) -> list[str]:
        """
        WHAT:   The messages the collector stored, after checking the chain.
        RETURN: the messages, in order; the test fails if the chain is broken
        """
        records = read_log(self.logs / "web01.jsonl")
        self.assertEqual([], verify(records, KEY))
        return [record.message for _, record in records]

    def test_normal_shipping_leaves_nothing_waiting(self) -> None:
        """
        WHAT:   The collector is up the whole time.
        WHY:    Store and forward must behave like plain shipping when nothing goes wrong.
        """
        with self.shipper() as shipper:
            for line in LINES[:3]:
                self.assertTrue(shipper.send(line))
            self.assertEqual(0, shipper.close())
        self.assertEqual(LINES[:3], self.stored())

    def test_outage_then_recovery(self) -> None:
        """
        WHAT:   The collector stops after two lines and comes back after five more.
        WHY:    The main promise: no line lost, order kept, chain unbroken.
        """
        with self.shipper() as shipper:
            for line in LINES[:2]:
                shipper.send(line)
            self.stop_collector()
            for line in LINES[2:7]:
                self.assertFalse(shipper.send(line))
            self.assertEqual(5, shipper.waiting)

            self.start_collector()
            self.assertTrue(shipper.send(LINES[7]))
            self.assertEqual(0, shipper.waiting)
        self.assertEqual(LINES[:8], self.stored())

    def test_records_keep_their_original_time(self) -> None:
        """
        WHAT:   Lines spooled during an outage.
        WHY:    A record's time must be when the line was written, not when it was delivered.
        """
        with self.shipper() as shipper:
            self.stop_collector()
            shipper.send("during the outage", time_ms=START_MS)
            self.start_collector()
            shipper.close()
        _, record = read_log(self.logs / "web01.jsonl")[0]
        self.assertEqual(START_MS, record.time_ms)

    def test_shipper_restart_sends_leftovers(self) -> None:
        """
        WHAT:   The shipper ends during an outage; a new run starts after the collector is back.
        WHY:    Spooled records must survive the shipper process ending.
        """
        with self.shipper() as shipper:
            shipper.send(LINES[0])
            self.stop_collector()
            shipper.send(LINES[1])
            shipper.send(LINES[2])
            self.assertEqual(2, shipper.close())

        self.start_collector()
        with self.shipper() as shipper:
            self.assertEqual(0, shipper.waiting)  # the constructor already delivered them
            shipper.send(LINES[3])
        self.assertEqual(LINES[:4], self.stored())

    def test_shipper_can_start_during_outage_after_first_run(self) -> None:
        """
        WHAT:   A second run starts while the collector is down.
        WHY:    After the first run the chain end is on disk, so it can keep sealing.
        """
        with self.shipper() as shipper:
            shipper.send(LINES[0])
        self.stop_collector()
        with self.shipper() as shipper:
            shipper.send(LINES[1])
            self.assertEqual(1, shipper.waiting)
        self.start_collector()
        with self.shipper() as shipper:
            shipper.close()
        self.assertEqual(LINES[:2], self.stored())

    def test_first_run_needs_the_collector(self) -> None:
        """
        WHAT:   A stream that was never shipped, with the collector down.
        WHY:    Without the collector there is no way to know where its chain
                stands (it may already hold records), so starting is refused.
        """
        self.stop_collector()
        with self.assertRaisesRegex(ShipError, "could not connect"):
            self.shipper()

    def test_crash_after_ack_does_not_duplicate(self) -> None:
        """
        WHAT:   The collector stored records, but the shipper crashed before
                clearing them from its spool.
        WHY:    On reconnect those records must be skipped, not sent twice
                (the collector would refuse the duplicate and stop shipping).
        """
        with self.shipper() as shipper:
            for line in LINES[:3]:
                shipper.send(line)
        # put the delivered records back in the spool, as if the crash came before clear()
        spool = Spool(self.spool_folder, "web01")
        for _, record in read_log(self.logs / "web01.jsonl"):
            spool.add(record)
        writer = ChainWriter(KEY, *spool.chain_end())
        spool.add(writer.seal(LINES[3], START_MS))

        with self.shipper() as shipper:
            self.assertEqual(0, shipper.waiting)
        self.assertEqual(LINES[:4], self.stored())

    def test_conflicting_chain_is_refused_and_spool_kept(self) -> None:
        """
        WHAT:   While this shipper's records wait, someone else writes the same stream.
        WHY:    Two chains for one stream cannot be merged without re-sealing,
                which would destroy the proof; the spool must be kept intact.
        """
        with self.shipper() as shipper:
            shipper.send(LINES[0])
            self.stop_collector()
            shipper.send("ours, spooled")
            self.start_collector()
            with Shipper("127.0.0.1", self.port, KEY, "web01") as other:
                other.send("someone else's")
            with self.assertRaisesRegex(RefusedError, "spool"):
                shipper.close()
        self.assertEqual(1, len(Spool(self.spool_folder, "web01")))
        self.assertEqual([LINES[0], "someone else's"], self.stored())

    def test_spool_edited_while_waiting_is_refused(self) -> None:
        """
        WHAT:   An attacker edits a spooled record before it is delivered.
        WHY:    Records are sealed before spooling, so the collector must
                refuse the edited one and store nothing from it.
        """
        with self.shipper() as shipper:
            shipper.send(LINES[0])
            self.stop_collector()
            shipper.send("Failed password for root from 203.0.113.7")
            spool_file = Spool(self.spool_folder, "web01").path
            spool_file.write_text(spool_file.read_text(encoding="utf-8").replace("203.0.113.7", "192.0.2.10"),
                                  encoding="utf-8")
            self.start_collector()
            with self.assertRaisesRegex(RefusedError, "invalid MAC"):
                shipper.close()
        self.assertEqual([LINES[0]], self.stored())

    def test_full_spool_stops_shipping(self) -> None:
        """
        WHAT:   An outage longer than the spool can hold.
        WHY:    The shipper must stop with SpoolFull rather than drop lines.
        """
        with SpoolingShipper("127.0.0.1", self.port, KEY, "web01", Spool(self.spool_folder, "web01", limit=2),
                             0.0, timeout=0.5) as shipper:
            shipper.send(LINES[0])
            self.stop_collector()
            shipper.send(LINES[1])
            shipper.send(LINES[2])
            with self.assertRaises(SpoolFull):
                shipper.send(LINES[3])

    def test_retry_interval_limits_reconnects(self) -> None:
        """
        WHAT:   A long retry interval during an outage.
        WHY:    A busy log must not try to reconnect on every line. A dropped
                connection gets one immediate reconnect attempt (restarts
                are usually quick); only after that fails does the shipper
                wait. close() still makes one final attempt.
        """
        with self.shipper(retry=3600) as shipper:
            shipper.send(LINES[0])
            self.stop_collector()
            shipper.send(LINES[1])                    # the drop is noticed
            shipper.send(LINES[2])                    # one reconnect attempt fails: the clock starts
            self.start_collector()
            self.assertFalse(shipper.send(LINES[3]))  # too soon to try again
            self.assertEqual(0, shipper.close())      # the final attempt delivers everything
        self.assertEqual(LINES[:4], self.stored())

    def test_spool_lines_use_the_log_format(self) -> None:
        """
        WHAT:   A spooled record on disk.
        WHY:    Same format as the collector's log, so verify can read a spool too.
        """
        with self.shipper() as shipper:
            self.stop_collector()
            shipper.send(LINES[0], time_ms=START_MS)
        spool = Spool(self.spool_folder, "web01")
        line = spool.path.read_text(encoding="utf-8").strip()
        self.assertEqual(record_to_line(spool.waiting()[0]), line)


if __name__ == "__main__":
    unittest.main()
