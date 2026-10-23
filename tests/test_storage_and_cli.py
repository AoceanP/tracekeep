"""
WHAT:   Tests for the stored file format and the command line.
WHY:    The log file is what people open and attackers edit; the command
        line is what people run. Both must behave exactly as documented.
"""

import contextlib
import io
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tests.helpers import KEY, sealed_chain
from tracekeep import cli
from tracekeep.storage import append, chain_end, is_valid_stream, line_to_record, read_log, record_to_line, stream_path


def run(*args: str) -> tuple[int, str, str]:
    """
    WHAT:   Runs the command line with the test key and captures its output.
    WHY:    Tests the real entry point without starting a new process.
    PRE:    none
    RETURN: (exit code, standard output, standard error)
    """
    out, err = io.StringIO(), io.StringIO()
    with mock.patch.dict(os.environ, {cli.KEY_VARIABLE: KEY.decode()}), \
            contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            code = cli.main(list(args))
        except SystemExit as exit_:
            code = exit_.code
    return code, out.getvalue(), err.getvalue()


class StorageTests(unittest.TestCase):
    """
    WHAT:   Reading and writing the JSON-lines log.
    WHY:    A round trip must give back exactly the same record, or every
            stored log would fail verification.
    """

    def test_round_trip(self) -> None:
        """
        WHAT:   A record written as a line and read back.
        WHY:    The hash depends on every field, including the time to the millisecond.
        PRE:    none
        RETURN: nothing; fails if anything changes
        """
        for record in sealed_chain(["a", "line with \"quotes\" and \\ and ünïcödé"]):
            self.assertEqual(line_to_record(record_to_line(record)), record)

    def test_broken_lines_are_none(self) -> None:
        """
        WHAT:   Lines that are not records: text, half JSON, missing fields, bad hex.
        WHY:    verify reports them as "unreadable" instead of crashing.
        PRE:    none
        RETURN: nothing; fails if any is read as a record
        """
        good = record_to_line(sealed_chain(["x"])[0])
        for line in ("hello", good[:20], '{"seq": 0}', good.replace('"prev": "', '"prev": "zz'),
                     good.replace('"seq": 0', '"seq": -1')):
            with self.subTest(line=line[:30]):
                self.assertIsNone(line_to_record(line))

    def test_chain_end_and_append(self) -> None:
        """
        WHAT:   Appending records and asking where the chain ends.
        WHY:    The collector resumes from this after a restart.
        PRE:    none
        RETURN: nothing; fails if the end is wrong
        """
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "web01.jsonl"
            self.assertEqual(chain_end(path)[0], 0)
            chain = sealed_chain(["a", "b"])
            for record in chain:
                append(path, record)
            self.assertEqual(chain_end(path), (2, chain[-1].digest))

    def test_stream_names(self) -> None:
        """
        WHAT:   Allowed and refused stream names.
        WHY:    The name becomes a file name; only safe characters may pass.
        PRE:    none
        RETURN: nothing; fails if a dangerous name is allowed
        """
        for name in ("web01", "db_main", "A-1"):
            self.assertTrue(is_valid_stream(name))
        for name in ("", "../x", "a/b", "a\\b", "a.b", "x" * 65, "con:"):
            self.assertFalse(is_valid_stream(name))
            with self.assertRaises(ValueError):
                stream_path(Path("."), name)


class CliTests(unittest.TestCase):
    """
    WHAT:   The command line: demo, verify, keys and exit codes.
    WHY:    Scripts rely on the exit codes, so each is checked.
    """

    def test_demo(self) -> None:
        """
        WHAT:   The demo command.
        WHY:    It is the README example: the intact log passes and each of
                the three changes is caught.
        PRE:    none
        RETURN: nothing; fails if the output differs
        """
        code, out, _ = run("demo")
        self.assertEqual(code, cli.OK)
        self.assertIn("6 records, chain intact", out)
        self.assertIn("3 problems found", out)

    def test_verify_exit_codes(self) -> None:
        """
        WHAT:   verify on an intact log, then on the same log with one character changed.
        WHY:    0 means intact, 3 means tampered: a scheduled check can alert on 3.
        PRE:    none
        RETURN: nothing; fails if the exit codes are wrong
        """
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "web01.jsonl"
            for record in sealed_chain(["user alice logged in", "user bob logged in"]):
                append(path, record)
            self.assertEqual(run("verify", str(path))[0], cli.OK)
            path.write_text(path.read_text(encoding="utf-8").replace("bob", "eve"), encoding="utf-8")
            code, out, _ = run("verify", str(path))
            self.assertEqual(code, cli.TAMPERED)
            self.assertIn("line    2  altered", out)
            self.assertEqual(len(read_log(path)), 2)

    def test_missing_key(self) -> None:
        """
        WHAT:   verify with no key set.
        WHY:    A clear error and exit code 1, never a stack trace.
        PRE:    none
        RETURN: nothing; fails otherwise
        """
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.dict(os.environ, {}, clear=True), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(["verify", "whatever.jsonl"])
        self.assertEqual(code, cli.ERROR)
        self.assertIn("no key", err.getvalue())

    def test_missing_file(self) -> None:
        """
        WHAT:   verify on a file that does not exist.
        WHY:    Exit code 1 with the reason.
        PRE:    none
        RETURN: nothing; fails otherwise
        """
        code, _, err = run("verify", "no-such-file.jsonl")
        self.assertEqual(code, cli.ERROR)
        self.assertIn("error:", err)

    def test_bad_command_line(self) -> None:
        """
        WHAT:   An unknown command, and ship without --stream.
        WHY:    Exit code 2, like every other tool in the series.
        PRE:    none
        RETURN: nothing; fails otherwise
        """
        self.assertEqual(run("explode")[0], cli.USAGE)
        self.assertEqual(run("ship", "x.log")[0], cli.USAGE)

    def test_no_connection(self) -> None:
        """
        WHAT:   ship when no collector is listening.
        WHY:    Exit code 1 and a message naming the address.
        PRE:    nothing listens on port 1
        RETURN: nothing; fails otherwise
        """
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / "app.log"
            source.write_text("hello\n", encoding="utf-8")
            code, _, err = run("ship", str(source), "--stream", "web01", "--port", "1")
        self.assertEqual(code, cli.ERROR)
        self.assertIn("could not connect", err)


if __name__ == "__main__":
    unittest.main()
