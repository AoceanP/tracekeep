"""
WHAT:   The command line: collect, ship, verify and demo.
WHY:    One program with subcommands, like git; every command returns an
        exit code a script can act on.

Exit codes: 0 success (verify: chain intact), 3 verify found tampering,
1 error, 2 bad command line.
"""

from __future__ import annotations

import argparse
import os
import sys
import tempfile
import threading
from pathlib import Path

from tracekeep import __version__
from tracekeep.chain import MIN_KEY_BYTES, ChainWriter, Problem, verify
from tracekeep.collector import Collector
from tracekeep.shipper import ShipError, Shipper
from tracekeep.storage import is_valid_stream, line_to_record, read_log, record_to_line

OK = 0
"""WHAT: exit code for success."""

ERROR = 1
"""WHAT: exit code when something could not be done (no key, no file, no connection)."""

USAGE = 2
"""WHAT: exit code for a bad command line (argparse uses 2 as well)."""

TAMPERED = 3
"""WHAT: exit code when verify finds tampering. WHY: lets a scheduled check raise an alarm."""

KEY_VARIABLE = "TRACEKEEP_KEY"
"""WHAT: the environment variable holding the shared key.
WHY: keeps the key out of the command line, where other users could see it in the process list."""

DEMO_KEY = b"demo-key-not-a-secret-0000"
"""WHAT: the fixed key used only by --demo. WHY: the demo needs no setup; it is public, so never use it for real logs."""

DEMO_LINES = [
    "sshd: Failed password for admin from 203.0.113.7 port 51234",
    "sshd: Failed password for admin from 203.0.113.7 port 51240",
    "sshd: Failed password for root from 203.0.113.7 port 51251",
    "sshd: Accepted password for alice from 192.0.2.10 port 40122",
    "sudo: alice : COMMAND=/usr/bin/systemctl restart nginx",
    "sshd: Disconnected from user alice 192.0.2.10 port 40122",
]
"""WHAT: the fake log lines the demo ships. WHY: realistic, but every address is from the documentation ranges (RFC 5737)."""


def load_key(key_file: str | None) -> bytes:
    """
    WHAT:   Gets the shared key from --key-file, or the TRACEKEEP_KEY variable.
    WHY:    Never from a plain command-line argument, which other users can
            see; the key itself is never printed.
    PRE:    none
    RETURN: the key bytes
    RAISES: ValueError if there is no key or it is too short
    """
    if key_file:
        key = Path(key_file).read_bytes().strip()
    else:
        key = os.environ.get(KEY_VARIABLE, "").encode("utf-8")
    if not key:
        raise ValueError(f"no key: set the {KEY_VARIABLE} environment variable or pass --key-file")
    if len(key) < MIN_KEY_BYTES:
        raise ValueError(f"the key must be at least {MIN_KEY_BYTES} bytes long")
    return key


def print_problems(path: Path, problems: list[Problem], total: int) -> None:
    """
    WHAT:   Prints the result of verify in plain words.
    WHY:    Says how many records were checked, then each problem with its line number.
    PRE:    total is the number of lines checked
    RETURN: nothing
    """
    if not problems:
        print(f"{path.name}: {total} records, chain intact")
        return
    print(f"{path.name}: {total} records, {len(problems)} problem{'s' if len(problems) > 1 else ''} found:")
    for problem in problems:
        print(f"  line {problem.line:>4}  {problem.kind:<13} {problem.detail}")


def command_collect(args: argparse.Namespace) -> int:
    """
    WHAT:   Runs a collector until Ctrl+C.
    WHY:    Listens on 127.0.0.1 unless --host says otherwise.
    PRE:    args came from the "collect" parser
    RETURN: the exit code
    """
    key = load_key(args.key_file)
    with Collector(Path(args.dir), key, args.host, args.port) as server:
        host, port = server.server_address[:2]
        print(f"collecting into {Path(args.dir)} on {host}:{port}, press Ctrl+C to stop", file=sys.stderr)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("stopped", file=sys.stderr)
    return OK


def command_ship(args: argparse.Namespace) -> int:
    """
    WHAT:   Sends each line of a file (or standard input) as a record.
    WHY:    Blank lines are skipped; each line is confirmed stored before the next.
    PRE:    args came from the "ship" parser
    RETURN: the exit code
    """
    if not is_valid_stream(args.stream):
        raise ValueError("the stream name must be 1 to 64 letters, digits, '_' or '-'")
    key = load_key(args.key_file)
    source = sys.stdin if args.file == "-" else open(args.file, encoding="utf-8")
    sent = 0
    with source, Shipper(args.host, args.port, key, args.stream) as shipper:
        for line in source:
            line = line.rstrip("\r\n")
            if line:
                shipper.send(line)
                sent += 1
    print(f"shipped {sent} record{'s' if sent != 1 else ''} to stream {args.stream}", file=sys.stderr)
    return OK


def command_verify(args: argparse.Namespace) -> int:
    """
    WHAT:   Checks a stored log file and lists every problem.
    WHY:    Works offline on any copy of a log; only the key is needed.
    PRE:    args came from the "verify" parser
    RETURN: OK if intact, TAMPERED if not
    """
    key = load_key(args.key_file)
    path = Path(args.file)
    records = read_log(path)
    problems = verify(records, key)
    print_problems(path, problems, len(records))
    return TAMPERED if problems else OK


def command_demo(_: argparse.Namespace) -> int:
    """
    WHAT:   Shows the whole idea in one run, with fake data in a temporary folder.
    WHY:    Ships six fake log lines to a collector on this machine, verifies
            them, then edits, deletes and forges lines in a copy and shows
            verify catching each change. Nothing is left behind afterwards.
    PRE:    none
    RETURN: OK
    """
    with tempfile.TemporaryDirectory(prefix="tracekeep-demo-") as folder:
        # 1. a collector on a free port of 127.0.0.1, running in the background
        with Collector(Path(folder), DEMO_KEY, "127.0.0.1", 0) as server:
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            port = server.server_address[1]

            # 2. ship the fake log lines
            print(f"1. shipping {len(DEMO_LINES)} log lines to a collector on 127.0.0.1:{port}")
            with Shipper("127.0.0.1", port, DEMO_KEY, "web01") as shipper:
                for line in DEMO_LINES:
                    shipper.send(line)
            server.shutdown()

        # 3. the stored log is intact
        log = Path(folder) / "web01.jsonl"
        print("\n2. verifying the stored log")
        print_problems(log, verify(read_log(log), DEMO_KEY), len(DEMO_LINES))

        # 4. an "attacker" edits a copy: hides the attacker's address, deletes the sudo line,
        #    and adds a new record 6 that was never sent. They can copy the chain's format
        #    exactly, but not the key, so they have to sign it with a guess.
        lines = log.read_text(encoding="utf-8").splitlines()
        lines[2] = lines[2].replace("203.0.113.7", "192.0.2.10")
        del lines[4]
        last = line_to_record(lines[-1])
        forger = ChainWriter(b"attacker-guessed-key-1234", last.seq + 1, last.digest)
        lines.append(record_to_line(forger.seal("sshd: Session closed normally", last.time_ms + 1000)))
        tampered = Path(folder) / "web01-tampered.jsonl"
        tampered.write_text("\n".join(lines) + "\n", encoding="utf-8")

        print("\n3. an attacker edits line 3, deletes line 5 and adds a forged record 6; verifying the copy")
        records = read_log(tampered)
        print_problems(tampered, verify(records, DEMO_KEY), len(records))
    return OK


def build_parser() -> argparse.ArgumentParser:
    """
    WHAT:   Defines the commands and their options.
    WHY:    argparse writes the help text and checks types, and exits with 2 on bad input.
    PRE:    none
    RETURN: the parser
    """
    parser = argparse.ArgumentParser(prog="tracekeep",
                                     description="Ship logs over TCP as a tamper-evident hash chain, and verify them.")
    parser.add_argument("--version", action="version", version=f"tracekeep {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)

    key_help = f"file containing the shared key (default: the {KEY_VARIABLE} environment variable)"

    collect = commands.add_parser("collect", help="receive and store records")
    collect.add_argument("--dir", default="logs", help="folder for the stored logs (default: logs)")
    collect.add_argument("--host", default="127.0.0.1", help="address to listen on (default: 127.0.0.1, this machine only)")
    collect.add_argument("--port", type=int, default=5140, help="port to listen on (default: 5140)")
    collect.add_argument("--key-file", help=key_help)
    collect.set_defaults(run=command_collect)

    ship = commands.add_parser("ship", help="send log lines from a file, or - for standard input")
    ship.add_argument("file", help="the log file to send, or - to read standard input")
    ship.add_argument("--stream", required=True, help="the stream (log) name, e.g. web01")
    ship.add_argument("--host", default="127.0.0.1", help="the collector's address (default: 127.0.0.1)")
    ship.add_argument("--port", type=int, default=5140, help="the collector's port (default: 5140)")
    ship.add_argument("--key-file", help=key_help)
    ship.set_defaults(run=command_ship)

    check = commands.add_parser("verify", help="check a stored log for tampering")
    check.add_argument("file", help="the stored .jsonl log")
    check.add_argument("--key-file", help=key_help)
    check.set_defaults(run=command_verify)

    demo = commands.add_parser("demo", help="ship, verify and tamper with fake logs, in a temporary folder")
    demo.set_defaults(run=command_demo)
    return parser


def main(argv: list[str] | None = None) -> int:
    """
    WHAT:   Parses the command line and runs the chosen command.
    WHY:    Expected failures print one clear line instead of a stack trace.
    PRE:    none
    RETURN: the exit code
    """
    args = build_parser().parse_args(argv)
    try:
        return args.run(args)
    except (ValueError, OSError, ShipError) as error:
        print(f"error: {error}", file=sys.stderr)
        return ERROR
