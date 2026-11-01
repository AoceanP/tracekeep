"""
WHAT:   The authenticated handshake of protocol version 2: the collector's
        CHALLENGE, the shipper's HELLO, and the collector's WELCOME.
WHY:    In version 1 anyone who could connect was told where a stream's
        chain ends, and could hold a connection open without proving
        anything. Now:
          - the collector reveals nothing until the shipper proves it holds
            the key, and the shipper checks the collector holds it too;
          - every handshake uses fresh random nonces from both sides, so a
            recorded handshake cannot be replayed;
          - the shipper must solve a small proof-of-work puzzle first,
            which the collector makes harder for addresses that keep
            failing. One shipper barely notices; an automated attacker
            making thousands of attempts pays for every one.
        This module is pure functions over bytes, with no sockets, so every
        check can be tested directly.

Payloads (big-endian):
    CHALLENGE  server nonce (32) | difficulty in bits (1)
    HELLO      client nonce (32) | solution (8) | proof (32) | stream name (UTF-8, rest)
    WELCOME    next seq (8) | last hash (32) | proof (32)
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import struct
from dataclasses import dataclass

NONCE_BYTES = 32
"""WHAT: size of each side's random nonce. WHY: 256 bits never repeats by chance."""

MAX_DIFFICULTY = 22
"""WHAT: the hardest puzzle a collector may set, in bits.
WHY: about 4 million hashes, a few seconds in Python: costly for an attacker
making many attempts, still bearable for a real shipper that keeps failing
(for example after a key change)."""

CHALLENGE = struct.Struct(">32sB")
"""WHAT: CHALLENGE payload: server nonce, difficulty."""

HELLO_HEAD = struct.Struct(">32sQ32s")
"""WHAT: the fixed start of a HELLO payload: client nonce, solution, proof; the stream name follows."""

WELCOME = struct.Struct(">Q32s32s")
"""WHAT: WELCOME payload: next sequence number, last hash, proof."""

_PUZZLE = b"tracekeep-puzzle-v2"
_HELLO = b"tracekeep-hello-v2"
_WELCOME = b"tracekeep-welcome-v2"
"""WHAT: labels mixed into every hash and HMAC.
WHY: domain separation: a proof made for one purpose can never be accepted for another."""


class HandshakeError(Exception):
    """
    WHAT:   A handshake message is malformed, its puzzle is unsolved, or its proof is wrong.
    WHY:    The collector counts these against the sender's address.
    """


@dataclass(frozen=True)
class Hello:
    """
    WHAT:   A decoded HELLO.
    """

    client_nonce: bytes
    """WHAT: the shipper's random nonce."""

    solution: int
    """WHAT: the puzzle solution."""

    proof: bytes
    """WHAT: HMAC proving the shipper holds the key."""

    stream: str
    """WHAT: the stream name, not yet validated."""


def new_nonce() -> bytes:
    """
    WHAT:   A fresh random nonce from the operating system's secure generator.
    RETURN: NONCE_BYTES random bytes
    """
    return secrets.token_bytes(NONCE_BYTES)


def encode_challenge(server_nonce: bytes, difficulty: int) -> bytes:
    """
    WHAT:   Builds a CHALLENGE payload.
    PRE:    server_nonce is NONCE_BYTES long; 0 <= difficulty <= MAX_DIFFICULTY
    RETURN: the payload
    """
    return CHALLENGE.pack(server_nonce, difficulty)


def decode_challenge(payload: bytes) -> tuple[bytes, int]:
    """
    WHAT:   Reads a CHALLENGE payload.
    WHY:    The shipper refuses a difficulty above MAX_DIFFICULTY, so a fake
            or hostile collector cannot make it spin forever.
    PRE:    none
    RETURN: (server nonce, difficulty)
    RAISES: HandshakeError if the payload is the wrong size or the puzzle too hard
    """
    if len(payload) != CHALLENGE.size:
        raise HandshakeError("malformed CHALLENGE")
    nonce, difficulty = CHALLENGE.unpack(payload)
    if difficulty > MAX_DIFFICULTY:
        raise HandshakeError(f"the collector asked for a {difficulty}-bit puzzle; the limit is {MAX_DIFFICULTY}")
    return nonce, difficulty


def _leading_zero_bits(digest: bytes) -> int:
    """
    WHAT:   Counts the zero bits at the start of a hash.
    RETURN: the count, 0 to 256
    """
    value = int.from_bytes(digest, "big")
    return len(digest) * 8 - value.bit_length()


def _puzzle_hash(server_nonce: bytes, client_nonce: bytes, solution: int) -> bytes:
    """
    WHAT:   The hash a puzzle solution is judged by.
    WHY:    Both nonces are in it, so a solution only works for this one
            connection and cannot be computed before connecting.
    RETURN: the SHA-256 hash
    """
    return hashlib.sha256(_PUZZLE + server_nonce + client_nonce + solution.to_bytes(8, "big")).digest()


def solve(server_nonce: bytes, client_nonce: bytes, difficulty: int) -> int:
    """
    WHAT:   Finds a solution: a number whose puzzle hash starts with `difficulty` zero bits.
    WHY:    There is no shortcut; on average it takes 2^difficulty hashes.
    PRE:    0 <= difficulty <= MAX_DIFFICULTY
    RETURN: the solution
    """
    solution = 0
    while _leading_zero_bits(_puzzle_hash(server_nonce, client_nonce, solution)) < difficulty:
        solution += 1
    return solution


def solved(server_nonce: bytes, client_nonce: bytes, solution: int, difficulty: int) -> bool:
    """
    WHAT:   Checks a solution with a single hash.
    WHY:    Checking costs the collector one hash; finding cost the shipper
            many. That asymmetry is the whole point.
    RETURN: True if the solution meets the difficulty
    """
    return _leading_zero_bits(_puzzle_hash(server_nonce, client_nonce, solution)) >= difficulty


def hello_proof(key: bytes, server_nonce: bytes, client_nonce: bytes, stream: str) -> bytes:
    """
    WHAT:   The HMAC a shipper sends to prove it holds the key.
    WHY:    It covers both nonces (no replay) and the stream name (a proof
            for one stream cannot open another).
    RETURN: the 32-byte proof
    """
    return hmac.new(key, _HELLO + server_nonce + client_nonce + stream.encode("utf-8"), hashlib.sha256).digest()


def welcome_proof(key: bytes, server_nonce: bytes, client_nonce: bytes, next_seq: int, prev: bytes) -> bytes:
    """
    WHAT:   The HMAC a collector sends to prove it holds the key too.
    WHY:    It covers the chain end, so a fake collector cannot steer the
            shipper to the wrong place in the chain.
    RETURN: the 32-byte proof
    """
    return hmac.new(key, _WELCOME + server_nonce + client_nonce + next_seq.to_bytes(8, "big") + prev,
                    hashlib.sha256).digest()


def encode_hello(key: bytes, server_nonce: bytes, difficulty: int, stream: str) -> tuple[bytes, bytes]:
    """
    WHAT:   Builds a shipper's HELLO: a new nonce, the solved puzzle, the proof, the stream.
    PRE:    the challenge was already checked with decode_challenge
    RETURN: (the HELLO payload, the client nonce, needed to check the WELCOME)
    """
    client_nonce = new_nonce()
    solution = solve(server_nonce, client_nonce, difficulty)
    proof = hello_proof(key, server_nonce, client_nonce, stream)
    return HELLO_HEAD.pack(client_nonce, solution, proof) + stream.encode("utf-8"), client_nonce


def decode_hello(payload: bytes) -> Hello:
    """
    WHAT:   Reads a HELLO payload without judging it.
    RETURN: the decoded HELLO
    RAISES: HandshakeError if it is too short or the name is not UTF-8
    """
    if len(payload) <= HELLO_HEAD.size:
        raise HandshakeError("malformed HELLO")
    client_nonce, solution, proof = HELLO_HEAD.unpack_from(payload)
    try:
        stream = payload[HELLO_HEAD.size:].decode("utf-8")
    except UnicodeDecodeError:
        raise HandshakeError("malformed HELLO: the stream name is not UTF-8") from None
    return Hello(client_nonce, solution, proof, stream)


def check_hello(key: bytes, server_nonce: bytes, difficulty: int, hello: Hello) -> None:
    """
    WHAT:   Accepts a HELLO only if its puzzle is solved and its proof is right.
    WHY:    The puzzle is checked first because it is cheap (one hash), so a
            flood of junk costs the collector as little as possible.
            compare_digest takes the same time for any wrong proof, so the
            proof cannot be guessed byte by byte from timing.
    RETURN: nothing
    RAISES: HandshakeError naming what failed
    """
    if not solved(server_nonce, hello.client_nonce, hello.solution, difficulty):
        raise HandshakeError("puzzle not solved")
    if not hmac.compare_digest(hello.proof, hello_proof(key, server_nonce, hello.client_nonce, hello.stream)):
        raise HandshakeError("authentication failed")


def encode_welcome(key: bytes, server_nonce: bytes, client_nonce: bytes, next_seq: int, prev: bytes) -> bytes:
    """
    WHAT:   Builds the collector's WELCOME with its own proof.
    RETURN: the WELCOME payload
    """
    return WELCOME.pack(next_seq, prev, welcome_proof(key, server_nonce, client_nonce, next_seq, prev))


def decode_welcome(key: bytes, server_nonce: bytes, client_nonce: bytes, payload: bytes) -> tuple[int, bytes]:
    """
    WHAT:   Reads a WELCOME and checks the collector's proof.
    WHY:    A collector without the key, such as an impostor on the network,
            is refused before any record is sent to it.
    RETURN: (next seq, last hash)
    RAISES: HandshakeError if malformed or the proof is wrong
    """
    if len(payload) != WELCOME.size:
        raise HandshakeError("malformed WELCOME")
    next_seq, prev, proof = WELCOME.unpack(payload)
    if not hmac.compare_digest(proof, welcome_proof(key, server_nonce, client_nonce, next_seq, prev)):
        raise HandshakeError("the collector could not prove it holds the key")
    return next_seq, prev
