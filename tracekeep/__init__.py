"""
WHAT:   tracekeep: ship logs over TCP as a tamper-evident hash chain, and verify them.
WHY:    Attackers edit or delete logs to hide what they did; a chain of
        hashes signed with a secret key makes any change detectable.
"""

__version__ = "1.0.0"
"""WHAT: the program version, shown by --version."""
