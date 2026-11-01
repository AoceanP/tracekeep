"""
WHAT:   TLS settings for the collector and the shipper.
WHY:    The hash chain proves logs were not changed, but without TLS
        anyone watching the network can read every log line. TLS 1.3
        encrypts the whole connection, handshake included. With a client
        certificate required (mutual TLS), a client without one is turned
        away before it can even see the CHALLENGE.
        Python's built-in ssl module is enough, so tracekeep still needs
        nothing outside the standard library.
"""

from __future__ import annotations

import ssl


def server_context(cert: str, key: str, client_ca: str | None = None) -> ssl.SSLContext:
    """
    WHAT:   The collector's TLS settings.
    WHY:    TLS 1.3 only: older versions have weaker handshakes and nothing
            here needs to talk to old clients.
    PRE:    cert and key are PEM files; client_ca, if given, is a PEM file
    RETURN: a server-side context; with client_ca, every shipper must
            present a certificate signed by it
    RAISES: OSError if a file cannot be read; ssl.SSLError if they do not match
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(cert, key)
    if client_ca:
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_verify_locations(client_ca)
    return context


def client_context(ca: str, cert: str | None = None, key: str | None = None) -> ssl.SSLContext:
    """
    WHAT:   The shipper's TLS settings.
    WHY:    The collector's certificate must be signed by `ca` and match the
            collector's name, so a machine pretending to be the collector
            is refused before anything is sent to it.
    PRE:    ca is a PEM file; cert and key are both given or both None
    RETURN: a client-side context (with a client certificate for mutual TLS)
    RAISES: OSError if a file cannot be read; ssl.SSLError if they do not match
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_verify_locations(ca)
    if cert:
        context.load_cert_chain(cert, key)
    return context
