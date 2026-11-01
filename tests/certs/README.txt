TEST CERTIFICATES ONLY. Never use these for real logs.

ca.pem                    a throwaway certificate authority (its private key was deleted after signing)
server.pem, server.key    the collector, for "localhost" and 127.0.0.1
client.pem, client.key    a shipper, for mutual TLS

The private keys are public on purpose: they exist so the TLS tests run
without setup. Anyone can read them, so they protect nothing.
They expire in 2036.
