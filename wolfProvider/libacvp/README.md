`libacvp-v2.3.1-wolfprov.patch` adds wolfProvider PQC integration tests to
libacvp v2.3.1.

The patch runs ML-KEM key generation and encapsulation/decapsulation for all
three parameter sets, ML-DSA key generation and signing/verification for all
three parameter sets, and an SLH-DSA key generation and signing/verification
round trip.
