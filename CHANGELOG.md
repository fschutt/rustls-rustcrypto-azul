# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## rustls-rustcrypto-azul 0.1.0 - 2026-10-24

The first release of the azul fork, built from upstream's master at `70f76c0`.

### Changed
- On the RustCrypto generation of elliptic-curve 0.14: p256/p384 0.14, ecdsa 0.17, rsa 0.10
  (release candidate), aead 0.6, aes-gcm 0.11, chacha20poly1305 0.11, digest/sha2 0.11, hmac 0.13,
  signature 3, ed25519-dalek/x25519-dalek 3, getrandom 0.4 (upstream's work).
- crypto-bigint 0.7.6 or newer (RUSTSEC-2026-0387).
- Signature algorithm identifiers come from rustls-pki-types; rustls-webpki 0.102 is no longer a
  dependency (upstream's work).
- A SEC1 EC key is checked against its curve and public key again, as in 0.0.2-alpha.
- Ed25519 keys in SEC1 form are refused (SEC1 encodes EC keys only; upstream's work).
- Minimum Rust version 1.87.

### Added
- `tests/handshake.rs`: in-memory handshakes for every suite, group and key type, client
  certificates, SEC1/PKCS#1 keys and a refused chain.
