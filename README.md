# rustls-rustcrypto-azul

> **azul fork.** This is `rustls-rustcrypto-azul`, a fork of
> [`rustls-rustcrypto`](https://github.com/RustCrypto/rustls-rustcrypto) for the
> [azul](https://github.com/fschutt/azul) GUI framework. The newest upstream release,
> 0.0.2-alpha, is built on p256/p384 0.13, whose crypto-bigint 0.5 leaks timing in its
> Montgomery multiplication (RUSTSEC-2026-0387), and it pulls in rustls-webpki 0.102, a line
> without security fixes. Upstream's master already moved to the elliptic-curve 0.14 /
> crypto-bigint 0.7 generation but is not released; a `[patch]` cannot reach the users of a
> published crate, so this fork publishes that master (commit `70f76c0`) with three changes:
>
> - crypto-bigint is held at 0.7.6 or newer, the first release with the timing fixes;
> - a SEC1 EC key is parsed by its curve's `SecretKey` again, so a key of another curve or with a
>   mismatching public key is refused, as in 0.0.2-alpha (upstream's master took the raw scalar);
> - an in-memory handshake test covering every suite, key exchange group and key type.
>
> The library keeps upstream's name, so `rustls_rustcrypto::provider()` works unchanged. Use the
> official `rustls-rustcrypto` crate once it releases this generation.

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
[![Build Status][build-image]][build-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
[![Project Chat][chat-image]][chat-link]

[RustCrypto]-based provider implementation for version 0.23 of [rustls], maintained by the RustCrypto organization.

## ⚠️USE THIS AT YOUR OWN RISK! DO NOT USE THIS IN PRODUCTION⚠️

Not only that this is incomplete that only few selected TLS suites implemented (it should be well enough to cover 70% of the usage), but the elephant in the room is that neither did rustls nor RustCrypto packages were formally verified and certified with FIPS compliance.

Note that RustCrypto performance is generally inferior than ring, but in exchange you got a pure Rust implementation that theoretically compiles everywhere Rust was ported to. In our case, we need to have `std` but foundational support for future `no_std` expansion is already here.

## Supported Cipher Suites

- TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
- TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
- TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
- TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
- TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
- TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
- TLS13_AES_128_GCM_SHA256
- TLS13_AES_256_GCM_SHA384
- TLS13_CHACHA20_POLY1305_SHA256

## License

Licensed under either of:

- [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
- [MIT license](http://opensource.org/licenses/MIT)

at your option.

Some code authored by [@ctz](https://github.com/ctz) was adapted from upstream rustls. Licensed as above with permission.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

[//]: # (badges)

[crate-image]: https://img.shields.io/crates/v/rustls-rustcrypto
[crate-link]: https://crates.io/crates/rustls-rustcrypto-azul
[docs-image]: https://docs.rs/rustls-rustcrypto-azul/badge.svg
[docs-link]: https://docs.rs/rustls-rustcrypto-azul/
[build-image]: https://github.com/RustCrypto/rustls-rustcrypto/actions/workflows/rustls-rustcrypto.yml/badge.svg
[build-link]: https://github.com/RustCrypto/rustls-rustcrypto/actions/workflows/rustls-rustcrypto.yml
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.87+-blue.svg
[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/434751-TLS

[//]: # (links)

[RustCrypto]: https://github.com/RustCrypto/
[rustls]: https://github.com/rustls/rustls/
