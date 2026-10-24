// Full TLS handshakes in memory, client and server both on this provider: every cipher suite, every
// key exchange group and every key type, then application data both ways. A handshake only completes
// when key exchange, signing, signature verification (the certificate chain through rustls-webpki and
// the handshake signature), the AEADs, the hashes and the HMAC/PRF all agree with each other.

use std::io::{Read, Write};
use std::sync::Arc;

use rustls::client::WebPkiServerVerifier;
use rustls::crypto::{CryptoProvider, SupportedKxGroup};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::server::WebPkiClientVerifier;
use rustls::{
    ClientConfig, ClientConnection, Connection, RootCertStore, ServerConfig, ServerConnection,
    SupportedCipherSuite,
};
use rustls_rustcrypto as provider;

fn data(name: &str) -> Vec<u8> {
    let path = format!("{}/tests/data/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
}

fn cert(name: &str) -> CertificateDer<'static> {
    CertificateDer::from_pem_slice(&data(name)).unwrap()
}

fn key(name: &str) -> PrivateKeyDer<'static> {
    PrivateKeyDer::from_pem_slice(&data(name)).unwrap()
}

fn roots(ca: &str) -> Arc<RootCertStore> {
    let mut roots = RootCertStore::empty();
    roots.add(cert(ca)).unwrap();
    Arc::new(roots)
}

/// The provider narrowed to one suite and one group, so the handshake can only use those.
fn narrowed(suite: SupportedCipherSuite, kx: &'static dyn SupportedKxGroup) -> Arc<CryptoProvider> {
    let mut p = provider::provider();
    p.cipher_suites = vec![suite];
    p.kx_groups = vec![kx];
    Arc::new(p)
}

/// Moves everything `from` wants to send into `to`; returns the number of bytes moved, or the error
/// `to` raised on them.
fn try_pump(from: &mut Connection, to: &mut Connection) -> Result<usize, rustls::Error> {
    let mut buf = Vec::new();
    while from.wants_write() {
        from.write_tls(&mut buf).unwrap();
    }
    let mut rest = &buf[..];
    while !rest.is_empty() {
        to.read_tls(&mut rest).unwrap();
        to.process_new_packets()?;
    }
    Ok(buf.len())
}

fn pump(from: &mut Connection, to: &mut Connection) -> usize {
    try_pump(from, to).unwrap()
}

fn send(from: &mut Connection, to: &mut Connection, msg: &[u8]) {
    from.writer().write_all(msg).unwrap();
    pump(from, to);
    let mut got = vec![0u8; msg.len()];
    to.reader().read_exact(&mut got).unwrap();
    assert_eq!(got, msg);
}

struct Case {
    suite: SupportedCipherSuite,
    kx: &'static dyn SupportedKxGroup,
    /// File stem of the server's key and certificate, and of the CA that issued it.
    server: &'static str,
    /// A PEM key file other than `<server>.key`, to load the same key in another encoding.
    server_key: Option<&'static str>,
    /// File stem of a client certificate the server requires, if any.
    client: Option<&'static str>,
}

impl Case {
    fn new(suite: SupportedCipherSuite, kx: &'static dyn SupportedKxGroup, server: &'static str) -> Self {
        Case { suite, kx, server, server_key: None, client: None }
    }

    fn run(&self) {
        let provider = narrowed(self.suite, self.kx);
        let version = self.suite.version();
        let server_key = key(self.server_key.unwrap_or(&format!("{}.key", self.server)));
        let server_chain = vec![cert(&format!("{}.pem", self.server))];

        let server_builder = ServerConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[version])
            .unwrap();
        let server_config = match self.client {
            Some(client) => {
                let verifier = WebPkiClientVerifier::builder_with_provider(
                    roots(&format!("{client}-ca.pem")),
                    provider.clone(),
                )
                .build()
                .unwrap();
                server_builder.with_client_cert_verifier(verifier)
            }
            None => server_builder.with_no_client_auth(),
        }
        .with_single_cert(server_chain, server_key)
        .unwrap();

        let server_verifier = WebPkiServerVerifier::builder_with_provider(
            roots(&format!("{}-ca.pem", self.server)),
            provider.clone(),
        )
        .build()
        .unwrap();
        let client_builder = ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[version])
            .unwrap()
            .with_webpki_verifier(server_verifier);
        let client_config = match self.client {
            Some(client) => client_builder
                .with_client_auth_cert(
                    vec![cert(&format!("{client}.pem"))],
                    key(&format!("{client}.key")),
                )
                .unwrap(),
            None => client_builder.with_no_client_auth(),
        };

        let name = ServerName::try_from("localhost").unwrap();
        let mut client: Connection =
            ClientConnection::new(Arc::new(client_config), name).unwrap().into();
        let mut server: Connection =
            ServerConnection::new(Arc::new(server_config)).unwrap().into();

        for _ in 0..16 {
            if pump(&mut client, &mut server) + pump(&mut server, &mut client) == 0 {
                break;
            }
        }
        assert!(!client.is_handshaking() && !server.is_handshaking(), "{self}: handshake stalled");
        for side in [&client, &server] {
            assert_eq!(side.negotiated_cipher_suite(), Some(self.suite), "{self}");
            assert_eq!(side.protocol_version(), Some(version.version), "{self}");
            let group = side.negotiated_key_exchange_group().map(|g| g.name());
            assert_eq!(group, Some(self.kx.name()), "{self}");
        }
        if let (Some(_), Connection::Server(s)) = (self.client, &server) {
            assert!(s.peer_certificates().is_some_and(|c| c.len() == 1), "{self}");
        }

        send(&mut client, &mut server, b"ping from the client");
        send(&mut server, &mut client, b"pong from the server, a little longer than the ping");
    }
}

impl std::fmt::Display for Case {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?} / {:?} / {}", self.suite.suite(), self.kx.name(), self.server)?;
        if let Some(k) = self.server_key {
            write!(f, " (key {k})")?;
        }
        if let Some(c) = self.client {
            write!(f, " + client {c}")?;
        }
        Ok(())
    }
}

fn kx_groups() -> &'static [&'static dyn SupportedKxGroup] {
    provider::provider().kx_groups.leak()
}

const TLS13: [SupportedCipherSuite; 3] = [
    provider::TLS13_AES_128_GCM_SHA256,
    provider::TLS13_AES_256_GCM_SHA384,
    provider::TLS13_CHACHA20_POLY1305_SHA256,
];

#[test]
fn tls13_every_suite_and_group() {
    for suite in TLS13 {
        for kx in kx_groups() {
            Case::new(suite, *kx, "p256").run();
        }
    }
}

#[test]
fn tls13_every_key_type() {
    for server in ["rsa", "p256", "p384", "ed25519"] {
        Case::new(provider::TLS13_AES_128_GCM_SHA256, kx_groups()[0], server).run();
    }
}

#[cfg(feature = "tls12")]
#[test]
fn tls12_every_suite_and_group() {
    let ecdsa = [
        provider::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        provider::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        provider::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    ];
    let rsa = [
        provider::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        provider::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        provider::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    ];
    for kx in kx_groups() {
        for suite in ecdsa {
            Case::new(suite, *kx, "p256").run();
        }
        for suite in rsa {
            Case::new(suite, *kx, "rsa").run();
        }
    }
    for server in ["p384", "ed25519"] {
        Case::new(ecdsa[0], kx_groups()[0], server).run();
    }
}

#[test]
fn client_certificates() {
    for (server, client) in [("p256", "rsa"), ("rsa", "ed25519"), ("ed25519", "p384")] {
        let mut case = Case::new(provider::TLS13_AES_256_GCM_SHA384, kx_groups()[0], server);
        case.client = Some(client);
        case.run();
    }
}

#[cfg(feature = "tls12")]
#[test]
fn tls12_client_certificate() {
    let mut case =
        Case::new(provider::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, kx_groups()[1], "rsa");
    case.client = Some("p256");
    case.run();
}

#[test]
fn sec1_and_pkcs1_keys_sign_handshakes() {
    for (server, file) in [("p256", "p256.sec1.key"), ("p384", "p384.sec1.key"), ("rsa", "rsa.pkcs1.key")] {
        let mut case = Case::new(provider::TLS13_CHACHA20_POLY1305_SHA256, kx_groups()[2], server);
        case.server_key = Some(file);
        case.run();
    }
}

#[test]
fn key_loading() {
    use provider::sign::ecdsa::{EcdsaSigningKeyP256, EcdsaSigningKeyP384};
    use rustls::SignatureAlgorithm;

    for (file, algorithm) in [
        ("rsa.key", SignatureAlgorithm::RSA),
        ("rsa.pkcs1.key", SignatureAlgorithm::RSA),
        ("p256.key", SignatureAlgorithm::ECDSA),
        ("p256.sec1.key", SignatureAlgorithm::ECDSA),
        ("p384.key", SignatureAlgorithm::ECDSA),
        ("p384.sec1.key", SignatureAlgorithm::ECDSA),
        ("ed25519.key", SignatureAlgorithm::ED25519),
    ] {
        let loaded = provider::sign::any_supported_type(&key(file)).unwrap();
        assert_eq!(loaded.algorithm(), algorithm, "{file}");
    }

    // A SEC1 key names its curve: a key of the other curve is refused, never reinterpreted.
    assert!(EcdsaSigningKeyP256::try_from(&key("p256.sec1.key")).is_ok());
    assert!(EcdsaSigningKeyP384::try_from(&key("p384.sec1.key")).is_ok());
    assert!(EcdsaSigningKeyP384::try_from(&key("p256.sec1.key")).is_err());
    assert!(EcdsaSigningKeyP256::try_from(&key("p384.sec1.key")).is_err());
    assert!(EcdsaSigningKeyP384::try_from(&key("p256.key")).is_err());
    assert!(EcdsaSigningKeyP256::try_from(&key("rsa.key")).is_err());
    assert!(provider::sign::any_ecdsa_type(&key("ed25519.key")).is_err());
    assert!(provider::sign::any_eddsa_type(&key("p256.key")).is_err());
}

#[test]
fn a_wrong_ca_is_refused() {
    let provider = narrowed(provider::TLS13_AES_128_GCM_SHA256, kx_groups()[0]);
    let server_config = ServerConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert("p256.pem")], key("p256.key"))
        .unwrap();
    // The client trusts the P-384 test CA, which did not issue the server's certificate.
    let verifier =
        WebPkiServerVerifier::builder_with_provider(roots("p384-ca.pem"), provider.clone())
            .build()
            .unwrap();
    let client_config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_webpki_verifier(verifier)
        .with_no_client_auth();

    let name = ServerName::try_from("localhost").unwrap();
    let mut client: Connection =
        ClientConnection::new(Arc::new(client_config), name).unwrap().into();
    let mut server: Connection = ServerConnection::new(Arc::new(server_config)).unwrap().into();
    let mut failed = None;
    for _ in 0..16 {
        pump(&mut client, &mut server);
        match try_pump(&mut server, &mut client) {
            Ok(0) => break,
            Ok(_) => {}
            Err(e) => {
                failed = Some(e);
                break;
            }
        }
    }
    match failed {
        Some(rustls::Error::InvalidCertificate(_)) => {}
        other => panic!("expected an invalid certificate, got {other:?}"),
    }
}
