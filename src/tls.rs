use crate::{IcError, Result};
use openssl::{
    asn1::Asn1Time,
    hash::MessageDigest,
    nid::Nid,
    pkey::PKey,
    ssl::{SslAcceptor, SslConnector, SslMethod, SslStream, SslVerifyMode, SslVersion},
    x509::{X509, X509Ref},
};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    net::{TcpStream, ToSocketAddrs},
    path::Path,
    sync::RwLock,
    time::Duration,
};
fn ssl_error(e: impl std::fmt::Display) -> IcError {
    IcError::new("TLS_ERROR", e.to_string())
}
fn identity(cert: &X509Ref) -> Result<(String, String)> {
    let c: Vec<_> = cert
        .subject_name()
        .entries_by_nid(Nid::COMMONNAME)
        .collect();
    if c.len() != 1 {
        return Err(IcError::new(
            "IDENTITY_MISMATCH",
            "Certificate requires exactly one CN",
        ));
    }
    let id = c[0].data().to_string().map_err(ssl_error)?;
    if !crate::policy::valid_id(&id) {
        return Err(IcError::new("IDENTITY_MISMATCH", "Invalid node CN"));
    }
    let now = Asn1Time::days_from_now(0).map_err(ssl_error)?;
    if cert.not_before() > now.as_ref() || cert.not_after() < now.as_ref() {
        return Err(IcError::new(
            "CERTIFICATE_EXPIRED",
            "Certificate expired or not yet valid",
        ));
    }
    Ok((
        id,
        hex::encode_upper(cert.digest(MessageDigest::sha256()).map_err(ssl_error)?),
    ))
}
pub fn certificate_identity(pem: &[u8]) -> Result<Value> {
    let cert = X509::from_pem(pem)
        .or_else(|_| X509::from_der(pem))
        .map_err(ssl_error)?;
    let (id, pin) = identity(&cert)?;
    Ok(
        json!({"nodeId":id,"fingerprint256":pin,"validFrom":cert.not_before().to_string(),"validTo":cert.not_after().to_string()}),
    )
}
/// Verify a public node identity before it can enter either trust store.
/// Each PEM field is bounded independently; only the certificate's issuing root is accepted.
pub fn verify_identity_bundle(bundle: &Value) -> Result<(String, String)> {
    use openssl::{
        stack::Stack,
        x509::{X509PurposeId, X509StoreContext, store::X509StoreBuilder},
    };
    let pem = |field: &str| -> Result<&str> {
        bundle[field]
            .as_str()
            .filter(|s| !s.is_empty() && s.len() <= 32768)
            .ok_or_else(|| {
                IcError::new(
                    "INVALID_CERTIFICATE",
                    "PEM field must be nonempty and at most 32 KiB",
                )
            })
    };
    let certs = X509::stack_from_pem(pem("certificatePem")?.as_bytes()).map_err(ssl_error)?;
    if certs.len() != 1 {
        return Err(IcError::new(
            "INVALID_CERTIFICATE",
            "Exactly one node certificate required",
        ));
    }
    let cert = &certs[0];
    let (id, pin) = identity(cert)?;
    if bundle["nodeId"] != id || bundle["fingerprint256"] != pin {
        return Err(IcError::new(
            "IDENTITY_MISMATCH",
            "Identity bundle CN or fingerprint mismatch",
        ));
    }
    let text = cert.to_text().map_err(ssl_error)?;
    if String::from_utf8_lossy(&text).contains("CA:TRUE") {
        return Err(IcError::new(
            "INVALID_CERTIFICATE",
            "Node certificate cannot be a CA",
        ));
    }
    let roots = X509::stack_from_pem(pem("caPem")?.as_bytes()).map_err(ssl_error)?;
    if roots.len() != 1 {
        return Err(IcError::new(
            "UNTRUSTED_CA",
            "Exactly one issuing root CA required",
        ));
    }
    let root = &roots[0];
    let root_key = root.public_key().map_err(ssl_error)?;
    if !String::from_utf8_lossy(&root.to_text().map_err(ssl_error)?).contains("CA:TRUE")
        || root.issued(root) != openssl::x509::X509VerifyResult::OK
        || !root.verify(&root_key).map_err(ssl_error)?
        || root.issued(cert) != openssl::x509::X509VerifyResult::OK
        || !cert.verify(&root_key).map_err(ssl_error)?
    {
        return Err(IcError::new(
            "UNTRUSTED_CA",
            "Node must be directly issued by its self-signed root CA",
        ));
    }
    for purpose in [X509PurposeId::SSL_CLIENT, X509PurposeId::SSL_SERVER] {
        let mut store = X509StoreBuilder::new().map_err(ssl_error)?;
        store.add_cert(root.clone()).map_err(ssl_error)?;
        store.set_purpose(purpose).map_err(ssl_error)?;
        let mut ctx = X509StoreContext::new().map_err(ssl_error)?;
        let chain = Stack::new().map_err(ssl_error)?;
        if !ctx
            .init(&store.build(), cert, &chain, |c| c.verify_cert())
            .map_err(ssl_error)?
        {
            return Err(IcError::new(
                "UNTRUSTED_CA",
                "Invalid node certificate chain or TLS purpose",
            ));
        }
    }
    Ok((id, pin))
}
pub struct Security {
    cert: X509,
    key: PKey<openssl::pkey::Private>,
    ca: Vec<X509>,
    pins: BTreeMap<String, Vec<String>>,
    paired: RwLock<BTreeMap<String, Value>>,
    pub fingerprint256: String,
}
impl Security {
    pub fn load(raw: &Value, base: &Path, node_id: &str) -> Result<Self> {
        let read = |name: &str| -> Result<Vec<u8>> {
            let p = raw[name]
                .as_str()
                .ok_or_else(|| IcError::new("SECURITY_REQUIRED", "cert/key/ca required"))?;
            Ok(std::fs::read(base.join(p))?)
        };
        let cert = X509::from_pem(&read("cert")?).map_err(ssl_error)?;
        let key = PKey::private_key_from_pem(&read("key")?).map_err(ssl_error)?;
        let ca = X509::stack_from_pem(&read("ca")?).map_err(ssl_error)?;
        if ca.is_empty() {
            return Err(IcError::new("SECURITY_REQUIRED", "CA required"));
        }
        let (id, pin) = identity(&cert)?;
        if id != node_id || !cert.public_key().map_err(ssl_error)?.public_eq(&key) {
            return Err(IcError::new(
                "IDENTITY_MISMATCH",
                "Local identity/key mismatch",
            ));
        }
        let peers = raw["trustedPeers"]
            .as_object()
            .ok_or_else(|| IcError::new("INVALID_CONFIG", "trustedPeers object required"))?;
        let mut pins = BTreeMap::new();
        for (id, value) in peers {
            if id == node_id || !crate::policy::valid_id(id) {
                return Err(IcError::new("INVALID_CONFIG", "Invalid trusted ID"));
            }
            let values = value.as_array().cloned().unwrap_or(vec![value.clone()]);
            if values.is_empty() || values.len() > 4 {
                return Err(IcError::new("INVALID_CONFIG", "One to four pins required"));
            }
            let mut normalized = vec![];
            for v in values {
                let raw = v.as_str().unwrap_or("");
                let colon_form = raw.len() == 95
                    && raw.bytes().enumerate().all(|(i, b)| {
                        if i % 3 == 2 {
                            b == b':'
                        } else {
                            b.is_ascii_hexdigit()
                        }
                    });
                if !(raw.len() == 64 && raw.bytes().all(|b| b.is_ascii_hexdigit())) && !colon_form {
                    return Err(IcError::new("INVALID_CONFIG", "Invalid SHA256 pin format"));
                }
                let s = raw.replace(':', "").to_uppercase();
                if s.len() != 64 || hex::decode(&s).is_err() {
                    return Err(IcError::new("INVALID_CONFIG", "Invalid SHA256 pin"));
                }
                normalized.push(s)
            }
            pins.insert(id.clone(), normalized);
        }
        let s = Self {
            cert,
            key,
            ca,
            pins,
            paired: RwLock::new(BTreeMap::new()),
            fingerprint256: pin,
        };
        s.acceptor()?;
        Ok(s)
    }
    pub fn public_identity(&self) -> Result<Value> {
        let (id, pin) = identity(&self.cert)?;
        // Export only our own issuing root, never roots learned from other pairings.
        let root = self
            .ca
            .iter()
            .find(|root| {
                root.issued(&self.cert) == openssl::x509::X509VerifyResult::OK
                    && root
                        .public_key()
                        .is_ok_and(|key| self.cert.verify(&key).unwrap_or(false))
            })
            .ok_or_else(|| IcError::new("UNTRUSTED_CA", "Local issuing CA missing"))?;
        let bundle = json!({"nodeId":id,"fingerprint256":pin,
            "certificatePem":String::from_utf8(self.cert.to_pem().map_err(ssl_error)?).map_err(ssl_error)?,
            "caPem":String::from_utf8(root.to_pem().map_err(ssl_error)?).map_err(ssl_error)?});
        verify_identity_bundle(&bundle)?;
        Ok(bundle)
    }
    pub fn add_paired_identity(&self, bundle: &Value) -> Result<()> {
        let (id, pin) = verify_identity_bundle(bundle)?;
        if identity(&self.cert)?.0 == id {
            return Err(IcError::new("IDENTITY_MISMATCH", "Cannot pair self"));
        }
        let mut paired = self.paired.write().unwrap();
        if self.pins.get(&id).is_some_and(|pins| !pins.contains(&pin))
            || paired
                .get(&id)
                .is_some_and(|old| old["fingerprint256"] != pin)
        {
            return Err(IcError::new(
                "ROTATION_REQUIRED",
                "Paired identity cannot silently rotate",
            ));
        }
        if !paired.contains_key(&id) && paired.len() >= 128 {
            return Err(IcError::new("PAIRING_LIMIT", "Too many paired identities"));
        }
        paired.insert(id, bundle.clone());
        Ok(())
    }
    pub fn remove_paired_identity(&self, id: &str) -> Result<()> {
        self.paired.write().unwrap().remove(id);
        Ok(())
    }
    fn peer_roots(&self, id: &str) -> Result<Vec<X509>> {
        if let Some(bundle) = self.paired.read().unwrap().get(id) {
            return X509::stack_from_pem(bundle["caPem"].as_str().unwrap().as_bytes())
                .map_err(ssl_error);
        }
        Ok(self.ca.clone())
    }
    /// Bootstrap listener only: TLS verifies possession of the client key.
    /// The caller MUST verify the presented bundle before recording any request.
    pub fn pairing_acceptor(&self) -> Result<SslAcceptor> {
        let mut b = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).map_err(ssl_error)?;
        b.set_min_proto_version(Some(SslVersion::TLS1_3))
            .map_err(ssl_error)?;
        b.set_max_proto_version(Some(SslVersion::TLS1_3))
            .map_err(ssl_error)?;
        b.set_certificate(&self.cert).map_err(ssl_error)?;
        b.set_private_key(&self.key).map_err(ssl_error)?;
        b.check_private_key().map_err(ssl_error)?;
        b.set_verify_callback(
            SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT,
            |_, _| true,
        );
        Ok(b.build())
    }
    pub fn verify_presented_bundle(cert: &X509Ref, bundle: &Value) -> Result<()> {
        if identity(cert)? != verify_identity_bundle(bundle)? {
            return Err(IcError::new(
                "IDENTITY_MISMATCH",
                "Presented TLS certificate does not match identity bundle",
            ));
        }
        Ok(())
    }
    pub fn pairing_connect(
        &self,
        host: &str,
        port: u16,
        expected_bundle: &Value,
    ) -> Result<SslStream<TcpStream>> {
        let (id, pin) = verify_identity_bundle(expected_bundle)?;
        let stream = self.pairing_connect_pinned(host, port, &id, &pin)?;
        Self::verify_presented_bundle(&stream.ssl().peer_certificate().unwrap(), expected_bundle)?;
        Ok(stream)
    }
    /// The independently verified pin is mandatory; this is never TOFU.
    pub fn pairing_connect_pinned(
        &self,
        host: &str,
        port: u16,
        expected_id: &str,
        expected_pin: &str,
    ) -> Result<SslStream<TcpStream>> {
        let pin = expected_pin.replace(':', "").to_ascii_uppercase();
        if !crate::policy::valid_id(expected_id) || pin.len() != 64 || hex::decode(&pin).is_err() {
            return Err(IcError::new(
                "INVALID_FINGERPRINT",
                "Valid node ID and independently verified SHA256 pin required",
            ));
        }
        self.validate_local()?;
        let addr = (host, port)
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| IcError::new("PEER_UNAVAILABLE", "No peer address"))?;
        let tcp = TcpStream::connect_timeout(&addr, Duration::from_secs(5))?;
        tcp.set_nodelay(true)?;
        tcp.set_read_timeout(Some(Duration::from_secs(5)))?;
        tcp.set_write_timeout(Some(Duration::from_secs(5)))?;
        let mut b = SslConnector::builder(SslMethod::tls()).map_err(ssl_error)?;
        b.set_min_proto_version(Some(SslVersion::TLS1_3))
            .map_err(ssl_error)?;
        b.set_max_proto_version(Some(SslVersion::TLS1_3))
            .map_err(ssl_error)?;
        b.set_certificate(&self.cert).map_err(ssl_error)?;
        b.set_private_key(&self.key).map_err(ssl_error)?;
        b.set_verify_callback(SslVerifyMode::PEER, |_, _| true);
        let mut c = b.build().configure().map_err(ssl_error)?;
        c.set_verify_hostname(false);
        let stream = c.connect(host, tcp).map_err(ssl_error)?;
        let cert = stream
            .ssl()
            .peer_certificate()
            .ok_or_else(|| IcError::new("IDENTITY_MISMATCH", "Missing certificate"))?;
        if identity(&cert)? != (expected_id.into(), pin) {
            return Err(IcError::new(
                "IDENTITY_MISMATCH",
                "Bootstrap peer differs from verified ID or pin",
            ));
        }
        Ok(stream)
    }
    pub fn acceptor(&self) -> Result<SslAcceptor> {
        let mut b = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).map_err(ssl_error)?;
        b.set_min_proto_version(Some(SslVersion::TLS1_3))
            .map_err(ssl_error)?;
        b.set_max_proto_version(Some(SslVersion::TLS1_3))
            .map_err(ssl_error)?;
        b.set_certificate(&self.cert).map_err(ssl_error)?;
        b.set_private_key(&self.key).map_err(ssl_error)?;
        b.check_private_key().map_err(ssl_error)?;
        for ca in &self.ca {
            b.cert_store_mut().add_cert(ca.clone()).map_err(ssl_error)?
        }
        // A single global root store cannot disambiguate independent CAs with
        // the same subject (and missing AKI). For paired leaves, verify against
        // their exact approved root independently, including both TLS purposes.
        // Static identities retain the ordinary configured-CA verification.
        // Node authenticates against the live pin map after this handshake.
        let paired = self.paired.read().unwrap().clone();
        b.set_verify_callback(
            SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT,
            move |preverified, ctx| {
                let Some(leaf) = ctx.chain().and_then(|chain| chain.get(0)) else {
                    return false;
                };
                let Ok((id, _)) = identity(leaf) else {
                    return false;
                };
                if let Some(bundle) = paired.get(&id) {
                    if Self::verify_presented_bundle(leaf, bundle).is_err() {
                        return false;
                    }
                    ctx.set_error(openssl::x509::X509VerifyResult::OK);
                    true
                } else {
                    preverified
                }
            },
        );
        Ok(b.build())
    }
    pub fn connect(
        &self,
        host: &str,
        port: u16,
        expected_id: &str,
    ) -> Result<SslStream<TcpStream>> {
        self.connect_tracked(host, port, expected_id, |_| Ok(()))
    }
    pub fn connect_tracked(
        &self,
        host: &str,
        port: u16,
        expected_id: &str,
        on_tcp: impl FnOnce(&TcpStream) -> Result<()>,
    ) -> Result<SslStream<TcpStream>> {
        let addr = (host, port)
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| IcError::new("PEER_UNAVAILABLE", "No peer address"))?;
        let tcp = TcpStream::connect_timeout(&addr, Duration::from_secs(5))?;
        tcp.set_nodelay(true)?;
        tcp.set_read_timeout(Some(Duration::from_secs(5)))?;
        tcp.set_write_timeout(Some(Duration::from_secs(5)))?;
        on_tcp(&tcp)?;
        let mut b = SslConnector::builder(SslMethod::tls()).map_err(ssl_error)?;
        b.set_min_proto_version(Some(SslVersion::TLS1_3))
            .map_err(ssl_error)?;
        b.set_max_proto_version(Some(SslVersion::TLS1_3))
            .map_err(ssl_error)?;
        b.set_certificate(&self.cert).map_err(ssl_error)?;
        b.set_private_key(&self.key).map_err(ssl_error)?;
        for ca in self.peer_roots(expected_id)? {
            b.cert_store_mut().add_cert(ca).map_err(ssl_error)?
        }
        b.set_verify(SslVerifyMode::PEER);
        let mut c = b.build().configure().map_err(ssl_error)?;
        c.set_verify_hostname(false);
        let stream = c.connect(host, tcp).map_err(ssl_error)?;
        let cert = stream
            .ssl()
            .peer_certificate()
            .ok_or_else(|| IcError::new("IDENTITY_MISMATCH", "Missing certificate"))?;
        self.authenticate(&cert, Some(expected_id))?;
        Ok(stream)
    }
    pub fn validate_local(&self) -> Result<()> {
        identity(&self.cert).map(|_| ())
    }
    pub fn authenticate(&self, cert: &X509Ref, expected: Option<&str>) -> Result<String> {
        let (id, pin) = identity(cert)?;
        if expected.is_some_and(|v| v != id) {
            return Err(IcError::new(
                "IDENTITY_MISMATCH",
                "Unexpected peer identity",
            ));
        }
        let paired = self.paired.read().unwrap();
        if !self.pins.get(&id).is_some_and(|p| p.contains(&pin))
            && !paired.get(&id).is_some_and(|b| b["fingerprint256"] == pin)
        {
            return Err(IcError::new("UNTRUSTED_IDENTITY", "Certificate not pinned"));
        }
        Ok(id)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn fixture_security(dir: &Path, id: &str) -> Security {
        crate::harness::fixture(dir, &[id.into()]).unwrap();
        Security::load(&json!({"cert":format!("{id}.pem"),"key":format!("{id}.key"),"ca":"ca.pem","trustedPeers":{}}), dir, id).unwrap()
    }
    #[test]
    fn pairing_bundle_checks_identity_ca_and_size() {
        let a = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();
        let local = fixture_security(a.path(), "local");
        let other = fixture_security(b.path(), "other");
        let bundle = local.public_identity().unwrap();
        assert_eq!(verify_identity_bundle(&bundle).unwrap().0, "local");
        let mut invalid = bundle.clone();
        invalid["nodeId"] = json!("wrong");
        assert!(verify_identity_bundle(&invalid).is_err());
        invalid = bundle.clone();
        invalid["fingerprint256"] = json!("0".repeat(64));
        assert!(verify_identity_bundle(&invalid).is_err());
        invalid = bundle.clone();
        invalid["caPem"] = other.public_identity().unwrap()["caPem"].clone();
        assert!(verify_identity_bundle(&invalid).is_err());
        invalid["certificatePem"] = json!("x".repeat(32769));
        assert!(verify_identity_bundle(&invalid).is_err());
        assert!(Security::verify_presented_bundle(&other.cert, &bundle).is_err());
    }
    #[test]
    fn paired_trust_is_live_and_rejects_silent_rotation() {
        let a = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();
        let c = tempfile::tempdir().unwrap();
        let local = fixture_security(a.path(), "local");
        let other = fixture_security(b.path(), "other");
        let rotated = fixture_security(c.path(), "other");
        assert!(local.authenticate(&other.cert, None).is_err());
        local
            .add_paired_identity(&other.public_identity().unwrap())
            .unwrap();
        assert_eq!(local.authenticate(&other.cert, None).unwrap(), "other");
        local
            .add_paired_identity(&other.public_identity().unwrap())
            .unwrap();
        assert!(
            local
                .add_paired_identity(&rotated.public_identity().unwrap())
                .is_err()
        );
        local.remove_paired_identity("other").unwrap();
        assert!(local.authenticate(&other.cert, None).is_err());
    }
    #[test]
    fn pairing_tls_bootstraps_independent_ca_without_business_trust() {
        use std::{net::TcpListener, sync::Arc, thread};
        let a = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();
        let master = Arc::new(fixture_security(a.path(), "master"));
        let servant = fixture_security(b.path(), "servant");
        let invitation = master.public_identity().unwrap();
        let candidate = servant.public_identity().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = master.clone();
        let worker = thread::spawn(move || {
            let (tcp, _) = listener.accept().unwrap();
            let stream = server.pairing_acceptor().unwrap().accept(tcp).unwrap();
            let cert = stream.ssl().peer_certificate().unwrap();
            Security::verify_presented_bundle(&cert, &candidate).unwrap();
            assert!(server.authenticate(&cert, None).is_err());
        });
        servant
            .pairing_connect("127.0.0.1", port, &invitation)
            .unwrap();
        worker.join().unwrap();
        assert!(master.authenticate(&servant.cert, None).is_err());
    }
    #[test]
    fn pinned_bootstrap_rejects_wrong_master_before_returning_stream() {
        use std::{net::TcpListener, thread};
        let a = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();
        let master = fixture_security(a.path(), "master");
        let servant = fixture_security(b.path(), "servant");
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let worker = thread::spawn(move || {
            let (tcp, _) = listener.accept().unwrap();
            let _ = master.pairing_acceptor().unwrap().accept(tcp);
        });
        assert!(
            servant
                .pairing_connect_pinned("127.0.0.1", port, "master", &"0".repeat(64))
                .is_err()
        );
        worker.join().unwrap();
    }
    #[test]
    fn normal_tls_uses_paired_roots_and_pin_revocation_live() {
        use std::{
            io::{Read, Write},
            net::TcpListener,
            sync::Arc,
            thread,
        };
        let a = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();
        let master = Arc::new(fixture_security(a.path(), "master"));
        let servant = fixture_security(b.path(), "servant");
        // Independent fixture CAs intentionally share a subject. Trust must select
        // the issuer by the paired identity, not the first matching subject.
        assert_eq!(
            master.ca[0].subject_name().to_der().unwrap(),
            servant.ca[0].subject_name().to_der().unwrap()
        );
        assert_ne!(
            master.ca[0].to_der().unwrap(),
            servant.ca[0].to_der().unwrap()
        );
        master
            .add_paired_identity(&servant.public_identity().unwrap())
            .unwrap();
        servant
            .add_paired_identity(&master.public_identity().unwrap())
            .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = master.clone();
        let worker = thread::spawn(move || {
            let (tcp, _) = listener.accept().unwrap();
            let mut stream = server.acceptor().unwrap().accept(tcp).unwrap();
            let cert = stream.ssl().peer_certificate().unwrap();
            assert_eq!(server.authenticate(&cert, None).unwrap(), "servant");
            stream.write_all(b"x").unwrap();
            server.remove_paired_identity("servant").unwrap();
            assert!(server.authenticate(&cert, None).is_err());
        });
        let mut stream = servant.connect("127.0.0.1", port, "master").unwrap();
        let mut byte = [0];
        stream.read_exact(&mut byte).unwrap();
        worker.join().unwrap();
    }
    #[test]
    fn certificate_identity_rejects_embedded_nul() {
        let key = PKey::from_rsa(openssl::rsa::Rsa::generate(2048).unwrap()).unwrap();
        let mut name = openssl::x509::X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", "master\0hidden").unwrap();
        let name = name.build();
        let mut cert = X509::builder().unwrap();
        cert.set_version(2).unwrap();
        cert.set_subject_name(&name).unwrap();
        cert.set_issuer_name(&name).unwrap();
        cert.set_pubkey(&key).unwrap();
        cert.set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        cert.set_not_after(&Asn1Time::days_from_now(1).unwrap())
            .unwrap();
        cert.sign(&key, MessageDigest::sha256()).unwrap();
        assert_eq!(
            certificate_identity(&cert.build().to_pem().unwrap())
                .unwrap_err()
                .code,
            "IDENTITY_MISMATCH"
        );
    }
}
