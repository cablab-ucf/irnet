//! X25519MLKEM768 (draft-ietf-tls-ecdhe-mlkem) on ring's X25519 and
//! RustCrypto's ML-KEM-768: pure Rust, so the browser's handshake is
//! post-quantum too. Shares and secret: ML-KEM's, then X25519's.

use ml_kem::{
    Decapsulate, Encapsulate, Kem, KeyExport, MlKem768, TryKeyInit, ml_kem_768::DecapsulationKey,
    ml_kem_768::EncapsulationKey,
};
use rustls::crypto::ring::{cipher_suite::*, default_provider, kx_group::X25519};
use rustls::crypto::{
    ActiveKeyExchange, CompletedKeyExchange, CryptoProvider, SharedSecret, SupportedKxGroup,
};
use rustls::{Error, NamedGroup, PeerMisbehaved, ProtocolVersion};

const EK: usize = 1184;
const CT: usize = 1088;

/// ring with X25519MLKEM768 first, plain X25519 offered in the same hello
/// for peers without it; ChaCha20 first, as wasm has no AES instructions
/// (AES-128 stays for QUIC's initial packets).
pub fn provider() -> CryptoProvider {
    CryptoProvider {
        kx_groups: vec![&Hybrid, X25519],
        cipher_suites: vec![TLS13_CHACHA20_POLY1305_SHA256, TLS13_AES_128_GCM_SHA256],
        ..default_provider()
    }
}

#[derive(Debug)]
struct Hybrid;

struct Active {
    dk: DecapsulationKey,
    x: Box<dyn ActiveKeyExchange>,
    share: Vec<u8>,
}

fn bad() -> Error {
    PeerMisbehaved::InvalidKeyShare.into()
}

fn split(b: &[u8], n: usize) -> Result<(&[u8], &[u8]), Error> {
    (b.len() == n + 32).then(|| b.split_at(n)).ok_or_else(bad)
}

impl SupportedKxGroup for Hybrid {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        let (dk, ek) = MlKem768::generate_keypair();
        let x = X25519.start()?;
        let share = [&ek.to_bytes()[..], x.pub_key()].concat();
        Ok(Box::new(Active { dk, x, share }))
    }

    fn start_and_complete(&self, share: &[u8]) -> Result<CompletedKeyExchange, Error> {
        let (ek, x) = split(share, EK)?;
        let (ct, k) = EncapsulationKey::new_from_slice(ek).map_err(|_| bad())?.encapsulate();
        let x = X25519.start_and_complete(x)?;
        Ok(CompletedKeyExchange {
            group: self.name(),
            pub_key: [&ct[..], &x.pub_key].concat(),
            secret: SharedSecret::from([&k[..], x.secret.secret_bytes()].concat()),
        })
    }

    fn name(&self) -> NamedGroup {
        NamedGroup::X25519MLKEM768
    }

    fn usable_for_version(&self, v: ProtocolVersion) -> bool {
        v == ProtocolVersion::TLSv1_3
    }
}

impl ActiveKeyExchange for Active {
    fn complete(self: Box<Self>, share: &[u8]) -> Result<SharedSecret, Error> {
        let (ct, x) = split(share, CT)?;
        let k = self.dk.decapsulate_slice(ct).map_err(|_| bad())?;
        let x = self.x.complete(x)?;
        Ok(SharedSecret::from([&k[..], x.secret_bytes()].concat()))
    }

    fn hybrid_component(&self) -> Option<(NamedGroup, &[u8])> {
        Some((NamedGroup::X25519, self.x.pub_key()))
    }

    fn complete_hybrid_component(self: Box<Self>, share: &[u8]) -> Result<SharedSecret, Error> {
        self.x.complete(share)
    }

    fn pub_key(&self) -> &[u8] {
        &self.share
    }

    fn group(&self) -> NamedGroup {
        NamedGroup::X25519MLKEM768
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::crypto::aws_lc_rs::kx_group::X25519MLKEM768 as AWS;

    /// Both directions against aws-lc's X25519MLKEM768, rustls' reference.
    fn agree(c: &dyn SupportedKxGroup, s: &dyn SupportedKxGroup) {
        let a = c.start().unwrap();
        let b = s.start_and_complete(a.pub_key()).unwrap();
        let k = a.complete(&b.pub_key).unwrap();
        assert_eq!(k.secret_bytes(), b.secret.secret_bytes());
        assert_eq!(k.secret_bytes().len(), 64);
    }

    #[test]
    fn interoperates_with_aws_lc() {
        agree(&Hybrid, AWS);
        agree(AWS, &Hybrid);
        agree(&Hybrid, &Hybrid);
    }

    #[test]
    fn falls_back_to_x25519_and_refuses_bad_shares() {
        let a = Hybrid.start().unwrap();
        let (_, x) = a.hybrid_component().unwrap();
        let b = X25519.start_and_complete(x).unwrap();
        let k = a.complete_hybrid_component(&b.pub_key).unwrap();
        assert_eq!(k.secret_bytes(), b.secret.secret_bytes());
        assert!(Hybrid.start_and_complete(&[0; EK + 31]).is_err());
        assert!(Hybrid.start().unwrap().complete(&[0; CT]).is_err());
        assert_eq!(provider().kx_groups[0].name(), NamedGroup::X25519MLKEM768);
    }
}
