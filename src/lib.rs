//! One post-quantum network setup for every cablab-ucf app: the TLS that
//! all of them speak ([`tls`], [`pq`]: these alone without feature
//! `endpoint`, and without iroh), and the iroh endpoint.

#![forbid(unsafe_code)]

#[cfg(not(any(feature = "aws-lc", feature = "pure")))]
compile_error!("irnet needs a TLS backend: feature `aws-lc` (native) or `pure` (wasm)");

#[cfg(feature = "endpoint")]
mod net;
#[cfg(feature = "pure")]
mod pq;
#[cfg(feature = "endpoint")]
pub mod psk;

#[cfg(feature = "endpoint")]
pub use net::*;
use rustls::NamedGroup;
use rustls::crypto::CryptoProvider;
use std::sync::Arc;

/// X25519MLKEM768 first. X25519 stays on offer for relays without it (their
/// hop carries only what is already sealed end to end); a peer's handshake
/// without it is refused.
pub fn tls() -> Arc<CryptoProvider> {
    #[cfg(feature = "aws-lc")]
    let p = rustls::crypto::aws_lc_rs::default_provider();
    #[cfg(all(feature = "pure", not(feature = "aws-lc")))]
    let p = pq::provider();
    Arc::new(p)
}

/// X25519MLKEM768 and nothing else: for a hop that must not fall back, as
/// pushir's to its relay, which hides who is sent to.
pub fn pq() -> Arc<CryptoProvider> {
    let mut p = (*tls()).clone();
    p.kx_groups.retain(|g| g.name() == NamedGroup::X25519MLKEM768);
    Arc::new(p)
}
