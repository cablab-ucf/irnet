//! One iroh endpoint for every cab-ucf app.

#![forbid(unsafe_code)]

#[cfg(feature = "pure")]
pub mod pq;
pub mod psk;

use iroh::RelayUrl;
use iroh::endpoint::{Builder, Endpoint, QuicTransportConfig, presets};
use rustls::crypto::CryptoProvider;
use std::sync::Arc;

/// The lab's relay, then n0's (irweb's page dials both).
pub const RELAYS: [&str; 2] = ["https://iroh.cxn.center./", "https://use1-1.relay.n0.iroh.link./"];

pub fn relays() -> Vec<RelayUrl> {
    RELAYS.map(|r| r.parse().expect("static relay url")).into()
}

/// X25519MLKEM768 first, X25519 for peers without it.
pub fn tls() -> Arc<CryptoProvider> {
    #[cfg(feature = "aws-lc")]
    let p = rustls::crypto::aws_lc_rs::default_provider();
    #[cfg(all(feature = "pure", not(feature = "aws-lc")))]
    let p = pq::provider();
    Arc::new(p)
}

/// 2 MiB stream windows (16 MB/s at 130 ms), BBRv3 for lossy paths.
pub fn transport() -> QuicTransportConfig {
    let q = QuicTransportConfig::builder()
        .stream_receive_window((2u32 << 20).into())
        .receive_window((8u32 << 20).into())
        .congestion_controller_factory(Arc::new(noq_proto::congestion::Bbr3Config::default()));
    // iroh #4647
    #[cfg(target_os = "android")]
    let q = q.enable_segmentation_offload(false);
    q.build()
}

/// No third-party lookup, no captive-portal probes.
pub fn endpoint() -> Builder {
    let b = Endpoint::builder(presets::Empty).crypto_provider(tls()).transport_config(transport());
    #[cfg(not(target_arch = "wasm32"))]
    let b = {
        let mut probes = iroh::endpoint::NetReportConfig::default();
        probes.captive_portal_check = false;
        b.net_report_config(probes)
    };
    #[cfg(not(any(target_os = "android", target_arch = "wasm32")))]
    let b = b.proxy_from_env().ca_tls_config(iroh::tls::CaTlsConfig::system());
    b
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroh::{RelayMode, SecretKey};

    #[test]
    fn handshakes_are_post_quantum() {
        assert_eq!(tls().kx_groups[0].name(), rustls::NamedGroup::X25519MLKEM768);
        assert_eq!(relays().len(), RELAYS.len());
    }

    /// Two endpoints as apps make them: one round trip, direct.
    #[tokio::test(flavor = "multi_thread")]
    async fn endpoints_talk() {
        const ALPN: &[u8] = b"irnet/test";
        let bind = |k: u8| {
            endpoint()
                .secret_key(SecretKey::from_bytes(&[k; 32]))
                .alpns(vec![ALPN.to_vec()])
                .relay_mode(RelayMode::Disabled)
                .bind()
        };
        let (a, b) = (bind(1).await.unwrap(), bind(2).await.unwrap());
        let at = b.addr();
        let echo = tokio::spawn(async move {
            let c = b.accept().await.unwrap().await.unwrap();
            let (mut tx, mut rx) = c.accept_bi().await.unwrap();
            tx.write_all(&rx.read_to_end(64).await.unwrap()).await.unwrap();
            tx.finish().unwrap();
            c.closed().await;
        });
        let c = a.connect(at, ALPN).await.unwrap();
        let (mut tx, mut rx) = c.open_bi().await.unwrap();
        tx.write_all(b"pq").await.unwrap();
        tx.finish().unwrap();
        assert_eq!(rx.read_to_end(64).await.unwrap(), b"pq");
        c.close(0u32.into(), b"");
        echo.await.unwrap();
    }

    /// A PSK channel opens for a PSK the acceptor holds, and not another.
    #[tokio::test(flavor = "multi_thread")]
    async fn psk_channel() {
        const ALPN: &[u8] = b"irnet/psk";
        let bind = |k: Option<u8>| {
            let b = endpoint().alpns(vec![ALPN.to_vec()]).relay_mode(RelayMode::Disabled);
            match k {
                Some(k) => b.secret_key(SecretKey::from_bytes(&[k; 32])),
                None => b,
            }
            .bind()
        };
        let (a, b) = (bind(None).await.unwrap(), bind(Some(2)).await.unwrap());
        for (mine, ok) in [([8; 32], true), ([9; 32], false)] {
            let (b2, at) = (b.clone(), b.addr());
            let srv = tokio::spawn(async move {
                let c = b2.accept().await.unwrap().await.unwrap();
                let (i, mut tx, mut rx) = psk::accept(&c, &[&[7; 32], &[8; 32]]).await?;
                assert_eq!(i, 1);
                tx.send(&rx.recv(64).await?).await?;
                tx.finish().await
            });
            let c = a.connect(at, ALPN).await.unwrap();
            let got = async {
                let (mut tx, mut rx) = psk::dial(&c, &mine).await?;
                tx.send(b"pq").await?;
                rx.recv(64).await
            };
            assert_eq!(got.await.ok(), ok.then(|| b"pq".to_vec()));
            assert_eq!(srv.await.unwrap().is_ok(), ok);
            c.close(0u32.into(), b"");
        }
    }
}
