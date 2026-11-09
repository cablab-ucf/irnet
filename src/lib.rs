//! One iroh endpoint for every cab-ucf app.

#![forbid(unsafe_code)]

#[cfg(not(any(feature = "aws-lc", feature = "pure")))]
compile_error!("irnet needs a TLS backend: feature `aws-lc` (native) or `pure` (wasm)");

#[cfg(feature = "pure")]
pub mod pq;
pub mod psk;

use iroh::endpoint::{AfterHandshakeOutcome, Builder, Connection, Endpoint, EndpointHooks};
use iroh::endpoint::{QuicTransportConfig, presets};
use iroh::{RelayMode, RelayUrl, TransportAddr, Watcher};
use n0_future::time::{Duration, Instant, timeout};
use rustls::crypto::CryptoProvider;
use std::sync::Arc;
use tracing::{info, warn};

/// The lab's relays: the only ones while any answers.
pub const RELAYS: [&str; 1] = ["https://iroh.cxn.center./"];

/// n0's relay: joined by [`fallback`] only while none of [`RELAYS`] answers.
pub const FALLBACK: &str = "https://use1-1.relay.n0.iroh.link./";

/// How long the lab's relays may all fail before [`fallback`] joins n0's,
/// and how long it stays there before trying the lab's alone again.
const GRACE: Duration = Duration::from_secs(10);
const RETRY: Duration = Duration::from_secs(600);

pub fn relays() -> Vec<RelayUrl> {
    RELAYS.map(|r| r.parse().expect("static relay url")).into()
}

fn n0(u: &RelayUrl) -> bool {
    u.host_str().is_some_and(|h| h.trim_end_matches('.').ends_with(".n0.iroh.link"))
}

/// Warns of each connection with a path through any of n0's relays at its handshake.
#[derive(Debug)]
struct N0;

impl EndpointHooks for N0 {
    async fn after_handshake(&self, c: &Connection) -> AfterHandshakeOutcome {
        if c.paths().iter().any(|p| matches!(p.remote_addr(), TransportAddr::Relay(u) if n0(u))) {
            warn!(peer = %c.remote_id(), "connection relayed through n0's servers");
        }
        AfterHandshakeOutcome::accept()
    }
}

/// Keeps `ep` on the lab's relays until it closes; spawn it beside `ep`.
/// Joins n0's relay, with a warning, only once none of the lab's has
/// answered for 10 s; leaves it once one does, or after 10 min to try the
/// lab's alone (a 10 s gap while they stay down).
pub async fn fallback(ep: Endpoint) {
    fall_back(ep, FALLBACK.parse().expect("static relay url"), GRACE).await
}

async fn fall_back(ep: Endpoint, url: RelayUrl, grace: Duration) {
    let mut w = ep.home_relay_status();
    let (mut on, mut until) = (false, Instant::now() + grace);
    ep.closed()
        .run_until(async {
            loop {
                if w.get().iter().any(|s| s.is_connected() && *s.url() != url) {
                    if on && ep.remove_relay(&url).await.is_some() {
                        info!("a lab relay answers: left {url}");
                    }
                    on = false;
                    if w.updated().await.is_err() {
                        return;
                    }
                    until = Instant::now() + grace;
                } else if let Ok(r) =
                    timeout(until.saturating_duration_since(Instant::now()), w.updated()).await
                {
                    if r.is_err() {
                        return;
                    }
                } else if on {
                    ep.remove_relay(&url).await;
                    (on, until) = (false, Instant::now() + grace);
                } else {
                    warn!("no lab relay answered for {grace:?}: relaying through {url}");
                    ep.insert_relay(url.clone(), Arc::new(url.clone().into())).await;
                    (on, until) = (true, Instant::now() + RETRY);
                }
            }
        })
        .await;
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

/// The lab's relays (see [`fallback`]), no third-party lookup, no
/// captive-portal probes; warns of each connection through n0's relays.
pub fn endpoint() -> Builder {
    let b = Endpoint::builder(presets::Empty)
        .crypto_provider(tls())
        .transport_config(transport())
        .relay_mode(RelayMode::custom(relays()))
        .hooks(N0);
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
    use iroh::SecretKey;

    #[test]
    fn handshakes_are_post_quantum() {
        assert_eq!(tls().kx_groups[0].name(), rustls::NamedGroup::X25519MLKEM768);
        assert_eq!(relays().len(), RELAYS.len());
        assert!(n0(&FALLBACK.parse().unwrap()) && !relays().iter().any(n0));
    }

    /// The fallback joins only after the lab's relays fail for its grace.
    #[tokio::test(flavor = "multi_thread")]
    async fn falls_back_only_after_grace() {
        let lab: RelayUrl = "https://lab.invalid./".parse().unwrap();
        let ep = endpoint().relay_mode(RelayMode::custom([lab])).bind().await.unwrap();
        let url: RelayUrl = "https://fallback.invalid./".parse().unwrap();
        tokio::spawn(fall_back(ep.clone(), url.clone(), Duration::from_millis(300)));
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(ep.remove_relay(&url).await.is_none());
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert!(ep.remove_relay(&url).await.is_some());
        ep.close().await;
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
                rx.end().await?;
                tx.finish().await
            });
            let c = a.connect(at, ALPN).await.unwrap();
            let got = async {
                let (mut tx, mut rx) = psk::dial(&c, &mine).await?;
                tx.send(b"pq").await?;
                tx.finish().await?;
                let m = rx.recv(64).await?;
                rx.end().await.map(|_| m)
            };
            assert_eq!(got.await.ok(), ok.then(|| b"pq".to_vec()));
            assert_eq!(srv.await.unwrap().is_ok(), ok);
            c.close(0u32.into(), b"");
        }
    }

    /// A peer that echoes the dialer's stream, holding no key, fails its
    /// proof; a stream cut short of its sealed end fails `end`.
    #[tokio::test(flavor = "multi_thread")]
    async fn psk_refuses_reflection_and_cuts() {
        const ALPN: &[u8] = b"irnet/psk";
        let bind = || endpoint().alpns(vec![ALPN.to_vec()]).relay_mode(RelayMode::Disabled).bind();
        let (a, b) = (bind().await.unwrap(), bind().await.unwrap());
        let (b2, at) = (b.clone(), b.addr());
        let srv = tokio::spawn(async move {
            let c = b2.accept().await.unwrap().await.unwrap();
            let (mut tx, mut rx) = c.accept_bi().await.unwrap();
            let mut buf = [0; 4096];
            while let Ok(Some(n)) = rx.read(&mut buf).await {
                tx.write_all(&buf[..n]).await.unwrap();
            }
            let c = b2.accept().await.unwrap().await.unwrap();
            let (_, mut tx, _rx) = psk::accept(&c, &[&[8; 32]]).await.unwrap();
            tx.send(b"cut").await.unwrap();
            drop(tx); // a bare FIN, not the sealed end
            c.closed().await;
        });
        let c = a.connect(at.clone(), ALPN).await.unwrap();
        assert!(psk::dial(&c, &[8; 32]).await.is_err());
        c.close(0u32.into(), b"");
        let c = a.connect(at, ALPN).await.unwrap();
        let (_tx, mut rx) = psk::dial(&c, &[8; 32]).await.unwrap();
        assert_eq!(rx.recv(64).await.unwrap(), b"cut");
        assert!(rx.end().await.is_err());
        c.close(0u32.into(), b"");
        srv.await.unwrap();
    }
}
