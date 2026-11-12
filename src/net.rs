//! The endpoint: the lab's relays, transport, hooks.

use crate::tls;
use iroh::endpoint::{AfterHandshakeOutcome, BeforeConnectOutcome, Builder, Connection, Endpoint};
use iroh::endpoint::{EndpointHooks, PathEvent, QuicTransportConfig, RelayStatus, presets};
use iroh::{EndpointAddr, EndpointId, RelayMode, RelayUrl, TransportAddr, Watcher};
use n0_future::time::{Duration, Instant, timeout};
use n0_future::{FutureExt, StreamExt};
use noq_proto::crypto::rustls::HandshakeData;
use rustls::NamedGroup;
use std::sync::Arc;
use tracing::{info, warn};

/// The lab's relays, best first: pushir's (X25519MLKEM768, a ping hours
/// apart), where an endpoint homes; then a stock one (X25519 only), joined
/// by [`fallback`] while the first does not answer.
pub const RELAYS: [&str; 2] = ["https://irpush.cxn.center./", "https://iroh.cxn.center./"];

/// n0's relay: joined by [`fallback`] only while none of [`RELAYS`] answers.
pub const FALLBACK: &str = "https://use1-1.relay.n0.iroh.link./";

/// How long the relays an endpoint has may all fail before [`fallback`]
/// joins the next, and how long it stays there if it cannot probe the
/// better ones.
const GRACE: Duration = Duration::from_secs(10);
const RETRY: Duration = Duration::from_secs(600);
const DAY: Duration = Duration::from_secs(86400);

pub fn relays() -> Vec<RelayUrl> {
    RELAYS.map(|r| r.parse().expect("static relay url")).into()
}

fn origin(u: &RelayUrl) -> (&str, Option<&str>, Option<u16>) {
    (u.scheme(), u.host_str().map(|h| h.trim_end_matches('.')), u.port_or_known_default())
}

/// Whether `u` is one of [`RELAYS`] (scheme, host, port), trailing dot or not.
fn lab(u: &RelayUrl) -> bool {
    relays().iter().any(|r| origin(r) == origin(u))
}

fn foreign(peer: EndpointId, a: &TransportAddr) {
    if let TransportAddr::Relay(u) = a
        && !lab(u)
    {
        warn!(%peer, relay = %u, "path through a relay not the lab's");
    }
}

/// The key exchange `c`'s handshake settled on.
fn kx(c: &Connection) -> Option<NamedGroup> {
    c.handshake_data()?.downcast::<HandshakeData>().ok()?.negotiated_key_exchange_group
}

/// Warns of each relay not the lab's (n0's included): those a dialed address
/// names, before any is contacted; those a connection's paths cross at its
/// handshake, and any it opens until it closes. Refuses a handshake that is
/// not post-quantum: a peer without X25519MLKEM768.
#[derive(Debug)]
struct Foreign;

impl EndpointHooks for Foreign {
    async fn before_connect(&self, to: &EndpointAddr, _: &[u8]) -> BeforeConnectOutcome {
        for u in to.relay_urls().filter(|u| !lab(u)) {
            warn!(peer = %to.id, relay = %u, "dialing through a relay not the lab's");
        }
        BeforeConnectOutcome::Accept
    }

    async fn after_handshake(&self, c: &Connection) -> AfterHandshakeOutcome {
        let (peer, mut opened) = (c.remote_id(), c.path_events());
        let kx = kx(c);
        if kx != Some(NamedGroup::X25519MLKEM768) {
            warn!(%peer, ?kx, "handshake not post-quantum: refused");
            return AfterHandshakeOutcome::Reject {
                error_code: 0u32.into(),
                reason: b"handshake not post-quantum".to_vec(),
            };
        }
        c.paths().iter().for_each(|p| foreign(peer, p.remote_addr()));
        // The event stream holds no handle, so the connection still closes on drop.
        n0_future::task::spawn(async move {
            while let Some(e) = opened.next().await {
                if let PathEvent::Opened { remote_addr, .. } = e {
                    foreign(peer, &remote_addr);
                }
            }
        });
        AfterHandshakeOutcome::accept()
    }
}

/// Keeps `ep` on the best relay that answers; spawn it beside `ep`. An
/// endpoint homes on the first of [`RELAYS`] alone. Once that has not
/// answered for 10 s the next joins (the lab's stock relay, then n0's, each
/// with a warning), and as soon as a better one answers again the rest
/// leave: a second endpoint on the better ones alone tells when (`ep`
/// itself would stay where it is unless another were a third faster). It
/// holds a clone of `ep`, so both run until `ep.close()`: dropping the
/// app's handles ends neither.
pub async fn fallback(ep: Endpoint) {
    let mut order = relays();
    order.push(FALLBACK.parse().expect("static relay url"));
    fall_back(ep, on, order, GRACE).await
}

/// The first of `set` that `s` says is connected.
fn at(s: &[RelayStatus], set: &[RelayUrl]) -> Option<usize> {
    set.iter().position(|u| s.iter().any(|s| s.is_connected() && s.url() == u))
}

async fn fall_back(
    ep: Endpoint,
    probe: fn(&[RelayUrl]) -> Builder,
    order: Vec<RelayUrl>,
    grace: Duration,
) {
    let mut w = ep.home_relay_status();
    // `ep` has `order[..=k]`.
    let mut k = 0;
    ep.closed()
        .run_until(async {
            loop {
                // The better relays, watched while we are not on the best.
                let better = match k {
                    0 => None,
                    _ => probe(&order[..k]).bind().await.ok(),
                };
                let mut p = better.as_ref().map(|b| b.home_relay_status());
                let mut until = Instant::now() + grace;
                let to = loop {
                    // A better one answers `ep` itself, or the probe.
                    let ours = at(&w.get(), &order[..k]);
                    let seen = p.as_mut().and_then(|p| at(&p.get(), &order[..k]));
                    if let Some(j) = ours.into_iter().chain(seen).min() {
                        break j;
                    }
                    let up = at(&w.get(), &order[..=k]).is_some();
                    if up {
                        until = Instant::now() + grace;
                    }
                    let left = until.saturating_duration_since(Instant::now());
                    let last = k + 1 == order.len();
                    if !up && !last && left.is_zero() {
                        break k + 1;
                    }
                    // No probe: after a while, the best alone, blind.
                    let blind = k > 0 && p.is_none();
                    let wait = match (up || last, blind) {
                        (true, true) => RETRY,
                        (true, false) => DAY,
                        _ => left,
                    };
                    let changed = async {
                        match p.as_mut() {
                            Some(p) => w.updated().or(p.updated()).await.is_ok(),
                            None => w.updated().await.is_ok(),
                        }
                    };
                    match timeout(wait, changed).await {
                        Ok(false) => return,
                        Err(_) if blind && (up || last) => break 0,
                        _ => {}
                    }
                };
                if let Some(b) = better {
                    b.close().await;
                }
                for u in order.iter().take(to + 1).skip(k + 1) {
                    warn!("no better relay answered for {grace:?}: relaying through {u}");
                    ep.insert_relay(u.clone(), Arc::new(u.clone().into())).await;
                }
                for u in order.iter().take(k + 1).skip(to + 1) {
                    if ep.remove_relay(u).await.is_some() {
                        info!("a better relay answers: left {u}");
                    }
                }
                k = to;
            }
        })
        .await;
}

/// What one stream may hold in flight: noq drops a connection whose stream
/// buffers over 1024 gaps, which 2 MiB of full packets cannot reach however
/// they are lost. A stream so carries 2 MiB per round trip (160 Mbit/s at
/// 100 ms): spread a large transfer over many.
const STREAM: u32 = 2 << 20;

/// What a connection may hold in flight each way once its peer is known
/// ([`wide`]), over all its streams: 64 MiB per round trip is 5 Gbit/s at
/// 100 ms and 50 Gbit/s at 10 ms, more than the one core a connection has
/// seals. Past that, open several connections.
pub const WINDOW: u32 = 64 << 20;

/// What a stranger may make us hold: [`wide`] lifts it to [`WINDOW`].
const NARROW: u32 = 8 << 20;

/// [`WINDOW`] to send, [`NARROW`] to receive until [`wide`]; BBRv3 for lossy
/// paths (noq calls it experimental; its other controllers, Cubic and
/// NewReno, take loss for congestion).
pub fn transport() -> QuicTransportConfig {
    let q = QuicTransportConfig::builder()
        .stream_receive_window(STREAM.into())
        .receive_window(NARROW.into())
        .send_window(WINDOW.into())
        .congestion_controller_factory(Arc::new(noq_proto::congestion::Bbr3Config::default()));
    // iroh #4647
    #[cfg(target_os = "android")]
    let q = q.enable_segmentation_offload(false);
    q.build()
}

/// Lets `c`'s peer fill [`WINDOW`], not the 8 MiB a stranger gets: for a
/// peer the app knows ([`psk::prove`] and [`psk::admit`] do it themselves).
pub fn wide(c: &Connection) {
    c.set_receive_window(WINDOW.into());
}

/// The lab's first relay (the next ones by [`fallback`]), no third-party
/// lookup, no captive-portal probes; warns of each relay not the lab's, dialed or on a
/// path, and refuses each handshake not post-quantum.
pub fn endpoint() -> Builder {
    on(&[])
}

/// [`endpoint`], homed on `relays` in place of the lab's first (none: the
/// lab's first): a deployment's own. Relays on this machine are met without the
/// environment's proxy.
pub fn on(relays: &[RelayUrl]) -> Builder {
    let relays = if relays.is_empty() { self::relays()[..1].to_vec() } else { relays.to_vec() };
    let local = |r: &RelayUrl| {
        let h = r.host_str().unwrap_or_default();
        h.starts_with("127.") || h == "localhost" || h == "[::1]"
    };
    let proxied = !relays.iter().any(local);
    let b = Endpoint::builder(presets::Empty)
        .crypto_provider(tls())
        .transport_config(transport())
        .relay_mode(RelayMode::custom(relays))
        .hooks(Foreign);
    #[cfg(not(target_arch = "wasm32"))]
    let b = {
        let mut probes = iroh::endpoint::NetReportConfig::default();
        probes.captive_portal_check = false;
        b.net_report_config(probes)
    };
    #[cfg(not(any(target_os = "android", target_arch = "wasm32")))]
    let b = b.ca_tls_config(iroh::tls::CaTlsConfig::system());
    #[cfg(not(any(target_os = "android", target_arch = "wasm32")))]
    let b = if proxied { b.proxy_from_env() } else { b };
    #[cfg(any(target_os = "android", target_arch = "wasm32"))]
    let _ = proxied;
    b
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{pq, psk};
    use iroh::SecretKey;
    use rustls::crypto::CryptoProvider;

    #[test]
    fn handshakes_are_post_quantum() {
        assert_eq!(tls().kx_groups[0].name(), NamedGroup::X25519MLKEM768);
        assert_eq!(pq().kx_groups.len(), 1);
        assert_eq!(pq().kx_groups[0].name(), NamedGroup::X25519MLKEM768);
        assert_eq!(relays().len(), RELAYS.len());
        assert!(RELAYS[0].contains("irpush"), "the post-quantum relay first");
        assert!(relays().iter().all(lab) && lab(&"https://iroh.cxn.center/".parse().unwrap()));
        assert!(!lab(&FALLBACK.parse().unwrap()));
        assert!(!lab(&"http://iroh.cxn.center/".parse().unwrap()));
        assert!(!lab(&"https://iroh.cxn.center:9/".parse().unwrap()));
    }

    /// Each next relay joins only after those before it fail for the grace:
    /// the lab's second, then n0's.
    #[tokio::test(flavor = "multi_thread")]
    async fn falls_back_only_after_grace() {
        let url = |h: &str| format!("https://{h}.invalid./").parse::<RelayUrl>().unwrap();
        let order = vec![url("first"), url("second"), url("last")];
        let ep = on(&order[..1]).bind().await.unwrap();
        tokio::spawn(fall_back(ep.clone(), on, order.clone(), Duration::from_millis(400)));
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(ep.remove_relay(&order[1]).await.is_none());
        tokio::time::sleep(Duration::from_millis(500)).await;
        let add = |u: &RelayUrl| ep.insert_relay(u.clone(), Arc::new(u.clone().into()));
        assert!(add(&order[1]).await.is_some(), "the second joined");
        assert!(ep.remove_relay(&order[2]).await.is_none(), "the last, not yet");
        tokio::time::sleep(Duration::from_millis(1500)).await;
        assert!(ep.remove_relay(&order[2]).await.is_some(), "then the last");
        ep.close().await;
    }

    /// The later relays leave as soon as a better one answers again.
    #[tokio::test(flavor = "multi_thread")]
    async fn leaves_the_fallback_when_the_lab_returns() {
        use iroh_relay::server::{RelayConfig, Server, ServerConfig};
        let serve = |at: std::net::SocketAddr| async move {
            let mut cfg = ServerConfig::default();
            cfg.relay = Some(RelayConfig::new(at));
            Server::spawn(cfg).await.unwrap()
        };
        // A lab relay that is down, to come back at the same address.
        let s = serve(([127, 0, 0, 1], 0).into()).await;
        let at = s.http_addr().unwrap();
        s.shutdown().await.unwrap();
        // No proxy from the environment: the lab relay here is on localhost.
        fn lab(r: &[RelayUrl]) -> Builder {
            let lab = RelayMode::custom(r.to_vec());
            Endpoint::builder(presets::Empty).crypto_provider(tls()).relay_mode(lab)
        }
        let url: RelayUrl = "https://fallback.invalid./".parse().unwrap();
        let order = vec![format!("http://{at}/").parse().unwrap(), url.clone()];
        let ep = lab(&order[..1]).bind().await.unwrap();
        tokio::spawn(fall_back(ep.clone(), lab, order, Duration::from_millis(300)));
        tokio::time::sleep(Duration::from_millis(800)).await;
        assert!(ep.insert_relay(url.clone(), Arc::new(url.clone().into())).await.is_some());
        let _s = serve(at).await;
        let mut w = ep.home_relay_status();
        let home = async {
            while !w.get().iter().any(|s| s.is_connected()) {
                w.updated().await.unwrap();
            }
        };
        tokio::time::timeout(Duration::from_secs(60), home).await.unwrap();
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert!(ep.remove_relay(&url).await.is_none());
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
        assert_eq!(kx(&c), Some(NamedGroup::X25519MLKEM768));
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
                anyhow::ensure!(rx.next(0).await?.is_none());
                drop(rx); // read to its sealed end: not a stop
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

    /// A peer that stops reading fails `send` in time, not never.
    #[tokio::test(flavor = "multi_thread")]
    async fn psk_send_fails_a_stalled_peer() {
        const ALPN: &[u8] = b"irnet/psk";
        let bind = || endpoint().alpns(vec![ALPN.to_vec()]).relay_mode(RelayMode::Disabled).bind();
        let (a, b) = (bind().await.unwrap(), bind().await.unwrap());
        let (b2, at) = (b.clone(), b.addr());
        let srv = tokio::spawn(async move {
            let c = b2.accept().await.unwrap().await.unwrap();
            let _held = psk::accept(&c, &[&[8; 32]]).await.unwrap();
            c.closed().await;
        });
        let c = a.connect(at, ALPN).await.unwrap();
        let (mut tx, _rx) = psk::dial(&c, &[8; 32]).await.unwrap();
        let sent = async {
            for _ in 0..8 {
                tx.send(&[0; 1 << 20]).await?;
            }
            anyhow::Ok(())
        };
        assert!(format!("{:#}", sent.await.unwrap_err()).contains("stalled"));
        c.close(0u32.into(), b"");
        srv.await.unwrap();
    }

    /// A peer whose handshake is not post-quantum is refused, whoever dials.
    #[tokio::test(flavor = "multi_thread")]
    async fn refuses_a_classical_handshake() {
        use rustls::crypto::aws_lc_rs::{default_provider, kx_group::X25519};
        const ALPN: &[u8] = b"irnet/test";
        let ours = || endpoint().alpns(vec![ALPN.to_vec()]).relay_mode(RelayMode::Disabled).bind();
        let classical = CryptoProvider { kx_groups: vec![X25519], ..default_provider() };
        let old = Endpoint::builder(presets::Empty)
            .crypto_provider(Arc::new(classical))
            .alpns(vec![ALPN.to_vec()])
            .relay_mode(RelayMode::Disabled)
            .bind();
        let (a, b, old) = (ours().await.unwrap(), ours().await.unwrap(), old.await.unwrap());
        for (from, to) in [(&old, &b), (&a, &old), (&a, &b)] {
            let (to2, at) = (to.clone(), to.addr());
            let srv = tokio::spawn(async move {
                let c = to2.accept().await?.await.ok()?;
                let mut rx = c.accept_uni().await.ok()?;
                rx.read_to_end(8).await.ok()
            });
            let sent = async {
                let c = from.connect(at, ALPN).await.ok()?;
                let mut tx = c.open_uni().await.ok()?;
                tx.write_all(b"pq").await.ok()?;
                tx.finish().ok()?;
                c.closed().await;
                Some(())
            };
            let _ = tokio::time::timeout(Duration::from_secs(5), sent).await;
            let got = tokio::time::timeout(Duration::from_secs(5), srv).await;
            let pq = from.id() != old.id() && to.id() != old.id();
            assert_eq!(got.ok().and_then(|g| g.unwrap()), pq.then(|| b"pq".to_vec()));
        }
    }

    /// A proved key opens the connection itself: raw streams, and the wide
    /// window a stranger does not get. Another key, or an echo, proves nothing.
    #[tokio::test(flavor = "multi_thread")]
    async fn psk_proof_opens_the_connection() {
        const ALPN: &[u8] = b"irnet/psk";
        let bind = || endpoint().alpns(vec![ALPN.to_vec()]).relay_mode(RelayMode::Disabled).bind();
        let (a, b) = (bind().await.unwrap(), bind().await.unwrap());
        // Whether 24 MiB fit streams nobody reads: past a stranger's 8 MiB.
        let fits = async |c: &Connection| {
            let all = async {
                for _ in 0..16 {
                    let mut tx = c.open_uni().await.unwrap();
                    tx.write_all(&[0; 3 << 19]).await.unwrap();
                    std::mem::forget(tx);
                }
            };
            tokio::time::timeout(Duration::from_secs(3), all).await.is_ok()
        };
        for (mine, admitted) in [(Some([8; 32]), true), (Some([9; 32]), false), (None, false)] {
            let (b2, at) = (b.clone(), b.addr());
            let srv = tokio::spawn(async move {
                let c = b2.accept().await.unwrap().await.unwrap();
                let i = match mine {
                    Some(_) => psk::admit(&c, &[&[7; 32], &[8; 32]]).await.ok(),
                    None => None,
                };
                let mut held = vec![];
                while let Ok(rx) = c.accept_uni().await {
                    held.push(rx);
                }
                i
            });
            let c = a.connect(at, ALPN).await.unwrap();
            let proved = match mine {
                Some(k) => psk::prove(&c, &k).await.is_ok(),
                None => false,
            };
            assert_eq!(proved, admitted);
            assert_eq!(fits(&c).await, admitted);
            c.close(0u32.into(), b"");
            assert_eq!(srv.await.unwrap(), admitted.then_some(1));
        }
        // An echo of the dialer's own proof is not the acceptor's.
        let (b2, at) = (b.clone(), b.addr());
        let srv = tokio::spawn(async move {
            let c = b2.accept().await.unwrap().await.unwrap();
            let (mut tx, mut rx) = c.accept_bi().await.unwrap();
            tx.write_all(&rx.read_to_end(64).await.unwrap()).await.unwrap();
            tx.finish().unwrap();
            c.closed().await;
        });
        let c = a.connect(at, ALPN).await.unwrap();
        assert!(psk::prove(&c, &[8; 32]).await.is_err());
        c.close(0u32.into(), b"");
        srv.await.unwrap();
    }

    /// How fast this machine moves bytes over loopback, raw over 32 streams
    /// after a proof and through the sealed channel: `cargo test --release
    /// speed -- --ignored --nocapture`.
    #[tokio::test(flavor = "multi_thread")]
    #[ignore]
    async fn speed() {
        const ALPN: &[u8] = b"irnet/speed";
        const STREAMS: usize = 32;
        const EACH: usize = 128 << 20;
        const SEALED: usize = 256 << 20;
        let bind = || endpoint().alpns(vec![ALPN.to_vec()]).relay_mode(RelayMode::Disabled).bind();
        let (a, b) = (bind().await.unwrap(), bind().await.unwrap());
        let at = b.addr();
        let srv = tokio::spawn(async move {
            let c = b.accept().await.unwrap().await.unwrap();
            psk::admit(&c, &[&[8; 32]]).await.unwrap();
            let mut all = n0_future::task::JoinSet::new();
            for _ in 0..STREAMS {
                let mut rx = c.accept_uni().await.unwrap();
                all.spawn(async move {
                    let (mut n, mut buf) = (0, vec![0; 1 << 20]);
                    while let Some(k) = rx.read(&mut buf).await.unwrap() {
                        n += k;
                    }
                    assert_eq!(n, EACH);
                });
            }
            all.join_all().await;
            let (_, _tx, mut rx) = psk::accept(&c, &[&[8; 32]]).await.unwrap();
            while rx.next(1 << 20).await.unwrap().is_some() {}
            c.closed().await;
        });
        let c = a.connect(at, ALPN).await.unwrap();
        psk::prove(&c, &[8; 32]).await.unwrap();
        let rate = |n: usize, t: std::time::Instant| n as f64 * 8e-9 / t.elapsed().as_secs_f64();
        let t = std::time::Instant::now();
        let mut all = n0_future::task::JoinSet::new();
        for _ in 0..STREAMS {
            let mut tx = c.open_uni().await.unwrap();
            all.spawn(async move {
                let buf = vec![0; 1 << 20];
                for _ in 0..EACH >> 20 {
                    tx.write_all(&buf).await.unwrap();
                }
                tx.finish().unwrap();
                tx.stopped().await.unwrap();
            });
        }
        all.join_all().await;
        println!("{STREAMS} raw streams: {:.2} Gbit/s", rate(STREAMS * EACH, t));
        let (t, buf) = (std::time::Instant::now(), vec![0; 1 << 20]);
        let (mut tx, _rx) = psk::dial(&c, &[8; 32]).await.unwrap();
        for _ in 0..SEALED >> 20 {
            tx.send(&buf).await.unwrap();
        }
        tx.finish().await.unwrap();
        println!("sealed channel: {:.2} Gbit/s", rate(SEALED, t));
        c.close(0u32.into(), b"");
        srv.await.unwrap();
    }
}
