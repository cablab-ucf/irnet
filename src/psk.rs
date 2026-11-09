//! A channel for holders of a pre-shared key, inside the TLS session:
//! HPKE (RFC 9180) PSK mode over X-Wing, a fresh key per side and a key per
//! direction, bound to the TLS session. Each side proves the key, the dialer
//! first; the end of the stream is sealed too.
//!
//! The key is depth, not the main lock. 32 random bytes hold if TLS falls.
//! A key stretched from a typed code only deters: HPKE's PSK mode is no
//! PAKE, so the peer this dials, or one who has broken TLS, can test codes
//! offline against the dialer's proof.

use anyhow::{Context, Result, anyhow, ensure};
use hpke::aead::{AeadCtxR, AeadCtxS, ChaCha20Poly1305 as A};
use hpke::{Deserializable, Kem, OpModeR, OpModeS, PskBundle, Serializable};
use hpke::{kdf::HkdfSha256 as K, kem::XWing};
use iroh::endpoint::{Connection, RecvStream, SendStream};
use n0_future::time::{Duration, timeout};

type Pk = <XWing as Kem>::PublicKey;
type Sk = <XWing as Kem>::PrivateKey;
type Enc = <XWing as Kem>::EncappedKey;

pub struct Tx(SendStream, AeadCtxS<A, K, XWing>);
pub struct Rx(RecvStream, AeadCtxR<A, K, XWing>);

const HELLO: &[u8] = b"irnet psk 2";
/// The sealed end's associated data, which no other frame carries.
const END: &[u8] = b"end";
/// The longest a handshake waits on one message.
const WAIT: Duration = Duration::from_secs(10);

async fn frame(r: &mut RecvStream, max: usize) -> Result<Vec<u8>> {
    let mut n = [0; 4];
    r.read_exact(&mut n).await?;
    let n = u32::from_be_bytes(n) as usize;
    ensure!(n <= max.saturating_add(16), "frame over {max} bytes");
    let mut b = vec![0; n];
    r.read_exact(&mut b).await?;
    Ok(b)
}

/// A handshake frame: a peer that stalls is dropped, not waited on.
async fn hs(r: &mut RecvStream, max: usize) -> Result<Vec<u8>> {
    timeout(WAIT, frame(r, max)).await.context("peer stalled")?
}

async fn put(s: &mut SendStream, b: &[u8]) -> Result<()> {
    s.write_all(&u32::try_from(b.len())?.to_be_bytes()).await?;
    Ok(s.write_all(b).await?)
}

fn mode(psk: &[u8; 32]) -> PskBundle<'_> {
    PskBundle::new(psk, b"irnet").expect("psk and id both set")
}

fn sender(psk: &[u8; 32], pk: &Pk, info: &[u8]) -> Result<(Enc, AeadCtxS<A, K, XWing>)> {
    hpke::setup_sender(&OpModeS::Psk(mode(psk)), pk, info).map_err(|e| anyhow!("{e}"))
}

fn receiver(psk: &[u8; 32], sk: &Sk, enc: &Enc, info: &[u8]) -> Option<AeadCtxR<A, K, XWing>> {
    hpke::setup_receiver(&OpModeR::Psk(mode(psk)), sk, enc, info).ok()
}

fn proves(rx: &mut AeadCtxR<A, K, XWing>, hello: &[u8]) -> bool {
    rx.open(hello, b"").is_ok_and(|m| m == HELLO)
}

/// Streams, keys, and the exporter halved per direction as [mine, theirs]:
/// a stream reflected back opens under neither.
async fn start(
    c: &Connection,
    dial: bool,
) -> Result<(SendStream, RecvStream, Sk, Pk, [[u8; 32]; 2])> {
    let (mut s, mut r) = if dial { c.open_bi().await? } else { c.accept_bi().await? };
    let mut tls = [[0; 32]; 2];
    c.export_keying_material(tls.as_flattened_mut(), b"EXPORTER-irnet-psk", b"")
        .map_err(|e| anyhow!("tls exporter: {e:?}"))?;
    if !dial {
        tls.swap(0, 1);
    }
    let (sk, pk) = XWing::gen_keypair();
    put(&mut s, &pk.to_bytes()).await?;
    let theirs = Pk::from_bytes(&hs(&mut r, 1216).await?).ok().context("bad key")?;
    Ok((s, r, sk, theirs, tls))
}

async fn enc(r: &mut RecvStream) -> Result<Enc> {
    Enc::from_bytes(&hs(r, 1120).await?).ok().context("bad key")
}

/// The dialer's end of the channel for `psk`, once the acceptor proves it.
pub async fn dial(c: &Connection, psk: &[u8; 32]) -> Result<(Tx, Rx)> {
    let (mut s, mut r, sk, pk, [mine, theirs]) = start(c, true).await?;
    let (e, tx) = sender(psk, &pk, &mine)?;
    put(&mut s, &e.to_bytes()).await?;
    let mut tx = Tx(s, tx);
    tx.send(HELLO).await?;
    let mut rx = receiver(psk, &sk, &enc(&mut r).await?, &theirs).context("bad key")?;
    ensure!(proves(&mut rx, &hs(&mut r, HELLO.len()).await?), "peer holds not our pre-shared key");
    Ok((tx, Rx(r, rx)))
}

/// The acceptor's end, for whichever of `psks` the dialer proves: its index.
pub async fn accept(c: &Connection, psks: &[&[u8; 32]]) -> Result<(usize, Tx, Rx)> {
    let (mut s, mut r, sk, pk, [mine, theirs]) = start(c, false).await?;
    let e = enc(&mut r).await?;
    let hello = hs(&mut r, HELLO.len()).await?;
    let (i, rx) = (psks.iter().enumerate())
        .find_map(|(i, p)| {
            let mut rx = receiver(p, &sk, &e, &theirs)?;
            proves(&mut rx, &hello).then_some((i, rx))
        })
        .context("peer holds no pre-shared key of ours")?;
    let (e, tx) = sender(psks[i], &pk, &mine)?;
    put(&mut s, &e.to_bytes()).await?;
    let mut tx = Tx(s, tx);
    tx.send(HELLO).await?;
    Ok((i, tx, Rx(r, rx)))
}

impl Tx {
    async fn seal(&mut self, m: &[u8], aad: &[u8]) -> Result<()> {
        let b = self.1.seal(m, aad).map_err(|e| anyhow!("{e}"))?;
        put(&mut self.0, &b).await
    }

    pub async fn send(&mut self, m: &[u8]) -> Result<()> {
        self.seal(m, b"").await
    }

    /// Seal the end and finish the stream; waits for the peer's acks or the
    /// connection's close. `Ok` is not delivery (only the peer's reply is),
    /// but a peer that stops reading is an error.
    pub async fn finish(mut self) -> Result<()> {
        self.seal(b"", END).await?;
        self.0.finish()?;
        ensure!(!matches!(self.0.stopped().await, Ok(Some(_))), "peer stopped reading");
        Ok(())
    }
}

impl Rx {
    /// The next frame, at most `max` bytes, or `None` at the peer's sealed end.
    pub async fn next(&mut self, max: usize) -> Result<Option<Vec<u8>>> {
        let b = frame(&mut self.0, max).await?;
        if let Ok(m) = self.1.open(&b, b"") {
            return Ok(Some(m));
        }
        self.1.open(&b, END).ok().context("frame fails its pre-shared key")?;
        Ok(None)
    }

    /// The next frame, at most `max` bytes.
    pub async fn recv(&mut self, max: usize) -> Result<Vec<u8>> {
        self.next(max).await?.context("peer ended the stream")
    }

    /// Read to the peer's sealed end: a stream cut short is an error.
    pub async fn end(mut self) -> Result<()> {
        ensure!(self.next(0).await?.is_none(), "frame past the end");
        self.0.read_to_end(0).await?;
        Ok(())
    }
}
