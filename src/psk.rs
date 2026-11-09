//! A channel for holders of a pre-shared key, inside the TLS session:
//! HPKE (RFC 9180) PSK mode over X-Wing, a fresh key per side. Holds if
//! TLS falls or one side's RNG is rigged. The dialer proves first.

use anyhow::{Context, Result, anyhow, ensure};
use hpke::aead::{AeadCtxR, AeadCtxS, ChaCha20Poly1305 as A};
use hpke::{Deserializable, Kem, OpModeR, OpModeS, PskBundle, Serializable};
use hpke::{kdf::HkdfSha256 as K, kem::XWing};
use iroh::endpoint::{Connection, RecvStream, SendStream};

type Pk = <XWing as Kem>::PublicKey;
type Sk = <XWing as Kem>::PrivateKey;
type Enc = <XWing as Kem>::EncappedKey;

pub struct Tx(SendStream, AeadCtxS<A, K, XWing>);
pub struct Rx(RecvStream, AeadCtxR<A, K, XWing>);

const HELLO: &[u8] = b"irnet psk 1";

async fn frame(r: &mut RecvStream, max: usize) -> Result<Vec<u8>> {
    let mut n = [0; 4];
    r.read_exact(&mut n).await?;
    let n = u32::from_be_bytes(n) as usize;
    ensure!(n <= max + 16, "frame over {max} bytes");
    let mut b = vec![0; n];
    r.read_exact(&mut b).await?;
    Ok(b)
}

async fn put(s: &mut SendStream, b: &[u8]) -> Result<()> {
    s.write_all(&(b.len() as u32).to_be_bytes()).await?;
    Ok(s.write_all(b).await?)
}

fn mode(psk: &[u8]) -> Result<PskBundle<'_>> {
    PskBundle::new(psk, b"irnet").map_err(|e| anyhow!("{e}"))
}

fn sender(psk: &[u8], pk: &Pk, tls: &[u8]) -> Result<(Enc, AeadCtxS<A, K, XWing>)> {
    hpke::setup_sender(&OpModeS::Psk(mode(psk)?), pk, tls).map_err(|e| anyhow!("{e}"))
}

fn receiver(psk: &[u8], sk: &Sk, enc: &Enc, tls: &[u8]) -> Option<AeadCtxR<A, K, XWing>> {
    hpke::setup_receiver(&OpModeR::Psk(mode(psk).ok()?), sk, enc, tls).ok()
}

async fn start(c: &Connection, dial: bool) -> Result<(SendStream, RecvStream, Sk, Pk, [u8; 32])> {
    let (mut s, mut r) = if dial { c.open_bi().await? } else { c.accept_bi().await? };
    let mut tls = [0; 32];
    c.export_keying_material(&mut tls, b"EXPORTER-irnet-psk", b"")
        .map_err(|e| anyhow!("tls exporter: {e:?}"))?;
    let (sk, pk) = XWing::gen_keypair();
    put(&mut s, &pk.to_bytes()).await?;
    let theirs = Pk::from_bytes(&frame(&mut r, 1216).await?).ok().context("bad key")?;
    Ok((s, r, sk, theirs, tls))
}

async fn enc(r: &mut RecvStream) -> Result<Enc> {
    Enc::from_bytes(&frame(r, 1120).await?).ok().context("bad key")
}

/// The dialer's end of the channel for `psk` (32 bytes or more).
pub async fn dial(c: &Connection, psk: &[u8]) -> Result<(Tx, Rx)> {
    let (mut s, mut r, sk, pk, tls) = start(c, true).await?;
    let (e, tx) = sender(psk, &pk, &tls)?;
    put(&mut s, &e.to_bytes()).await?;
    let mut tx = Tx(s, tx);
    tx.send(HELLO).await?;
    let rx = receiver(psk, &sk, &enc(&mut r).await?, &tls).context("bad key")?;
    Ok((tx, Rx(r, rx)))
}

/// The acceptor's end, for whichever of `psks` the dialer holds: its index.
pub async fn accept(c: &Connection, psks: &[&[u8]]) -> Result<(usize, Tx, Rx)> {
    let (mut s, mut r, sk, pk, tls) = start(c, false).await?;
    let e = enc(&mut r).await?;
    let hello = frame(&mut r, HELLO.len()).await?;
    let (i, rx) = (psks.iter().enumerate())
        .find_map(|(i, p)| {
            let mut rx = receiver(p, &sk, &e, &tls)?;
            (rx.open(&hello, b"").ok()? == HELLO).then_some((i, rx))
        })
        .context("peer holds no pre-shared key of ours")?;
    let (e, tx) = sender(psks[i], &pk, &tls)?;
    put(&mut s, &e.to_bytes()).await?;
    Ok((i, Tx(s, tx), Rx(r, rx)))
}

impl Tx {
    pub async fn send(&mut self, m: &[u8]) -> Result<()> {
        let b = self.1.seal(m, b"").map_err(|e| anyhow!("{e}"))?;
        put(&mut self.0, &b).await
    }

    /// End the stream, once the peer has read all of it.
    pub async fn finish(mut self) -> Result<()> {
        self.0.finish()?;
        let _ = self.0.stopped().await;
        Ok(())
    }
}

impl Rx {
    /// The next frame, at most `max` bytes.
    pub async fn recv(&mut self, max: usize) -> Result<Vec<u8>> {
        let b = frame(&mut self.0, max).await?;
        self.1.open(&b, b"").ok().context("frame fails its pre-shared key")
    }

    /// Read to the peer's end, which releases its [`Tx::finish`].
    pub async fn end(mut self) -> Result<()> {
        self.0.read_to_end(0).await?;
        Ok(())
    }
}
