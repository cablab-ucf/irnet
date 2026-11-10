//! Proof of a pre-shared key, bound to the TLS session; and, for small
//! secrets, a sealed channel under it.
//!
//! [`prove`] and [`admit`]: each side shows HMAC-SHA256 of the session's TLS
//! exporter under the key, the dialer first: 64 bytes and no key exchange,
//! so a stranger costs the acceptor one hash per key. The connection is
//! then the peer's: its streams are used as they are, at QUIC's full speed
//! and with [`crate::wide`] windows. Its secrecy is TLS's (X25519MLKEM768).
//!
//! [`dial`] and [`accept`]: the same proof, then HPKE (RFC 9180) PSK mode
//! over X-Wing to the dialer's fresh key and a key per direction from its
//! exporter (ChaCha20-Poly1305); the end of the stream is sealed too. With
//! 32 random bytes it holds if TLS falls. One stream and a copy per frame:
//! for secrets, not bulk.
//!
//! A key stretched from a typed code only deters: this is no PAKE, so the
//! peer this dials, or one who has broken TLS, can test codes offline
//! against the dialer's proof.

use anyhow::{Context, Result, anyhow, ensure};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use hmac::{Hmac, Mac};
use hpke::aead::ExportOnlyAead as E;
use hpke::{Deserializable, Kem, OpModeR, OpModeS, PskBundle, Serializable};
use hpke::{kdf::HkdfSha256 as K, kem::XWing};
use iroh::endpoint::{Connection, RecvStream, SendStream};
use n0_future::time::{Duration, timeout};
use sha2::Sha256;

type Pk = <XWing as Kem>::PublicKey;
type Enc = <XWing as Kem>::EncappedKey;

/// One direction's key and frame count (its nonce).
struct Half(ChaCha20Poly1305, u64);

/// The sending half. Not cancel-safe: a `send` dropped mid-frame (a losing
/// `select!` branch) breaks the stream, which the peer then fails; time out
/// a whole exchange instead. A write the peer takes none of for 10 s fails.
pub struct Tx(SendStream, Half);
/// The receiving half. Not cancel-safe, as [`Tx`]. Read it to `None` or
/// [`Rx::end`]: dropped sooner, it tells the peer's [`Tx::finish`] it stopped.
/// It waits out a silent peer, which may be an idle one: time out a reply.
pub struct Rx(RecvStream, Half);

const V: &[u8] = b"irnet psk 3";
/// The sealed end's associated data, which no other frame carries.
const END: &[u8] = b"end";
/// An X-Wing public key, its encapsulation, a proof.
const PK: usize = 1216;
const ENC: usize = 1120;
const TAG: usize = 32;
/// The longest a handshake may take, a write may make no progress, or the
/// stream's end may trail its sealed end, however the peer stalls them.
const WAIT: Duration = Duration::from_secs(if cfg!(test) { 2 } else { 10 });
/// The longest [`Tx::finish`] waits for the peer's acks of what is sent.
const DRAIN: Duration = Duration::from_secs(60);

async fn frame(r: &mut RecvStream, max: usize) -> Result<Vec<u8>> {
    let mut n = [0; 4];
    r.read_exact(&mut n).await?;
    let n = u32::from_be_bytes(n) as usize;
    ensure!(n <= max, "frame over {max} bytes");
    let mut b = vec![0; n];
    r.read_exact(&mut b).await?;
    Ok(b)
}

async fn put(s: &mut SendStream, b: &[u8]) -> Result<()> {
    let n = u32::try_from(b.len())?.to_be_bytes();
    for mut b in [&n[..], b] {
        while !b.is_empty() {
            b = &b[timeout(WAIT, s.write(b)).await.context("peer stalled")??..];
        }
    }
    Ok(())
}

fn mac(psk: &[u8; 32], parts: &[&[u8]]) -> Hmac<Sha256> {
    let mut m = <Hmac<Sha256> as KeyInit>::new_from_slice(psk).expect("any key length");
    parts.iter().for_each(|p| m.update(p));
    m
}

/// The stream, and what binds a proof to this TLS session: its exporter.
async fn start(c: &Connection, dial: bool) -> Result<(SendStream, RecvStream, [u8; 32])> {
    let (s, r) = if dial { c.open_bi().await? } else { c.accept_bi().await? };
    let mut tls = [0; 32];
    c.export_keying_material(&mut tls, b"EXPORTER-irnet-psk", b"")
        .map_err(|e| anyhow!("tls exporter: {e:?}"))?;
    Ok((s, r, tls))
}

/// HPKE's own key, apart from the one the proofs are made with.
fn sealing(psk: &[u8; 32]) -> [u8; 32] {
    mac(psk, &[V, b" seal"]).finalize().into_bytes().into()
}

/// The two directions' keys, as (the dialer's, the acceptor's).
fn halves(export: impl Fn(&[u8], &mut [u8]) -> Result<(), hpke::HpkeError>) -> Result<[Half; 2]> {
    let half = |label: &[u8]| -> Result<Half> {
        let mut k = [0; 32];
        export(label, &mut k).map_err(|e| anyhow!("{e}"))?;
        Ok(Half(ChaCha20Poly1305::new(&k.into()), 0))
    };
    Ok([half(b"dial")?, half(b"accept")?])
}

/// The dialer's part: its proof (and fresh key, to seal), then the
/// acceptor's proof over both (and its encapsulation).
async fn dialer(c: &Connection, psk: &[u8; 32], seal: bool) -> Result<Option<(Tx, Rx)>> {
    let (mut s, mut r, tls) = start(c, true).await?;
    let key = seal.then(XWing::gen_keypair);
    let pk = key.as_ref().map_or(vec![], |k| k.1.to_bytes().to_vec());
    let tag = mac(psk, &[V, b" dial", &tls, &pk]).finalize().into_bytes();
    put(&mut s, &[&pk[..], &tag].concat()).await?;
    if !seal {
        s.finish()?;
    }
    let m = frame(&mut r, ENC + TAG).await?;
    let (enc, tag) = m.split_at_checked(m.len().wrapping_sub(TAG)).context("short proof")?;
    mac(psk, &[V, b" accept", &tls, &pk, enc])
        .verify_slice(tag)
        .ok()
        .context("peer holds not our pre-shared key")?;
    let Some((sk, _)) = key else {
        ensure!(enc.is_empty(), "peer seals a channel we did not ask for");
        r.read_to_end(0).await?;
        return Ok(None);
    };
    let enc = Enc::from_bytes(enc).ok().context("bad key")?;
    let k = sealing(psk);
    let mode = OpModeR::Psk(PskBundle::new(&k, b"irnet").expect("psk and id both set"));
    let ctx =
        hpke::setup_receiver::<E, K, XWing>(&mode, &sk, &enc, &tls).ok().context("bad key")?;
    let [mine, theirs] = halves(|l, k| ctx.export(l, k))?;
    Ok(Some((Tx(s, mine), Rx(r, theirs))))
}

/// The acceptor's part, for whichever of `psks` the dialer proves.
async fn acceptor(
    c: &Connection,
    psks: &[&[u8; 32]],
    seal: bool,
) -> Result<(usize, Option<(Tx, Rx)>)> {
    let (mut s, mut r, tls) = start(c, false).await?;
    let m = frame(&mut r, PK + TAG).await?;
    ensure!(m.len() == TAG + if seal { PK } else { 0 }, "peer asks for another channel");
    let (pk, tag) = m.split_at(m.len() - TAG);
    let i = (psks.iter())
        .position(|p| mac(p, &[V, b" dial", &tls, pk]).verify_slice(tag).is_ok())
        .context("peer holds no pre-shared key of ours")?;
    let (enc, keys) = if seal {
        let pk = Pk::from_bytes(pk).ok().context("bad key")?;
        let k = sealing(psks[i]);
        let mode = OpModeS::Psk(PskBundle::new(&k, b"irnet").expect("psk and id both set"));
        let (enc, ctx) =
            hpke::setup_sender::<E, K, XWing>(&mode, &pk, &tls).map_err(|e| anyhow!("{e}"))?;
        (enc.to_bytes().to_vec(), Some(halves(|l, k| ctx.export(l, k))?))
    } else {
        (vec![], None)
    };
    let tag = mac(psks[i], &[V, b" accept", &tls, pk, &enc]).finalize().into_bytes();
    put(&mut s, &[&enc[..], &tag].concat()).await?;
    let Some([theirs, mine]) = keys else {
        s.finish()?;
        r.read_to_end(0).await?;
        return Ok((i, None));
    };
    Ok((i, Some((Tx(s, mine), Rx(r, theirs)))))
}

/// Prove `psk` to the peer and have it proved back: `c` is then a holder's,
/// to use as it is, with [`crate::wide`] windows. Opens a bi stream, which
/// [`admit`] takes as the next: open none before.
pub async fn prove(c: &Connection, psk: &[u8; 32]) -> Result<()> {
    timeout(WAIT, dialer(c, psk, false)).await.context("peer stalled")??;
    crate::wide(c);
    Ok(())
}

/// [`prove`]'s other end, for whichever of `psks` the dialer proves: its
/// index. Takes the next bi stream the peer opens: accept none before.
pub async fn admit(c: &Connection, psks: &[&[u8; 32]]) -> Result<usize> {
    let (i, _) = timeout(WAIT, acceptor(c, psks, false)).await.context("peer stalled")??;
    crate::wide(c);
    Ok(i)
}

/// The dialer's end of the sealed channel for `psk`, once the acceptor
/// proves it. Opens a bi stream, which [`accept`] takes as the next: open
/// none before.
pub async fn dial(c: &Connection, psk: &[u8; 32]) -> Result<(Tx, Rx)> {
    let ends = timeout(WAIT, dialer(c, psk, true)).await.context("peer stalled")??;
    ends.context("no channel")
}

/// The acceptor's end, for whichever of `psks` the dialer proves: its index.
/// Takes the next bi stream the peer opens: accept none before.
pub async fn accept(c: &Connection, psks: &[&[u8; 32]]) -> Result<(usize, Tx, Rx)> {
    let (i, ends) = timeout(WAIT, acceptor(c, psks, true)).await.context("peer stalled")??;
    let (tx, rx) = ends.context("no channel")?;
    Ok((i, tx, rx))
}

impl Half {
    fn nonce(&self) -> Nonce {
        let mut n = [0; 12];
        n[4..].copy_from_slice(&self.1.to_be_bytes());
        n.into()
    }

    fn seal(&mut self, msg: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        let b = self.0.encrypt(&self.nonce(), Payload { msg, aad });
        self.1 = self.1.checked_add(1).context("channel spent")?;
        b.map_err(|e| anyhow!("{e}"))
    }

    /// The frame's message under `aad`; its nonce is spent only if it opens.
    fn open(&mut self, msg: &[u8], aad: &[u8]) -> Option<Vec<u8>> {
        let m = self.0.decrypt(&self.nonce(), Payload { msg, aad }).ok()?;
        self.1 = self.1.checked_add(1)?;
        Some(m)
    }
}

impl Tx {
    async fn seal(&mut self, m: &[u8], aad: &[u8]) -> Result<()> {
        let b = self.1.seal(m, aad)?;
        put(&mut self.0, &b).await
    }

    pub async fn send(&mut self, m: &[u8]) -> Result<()> {
        self.seal(m, b"").await
    }

    /// Seal the end and finish the stream; waits for the peer's acks or the
    /// connection's close, 60 s at most. `Ok` is not delivery (only the
    /// peer's reply is), but a peer that stops reading is an error.
    pub async fn finish(mut self) -> Result<()> {
        self.seal(b"", END).await?;
        self.0.finish()?;
        let stopped = timeout(DRAIN, self.0.stopped()).await.context("peer stalled")?;
        ensure!(!matches!(stopped, Ok(Some(_))), "peer stopped reading");
        Ok(())
    }
}

impl Rx {
    /// The next frame, at most `max` bytes, or `None` at the peer's sealed end
    /// (and the stream's, so dropping `Rx` then stops nothing).
    pub async fn next(&mut self, max: usize) -> Result<Option<Vec<u8>>> {
        let b = frame(&mut self.0, max.saturating_add(16)).await?;
        if let Some(m) = self.1.open(&b, b"") {
            return Ok(Some(m));
        }
        self.1.open(&b, END).context("frame fails its pre-shared key")?;
        timeout(WAIT, self.0.read_to_end(0)).await.context("peer stalled")??;
        Ok(None)
    }

    /// The next frame, at most `max` bytes.
    pub async fn recv(&mut self, max: usize) -> Result<Vec<u8>> {
        self.next(max).await?.context("peer ended the stream")
    }

    /// Read to the peer's sealed end: a stream cut short is an error.
    pub async fn end(mut self) -> Result<()> {
        ensure!(self.next(0).await?.is_none(), "frame past the end");
        Ok(())
    }
}
