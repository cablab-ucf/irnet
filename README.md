# irnet

One iroh endpoint for every cablab-ucf app.

```rust
let ep = irnet::endpoint().secret_key(key).alpns(vec![ALPN.into()]).bind().await?;
tokio::spawn(irnet::fallback(ep.clone()));
irnet::psk::prove(&conn, &psk).await?;                        // or psk::admit: then conn's own streams
let (tx, rx) = irnet::psk::dial(&conn, &psk).await?;          // or psk::accept: a sealed channel
```

- Features: `endpoint` (default) is the iroh endpoint and `psk`; without it
  irnet is `tls` and `pq` alone, twelve crates and no iroh, for a crate that
  meets a relay itself (pushir). So every crate takes its post-quantum TLS
  from here.
- `pq()`: X25519MLKEM768 and nothing else, for a hop that must not fall
  back. `on(relays)`: `endpoint()` on a deployment's own relays.
- `tls()`: X25519MLKEM768 first (aws-lc-rs; `pure`: ring + RustCrypto ML-KEM
  for wasm, tested against aws-lc). A peer without it is refused. A relay
  without it gets X25519: what crosses it is sealed end to end already, but
  who talks to whom is then hidden from today's computers only.
- `endpoint()`: homes on the lab's relays only; no n0 DNS, pkarr, UPnP or
  captive-portal probes: a peer is reached only by the address you give it,
  through any relay that address names. Warns of each relay not the lab's:
  one an address names, before it is dialed, and one a path crosses, at the
  handshake or after.
- Speed: BBRv3. A stream carries 2 MiB per round trip (noq drops a
  connection whose stream buffers over 1024 gaps; 2 MiB cannot), a
  connection 64 MiB over all its streams once its peer is known (`wide`;
  8 MiB for a stranger): 5 Gbit/s at 100 ms, 50 at 10 ms. So a large
  transfer goes over many streams, and past one core's worth over several
  connections. `cargo test --release speed -- --ignored --nocapture`
  measures this machine.
- `fallback`: joins n0's relay, with a warning, only once no lab relay has
  answered for 10 s; leaves it as soon as one answers again, which a second
  endpoint on the lab's relays alone watches for meanwhile.
- `psk::prove`, `psk::admit`: each side shows HMAC-SHA256 of the TLS
  session's exporter under a 32-byte pre-shared key: 64 bytes, no key
  exchange, a hash per key for the acceptor. The connection is then the
  peer's, `wide`, its streams used as they are: the way for bulk. Its
  secrecy is TLS's.
- `psk::dial`, `psk::accept`: the same proof, then a sealed channel: HPKE
  (RFC 9180) PSK mode over X-Wing to the dialer's fresh key, a key per
  direction, the end of the stream sealed. With a random key it holds if
  TLS falls. One stream and a copy per frame: for secrets, not bulk. A peer
  that stalls a handshake, a write or a finish fails it (10 s, 10 s, 60 s);
  one silent between frames is the app's to time out.
- A key stretched from a typed code is only a deterrent: this is no PAKE, so
  the peer you dial, or one who has broken TLS, can test codes offline (use
  pairir). If a side's RNG is rigged, TLS falls and only the key holds.

License: GPL-3.0-or-later.
