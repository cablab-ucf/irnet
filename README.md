# irnet

One iroh endpoint for every cab-ucf app.

```rust
let ep = irnet::endpoint().secret_key(key).alpns(vec![ALPN.into()]).bind().await?;
tokio::spawn(irnet::fallback(ep.clone()));
let (tx, rx) = irnet::psk::dial(&conn, &psk).await?;          // or psk::accept
```

- `tls()`: X25519MLKEM768 first (aws-lc-rs; `pure`: ring + RustCrypto ML-KEM
  for wasm, tested against aws-lc). A peer without it gets X25519, and the
  endpoint a warning.
- `endpoint()`: homes on the lab's relays only; no n0 DNS, pkarr, UPnP or
  captive-portal probes: a peer is reached only by the address you give it,
  through any relay that address names. BBRv3, 2 MiB stream windows. Warns
  of each relay not the lab's: one an address names, before it is dialed,
  and one a path crosses, at the handshake or after.
- `fallback`: joins n0's relay, with a warning, only once no lab relay has
  answered for 10 s; leaves it as soon as one answers again, which a second
  endpoint on the lab's relays alone watches for meanwhile.
- `psk`: a channel for holders of a 32-byte pre-shared key inside the
  connection: HPKE (RFC 9180) PSK mode over X-Wing, fresh keys per side, a
  key per direction, bound to the TLS session; each side proves the key and
  the end of the stream is sealed. With a random key it holds if TLS falls.
  A peer that stalls a handshake, a write or a finish fails it (10 s, 10 s,
  60 s); one silent between frames is the app's to time out.
  A key stretched from a typed code is only a deterrent: HPKE's PSK mode is
  no PAKE, so the peer you dial, or one who has broken TLS, can test codes
  offline. If a side's RNG is rigged, TLS falls and only the key holds.

License: GPL-3.0-or-later.
