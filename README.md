# irnet

One iroh endpoint for every cab-ucf app.

```rust
let ep = irnet::endpoint().secret_key(key).alpns(vec![ALPN.into()]).bind().await?;
tokio::spawn(irnet::fallback(ep.clone()));
let (tx, rx) = irnet::psk::dial(&conn, &psk).await?;          // or psk::accept
```

- `tls()`: X25519MLKEM768 first (aws-lc-rs; `pure`: ring + RustCrypto ML-KEM
  for wasm, tested against aws-lc).
- `endpoint()`: the lab's relays only; no n0 DNS, pkarr, UPnP or
  captive-portal probes: a peer is reached only by the address you give it.
  BBRv3, 2 MiB stream windows. Warns of any connection through n0's relays.
- `fallback`: joins n0's relay, with a warning, only once no lab relay has
  answered for 10 s; leaves it once one does, or every 10 min to retry.
- `psk`: a channel for holders of a 32-byte pre-shared key inside the
  connection: HPKE (RFC 9180) PSK mode over X-Wing, fresh keys per side, a
  key per direction, bound to the TLS session; each side proves the key and
  the end of the stream is sealed. With a random key it holds if TLS falls.
  A key stretched from a typed code is only a deterrent: HPKE's PSK mode is
  no PAKE, so the peer you dial, or one who has broken TLS, can test codes
  offline. If a side's RNG is rigged, TLS falls and only the key holds.

License: GPL-3.0-or-later.
