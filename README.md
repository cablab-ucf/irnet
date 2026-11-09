# irnet

One iroh endpoint for every cab-ucf app.

```rust
let ep = irnet::endpoint().secret_key(key).alpns(vec![ALPN.into()])
    .relay_mode(RelayMode::custom(irnet::relays())).bind().await?;
let (tx, rx) = irnet::psk::dial(&conn, &psk).await?;          // or psk::accept
```

- `tls()`: X25519MLKEM768 first (aws-lc-rs; `pure`: ring + RustCrypto ML-KEM
  for wasm, tested against aws-lc).
- `endpoint()`: no n0 DNS, pkarr, UPnP or captive-portal probes: a peer is
  reached only by the address you give it. BBRv3, 2 MiB stream windows.
- `RELAYS`: the lab's, then n0's as a last resort.
- `psk`: a channel for holders of a pre-shared key inside the connection:
  HPKE (RFC 9180) PSK mode over X-Wing, fresh keys per side, bound to the TLS
  session. Holds if TLS falls or one side's RNG is rigged.

License: GPL-3.0-or-later.
