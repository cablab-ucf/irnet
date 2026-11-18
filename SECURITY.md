# Security

irnet is the lab's network layer over iroh: post-quantum TLS for every
connection, a pre-shared-key binding, and the lab's relays with fallback.
Report a vulnerability privately (GitHub security advisory on this
repository).

## Properties

- TLS 1.3 key exchange X25519MLKEM768 only, both roles; a peer that does not
  offer it is refused. The pure-Rust hybrid follows
  draft-ietf-tls-ecdhe-mlkem (share order and sizes, the FIPS 203 modulus
  check) and interoperates with aws-lc.
- PSK binding (psk.rs): the dialer sends HMAC(psk, "irnet psk 3 dial" ‖ E ‖
  pk), the acceptor HMAC(psk, "… accept" ‖ E ‖ pk ‖ enc), E being the TLS
  exporter "EXPORTER-irnet-psk" (the same in both roles, bound to both
  endpoints' keys). No unknown key share or misbinding; distinct labels stop
  reflection; E is fresh each session, resumption included. The mode is
  inside both MACs.
- Sealed mode: HPKE PSK mode over X-Wing with info = E, one key per
  direction, counter nonces, a sealed end (truncation detected).
- Frame lengths are bounded before allocation.

## Known limits (accepted, with reason)

- If the lab's relays do not answer for 10 s (or are blocked), the relay hop
  falls back to iroh's relays with classical TLS: endpoint ids and dial
  metadata are then exposed to that operator. Peer connections stay
  post-quantum (non-PQ peers are refused).
- A shared symmetric key allows key-compromise impersonation, as any PSK.

## Wire compatibility

The relay TLS, its names and ALPNs, and `RELAYS` stay as chatir v0.4.5 peers
speak them (CLAUDE.md).
