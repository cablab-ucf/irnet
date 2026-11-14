# Notes for Claude

- CI and release builds are deliberate, never routine: Actions minutes are
  scarce (private repos' Actions do not run; chatir's ci.yml is off by hand).
  Verify locally (`cargo fmt`, `clippy -D warnings`, tests). Never dispatch a
  workflow or push a tag to see whether something builds. A release is built
  once, when everything it ships is verified, merged and built as it should
  ship; not a version that is replaced hours later.
- The wire stays compatible with chatir v0.4.5 and later: the relay TLS
  (post-quantum handshake, its names and ALPNs) and `RELAYS`. Change it
  only when nothing else works, keeping the old form beside the new.
