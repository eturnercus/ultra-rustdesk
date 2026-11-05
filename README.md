<p align="center">
  <img src="res/logo-header.svg" alt="Ultra RustDesk" width="420"><br>
  <b>Ultra RustDesk</b> — a remote desktop built for direct, low-latency connections on difficult networks<br>
  <a href="docs/README-RU.md">Русский</a> | English
</p>

> [!Caution]
> **Use it only on devices you own or are allowed to control.** Unauthorized access to other people's
> computers is illegal. The authors are not responsible for misuse.

Ultra RustDesk is a fork of [RustDesk](https://github.com/rustdesk/rustdesk) maintained by **eturnercus**.
It keeps RustDesk's video, input, clipboard and file transfer, and replaces how two devices find and talk
to each other: direct connections come first, they are always end-to-end encrypted, and several
transports are tried in parallel so a session starts quickly even when some of them are blocked or slow.

Platforms: **Windows x64**, **Linux x86_64** (`.deb`, AppImage), **Android** (arm64, armv7, x86_64, universal APK).

---

## What is different from RustDesk

| | RustDesk | Ultra RustDesk |
|---|---|---|
| Direct IP connection | **not encrypted** (only a server can vouch for keys) | always end-to-end encrypted, key pinned on first use |
| Transports for a direct connection | TCP | **QUIC and TCP raced in parallel** |
| Direct access | off by default | on by default |
| Default / maximum frame rate | 30 / 120 FPS (30 without your own server) | **60 / 144 FPS** |
| Needs public RustDesk servers | for ID connections | no, for direct connections |
| LAN devices found by discovery | connected through a server | **connected directly**, no server |
| Router port forwarding | manual | **automatic (UPnP)** |
| Self-updates from rustdesk.com | yes | **disabled** (would replace the fork) |
| Android package | `com.carriez.flutter_hbb` | `com.eturnercus.ultrarustdesk` (installs next to RustDesk) |

### End-to-end encryption with pinned keys

Upstream RustDesk trusts a peer's key only when its rendezvous server signs it, so direct IP sessions ran
in plaintext and showed an "Insecure Connection" warning. In Ultra RustDesk:

- the controlled device sends its Ed25519 public key together with its signed identity;
- the controlling device remembers that key for the address on the first connection (trust on first use,
  like SSH) and **refuses** a later connection that presents a different key;
- a session never falls back to plaintext;
- the device's own key fingerprint is always shown in **Settings → About**, so you can compare it once.

Code: [`src/ultra_pin.rs`](src/ultra_pin.rs).

### QUIC transport and parallel racing

- QUIC over UDP on the **same port** as the direct TCP listener (21118 by default).
- To the network it looks like ordinary HTTP/3 (ALPN `h3`, TLS 1.3). The QUIC certificate is throwaway;
  who the peer is gets decided by the pinned-key handshake inside, not by the certificate.
- Tuned for latency: BBR congestion control, 16/32 MB flow-control windows so a video frame never waits
  for the receiver, 4 s keep-alive so NAT mappings stay open.
- The controller starts QUIC immediately and TCP 250 ms later; the first one to finish the encrypted
  handshake wins. If UDP is blocked, this costs a quarter of a second, and only once: the winner is
  remembered per device, and where TCP won, it starts at once next time.

### LAN and UPnP

- LAN discovery replies carry the direct port. A device found on the **LAN** tab is connected
  directly even when you click it by ID; its signed ID must match, and its key is pinned under that ID.
- While direct access is on, the app asks the router (UPnP IGD) to forward the direct port, TCP and
  UDP, and writes the external address to the log. Set the option `enable-ultra-upnp` to `N` to turn
  it off.

Code: [`src/ultra_upnp.rs`](src/ultra_upnp.rs), `try_lan_direct` in [`src/ultra_pin.rs`](src/ultra_pin.rs).

Code: [`libs/hbb_common/src/quic.rs`](libs/hbb_common/src/quic.rs), `connect_direct` in
[`src/ultra_pin.rs`](src/ultra_pin.rs), `direct_server` in [`src/rendezvous_mediator.rs`](src/rendezvous_mediator.rs).

### Low latency

- 60 FPS for every new viewer by default, up to 144 FPS; quality and FPS are never capped to 30.
- Network QoS still lowers the frame rate on a slow link and raises it back.
- RustDesk's hardware encoders/decoders stay enabled in the builds.

---

## How to connect

1. **Install** Ultra RustDesk on both devices.
2. On the device you want to control, make sure **TCP and UDP port 21118** are reachable from the other
   device: same LAN, a public/IPv6 address, or a port forward on the router (done automatically when
   the router supports UPnP). On a LAN you can also just pick the device on the **LAN** tab.
3. On the controlling device, type the address into the ID field: `192.168.1.20`, `203.0.113.7:21118` or
   `myhost.example.com:21118`, and connect.
4. **First connection:** a dialog shows a 6-digit pairing code. The remote device shows its own code
   as the first 6 digits of its fingerprint in *Settings → About*. Press **Continue** only if they
   match; **Disconnect** forgets the key.
5. The connection window shows which transport won (`QUIC` or `TCP`).

If the remote device was reinstalled, its key changes and the connection is refused. Open the device's
menu (⋮) in the Recent / Favorites / LAN list and choose **Forget pinned key**, then connect again.
The keys live in `ultra_pins.json` in the config folder (Windows: `%AppData%\UltraRustDesk\config\`,
Linux: `~/.config/ultrarustdesk/`), separate from a stock RustDesk's settings.

---

## Downloads and builds

Builds are made by GitHub Actions ([`.github/workflows/ultra-build.yml`](.github/workflows/ultra-build.yml)):

- **Actions → Ultra RustDesk Build → Run workflow** builds everything and publishes it to the
  `ultra-nightly` release;
- pushing a tag like `v1.5.1-ultra.1` publishes a release with that name.

Building locally follows the upstream instructions: <https://rustdesk.com/docs/en/dev/build/>.
Ultra RustDesk needs **Rust 1.85 or newer** (QUIC library).

---

## Current limitations

- If **both** devices are behind carrier-grade NAT (typical for mobile internet), a direct connection is
  impossible. The same usually applies to connecting **to** a phone over mobile internet.
- Direct mode does not interoperate with stock RustDesk: a stock client cannot complete the encrypted
  handshake, by design.
- The settings folder is separate, but the Windows service and executable are still named `RustDesk`,
  so do not install Ultra RustDesk and stock RustDesk as services on the same Windows machine.

## Roadmap

| Transport / feature | Status |
|---|---|
| TCP direct, end-to-end encrypted, pinned keys | ✅ done |
| QUIC direct (HTTP/3-like, BBR), raced against TCP | ✅ done |
| 60 FPS default, 144 FPS max | ✅ done |
| Direct connection to LAN-discovered devices; remembering the winning transport | ✅ done |
| UPnP port forwarding | ✅ done |
| "Forget pinned key" in the device menu | ✅ done |
| Upstream self-update disabled | ✅ done |
| Pairing code confirmation on the first connection | ✅ done |
| Own settings folder (`UltraRustDesk`) | ✅ done |
| Obfuscated QUIC inspired by Hysteria2 | not started |
| TLS 1.3 over TCP 443 | not started |
| WebSocket through a CDN | not started |
| Switching transport without dropping the session | not started |
| Renaming the Windows service and executables | not started |

Design notes: [`docs/ULTRA_DESIGN.md`](docs/ULTRA_DESIGN.md).

---

## License and credits

Ultra RustDesk is distributed under the **GNU AGPL-3.0**, like RustDesk ([LICENCE](LICENCE)).

- Fork and changes: **eturnercus**
- Based on RustDesk, © Purslane Tech Pte. Ltd. and contributors — <https://github.com/rustdesk/rustdesk>
- QUIC: [quinn](https://github.com/quinn-rs/quinn). The planned obfuscated transport borrows ideas from
  [Hysteria](https://github.com/apernet/hysteria) (MIT) and is not wire-compatible with it.
