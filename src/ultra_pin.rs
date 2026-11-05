//! Ultra RustDesk: end-to-end encryption for direct (serverless) connections.
//!
//! Upstream RustDesk trusts a peer's signing key only when the rendezvous server vouches for it,
//! so direct IP connections ran with no encryption at all. Here the controlled side always sends
//! its Ed25519 signing key with its signed identity, and the controlling side pins that key per
//! address on first use (trust on first use, like SSH). A later connection to the same address
//! that presents a different key is refused as a possible man-in-the-middle.

use base::message_proto::*;
use hbb_common::{
    anyhow::anyhow, bail, config::Config, log, protobuf::Message as _, sodiumoxide::crypto::sign,
    timeout, ResultType, Stream,
};
use std::{collections::HashMap, sync::Mutex};

const PINS_FILE: &str = "ultra_pins.json";
const HANDSHAKE_TIMEOUT_MS: u64 = 10_000;

static PINS_LOCK: Mutex<()> = Mutex::new(());
/// Keys pinned during this run that the user has not confirmed yet: (pin key, pairing code).
static UNCONFIRMED: Mutex<Vec<(String, String)>> = Mutex::new(Vec::new());

/// Six digits derived from a signing key, shown on both devices so the user can compare them.
pub fn pairing_code(pk: &[u8]) -> String {
    use hbb_common::sha2::{Digest, Sha256};
    let h = Sha256::digest(pk);
    let n = u32::from_be_bytes([0, h[0], h[1], h[2]]) % 1_000_000;
    format!("{:03} {:03}", n / 1000, n % 1000)
}

/// The pairing code of a key pinned for `id` (as typed, or found on the LAN) that still awaits
/// the user's confirmation; taking it clears it.
pub fn take_unconfirmed(id: &str) -> Option<String> {
    let names = [pin_key(id), pin_key(&format!("id:{}", id))];
    let mut list = UNCONFIRMED.lock().unwrap_or_else(|e| e.into_inner());
    let pos = list.iter().position(|(k, _)| names.contains(k))?;
    Some(list.remove(pos).1)
}

/// Asks the user to compare the pairing code with the one the remote device shows.
pub async fn confirm_pairing(
    interface: &impl crate::client::Interface,
    receiver: &mut hbb_common::tokio::sync::mpsc::UnboundedReceiver<crate::client::Data>,
    code: &str,
) -> bool {
    use crate::client::Data;
    interface.msgbox(
        "insecure-connection-ultra-pair-nocancel-hasclose",
        "Confirm device",
        &format!("ultra-pair_tip {}", code),
        "",
    );
    while let Some(data) = receiver.recv().await {
        match data {
            Data::ContinueInsecureConnection => return true,
            Data::RejectInsecureConnection | Data::Close => return false,
            _ => {}
        }
    }
    false
}

/// What became of the peer's key against the pin store.
#[derive(Debug, PartialEq, Eq)]
pub enum PinResult {
    /// First connection to this address: the key is now pinned.
    NewlyPinned,
    /// The key matches the one pinned earlier.
    Match,
}

fn load_pins() -> HashMap<String, String> {
    let path = Config::path(PINS_FILE);
    std::fs::read_to_string(&path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn store_pins(pins: &HashMap<String, String>) -> ResultType<()> {
    let path = Config::path(PINS_FILE);
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, serde_json::to_string_pretty(pins)?)?;
    std::fs::rename(&tmp, &path)?;
    Ok(())
}

/// Normalises the address the user typed so `1.2.3.4` and `1.2.3.4:21118` share one pin.
fn pin_key(peer: &str) -> String {
    let peer = peer.trim().to_lowercase();
    if hbb_common::is_ip_str(&peer) {
        hbb_common::socket_client::check_port(&peer, hbb_common::config::RELAY_PORT + 1)
    } else {
        peer
    }
}

/// Checks `pk` against the key pinned for `peer`, pinning it when there is none yet.
pub fn check_and_pin(peer: &str, pk: &[u8]) -> ResultType<PinResult> {
    let _guard = PINS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let key = pin_key(peer);
    let hex = hex_of(pk);
    let mut pins = load_pins();
    match pins.get(&key) {
        Some(pinned) if *pinned == hex => Ok(PinResult::Match),
        Some(pinned) => bail!(
            "SECURITY: the key of {} has changed (pinned {}, got {}). Possible man-in-the-middle; \
             the connection was refused. If the remote device was reinstalled, choose \"Forget pinned key\" in its menu and retry.",
            key,
            crate::common::pk_to_fingerprint(hex_to_bytes(pinned)),
            crate::common::pk_to_fingerprint(pk.to_vec())
        ),
        None => {
            pins.insert(key.clone(), hex);
            store_pins(&pins)?;
            UNCONFIRMED
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push((key.clone(), pairing_code(pk)));
            log::info!(
                "Pinned key of {}: {}",
                key,
                crate::common::pk_to_fingerprint(pk.to_vec())
            );
            Ok(PinResult::NewlyPinned)
        }
    }
}

/// Forgets the key pinned for `peer`, so the next connection pins afresh.
pub fn remove_pin(peer: &str) -> ResultType<bool> {
    let _guard = PINS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut pins = load_pins();
    let removed = pins.remove(&pin_key(peer)).is_some();
    if removed {
        store_pins(&pins)?;
    }
    Ok(removed)
}

/// Forgets every key pinned for what the user knows as `peer`: the address itself, and the ID
/// a LAN connection pinned it under.
pub fn forget(peer: &str) -> bool {
    let mut removed = false;
    for name in [peer.to_owned(), format!("id:{}", peer)] {
        match remove_pin(&name) {
            Ok(r) => removed |= r,
            Err(e) => log::warn!("Failed to forget the key of {}: {}", name, e),
        }
    }
    removed
}

fn hex_of(b: &[u8]) -> String {
    b.iter().map(|u| format!("{:02x}", u)).collect()
}

fn hex_to_bytes(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .filter_map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok())
        .collect()
}

/// Controlling side of a direct connection: receives the peer's signed identity, checks its
/// signing key against the pin store, and keys the stream. Fails closed: a direct session never
/// proceeds unencrypted. Returns the peer's signing key.
/// With `expected_id`, the identity the peer signed must be that ID (LAN peers found by ID).
pub async fn secure_direct_connection(
    peer: &str,
    expected_id: Option<&str>,
    conn: &mut Stream,
) -> ResultType<Vec<u8>> {
    let bytes = match timeout(HANDSHAKE_TIMEOUT_MS, conn.next()).await? {
        Some(res) => res?,
        None => bail!("Direct handshake: connection closed before the peer identity arrived"),
    };
    let msg_in = Message::parse_from_bytes(&bytes)
        .map_err(|_| anyhow!("Direct handshake: invalid message format"))?;
    let si = match msg_in.union {
        Some(message::Union::SignedId(si)) => si,
        _ => bail!("Direct handshake: the peer did not send its identity (not an Ultra RustDesk peer?)"),
    };
    if si.direct_sign_pk.len() != sign::PUBLICKEYBYTES {
        bail!("Direct handshake: the peer sent no signing key (not an Ultra RustDesk peer?)");
    }
    let mut pk = [0u8; sign::PUBLICKEYBYTES];
    pk.copy_from_slice(&si.direct_sign_pk);
    let sign_pk = sign::PublicKey(pk);
    // Verify before pinning, so a garbage blob never ends up in the pin store.
    let (id, their_pk_b, _fp, kx_version) = crate::common::decode_id_pk_dtls(&si.id, &sign_pk)?;
    if let Some(expected) = expected_id {
        if id != expected {
            bail!("Direct handshake: the device at this address is {}, not {}", id, expected);
        }
    }
    check_and_pin(peer, &pk)?;

    let (asymmetric_value, symmetric_value, key) =
        crate::common::create_symmetric_key_msg(their_pk_b);
    let picked = hbb_common::tcp::kx_version_for(kx_version);
    let mut msg_out = Message::new();
    msg_out.set_public_key(PublicKey {
        asymmetric_value: asymmetric_value.clone(),
        symmetric_value,
        kx_version: picked,
        ..Default::default()
    });
    timeout(HANDSHAKE_TIMEOUT_MS, conn.send(&msg_out)).await??;
    conn.set_negotiated_key(
        key,
        true,
        &hbb_common::tcp::KxTranscript {
            initiator_pk: &asymmetric_value,
            responder_pk: &their_pk_b,
            advertised: kx_version,
            picked,
        },
    )?;
    if !conn.is_secured() {
        bail!("Direct handshake: the stream is not encrypted");
    }
    Ok(pk.to_vec())
}

/// How long QUIC gets on its own before TCP joins the race. QUIC usually wins (lower latency,
/// no head-of-line blocking); where UDP is blocked this is all the delay TCP costs.
const TCP_HEAD_START_MS: u64 = 250;
const TRANSPORTS_FILE: &str = "ultra_transports.json";

/// The transport that won the last connection to `peer`, if any.
fn last_transport(peer: &str) -> Option<String> {
    let path = Config::path(TRANSPORTS_FILE);
    let map: HashMap<String, String> = std::fs::read_to_string(path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())?;
    map.get(&pin_key(peer)).cloned()
}

fn remember_transport(peer: &str, transport: &str) {
    let _guard = PINS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let path = Config::path(TRANSPORTS_FILE);
    let mut map: HashMap<String, String> = std::fs::read_to_string(&path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();
    if map.get(&pin_key(peer)).map(String::as_str) == Some(transport) {
        return;
    }
    map.insert(pin_key(peer), transport.to_owned());
    if let Ok(s) = serde_json::to_string_pretty(&map) {
        if let Err(e) = std::fs::write(&path, s) {
            log::warn!("Failed to store {}: {}", path.display(), e);
        }
    }
}

/// Connects to a direct peer over QUIC and TCP at once, runs the pinned-key handshake on each,
/// and keeps whichever finishes first. Returns the stream, the peer signing key and the
/// transport name. A key mismatch on either path is reported over any other failure.
pub async fn connect_direct(
    peer: &str,
    expected_id: Option<&str>,
    target: String,
) -> ResultType<(Stream, Vec<u8>, &'static str)> {
    use hbb_common::{config::CONNECT_TIMEOUT, futures::future::{select, Either}, quic, socket_client::connect_tcp_local};

    let quic = async {
        let addr = hbb_common::tokio::net::lookup_host(target.as_str())
            .await?
            .next()
            .ok_or_else(|| anyhow!("cannot resolve {}", target))?;
        let mut s = Stream::Tcp(quic::connect(addr, quic::DEFAULT_SNI, CONNECT_TIMEOUT).await?);
        let pk = secure_direct_connection(peer, expected_id, &mut s).await?;
        Ok::<_, hbb_common::anyhow::Error>((s, pk, "QUIC"))
    };
    // Where TCP won last time (UDP blocked or worse), do not make it wait for QUIC again.
    let tcp_delay = if last_transport(peer).as_deref() == Some("TCP") {
        0
    } else {
        TCP_HEAD_START_MS
    };
    let tcp = async {
        hbb_common::tokio::time::sleep(std::time::Duration::from_millis(tcp_delay)).await;
        let mut s = connect_tcp_local(target.clone(), None, CONNECT_TIMEOUT).await?;
        let pk = secure_direct_connection(peer, expected_id, &mut s).await?;
        Ok::<_, hbb_common::anyhow::Error>((s, pk, "TCP"))
    };
    let (quic, tcp) = (Box::pin(quic), Box::pin(tcp));
    let (first_err, rest) = match select(quic, tcp).await {
        Either::Left((Ok(x), _)) | Either::Right((Ok(x), _)) => {
            log::info!("Direct connection to {} over {}", peer, x.2);
            remember_transport(peer, x.2);
            return Ok(x);
        }
        Either::Left((Err(e), tcp)) => (e, Either::Left(tcp)),
        Either::Right((Err(e), quic)) => (e, Either::Right(quic)),
    };
    let second = match rest {
        Either::Left(tcp) => tcp.await,
        Either::Right(quic) => quic.await,
    };
    match second {
        Ok(x) => {
            log::info!("Direct connection to {} over {} (other path: {})", peer, x.2, first_err);
            remember_transport(peer, x.2);
            Ok(x)
        }
        Err(second_err) => {
            let security = |e: &hbb_common::anyhow::Error| e.to_string().starts_with("SECURITY");
            if security(&second_err) {
                Err(second_err)
            } else if security(&first_err) {
                Err(first_err)
            } else {
                bail!("Direct connection failed: {}; {}", first_err, second_err)
            }
        }
    }
}

const LAN_DIRECT_TIMEOUT_MS: u64 = 3_000;

/// For a peer typed by ID: when LAN discovery found it with a direct port, connects to it
/// directly, with no server involved. `None` means "not on the LAN, use the usual path"; a key
/// mismatch is returned as an error so it is never silently bypassed through a server.
pub async fn try_lan_direct(id: &str) -> Option<ResultType<(Stream, Vec<u8>, &'static str)>> {
    let peer = hbb_common::config::LanPeers::load()
        .peers
        .into_iter()
        .find(|p| p.id == id && p.direct_port > 0)?;
    let pin_name = format!("id:{}", id);
    for ip in peer.ip_mac.keys() {
        let Ok(ip) = ip.parse::<std::net::IpAddr>() else {
            continue;
        };
        let target = std::net::SocketAddr::new(ip, peer.direct_port).to_string();
        match timeout(LAN_DIRECT_TIMEOUT_MS, connect_direct(&pin_name, Some(id), target.clone())).await {
            Ok(Ok(x)) => {
                log::info!("LAN direct connection to {} at {}", id, target);
                return Some(Ok(x));
            }
            Ok(Err(e)) if e.to_string().starts_with("SECURITY") => return Some(Err(e)),
            Ok(Err(e)) => log::info!("LAN direct connection to {} at {} failed: {}", id, target, e),
            Err(_) => log::info!("LAN direct connection to {} at {} timed out", id, target),
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pin_key_normalises_default_port() {
        assert_eq!(pin_key("10.0.0.5"), pin_key("10.0.0.5:21118"));
        assert_ne!(pin_key("10.0.0.5"), pin_key("10.0.0.5:9000"));
    }

    #[test]
    fn hex_round_trip() {
        let b = vec![0u8, 1, 0xab, 0xff];
        assert_eq!(hex_to_bytes(&hex_of(&b)), b);
    }
}
