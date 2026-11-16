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
/// `confirmed`: the key was already verified (a connection code carries its hash), so the user
/// is not asked to compare pairing codes.
pub fn check_and_pin(peer: &str, pk: &[u8], confirmed: bool) -> ResultType<PinResult> {
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
            if !confirmed {
                UNCONFIRMED
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push((key.clone(), pairing_code(pk)));
            }
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
    expected_key: Option<[u8; CODE_KEY_HASH_LEN]>,
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
    if let Some(expected) = expected_key {
        if key_hash(&pk) != expected {
            bail!("SECURITY: the device at this address does not have the key its connection code names. Possible man-in-the-middle, or the code is outdated; the connection was refused.");
        }
    }
    check_and_pin(peer, &pk, expected_key.is_some())?;

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
    expected_key: Option<[u8; CODE_KEY_HASH_LEN]>,
    target: String,
) -> ResultType<(Stream, Vec<u8>, &'static str)> {
    use hbb_common::{futures::future::{select, Either}, quic, socket_client::connect_tcp_local};
    // Below the 15 s overall cap, so each transport reports its own reason in the log.
    const CONNECT_TIMEOUT: u64 = 10_000;

    let quic_inner = async {
        let addr = hbb_common::tokio::net::lookup_host(target.as_str())
            .await?
            .next()
            .ok_or_else(|| anyhow!("cannot resolve {}", target))?;
        let mut s = Stream::Tcp(quic::connect(addr, quic::DEFAULT_SNI, CONNECT_TIMEOUT).await?);
        let pk = secure_direct_connection(peer, expected_id, expected_key, &mut s).await?;
        Ok::<_, hbb_common::anyhow::Error>((s, pk, "QUIC"))
    };
    // Where TCP won last time (UDP blocked or worse), do not make it wait for QUIC again.
    let tcp_delay = if last_transport(peer).as_deref() == Some("TCP") {
        0
    } else {
        TCP_HEAD_START_MS
    };
    let tcp_inner = async {
        hbb_common::tokio::time::sleep(std::time::Duration::from_millis(tcp_delay)).await;
        let mut s = connect_tcp_local(target.clone(), None, CONNECT_TIMEOUT).await?;
        let pk = secure_direct_connection(peer, expected_id, expected_key, &mut s).await?;
        Ok::<_, hbb_common::anyhow::Error>((s, pk, "TCP"))
    };
    crate::ultra_diag::note(
        "TRY",
        format!("{}: QUIC (UDP) now, TCP after {} ms", target, tcp_delay),
    );
    let started = std::time::Instant::now();
    let report = |name: &'static str, r: &ResultType<(Stream, Vec<u8>, &'static str)>| match r {
        Ok(_) => crate::ultra_diag::note(
            name,
            format!("{}: encrypted handshake done in {} ms", target, crate::ultra_diag::ms(started)),
        ),
        Err(e) => crate::ultra_diag::note(
            name,
            format!("{}: failed after {} ms: {}", target, crate::ultra_diag::ms(started), e),
        ),
    };
    let quic = async {
        let r = quic_inner.await;
        report("QUIC", &r);
        r
    };
    let tcp = async {
        let r = tcp_inner.await;
        report("TCP", &r);
        r
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
        match timeout(LAN_DIRECT_TIMEOUT_MS, connect_direct(&pin_name, Some(id), None, target.clone())).await {
            Ok(Ok(x)) => {
                crate::ultra_diag::note("LAN", format!("{} connected directly at {}", id, target));
                return Some(Ok(x));
            }
            Ok(Err(e)) if e.to_string().starts_with("SECURITY") => return Some(Err(e)),
            Ok(Err(e)) => crate::ultra_diag::note("LAN", format!("{} at {} failed: {}", id, target, e)),
            Err(_) => crate::ultra_diag::note("LAN", format!("{} at {}: no answer in {} ms", id, target, LAN_DIRECT_TIMEOUT_MS)),
        }
    }
    None
}

// ---------------------------------------------------------------- connection codes
//
// A connection code is what a user types instead of an ID when no server is used:
// "UR" + base32(kind, address, port, first bytes of SHA-256 of the signing key). The key hash
// lets the controller verify the device on the first connection without a pairing dialog.

const CODE_PREFIX: &str = "UR";
const CODE_KEY_HASH_LEN: usize = 6;
const B32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
/// Where the UPnP thread leaves the router's external address for the code.
pub const OPTION_EXTERNAL_IP: &str = "ultra-external-ip";

fn key_hash(pk: &[u8]) -> [u8; CODE_KEY_HASH_LEN] {
    use hbb_common::sha2::{Digest, Sha256};
    let h = Sha256::digest(pk);
    let mut out = [0u8; CODE_KEY_HASH_LEN];
    out.copy_from_slice(&h[..CODE_KEY_HASH_LEN]);
    out
}

fn b32_encode(data: &[u8]) -> String {
    let mut out = String::new();
    let (mut buf, mut bits) = (0u32, 0u32);
    for &b in data {
        buf = (buf << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(B32[((buf >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(B32[((buf << (5 - bits)) & 31) as usize] as char);
    }
    out
}

fn b32_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let (mut buf, mut bits) = (0u32, 0u32);
    for c in s.bytes() {
        let v = B32.iter().position(|&x| x == c.to_ascii_uppercase())? as u32;
        buf = (buf << 5) | v;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
    }
    Some(out)
}

const CODE_MULTI: u8 = 2;

fn push_ip(data: &mut Vec<u8>, ip: &std::net::IpAddr) {
    match ip {
        std::net::IpAddr::V4(ip) => {
            data.push(4);
            data.extend_from_slice(&ip.octets());
        }
        std::net::IpAddr::V6(ip) => {
            data.push(6);
            data.extend_from_slice(&ip.octets());
        }
    }
}

/// A code naming every address the device can be reached at (LAN, public IPv4, IPv6), the
/// direct port and the key hash. The controller tries all addresses at once.
pub fn encode_connection_code(ips: &[std::net::IpAddr], port: u16, pk: &[u8]) -> String {
    let mut data = Vec::new();
    if ips.len() == 1 {
        push_ip(&mut data, &ips[0]);
    } else {
        data.push(CODE_MULTI);
        data.push(ips.len() as u8);
        for ip in ips {
            push_ip(&mut data, ip);
        }
    }
    data.extend_from_slice(&port.to_be_bytes());
    data.extend_from_slice(&key_hash(pk));
    format!("{}{}", CODE_PREFIX, b32_encode(&data))
}

fn take_ip(data: &[u8]) -> Option<(std::net::IpAddr, usize)> {
    match data.first()? {
        4 if data.len() >= 5 => Some((<[u8; 4]>::try_from(&data[1..5]).ok()?.into(), 5)),
        6 if data.len() >= 17 => Some((<[u8; 16]>::try_from(&data[1..17]).ok()?.into(), 17)),
        _ => None,
    }
}

/// The addresses and key hash in a connection code; `None` if `code` is not one.
pub fn decode_connection_code(
    code: &str,
) -> Option<(Vec<std::net::SocketAddr>, [u8; CODE_KEY_HASH_LEN])> {
    let code: String = code.chars().filter(|c| !c.is_whitespace() && *c != '-').collect();
    if !code.is_ascii()
        || code.len() < CODE_PREFIX.len()
        || !code[..CODE_PREFIX.len()].eq_ignore_ascii_case(CODE_PREFIX)
    {
        return None;
    }
    let data = b32_decode(&code[CODE_PREFIX.len()..])?;
    let mut ips = Vec::new();
    let mut at = 0;
    if *data.first()? == CODE_MULTI {
        let n = *data.get(1)? as usize;
        at = 2;
        for _ in 0..n {
            let (ip, len) = take_ip(data.get(at..)?)?;
            ips.push(ip);
            at += len;
        }
    } else {
        let (ip, len) = take_ip(&data)?;
        ips.push(ip);
        at += len;
    }
    if ips.is_empty() || data.len() != at + 2 + CODE_KEY_HASH_LEN {
        return None;
    }
    let port = u16::from_be_bytes([data[at], data[at + 1]]);
    let mut hash = [0u8; CODE_KEY_HASH_LEN];
    hash.copy_from_slice(&data[at + 2..]);
    Some((
        ips.into_iter()
            .map(|ip| std::net::SocketAddr::new(ip, port))
            .collect(),
        hash,
    ))
}

/// Reachable from the internet: not private, carrier-grade NAT, loopback or link-local.
pub fn is_public_ip(ip: &std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            let o = v4.octets();
            !(v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || (o[0] == 100 && (o[1] & 0xc0) == 64))
        }
        std::net::IpAddr::V6(v6) => (v6.segments()[0] & 0xe000) == 0x2000,
    }
}

/// The local address the OS would use towards `probe`; no packet is sent.
#[cfg(not(target_os = "ios"))]
fn outgoing_ip(bind: &str, probe: &str) -> Option<std::net::IpAddr> {
    let s = std::net::UdpSocket::bind(bind).ok()?;
    s.connect(probe).ok()?;
    Some(s.local_addr().ok()?.ip())
}

/// This device's global IPv6 address, if it has one.
#[cfg(not(target_os = "ios"))]
pub fn my_global_ipv6() -> Option<std::net::Ipv6Addr> {
    match outgoing_ip("[::]:0", "[2001:4860:4860::8888]:80")? {
        std::net::IpAddr::V6(ip) if is_public_ip(&std::net::IpAddr::V6(ip)) => Some(ip),
        _ => None,
    }
}

/// Every address this device can be reached at: its LAN IPv4 (works inside this network), the
/// router's public IPv4 from UPnP (only when it really is public, not carrier-grade NAT) and a
/// global IPv6 address (often reachable even without a public IPv4).
#[cfg(not(target_os = "ios"))]
pub fn my_addresses() -> Vec<std::net::IpAddr> {
    let mut ips = Vec::new();
    if let Some(ip) = outgoing_ip("0.0.0.0:0", "8.8.8.8:80") {
        if !ip.is_unspecified() && !ip.is_loopback() {
            ips.push(ip);
        }
    }
    // The router's WAN address goes in even when it is private: with a router behind another
    // router (or an office network), devices in the outer network reach the PC through it.
    if let Ok(ip) = Config::get_option(OPTION_EXTERNAL_IP).parse::<std::net::IpAddr>() {
        if !ip.is_unspecified() && !ip.is_loopback() && !ips.contains(&ip) {
            ips.push(ip);
        }
    }
    if let Some(ip) = outgoing_ip("[::]:0", "[2001:4860:4860::8888]:80") {
        if is_public_ip(&ip) {
            ips.push(ip);
        }
    }
    ips
}

/// This device's connection code. Empty when direct access is off.
#[cfg(not(target_os = "ios"))]
pub fn my_connection_code() -> String {
    if crate::rendezvous_mediator::ultra_direct_advert().is_empty() {
        return String::new();
    }
    let ips = my_addresses();
    note_addresses(&ips);
    if ips.is_empty() {
        return String::new();
    }
    let port = crate::rendezvous_mediator::get_direct_port() as u16;
    encode_connection_code(&ips, port, &Config::get_key_pair().1)
}

#[cfg(not(target_os = "ios"))]
fn note_addresses(ips: &[std::net::IpAddr]) {
    static LAST: Mutex<Option<Vec<std::net::IpAddr>>> = Mutex::new(None);
    let mut last = LAST.lock().unwrap_or_else(|e| e.into_inner());
    if last.as_deref() == Some(ips) {
        return;
    }
    *last = Some(ips.to_vec());
    let external = Config::get_option(OPTION_EXTERNAL_IP);
    let describe = |ip: &std::net::IpAddr| match ip {
        std::net::IpAddr::V6(_) => format!("{} (IPv6, internet)", ip),
        _ if is_public_ip(ip) => format!("{} (public IPv4, internet)", ip),
        _ if ip.to_string() == external => format!("{} (router WAN, its outer network only)", ip),
        _ => format!("{} (LAN only)", ip),
    };
    let mut msg = if ips.is_empty() {
        "no usable address".to_owned()
    } else {
        ips.iter().map(describe).collect::<Vec<_>>().join(", ")
    };
    if let Ok(ip) = external.parse::<std::net::IpAddr>() {
        if !is_public_ip(&ip) {
            msg.push_str(&format!(
                "; the router's WAN address {} is not public (provider NAT): not reachable from the internet over IPv4",
                ip
            ));
        }
    }
    if !ips.iter().any(|ip| ip.is_ipv6()) {
        msg.push_str("; no global IPv6 address");
    }
    crate::ultra_diag::note("ADDR", format!("connection code addresses: {}", msg));
}

/// "internet" when the code holds a public address, "lan" when it works only inside the local
/// network, "" when `code` is not a connection code.
pub fn connection_code_scope(code: &str) -> &'static str {
    match decode_connection_code(code) {
        Some((addrs, _)) if addrs.iter().any(|a| is_public_ip(&a.ip())) => "internet",
        Some(_) => "lan",
        None => "",
    }
}

const CODE_CONNECT_TIMEOUT_MS: u64 = 15_000;

/// Connects to the device a connection code names, trying all its addresses at once.
pub async fn connect_code(
    peer: &str,
    addrs: Vec<std::net::SocketAddr>,
    key: [u8; CODE_KEY_HASH_LEN],
) -> ResultType<(Stream, Vec<u8>, &'static str)> {
    crate::ultra_diag::note("CODE", format!("{} address(es) in the code: {}", addrs.len(), list(&addrs)));
    connect_many(peer, addrs, Some(key)).await
}

/// Connects to a typed address or host name. A name is resolved to all its IPv6 and IPv4
/// addresses, and they are tried at once, like the addresses of a connection code.
pub async fn connect_host(peer: &str, target: &str) -> ResultType<(Stream, Vec<u8>, &'static str)> {
    let t = std::time::Instant::now();
    let mut addrs: Vec<std::net::SocketAddr> = match hbb_common::tokio::net::lookup_host(target).await {
        Ok(it) => it.collect(),
        Err(e) => {
            crate::ultra_diag::note("DNS", format!("{}: cannot resolve: {}", target, e));
            bail!("Cannot resolve {}: {}", target, e);
        }
    };
    addrs.dedup();
    crate::ultra_diag::note(
        "DNS",
        format!("{} -> {} ({} ms)", target, list(&addrs), crate::ultra_diag::ms(t)),
    );
    connect_many(peer, addrs, None).await
}

fn list(addrs: &[std::net::SocketAddr]) -> String {
    addrs.iter().map(|a| a.to_string()).collect::<Vec<_>>().join(", ")
}

/// Typed names without a port ("myhost.example.com") are hosts too, on the default direct port.
pub fn is_bare_host(peer: &str) -> bool {
    let p = peer.trim();
    p.contains('.')
        && !p.contains(':')
        && p.chars().any(|c| c.is_ascii_alphabetic())
        && p.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
        && decode_connection_code(p).is_none()
}

/// When every address is a private one outside this device's own network, says so: that is
/// the usual reason for a timeout (the code was made in another network).
fn note_other_network(addrs: &[std::net::SocketAddr]) {
    #[cfg(not(target_os = "ios"))]
    {
        if addrs.is_empty() || addrs.iter().any(|a| is_public_ip(&a.ip())) {
            return;
        }
        let Some(std::net::IpAddr::V4(mine)) = outgoing_ip("0.0.0.0:0", "8.8.8.8:80") else {
            return;
        };
        let same_net = addrs.iter().any(|a| match a.ip() {
            std::net::IpAddr::V4(t) => t.octets()[..3] == mine.octets()[..3],
            _ => false,
        });
        if !same_net {
            crate::ultra_diag::note(
                "HINT",
                format!(
                    "the code has only private addresses ({}), and this device is in another network ({}): \
                     they cannot reach each other. Connect both to the same network, or give the PC a public \
                     address or IPv6 (UPnP or port forwarding of 21118 TCP+UDP on its router)",
                    list(addrs),
                    mine
                ),
            );
        }
    }
}

/// Tries every address at once (each one QUIC and TCP raced); the first to finish the verified
/// handshake wins. A key mismatch is reported over other errors, and nothing waits forever.
async fn connect_many(
    peer: &str,
    addrs: Vec<std::net::SocketAddr>,
    key: Option<[u8; CODE_KEY_HASH_LEN]>,
) -> ResultType<(Stream, Vec<u8>, &'static str)> {
    use hbb_common::futures::stream::{FuturesUnordered, StreamExt};
    let started = std::time::Instant::now();
    let mut tries: FuturesUnordered<_> = addrs
        .iter()
        .map(|a| {
            let target = a.to_string();
            async move {
                let r = connect_direct(peer, None, key, target.clone()).await;
                (target, r)
            }
        })
        .collect();
    let mut security = None;
    let run = async {
        while let Some((target, r)) = tries.next().await {
            match r {
                Ok(x) => {
                    crate::ultra_diag::note(
                        "OK",
                        format!("connected to {} over {} in {} ms", target, x.2, crate::ultra_diag::ms(started)),
                    );
                    return Some(x);
                }
                Err(e) => {
                    if e.to_string().starts_with("SECURITY") {
                        security = Some(e);
                    }
                }
            }
        }
        None
    };
    let res = timeout(CODE_CONNECT_TIMEOUT_MS, run).await;
    match res {
        Ok(Some(x)) => Ok(x),
        Ok(None) => match security {
            Some(e) => Err(e),
            None => {
                crate::ultra_diag::note("FAIL", "no address answered; see the lines above for why");
                note_other_network(&addrs);
                bail!("ultra-unreachable-tip")
            }
        },
        Err(_) => match security {
            Some(e) => Err(e),
            None => {
                crate::ultra_diag::note(
                    "FAIL",
                    format!("gave up after {} s: no address finished the handshake", CODE_CONNECT_TIMEOUT_MS / 1000),
                );
                note_other_network(&addrs);
                bail!("ultra-unreachable-tip")
            }
        },
    }
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
    fn connection_code_round_trip() {
        let ip: std::net::IpAddr = "203.0.113.7".parse().unwrap();
        let code = encode_connection_code(&[ip], 21118, b"some signing key");
        assert!(code.starts_with("UR"));
        let (a, h) = decode_connection_code(&code.to_lowercase()).unwrap();
        assert_eq!(a, vec![std::net::SocketAddr::new(ip, 21118)]);
        assert_eq!(h, key_hash(b"some signing key"));
        assert_eq!(connection_code_scope(&code), "internet");
        let ips: Vec<std::net::IpAddr> =
            vec!["192.168.1.5".parse().unwrap(), "2001:db8::7".parse().unwrap()];
        let code = encode_connection_code(&ips, 9000, b"k");
        let (a, _) = decode_connection_code(&code).unwrap();
        assert_eq!(a.len(), 2);
        assert_eq!(a[1], "[2001:db8::7]:9000".parse().unwrap());
        assert_eq!(connection_code_scope(&encode_connection_code(&ips[..1], 1, b"k")), "lan");
        assert!(!is_public_ip(&"100.72.1.1".parse().unwrap()));
        assert!(is_public_ip(&"2a00:1450::1".parse().unwrap()));
        assert!(decode_connection_code("123456789").is_none());
        assert!(decode_connection_code("192.168.1.2").is_none());
    }

    #[test]
    fn hex_round_trip() {
        let b = vec![0u8, 1, 0xab, 0xff];
        assert_eq!(hex_to_bytes(&hex_of(&b)), b);
    }
}
