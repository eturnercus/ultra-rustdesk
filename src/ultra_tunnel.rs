//! Ultra RustDesk: P2P tunnel through NAT, with no server of our own.
//!
//! Two devices behind home routers cannot reach each other directly: neither has an address the
//! other can dial. They can still open a direct path if both send packets to each other at the
//! same time ("hole punching"): each router then sees the other side's packets as replies.
//!
//! What each side needs is the other's external address, and the routers only give that away
//! to a STUN server (it answers "you came from 203.0.113.7:51234" and nothing else; no data
//! passes through it). The addresses are swapped by hand, as two short codes:
//!
//! 1. the PC makes an invite code ("UT...": its external, LAN and IPv6 addresses, a one-time
//!    nonce and the hash of its signing key) and its owner sends it to the controller;
//! 2. the controller enters it like any connection code and gets an answer code ("UA...") with
//!    its own addresses, which goes back to the PC owner;
//! 3. the PC owner pastes the answer: the PC starts punching towards the controller, while the
//!    controller keeps opening QUIC connections towards the PC until one gets through.
//!
//! The result is an encrypted QUIC tunnel between the two machines; inside it the usual
//! pinned-key handshake and password login run, exactly as for any direct connection.

use hbb_common::{bail, config::Config, log, rand, tokio, ResultType, Stream};
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs, UdpSocket},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};

use crate::ultra_pin::{
    b32_decode, b32_encode, hex_of, key_hash, outgoing_ip, push_ip, take_ip, CODE_KEY_HASH_LEN,
};

const INVITE_PREFIX: &str = "UT";
const ANSWER_PREFIX: &str = "UA";
const VERSION: u8 = 1;
/// Answer "what is my external address" only; never see any session data. Several in
/// different countries, so a few of them being blocked does not matter.
const STUN_SERVERS: &[&str] = &[
    "stun.l.google.com:19302",
    "stun.cloudflare.com:3478",
    "stun.sipnet.ru:3478",
    "stun1.l.google.com:19302",
    "stun.nextcloud.com:3478",
    "stun.stunprotocol.org:3478",
];
/// Comma-separated STUN servers that replace the list above.
const OPTION_STUN: &str = "ultra-stun-servers";
const STUN_WAIT: Duration = Duration::from_millis(1_500);
/// NAT mappings for UDP are dropped after 30 s or more of silence; refresh well before that.
const KEEPALIVE: Duration = Duration::from_secs(15);
const INVITE_LIFETIME: Duration = Duration::from_secs(20 * 60);
/// How long both sides keep punching and connecting after the answer is entered.
const TUNNEL_TIMEOUT_MS: u64 = 180_000;
const ATTEMPT_MS: u64 = 3_000;
/// Too short to be a QUIC packet, so the peer's QUIC endpoint drops it unanswered.
const PUNCH: &[u8] = b"\x00UT";

type Prepared = (Vec<UdpSocket>, Vec<SocketAddr>, Arc<AtomicBool>);

// ---------------------------------------------------------------- codes

struct Code {
    nonce: [u8; 4],
    addrs: Vec<SocketAddr>,
    key: Option<[u8; CODE_KEY_HASH_LEN]>,
}

fn encode(prefix: &str, nonce: &[u8; 4], addrs: &[SocketAddr], key: Option<&[u8]>) -> String {
    let mut data = vec![VERSION];
    data.extend_from_slice(nonce);
    data.push(addrs.len() as u8);
    for a in addrs {
        push_ip(&mut data, &a.ip());
        data.extend_from_slice(&a.port().to_be_bytes());
    }
    if let Some(pk) = key {
        data.extend_from_slice(&key_hash(pk));
    }
    format!("{}{}", prefix, b32_encode(&data))
}

fn decode(prefix: &str, code: &str) -> Option<Code> {
    let code: String = code.chars().filter(|c| !c.is_whitespace() && *c != '-').collect();
    if !code.is_ascii() || code.len() < 12 || !code[..2].eq_ignore_ascii_case(prefix) {
        return None;
    }
    let data = b32_decode(&code[2..])?;
    if *data.first()? != VERSION {
        return None;
    }
    let nonce: [u8; 4] = data.get(1..5)?.try_into().ok()?;
    let n = *data.get(5)? as usize;
    let mut at = 6;
    let mut addrs = Vec::new();
    for _ in 0..n {
        let (ip, len) = take_ip(data.get(at..)?)?;
        at += len;
        let port = u16::from_be_bytes([*data.get(at)?, *data.get(at + 1)?]);
        at += 2;
        addrs.push(SocketAddr::new(ip, port));
    }
    let key = if prefix == INVITE_PREFIX {
        let k: [u8; CODE_KEY_HASH_LEN] = data.get(at..at + CODE_KEY_HASH_LEN)?.try_into().ok()?;
        at += CODE_KEY_HASH_LEN;
        Some(k)
    } else {
        None
    };
    if at != data.len() || addrs.is_empty() {
        return None;
    }
    Some(Code { nonce, addrs, key })
}

/// True for an invite code ("UT..."), which the controller enters like an ID.
pub fn is_invite(code: &str) -> bool {
    decode(INVITE_PREFIX, code).is_some()
}

fn list(addrs: &[SocketAddr]) -> String {
    addrs.iter().map(|a| a.to_string()).collect::<Vec<_>>().join(", ")
}

// ---------------------------------------------------------------- STUN (RFC 5389)

const MAGIC: [u8; 4] = [0x21, 0x12, 0xa4, 0x42];

fn stun_request(txid: &[u8; 12]) -> [u8; 20] {
    let mut r = [0u8; 20];
    r[1] = 0x01; // Binding request, no attributes
    r[4..8].copy_from_slice(&MAGIC);
    r[8..20].copy_from_slice(txid);
    r
}

fn parse_stun(buf: &[u8], txid: &[u8; 12]) -> Option<SocketAddr> {
    if buf.len() < 20 || buf[0..2] != [0x01, 0x01] || buf[4..8] != MAGIC || &buf[8..20] != txid {
        return None;
    }
    let mut plain = None;
    let mut at = 20;
    while at + 4 <= buf.len() {
        let kind = u16::from_be_bytes([buf[at], buf[at + 1]]);
        let len = u16::from_be_bytes([buf[at + 2], buf[at + 3]]) as usize;
        let v = buf.get(at + 4..at + 4 + len)?;
        at += 4 + ((len + 3) & !3);
        if (kind != 0x0020 && kind != 0x0001) || v.len() < 8 {
            continue;
        }
        let xor = kind == 0x0020;
        let mut port = u16::from_be_bytes([v[2], v[3]]);
        if xor {
            port ^= 0x2112;
        }
        let ip = match v[1] {
            1 => {
                let mut o: [u8; 4] = v[4..8].try_into().ok()?;
                if xor {
                    for i in 0..4 {
                        o[i] ^= MAGIC[i];
                    }
                }
                IpAddr::V4(Ipv4Addr::from(o))
            }
            2 if v.len() >= 20 => {
                let mut o: [u8; 16] = v[4..20].try_into().ok()?;
                if xor {
                    let mut mask = [0u8; 16];
                    mask[..4].copy_from_slice(&MAGIC);
                    mask[4..].copy_from_slice(txid);
                    for i in 0..16 {
                        o[i] ^= mask[i];
                    }
                }
                IpAddr::V6(Ipv6Addr::from(o))
            }
            _ => continue,
        };
        let a = SocketAddr::new(ip, port);
        if xor {
            return Some(a);
        }
        plain = Some(a);
    }
    plain
}

fn stun_servers() -> Vec<String> {
    let custom = Config::get_option(OPTION_STUN);
    if custom.trim().is_empty() {
        STUN_SERVERS.iter().map(|s| s.to_string()).collect()
    } else {
        custom.split(',').map(|s| s.trim().to_owned()).filter(|s| !s.is_empty()).collect()
    }
}

/// Asks every STUN server at once, from `socket`, what external IPv4 address it sees.
/// Returns the distinct answers and the first server that answered (for keep-alives).
fn stun_v4(socket: &UdpSocket) -> (Vec<SocketAddr>, Option<SocketAddr>) {
    let mut asked = Vec::new();
    for name in stun_servers() {
        let Some(server) = name.to_socket_addrs().ok().and_then(|mut it| it.find(|a| a.is_ipv4()))
        else {
            crate::ultra_diag::note("STUN", format!("{}: cannot resolve", name));
            continue;
        };
        let txid: [u8; 12] = rand::random();
        if socket.send_to(&stun_request(&txid), server).is_ok() {
            asked.push((name, server, txid));
        }
    }
    let mut found: Vec<SocketAddr> = Vec::new();
    let mut first = None;
    let deadline = Instant::now() + STUN_WAIT;
    let mut buf = [0u8; 512];
    let mut answered = 0;
    while answered < asked.len() {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() || socket.set_read_timeout(Some(left)).is_err() {
            break;
        }
        let Ok((n, from)) = socket.recv_from(&mut buf) else {
            break;
        };
        let Some((name, server, txid)) = asked.iter().find(|(_, s, _)| *s == from) else {
            continue;
        };
        if let Some(mapped) = parse_stun(&buf[..n], txid) {
            answered += 1;
            crate::ultra_diag::note("STUN", format!("{} sees this device as {}", name, mapped));
            first.get_or_insert(*server);
            if !found.contains(&mapped) {
                found.push(mapped);
            }
        }
    }
    socket.set_read_timeout(None).ok();
    if asked.is_empty() || found.is_empty() {
        crate::ultra_diag::note(
            "STUN",
            "no STUN server answered (blocked?): only LAN and IPv6 addresses go in the code",
        );
    } else if found.iter().any(|a| a.port() != found[0].port()) {
        crate::ultra_diag::note(
            "HINT",
            "this network changes the external port for every destination (symmetric NAT, typical \
             of mobile operators and some offices): punching through it often fails. Use another \
             network (home Wi-Fi), or IPv6 on both sides",
        );
    }
    (found, first)
}

/// Keeps the NAT mapping of `socket` alive while the codes are being passed around.
fn keep_alive(socket: &UdpSocket, server: Option<SocketAddr>) -> Arc<AtomicBool> {
    let stop = Arc::new(AtomicBool::new(false));
    if let (Some(server), Ok(s)) = (server, socket.try_clone()) {
        let stop = stop.clone();
        std::thread::spawn(move || {
            let started = Instant::now();
            let mut sent = Instant::now();
            while !stop.load(Ordering::SeqCst) && started.elapsed() < INVITE_LIFETIME {
                std::thread::sleep(Duration::from_secs(1));
                if sent.elapsed() >= KEEPALIVE {
                    sent = Instant::now();
                    let txid: [u8; 12] = rand::random();
                    s.send_to(&stun_request(&txid), server).ok();
                }
            }
        });
    }
    stop
}

/// Fresh sockets (IPv4, and IPv6 when this device has a global address) and every address the
/// peer can try: the external one(s) from STUN, the LAN one and the global IPv6 one.
fn prepare(want_v6: bool) -> ResultType<Prepared> {
    let v4 = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?;
    let port4 = v4.local_addr()?.port();
    let (mut addrs, stun_server) = stun_v4(&v4);
    if let Some(ip @ IpAddr::V4(_)) = outgoing_ip("0.0.0.0:0", "8.8.8.8:80") {
        let lan = SocketAddr::new(ip, port4);
        if !ip.is_unspecified() && !addrs.contains(&lan) {
            addrs.push(lan);
        }
    }
    let stop = keep_alive(&v4, stun_server);
    let mut sockets = vec![v4];
    if want_v6 {
        if let Some(ip) = crate::ultra_pin::my_global_ipv6() {
            match UdpSocket::bind((ip, 0)) {
                Ok(v6) => {
                    addrs.push(SocketAddr::new(IpAddr::V6(ip), v6.local_addr()?.port()));
                    sockets.push(v6);
                }
                Err(e) => crate::ultra_diag::note("TUNNEL", format!("IPv6 socket: {}", e)),
            }
        }
    }
    if addrs.is_empty() {
        bail!("this device has no usable address (no network?)");
    }
    if addrs.len() > 8 {
        addrs.truncate(8);
    }
    Ok((sockets, addrs, stop))
}

/// Sends punch packets from `sockets` to every address of the same family until `stop`.
fn punch(sockets: &[UdpSocket], peer: &[SocketAddr], stop: Arc<AtomicBool>) {
    let pairs: Vec<(UdpSocket, SocketAddr)> = sockets
        .iter()
        .filter_map(|s| s.try_clone().ok())
        .flat_map(|s| {
            let v4 = s.local_addr().map(|a| a.is_ipv4()).unwrap_or(true);
            peer.iter()
                .filter(move |a| a.is_ipv4() == v4)
                .filter_map(move |a| s.try_clone().ok().map(|s| (s, *a)))
                .collect::<Vec<_>>()
        })
        .collect();
    std::thread::spawn(move || {
        let started = Instant::now();
        while !stop.load(Ordering::SeqCst)
            && started.elapsed() < Duration::from_millis(TUNNEL_TIMEOUT_MS)
        {
            for (s, a) in &pairs {
                s.send_to(PUNCH, a).ok();
            }
            // Dense at first, while the controller is most likely retrying, then sparse.
            let pause = if started.elapsed() < Duration::from_secs(30) { 200 } else { 1_000 };
            std::thread::sleep(Duration::from_millis(pause));
        }
    });
}

// ---------------------------------------------------------------- PC side (controlled)

struct Invite {
    nonce: [u8; 4],
    code: String,
    sockets: Vec<UdpSocket>,
    stop: Arc<AtomicBool>,
    made: Instant,
}

struct Host {
    /// What the tunnel window shows: "", "preparing", "invite:CODE", "badanswer:CODE" (the
    /// invite is still open), "waiting:CODE", "connected:ADDR", "closed", "error:TEXT".
    state: String,
    invite: Option<Invite>,
}

static HOST: Mutex<Host> = Mutex::new(Host {
    state: String::new(),
    invite: None,
});
static SERVICE: Mutex<Option<(crate::server::ServerPtr, tokio::runtime::Handle)>> =
    Mutex::new(None);

/// Called once where the service starts: incoming tunnels are handed to this server.
pub fn set_server(server: crate::server::ServerPtr) {
    *SERVICE.lock().unwrap_or_else(|e| e.into_inner()) =
        Some((server, tokio::runtime::Handle::current()));
}

fn set_state(s: String) {
    HOST.lock().unwrap_or_else(|e| e.into_inner()).state = s;
}

/// The state the PC's tunnel window shows (see `Host::state`).
pub fn host_state() -> String {
    let mut h = HOST.lock().unwrap_or_else(|e| e.into_inner());
    if h.invite.as_ref().map(|i| i.made.elapsed() > INVITE_LIFETIME) == Some(true) {
        h.invite = None;
        h.state = "error:the invite code expired; open the tunnel window again".to_owned();
    }
    h.state.clone()
}

/// Makes a new invite code (in the background; poll `host_state`).
pub fn host_invite() {
    {
        let mut h = HOST.lock().unwrap_or_else(|e| e.into_inner());
        if h.state == "preparing" {
            return;
        }
        if let Some(i) = h.invite.take() {
            i.stop.store(true, Ordering::SeqCst);
        }
        h.state = "preparing".to_owned();
    }
    std::thread::spawn(|| {
        if crate::rendezvous_mediator::ultra_direct_advert().is_empty() {
            set_state("error:direct access is off (Settings → Security → Enable direct IP access)".to_owned());
            return;
        }
        crate::ultra_diag::note("TUNNEL", "making an invite code");
        match prepare(true) {
            Ok((sockets, addrs, stop)) => {
                let nonce: [u8; 4] = rand::random();
                let code = encode(INVITE_PREFIX, &nonce, &addrs, Some(Config::get_key_pair().1.as_slice()));
                crate::ultra_diag::note("TUNNEL", format!("invite code addresses: {}", list(&addrs)));
                let mut h = HOST.lock().unwrap_or_else(|e| e.into_inner());
                h.state = format!("invite:{}", code);
                h.invite = Some(Invite {
                    nonce,
                    code,
                    sockets,
                    stop,
                    made: Instant::now(),
                });
            }
            Err(e) => {
                crate::ultra_diag::note("TUNNEL", format!("cannot make an invite: {}", e));
                set_state(format!("error:{}", e));
            }
        }
    });
}

/// Takes the controller's answer code: starts punching towards it and accepts its connection.
pub fn host_accept(answer: &str) {
    let ans = decode(ANSWER_PREFIX, answer);
    let invite = {
        let mut h = HOST.lock().unwrap_or_else(|e| e.into_inner());
        let open = h.invite.as_ref().map(|i| (i.nonce, i.code.clone()));
        match (open, ans.as_ref()) {
            (Some((nonce, _)), Some(a)) if nonce == a.nonce => {}
            (Some((_, code)), _) => {
                // Not a valid answer, or one made for an older invite: the invite stays open.
                h.state = format!("badanswer:{}", code);
                drop(h);
                crate::ultra_diag::note(
                    "TUNNEL",
                    "the answer code is wrong or was made for an older invite (the controller must enter the invite shown now)",
                );
                return;
            }
            (None, _) => {
                h.state = "error:no invite is open; open the tunnel window again".to_owned();
                return;
            }
        }
        let Some(i) = h.invite.take() else { return };
        h.state = format!("waiting:{}", i.code);
        i
    };
    let Some((server, handle)) = SERVICE.lock().unwrap_or_else(|e| e.into_inner()).clone() else {
        set_state("error:the service is not running".to_owned());
        return;
    };
    let Some(ans) = ans else { return };
    invite.stop.store(true, Ordering::SeqCst);
    crate::ultra_diag::note(
        "TUNNEL",
        format!("answer accepted; punching towards {} for up to {} s", list(&ans.addrs), TUNNEL_TIMEOUT_MS / 1000),
    );
    let stop = Arc::new(AtomicBool::new(false));
    punch(&invite.sockets, &ans.addrs, stop.clone());
    let sockets = invite.sockets;
    handle.spawn(async move {
        // Inside the runtime: the QUIC endpoints spawn their drivers on it.
        let listener = match hbb_common::quic::Listener::on_sockets(sockets) {
            Ok(l) => l,
            Err(e) => {
                stop.store(true, Ordering::SeqCst);
                set_state(format!("error:{}", e));
                return;
            }
        };
        let accepted = hbb_common::timeout(TUNNEL_TIMEOUT_MS, listener.accept()).await;
        stop.store(true, Ordering::SeqCst);
        let Ok(Some((stream, addr))) = accepted else {
            crate::ultra_diag::note(
                "TUNNEL",
                "nobody got through in time: see the controller's log; with symmetric NAT on both sides punching cannot work",
            );
            set_state("error:no connection came through the tunnel in time".to_owned());
            return;
        };
        crate::ultra_diag::note("IN", format!("{}: incoming through the P2P tunnel", addr));
        set_state(format!("connected:{}", addr));
        if let Err(e) = crate::server::create_tcp_connection(
            server,
            Stream::Tcp(stream),
            addr,
            true,
            crate::server::ConnectionMeta::default(),
        )
        .await
        {
            crate::ultra_diag::note("IN", format!("{}: dropped: {}", addr, e));
        }
        // The session is over: the tunnel goes with it.
        drop(listener);
        set_state("closed".to_owned());
    });
}

// ---------------------------------------------------------------- controller side

struct Pending {
    nonce: [u8; 4],
    answer: String,
    sockets: Vec<UdpSocket>,
    stop: Arc<AtomicBool>,
}

static PENDING: Mutex<Option<Pending>> = Mutex::new(None);

/// The answer code for an invite (blocking: asks the STUN servers). The sockets behind it are
/// kept for `connect`, which uses them so the NAT mappings named in the answer are the ones used.
pub fn answer_for(invite: &str) -> ResultType<String> {
    let Some(inv) = decode(INVITE_PREFIX, invite) else {
        bail!("not an invite code");
    };
    if let Some(p) = PENDING.lock().unwrap_or_else(|e| e.into_inner()).as_ref() {
        if p.nonce == inv.nonce {
            return Ok(p.answer.clone());
        }
    }
    crate::ultra_diag::note("TUNNEL", format!("invite addresses: {}", list(&inv.addrs)));
    let (sockets, addrs, stop) = prepare(inv.addrs.iter().any(|a| a.is_ipv6()))?;
    let answer = encode(ANSWER_PREFIX, &inv.nonce, &addrs, None);
    crate::ultra_diag::note("TUNNEL", format!("answer code addresses: {}", list(&addrs)));
    let old = PENDING.lock().unwrap_or_else(|e| e.into_inner()).replace(Pending {
        nonce: inv.nonce,
        answer: answer.clone(),
        sockets,
        stop,
    });
    if let Some(old) = old {
        old.stop.store(true, Ordering::SeqCst);
    }
    Ok(answer)
}

/// Connects through the tunnel an invite code describes. Keeps trying every address of the
/// invite for up to three minutes, while the PC owner pastes the answer code.
pub async fn connect(invite: &str) -> ResultType<(Stream, Vec<u8>, &'static str)> {
    use hbb_common::futures::stream::{FuturesUnordered, StreamExt};
    let Some(inv) = decode(INVITE_PREFIX, invite) else {
        bail!("not an invite code");
    };
    let Some(key) = inv.key else {
        bail!("not an invite code");
    };
    let taken = {
        let mut p = PENDING.lock().unwrap_or_else(|e| e.into_inner());
        if p.as_ref().map(|p| p.nonce) == Some(inv.nonce) {
            p.take()
        } else {
            None
        }
    };
    let pending = match taken {
        Some(p) => p,
        None => {
            // Entered without the answer step (e.g. from the recent list): make the answer now;
            // it is in the log for the PC owner.
            let code = invite.to_owned();
            let answer = tokio::task::spawn_blocking(move || answer_for(&code)).await??;
            crate::ultra_diag::note("TUNNEL", format!("send this answer code to the PC owner: {}", answer));
            match PENDING.lock().unwrap_or_else(|e| e.into_inner()).take() {
                Some(p) => p,
                None => bail!("the tunnel could not be prepared"),
            }
        }
    };
    let mut endpoints = Vec::new();
    for s in pending.sockets {
        let v4 = s.local_addr().map(|a| a.is_ipv4()).unwrap_or(true);
        endpoints.push((v4, hbb_common::quic::client_endpoint_on(s)?));
    }
    pending.stop.store(true, Ordering::SeqCst);
    let pin_name = format!("tunnel:{}", hex_of(&key));
    crate::ultra_diag::note(
        "TUNNEL",
        format!(
            "connecting to {} until the PC accepts the answer code (up to {} s)",
            list(&inv.addrs),
            TUNNEL_TIMEOUT_MS / 1000
        ),
    );
    let started = Instant::now();
    let mut tries: FuturesUnordered<_> = inv
        .addrs
        .iter()
        .filter_map(|addr| {
            let ep = endpoints.iter().find(|(v4, _)| *v4 == addr.is_ipv4())?.1.clone();
            let addr = *addr;
            let pin_name = pin_name.clone();
            Some(async move {
                let mut reported = false;
                loop {
                    let r = async {
                        let mut s = Stream::Tcp(hbb_common::quic::connect_from(&ep, addr, ATTEMPT_MS).await?);
                        let pk = crate::ultra_pin::secure_direct_connection(&pin_name, None, Some(key), &mut s).await?;
                        Ok::<_, hbb_common::anyhow::Error>((s, pk, "P2P tunnel"))
                    }
                    .await;
                    match r {
                        Ok(x) => return Ok((addr, x)),
                        Err(e) if e.to_string().starts_with("SECURITY") => return Err(e),
                        Err(e) => {
                            if !reported {
                                reported = true;
                                crate::ultra_diag::note("TUNNEL", format!("{}: {} (retrying)", addr, e));
                            }
                        }
                    }
                    tokio::time::sleep(Duration::from_millis(300)).await;
                }
            })
        })
        .collect();
    if tries.is_empty() {
        bail!("the invite has no address this device can use (IPv6 only?)");
    }
    let run = async {
        let mut security = None;
        while let Some(r) = tries.next().await {
            match r {
                Ok(x) => return Ok(x),
                Err(e) => security = Some(e),
            }
        }
        Err(security.unwrap_or_else(|| hbb_common::anyhow::anyhow!("ultra-unreachable-tip")))
    };
    match hbb_common::timeout(TUNNEL_TIMEOUT_MS, run).await {
        Ok(Ok((addr, x))) => {
            crate::ultra_diag::note(
                "OK",
                format!("P2P tunnel to {} in {} ms", addr, crate::ultra_diag::ms(started)),
            );
            log::info!("P2P tunnel to {}", addr);
            Ok(x)
        }
        Ok(Err(e)) => Err(e),
        Err(_) => {
            crate::ultra_diag::note(
                "FAIL",
                "the tunnel did not open: was the answer code pasted on the PC in time? If it was, \
                 one of the networks blocks punching (symmetric NAT, see the HINT lines)",
            );
            bail!("ultra-tunnel-failed-tip")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_round_trip() {
        let addrs: Vec<SocketAddr> = vec![
            "203.0.113.7:51234".parse().unwrap(),
            "192.168.1.11:40000".parse().unwrap(),
            "[2a01:db8::7]:40001".parse().unwrap(),
        ];
        let nonce = [1, 2, 3, 4];
        let invite = encode(INVITE_PREFIX, &nonce, &addrs, Some(b"key"));
        let c = decode(INVITE_PREFIX, &invite).unwrap();
        assert_eq!(c.addrs, addrs);
        assert_eq!(c.nonce, nonce);
        assert_eq!(c.key, Some(key_hash(b"key")));
        assert!(is_invite(&invite.to_lowercase()));
        let answer = encode(ANSWER_PREFIX, &nonce, &addrs[..1], None);
        assert_eq!(decode(ANSWER_PREFIX, &answer).unwrap().addrs, addrs[..1]);
        assert!(!is_invite(&answer));
        assert!(crate::ultra_pin::decode_connection_code(&invite).is_none());
    }

    #[test]
    fn parses_xor_mapped_address() {
        let txid = [7u8; 12];
        let mut r = vec![0x01, 0x01, 0, 12];
        r.extend_from_slice(&MAGIC);
        r.extend_from_slice(&txid);
        r.extend_from_slice(&[0x00, 0x20, 0, 8, 0, 1]);
        r.extend_from_slice(&(51234u16 ^ 0x2112).to_be_bytes());
        let ip = [203u8, 0, 113, 7];
        for i in 0..4 {
            r.push(ip[i] ^ MAGIC[i]);
        }
        assert_eq!(parse_stun(&r, &txid), Some("203.0.113.7:51234".parse().unwrap()));
        assert_eq!(parse_stun(&r, &[0u8; 12]), None);
    }

    #[tokio::test]
    async fn tunnel_over_loopback() {
        let server_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = server_sock.local_addr().unwrap();
        let listener = hbb_common::quic::Listener::on_sockets(vec![server_sock]).unwrap();
        let client = hbb_common::quic::client_endpoint_on(UdpSocket::bind("127.0.0.1:0").unwrap()).unwrap();
        let server = tokio::spawn(async move { listener.accept().await.map(|x| x.1) });
        hbb_common::quic::connect_from(&client, addr, 5_000).await.unwrap();
        assert!(server.await.unwrap().is_some());
    }
}
