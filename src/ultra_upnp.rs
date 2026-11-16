//! Ultra RustDesk: UPnP IGD port mapping for the direct-access port.
//!
//! Asks the home router (when it speaks UPnP) to forward the direct port, TCP and UDP, to this
//! device, so it can be reached from outside without a manual port forward. The mapping is
//! renewed while direct access stays on. Turn it off with the option `enable-ultra-upnp = N`.
//!
//! Plain HTTP/1.1 + SOAP over std sockets, on its own thread: no new dependencies and nothing
//! blocking the async runtime.

use hbb_common::{bail, config::Config, log, ResultType};
use std::{
    io::{Read, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, UdpSocket},
    sync::atomic::{AtomicU16, Ordering},
    time::Duration,
};

pub const OPTION_ENABLE_UPNP: &str = "enable-ultra-upnp";
const LEASE_SECS: u32 = 3600;
const RENEW_EVERY: Duration = Duration::from_secs(1500);
const IO_TIMEOUT: Duration = Duration::from_secs(3);
const SEARCH_TARGETS: [&str; 2] = [
    "urn:schemas-upnp-org:device:InternetGatewayDevice:1",
    "urn:schemas-upnp-org:device:InternetGatewayDevice:2",
];
const SERVICE_TYPES: [&str; 3] = [
    "urn:schemas-upnp-org:service:WANIPConnection:2",
    "urn:schemas-upnp-org:service:WANIPConnection:1",
    "urn:schemas-upnp-org:service:WANPPPConnection:1",
];

/// The port the mapping thread is keeping open; 0 when none.
static MAPPED_PORT: AtomicU16 = AtomicU16::new(0);

fn enabled() -> bool {
    hbb_common::config::option2bool(OPTION_ENABLE_UPNP, &Config::get_option(OPTION_ENABLE_UPNP))
}

/// Keeps `port` mapped on the router until `still_wanted()` says otherwise or the port changes.
/// Returns at once if a thread for this port is already running.
pub fn keep_mapped(port: u16, still_wanted: fn() -> u16) {
    if !enabled() || MAPPED_PORT.swap(port, Ordering::SeqCst) == port {
        return;
    }
    let spawned = std::thread::Builder::new()
        .name("ultra-upnp".to_owned())
        .spawn(move || {
            let mut gateway: Option<Gateway> = None;
            while still_wanted() == port && enabled() {
                if gateway.is_none() {
                    gateway = match Gateway::discover() {
                        Ok(g) => Some(g),
                        Err(e) => {
                            crate::ultra_diag::note("UPNP", format!("no router answered ({}): forward port {} TCP+UDP by hand for access from the internet", e, port));
                            None
                        }
                    };
                }
                if let Some(g) = gateway.as_ref() {
                    g.open_v6(port);
                    match g.map(port) {
                        Ok(()) => match g.external_ip() {
                            Ok(ip) => {
                                crate::ultra_diag::note(
                                    "UPNP",
                                    format!("port {} (TCP+UDP) forwarded, router WAN address {}", port, ip),
                                );
                                set_external_ip(&ip);
                            }
                            Err(_) => crate::ultra_diag::note("UPNP", format!("port {} (TCP+UDP) forwarded", port)),
                        },
                        Err(e) => {
                            crate::ultra_diag::note("UPNP", format!("forwarding port {} failed: {}", port, e));
                            gateway = None;
                        }
                    }
                }
                let mut slept = Duration::ZERO;
                while slept < RENEW_EVERY && still_wanted() == port && enabled() {
                    std::thread::sleep(Duration::from_secs(5));
                    slept += Duration::from_secs(5);
                }
            }
            if let Some(g) = gateway.as_ref() {
                g.unmap(port);
            }
            set_external_ip("");
            let _ = MAPPED_PORT.compare_exchange(port, 0, Ordering::SeqCst, Ordering::SeqCst);
        });
    if let Err(e) = spawned {
        log::warn!("UPnP: cannot start thread: {}", e);
        MAPPED_PORT.store(0, Ordering::SeqCst);
    }
}

/// Lets the connection code use the router's public address.
fn set_external_ip(ip: &str) {
    let valid = ip.is_empty() || ip.parse::<IpAddr>().map(|a| !a.is_unspecified()).unwrap_or(false);
    if valid && Config::get_option(crate::ultra_pin::OPTION_EXTERNAL_IP) != ip {
        Config::set_option(crate::ultra_pin::OPTION_EXTERNAL_IP.to_owned(), ip.to_owned());
    }
}

struct Gateway {
    host: SocketAddr,
    control_path: String,
    service_type: String,
    local_ip: Ipv4Addr,
    /// Control path of the router's IPv6 firewall service (IGDv2), when it has one.
    v6_firewall: Option<String>,
}

const V6_FIREWALL: &str = "urn:schemas-upnp-org:service:WANIPv6FirewallControl:1";

fn control_path_of(body: &str, service_type: &str) -> Option<String> {
    let at = body.find(&format!("<serviceType>{}</serviceType>", service_type))?;
    let rest = &body[at..];
    let end = rest.find("</service>").unwrap_or(rest.len());
    let control = between(&rest[..end], "<controlURL>", "</controlURL>")?;
    Some(if control.starts_with("http://") {
        split_url(control).ok()?.1
    } else if control.starts_with('/') {
        control.to_owned()
    } else {
        format!("/{}", control)
    })
}

impl Gateway {
    fn discover() -> ResultType<Self> {
        let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?;
        socket.set_read_timeout(Some(Duration::from_secs(2)))?;
        for st in SEARCH_TARGETS {
            let req = format!(
                "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: {}\r\n\r\n",
                st
            );
            socket.send_to(req.as_bytes(), (Ipv4Addr::new(239, 255, 255, 250), 1900))?;
        }
        let mut buf = [0u8; 2048];
        while let Ok((n, _)) = socket.recv_from(&mut buf) {
            let text = String::from_utf8_lossy(&buf[..n]);
            let Some(location) = header(&text, "location") else {
                continue;
            };
            match Self::from_location(&location) {
                Ok(g) => return Ok(g),
                Err(e) => log::debug!("UPnP: {} is not usable: {}", location, e),
            }
        }
        bail!("no UPnP internet gateway answered")
    }

    fn from_location(location: &str) -> ResultType<Self> {
        let (host, path) = split_url(location)?;
        let body = http(host, "GET", &path, &[], "")?;
        for st in SERVICE_TYPES {
            let Some(at) = body.find(&format!("<serviceType>{}</serviceType>", st)) else {
                continue;
            };
            let rest = &body[at..];
            let end = rest.find("</service>").unwrap_or(rest.len());
            let Some(control) = between(&rest[..end], "<controlURL>", "</controlURL>") else {
                continue;
            };
            let control_path = if control.starts_with("http://") {
                split_url(control)?.1
            } else if control.starts_with('/') {
                control.to_owned()
            } else {
                format!("/{}", control)
            };
            let local_ip = {
                let probe = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?;
                probe.connect(host)?;
                match probe.local_addr()?.ip() {
                    IpAddr::V4(ip) => ip,
                    IpAddr::V6(_) => bail!("gateway reached over IPv6"),
                }
            };
            return Ok(Self {
                host,
                control_path,
                service_type: st.to_owned(),
                local_ip,
                v6_firewall: control_path_of(&body, V6_FIREWALL),
            });
        }
        bail!("no WAN connection service in the device description")
    }

    fn soap(&self, action: &str, args: &str) -> ResultType<String> {
        let body = format!(
            "<?xml version=\"1.0\"?>\r\n<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><s:Body><u:{action} xmlns:u=\"{st}\">{args}</u:{action}></s:Body></s:Envelope>",
            action = action,
            st = self.service_type,
            args = args
        );
        let soap_action = format!("\"{}#{}\"", self.service_type, action);
        http(
            self.host,
            "POST",
            &self.control_path,
            &[
                ("Content-Type", "text/xml; charset=\"utf-8\""),
                ("SOAPAction", &soap_action),
            ],
            &body,
        )
    }

    fn map(&self, port: u16) -> ResultType<()> {
        for proto in ["TCP", "UDP"] {
            let args = format!(
                "<NewRemoteHost></NewRemoteHost><NewExternalPort>{port}</NewExternalPort><NewProtocol>{proto}</NewProtocol><NewInternalPort>{port}</NewInternalPort><NewInternalClient>{ip}</NewInternalClient><NewEnabled>1</NewEnabled><NewPortMappingDescription>Ultra RustDesk</NewPortMappingDescription><NewLeaseDuration>{lease}</NewLeaseDuration>",
                port = port,
                proto = proto,
                ip = self.local_ip,
                lease = LEASE_SECS
            );
            self.soap("AddPortMapping", &args)?;
        }
        Ok(())
    }

    /// Asks the router to let incoming IPv6 to this device's global address and `port` through
    /// its firewall (TCP and UDP). Most routers block incoming IPv6 by default.
    fn open_v6(&self, port: u16) {
        let Some(ip) = crate::ultra_pin::my_global_ipv6() else {
            return;
        };
        let Some(path) = self.v6_firewall.as_deref() else {
            crate::ultra_diag::note(
                "UPNP",
                format!("the router has no IPv6 firewall control: if IPv6 connections fail, allow incoming port {} to {} in its IPv6 firewall", port, ip),
            );
            return;
        };
        for (name, proto) in [("TCP", 6), ("UDP", 17)] {
            let args = format!(
                "<RemoteHost></RemoteHost><RemotePort>0</RemotePort><InternalClient>{ip}</InternalClient><InternalPort>{port}</InternalPort><Protocol>{proto}</Protocol><LeaseTime>{lease}</LeaseTime>",
                ip = ip,
                port = port,
                proto = proto,
                lease = LEASE_SECS
            );
            let body = format!(
                "<?xml version=\"1.0\"?>\r\n<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><s:Body><u:AddPinhole xmlns:u=\"{st}\">{args}</u:AddPinhole></s:Body></s:Envelope>",
                st = V6_FIREWALL,
                args = args
            );
            let soap_action = format!("\"{}#AddPinhole\"", V6_FIREWALL);
            match http(
                self.host,
                "POST",
                path,
                &[
                    ("Content-Type", "text/xml; charset=\"utf-8\""),
                    ("SOAPAction", &soap_action),
                ],
                &body,
            ) {
                Ok(_) => crate::ultra_diag::note(
                    "UPNP",
                    format!("IPv6 firewall opened: {} [{}]:{}", name, ip, port),
                ),
                Err(e) => crate::ultra_diag::note(
                    "UPNP",
                    format!("the router refused to open IPv6 {} [{}]:{}: {}", name, ip, port, e),
                ),
            }
        }
    }

    fn unmap(&self, port: u16) {
        for proto in ["TCP", "UDP"] {
            let args = format!(
                "<NewRemoteHost></NewRemoteHost><NewExternalPort>{}</NewExternalPort><NewProtocol>{}</NewProtocol>",
                port, proto
            );
            if let Err(e) = self.soap("DeletePortMapping", &args) {
                log::debug!("UPnP: removing {} mapping of {} failed: {}", proto, port, e);
            }
        }
    }

    fn external_ip(&self) -> ResultType<String> {
        let body = self.soap("GetExternalIPAddress", "")?;
        between(&body, "<NewExternalIPAddress>", "</NewExternalIPAddress>")
            .map(|s| s.trim().to_owned())
            .ok_or_else(|| hbb_common::anyhow::anyhow!("no external address in reply"))
    }
}

fn header(text: &str, name: &str) -> Option<String> {
    text.lines().find_map(|l| {
        let (k, v) = l.split_once(':')?;
        (k.trim().eq_ignore_ascii_case(name)).then(|| v.trim().to_owned())
    })
}

fn between<'a>(s: &'a str, start: &str, end: &str) -> Option<&'a str> {
    let a = s.find(start)? + start.len();
    let b = s[a..].find(end)? + a;
    Some(&s[a..b])
}

/// Splits `http://host:port/path` into the address and the path. Only plain HTTP to a literal
/// IPv4 address is accepted, which is what gateways advertise on the LAN.
fn split_url(url: &str) -> ResultType<(SocketAddr, String)> {
    let Some(rest) = url.strip_prefix("http://") else {
        bail!("not a plain HTTP URL: {}", url);
    };
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], rest[i..].to_owned()),
        None => (rest, "/".to_owned()),
    };
    let addr: SocketAddr = if authority.contains(':') {
        authority.parse()?
    } else {
        SocketAddr::new(authority.parse()?, 80)
    };
    if !addr.ip().is_ipv4() || addr.ip().is_loopback() {
        bail!("unexpected gateway address {}", addr);
    }
    Ok((addr, path))
}

fn http(
    host: SocketAddr,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &str,
) -> ResultType<String> {
    let mut stream = TcpStream::connect_timeout(&host, IO_TIMEOUT)?;
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    let mut req = format!(
        "{} {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nContent-Length: {}\r\n",
        method,
        path,
        host,
        body.len()
    );
    for (k, v) in headers {
        req.push_str(&format!("{}: {}\r\n", k, v));
    }
    req.push_str("\r\n");
    req.push_str(body);
    stream.write_all(req.as_bytes())?;
    let mut raw = Vec::new();
    // A router's reply is a few KB; cap it so a misbehaving device cannot make us buffer more.
    stream.take(256 * 1024).read_to_end(&mut raw)?;
    let Some(split) = raw.windows(4).position(|w| w == b"\r\n\r\n") else {
        bail!("malformed HTTP reply");
    };
    let head = String::from_utf8_lossy(&raw[..split]).into_owned();
    let payload = &raw[split + 4..];
    let status = head.lines().next().unwrap_or_default();
    if !status.contains(" 200 ") {
        bail!("{}", status);
    }
    let chunked = header(&head, "transfer-encoding")
        .map(|v| v.eq_ignore_ascii_case("chunked"))
        .unwrap_or(false);
    let body = if chunked {
        dechunk(payload)
    } else {
        payload.to_vec()
    };
    Ok(String::from_utf8_lossy(&body).into_owned())
}

fn dechunk(mut s: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    while let Some(eol) = s.windows(2).position(|w| w == b"\r\n") {
        let size = String::from_utf8_lossy(&s[..eol]).into_owned();
        let Ok(n) = usize::from_str_radix(size.split(';').next().unwrap_or("").trim(), 16) else {
            break;
        };
        let rest = &s[eol + 2..];
        if n == 0 {
            break;
        }
        if rest.len() < n {
            out.extend_from_slice(rest);
            break;
        }
        out.extend_from_slice(&rest[..n]);
        s = rest[n..].strip_prefix(b"\r\n").unwrap_or(&rest[n..]);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_gateway_url() {
        let (addr, path) = split_url("http://192.168.1.1:5000/rootDesc.xml").unwrap();
        assert_eq!(addr, "192.168.1.1:5000".parse().unwrap());
        assert_eq!(path, "/rootDesc.xml");
        assert!(split_url("https://192.168.1.1/x").is_err());
    }

    #[test]
    fn decodes_chunked_body() {
        assert_eq!(dechunk(b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n"), b"hello world");
    }
}
