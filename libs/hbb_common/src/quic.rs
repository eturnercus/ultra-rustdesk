//! Ultra RustDesk: QUIC transport for direct connections.
//!
//! One QUIC connection carries one bidirectional stream, wrapped so it looks like a TCP stream
//! to the rest of the code base (`tcp::FramedStream`). Everything above it, the end-to-end
//! key exchange included, is unchanged: QUIC's own TLS is only an outer layer that makes the
//! traffic look like ordinary HTTP/3. Peer authentication is done by the inner handshake
//! (pinned Ed25519 keys), which is why the client accepts any QUIC certificate.
//!
//! Tuned for latency: BBR congestion control, large flow-control windows so a video burst is
//! never throttled by the receiver, and short keep-alives so NAT mappings stay open.

use crate::{bail, tcp::FramedStream, ResultType};
use quinn::{
    congestion::BbrConfig,
    crypto::rustls::{QuicClientConfig, QuicServerConfig},
    rustls::{
        self,
        client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
        crypto::{ring::default_provider, verify_tls12_signature, verify_tls13_signature, CryptoProvider},
        pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime},
        DigitallySignedStruct, SignatureScheme,
    },
    Endpoint, IdleTimeout, RecvStream, SendStream, TransportConfig, VarInt,
};
use std::convert::TryFrom;
use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::{mpsc, Mutex},
};

/// Looks like HTTP/3 to anything that inspects the handshake.
const ALPN: &[u8] = b"h3";
/// Sent by the client right after opening the stream: QUIC only announces a stream to the peer
/// once data flows on it, and the controlled side speaks first in the handshake above us.
const PREAMBLE: &[u8; 8] = b"URDq\x00\x01\x00\x00";
/// SNI the client presents. Any name works: the certificate is not checked by name.
pub const DEFAULT_SNI: &str = "www.bing.com";

fn provider() -> Arc<CryptoProvider> {
    Arc::new(default_provider())
}

fn transport_config() -> TransportConfig {
    let mut t = TransportConfig::default();
    t.congestion_controller_factory(Arc::new(BbrConfig::default()));
    t.keep_alive_interval(Some(Duration::from_secs(4)));
    t.max_idle_timeout(Some(IdleTimeout::from(VarInt::from_u32(30_000))));
    // Video comes in bursts of a whole frame; never make the sender wait for window updates.
    t.stream_receive_window(VarInt::from_u32(16 * 1024 * 1024));
    t.receive_window(VarInt::from_u32(32 * 1024 * 1024));
    t.send_window(32 * 1024 * 1024);
    t.initial_rtt(Duration::from_millis(50));
    t.max_concurrent_uni_streams(VarInt::from_u32(0));
    t.max_concurrent_bidi_streams(VarInt::from_u32(4));
    t
}

/// The one stream of a QUIC connection, with the handles that keep the connection alive.
pub struct QuicIo {
    recv: RecvStream,
    send: SendStream,
    _conn: quinn::Connection,
    _endpoint: Option<Endpoint>,
}

impl AsyncRead for QuicIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        AsyncRead::poll_read(Pin::new(&mut self.recv), cx, buf)
    }
}

impl AsyncWrite for QuicIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        AsyncWrite::poll_write(Pin::new(&mut self.send), cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_flush(Pin::new(&mut self.send), cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_shutdown(Pin::new(&mut self.send), cx)
    }
}

// ---------------------------------------------------------------- client

/// Accepts any certificate but still checks the handshake signatures, so the TLS layer is sound
/// as a transport; who the peer is gets settled by the pinned-key handshake inside.
#[derive(Debug)]
struct AnyCert(Arc<CryptoProvider>);

impl ServerCertVerifier for AnyCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

fn client_config() -> ResultType<quinn::ClientConfig> {
    let provider = provider();
    let mut tls = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AnyCert(provider)))
        .with_no_client_auth();
    tls.alpn_protocols = vec![ALPN.to_vec()];
    let mut cfg = quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(tls)?));
    cfg.transport_config(Arc::new(transport_config()));
    Ok(cfg)
}

/// Opens a QUIC connection to `addr` and returns its stream framed like a TCP stream.
pub async fn connect(addr: SocketAddr, sni: &str, timeout_ms: u64) -> ResultType<FramedStream> {
    let bind: SocketAddr = if addr.is_ipv4() {
        (IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0).into()
    } else {
        (IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0).into()
    };
    let mut endpoint = Endpoint::client(bind)?;
    endpoint.set_default_client_config(client_config()?);
    let fut = async {
        let conn = endpoint.connect(addr, sni)?.await?;
        let (mut send, recv) = conn.open_bi().await?;
        send.write_all(PREAMBLE).await?;
        Ok::<_, anyhow::Error>((conn, send, recv))
    };
    let (conn, send, recv) = match crate::timeout(timeout_ms, fut).await {
        Ok(res) => res?,
        Err(_) => bail!("QUIC connect to {} timed out", addr),
    };
    let io = QuicIo {
        recv,
        send,
        _conn: conn,
        _endpoint: Some(endpoint),
    };
    Ok(FramedStream::from(io, addr))
}

/// A client endpoint on a socket that already has a NAT mapping (P2P tunnel).
pub fn client_endpoint_on(socket: std::net::UdpSocket) -> ResultType<Endpoint> {
    socket.set_nonblocking(true)?;
    let mut endpoint = Endpoint::new(
        quinn::EndpointConfig::default(),
        None,
        socket,
        Arc::new(quinn::TokioRuntime),
    )?;
    endpoint.set_default_client_config(client_config()?);
    Ok(endpoint)
}

/// One connection attempt from `endpoint`; the stream keeps the endpoint alive.
pub async fn connect_from(
    endpoint: &Endpoint,
    addr: SocketAddr,
    timeout_ms: u64,
) -> ResultType<FramedStream> {
    let fut = async {
        let conn = endpoint.connect(addr, DEFAULT_SNI)?.await?;
        let (mut send, recv) = conn.open_bi().await?;
        send.write_all(PREAMBLE).await?;
        Ok::<_, anyhow::Error>((conn, send, recv))
    };
    let (conn, send, recv) = match crate::timeout(timeout_ms, fut).await {
        Ok(res) => res?,
        Err(_) => bail!("no answer in {} ms", timeout_ms),
    };
    let io = QuicIo {
        recv,
        send,
        _conn: conn,
        _endpoint: Some(endpoint.clone()),
    };
    Ok(FramedStream::from(io, addr))
}

// ---------------------------------------------------------------- server

fn server_config() -> ResultType<quinn::ServerConfig> {
    // A fresh throwaway certificate per run: it identifies nothing (see the module docs).
    let cert = rcgen::generate_simple_self_signed(vec![DEFAULT_SNI.to_owned()])?;
    let cert_der = CertificateDer::from(cert.cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()));
    let mut tls = rustls::ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)?;
    tls.alpn_protocols = vec![ALPN.to_vec()];
    tls.max_early_data_size = 0;
    let mut cfg = quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(tls)?));
    cfg.transport_config(Arc::new(transport_config()));
    Ok(cfg)
}

type Accepted = (FramedStream, SocketAddr);

/// A QUIC listener for direct connections, on IPv4 and (when the OS allows a second socket on
/// the same port) IPv6. Handshakes run concurrently, so a stalled client cannot hold up others.
pub struct Listener {
    endpoints: Vec<Endpoint>,
    rx: Mutex<mpsc::Receiver<Accepted>>,
}

impl Listener {
    /// Listens on UDP `port` on every interface.
    pub fn bind(port: u16) -> ResultType<Self> {
        let cfg = server_config()?;
        let mut endpoints = vec![Endpoint::server(
            cfg.clone(),
            (IpAddr::V4(Ipv4Addr::UNSPECIFIED), port).into(),
        )?];
        // IPv6-only socket: a dual-stack one would clash with the IPv4 socket on the same port
        // (Linux), and the IPv6 listener would silently not start.
        match v6_only_udp(port).and_then(|socket| {
            Endpoint::new(
                quinn::EndpointConfig::default(),
                Some(cfg),
                socket,
                Arc::new(quinn::TokioRuntime),
            )
        }) {
            Ok(e) => endpoints.push(e),
            Err(e) => log::warn!("QUIC IPv6 listener not started: {}", e),
        }
        let (tx, rx) = mpsc::channel(16);
        for endpoint in &endpoints {
            let endpoint = endpoint.clone();
            let tx = tx.clone();
            tokio::spawn(async move {
                while let Some(incoming) = endpoint.accept().await {
                    let tx = tx.clone();
                    tokio::spawn(async move {
                        match crate::timeout(10_000, accept_one(incoming)).await {
                            Ok(Ok(x)) => {
                                tx.send(x).await.ok();
                            }
                            Ok(Err(e)) => log::debug!("QUIC accept failed: {}", e),
                            Err(_) => log::debug!("QUIC accept timed out"),
                        }
                    });
                }
            });
        }
        Ok(Self {
            endpoints,
            rx: Mutex::new(rx),
        })
    }

    /// A listener on sockets that already have NAT mappings (P2P tunnel).
    pub fn on_sockets(sockets: Vec<std::net::UdpSocket>) -> ResultType<Self> {
        let cfg = server_config()?;
        let mut endpoints = Vec::new();
        for socket in sockets {
            socket.set_nonblocking(true)?;
            endpoints.push(Endpoint::new(
                quinn::EndpointConfig::default(),
                Some(cfg.clone()),
                socket,
                Arc::new(quinn::TokioRuntime),
            )?);
        }
        let (tx, rx) = mpsc::channel(4);
        for endpoint in &endpoints {
            let endpoint = endpoint.clone();
            let tx = tx.clone();
            tokio::spawn(async move {
                while let Some(incoming) = endpoint.accept().await {
                    let tx = tx.clone();
                    tokio::spawn(async move {
                        match crate::timeout(10_000, accept_one(incoming)).await {
                            Ok(Ok(x)) => {
                                tx.send(x).await.ok();
                            }
                            Ok(Err(e)) => log::debug!("QUIC tunnel accept failed: {}", e),
                            Err(_) => log::debug!("QUIC tunnel accept timed out"),
                        }
                    });
                }
            });
        }
        Ok(Self {
            endpoints,
            rx: Mutex::new(rx),
        })
    }

    /// "IPv4 and IPv6" or "IPv4 only", for the connection journal.
    pub fn families(&self) -> &'static str {
        if self.endpoints.len() > 1 {
            "IPv4 and IPv6"
        } else {
            "IPv4 only"
        }
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.endpoints[0].local_addr()
    }

    /// Waits for the next connection whose client opened the stream with our preamble.
    /// Returns `None` once every endpoint is closed.
    pub async fn accept(&self) -> Option<Accepted> {
        self.rx.lock().await.recv().await
    }

    pub fn close(&self) {
        for e in &self.endpoints {
            e.close(VarInt::from_u32(0), b"");
        }
    }
}

async fn accept_one(incoming: quinn::Incoming) -> ResultType<Accepted> {
    let conn = incoming.await?;
    let addr = crate::try_into_v4(conn.remote_address());
    let (send, mut recv) = conn.accept_bi().await?;
    let mut pre = [0u8; PREAMBLE.len()];
    recv.read_exact(&mut pre).await?;
    if &pre != PREAMBLE {
        conn.close(VarInt::from_u32(0x100), b"");
        bail!("bad preamble from {}", addr);
    }
    let io = QuicIo {
        recv,
        send,
        _conn: conn,
        _endpoint: None,
    };
    Ok((FramedStream::from(io, addr), addr))
}

impl Drop for Listener {
    fn drop(&mut self) {
        self.close();
    }
}

fn v6_only_udp(port: u16) -> io::Result<std::net::UdpSocket> {
    use socket2::{Domain, Protocol, SockAddr, Socket, Type};
    let socket = Socket::new(Domain::ipv6(), Type::dgram(), Some(Protocol::udp()))?;
    socket.set_only_v6(true)?;
    socket.bind(&SockAddr::from(SocketAddr::new(
        IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        port,
    )))?;
    socket.set_nonblocking(true)?;
    Ok(socket.into_udp_socket())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;

    #[tokio::test]
    async fn loopback_round_trip() {
        let listener = Listener::bind(0).unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            // The controlled side speaks first, as in the real handshake.
            s.send_bytes(Bytes::from_static(b"hello")).await.unwrap();
            let got = s.next().await.unwrap().unwrap();
            assert_eq!(&got[..], b"world");
        });
        let addr: SocketAddr = (Ipv4Addr::LOCALHOST, port).into();
        let mut c = connect(addr, DEFAULT_SNI, 5_000).await.unwrap();
        let got = c.next().await.unwrap().unwrap();
        assert_eq!(&got[..], b"hello");
        c.send_bytes(Bytes::from_static(b"world")).await.unwrap();
        server.await.unwrap();
    }
}
