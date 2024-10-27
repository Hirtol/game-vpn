use crate::{
    hooking::_SOCKET,
    queue::{PacketQueue, PacketSocketQueue},
    socket_directory::{LocalPort, SocketDirectory, SocketOption},
};
use gbe_proxy_common::{bincode::Encode, C2SHeader, C2SMessage, Protocol, S2CHeader, S2CMessage, SocketAddrEncodable};
use papaya::Guard;
use quinn::{crypto::rustls::QuicClientConfig, ClientConfig, Connection, Endpoint, RecvStream, SendStream};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use std::{
    collections::VecDeque,
    fmt::Debug,
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
};
use windows::Win32::Networking::WinSock::{htons};
use windows_sys::Win32::Networking::WinSock::{
    AF_INET, IN_ADDR, IN_ADDR_0, IPPROTO_TCP, SOCKADDR, SOCKADDR_IN, SOCKET,
    SOCK_STREAM,
};

/// An address with our fictional ip, but possible different port(s)
pub type LocalAddress = SocketAddrEncodable;
/// An address with a different fictional ip, and possible different port(s)
pub type RemoteAddress = SocketAddrEncodable;
pub type Port = u16;

pub struct DormantClientState {
    /// Keep track of all sockets, fictional or otherwise, and update as needed
    pub dir: SocketDirectory,
}

impl DormantClientState {
    pub fn new() -> Self {
        Self {
            dir: SocketDirectory::new(),
        }
    }

    /// Handle the manual closure of a [SOCKET].
    pub fn on_close(&self, socket: SOCKET) {
        self.dir.close_socket(socket);
    }

    pub fn on_socket_bind(&self, socket: SOCKET, bind: SocketAddrEncodable) {
        let set_port = if bind.port != 0 {
            Some(bind.port)
        } else {
            // We know that `bind` has been called, so lets check what port was assigned by the OS
            self.dir.get_bound_port(socket)
        };
        let _ = self.get_or_create_address(socket, set_port);
    }

    pub fn on_socket_create(&self, socket: SOCKET, sock_type: SocketOption) {
        self.dir.on_socket_create(socket, sock_type);
    }

    /// Create a new [LocalAddress] port to associate a particular socket with.
    /// If `set_port` is `None` then it is assumed the given socket has never been bound/connected, thus a custom `bind`
    /// call will be issued to find a good port.
    ///
    /// All relevant queues are updated if a new [LocalAddress] is created
    #[tracing::instrument(skip(self))]
    fn get_or_create_address(&self, socket: SOCKET, set_port: Option<u16>) -> LocalPort {
        let socket_type = self
            .dir
            .get_or_create_socket_opt(socket)
            .expect("Could not get or create address");
        match socket_type {
            SocketOption::UDP => {
                let pin = self.dir.udp_sockets.local_socket_addr_mapping.pin();
                if let Some(existing_addr) = pin.get(&socket) {
                    *existing_addr
                } else {
                    let new_addr = set_port.unwrap_or_else(|| self.create_port(socket));
                    self.dir.udp_sockets.bind_to_port(socket, new_addr);
                    new_addr
                }
            }
            SocketOption::TCP => {
                let pin = self.dir.tcp_sockets.local_socket_addr_mapping.pin();
                if let Some(existing_addr) = pin.get(&socket) {
                    *existing_addr
                } else {
                    let new_addr = set_port.unwrap_or_else(|| self.create_port(socket));
                    self.dir.tcp_sockets.bind_to_address(socket, new_addr);
                    new_addr
                }
            }
        }
    }

    /// Unwrap the inner value, or call `bind` to assign a random port to the given socket.
    fn create_port(&self, socket: SOCKET) -> LocalPort {
        let result = unsafe {
            let mut bind_goal = SOCKADDR_IN {
                sin_family: AF_INET,
                sin_port: htons(0),
                sin_addr: IN_ADDR {
                    S_un: IN_ADDR_0 { S_addr: 0 },
                },
                sin_zero: [0; 8],
            };

            crate::hooking::_BIND.call(
                socket,
                &mut bind_goal as *mut SOCKADDR_IN as *mut SOCKADDR,
                std::mem::size_of::<SOCKADDR_IN>() as i32,
            )
        };

        let new_port = if result == 0 {
            self.dir.get_bound_port(socket)
        } else {
            None
        }
        .unwrap_or_else(|| {
            tracing::error!("Unable to assign port for socket, pretending it is the 0 port");
            0
        });

        tracing::trace!(?socket, ?new_port, "Created new local port");

        new_port
    }
}

pub struct QuicClient {
    fictional_ip: Ipv4Addr,
    endpoint: Endpoint,
    connection: Connection,
    read: tokio::sync::Mutex<RecvStream>,
    write: tokio::sync::Mutex<SendStream>,

    /// Keep track of all sockets, fictional or otherwise, and update as needed
    pub dormant: Arc<DormantClientState>,

    /// Packet queue for each socket (IP:PORT) combo
    pub packet_queue: papaya::HashMap<SOCKET, PacketSocketQueue>,
    pub accepted_queue: papaya::HashMap<SOCKET, std::sync::Mutex<VecDeque<(SOCKET, RemoteAddress)>>>,
}

impl QuicClient {
    pub async fn new(server_addr: SocketAddr, dormant_state: Arc<DormantClientState>) -> eyre::Result<Self> {
        let mut endpoint = Endpoint::client((Ipv4Addr::from_bits(0), 0).into())?;

        endpoint.set_default_client_config(ClientConfig::new(Arc::new(QuicClientConfig::try_from(
            rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(SkipServerVerification::new())
                .with_no_client_auth(),
        )?)));

        // connect to server
        let connection = endpoint.connect(server_addr, "localhost")?.await?;
        tracing::info!(addr=?connection.remote_address(), "Successfully connected");

        let (mut write, mut read) = connection.open_bi().await?;

        // Request fictional IP
        let msg = C2SHeader {
            msg_type: C2SMessage::RequestIp,
        };
        let _ = gbe_proxy_common::write_message(&mut write, msg).await?;

        let (ip, _): (S2CHeader, _) = gbe_proxy_common::read_message(&mut read, &mut Vec::new()).await?;
        let fictional_ip = match ip.msg_type {
            S2CMessage::Ip(ip_addr) => Ipv4Addr::from(ip_addr),
            _ => unreachable!(),
        };

        tracing::info!(?fictional_ip, "Received Fictional IP from server");

        Ok(Self {
            fictional_ip,
            endpoint,
            connection,
            read: tokio::sync::Mutex::new(read),
            write: tokio::sync::Mutex::new(write),
            packet_queue: Default::default(),
            accepted_queue: Default::default(),
            dormant: dormant_state,
        })
    }

    pub async fn run(&self) -> eyre::Result<()> {
        // Permanently hold the read-lock, no one else needs it
        let mut read_lock = self.read.lock().await;
        let mut buffer = Vec::new();

        loop {
            let read_message: S2CHeader = gbe_proxy_common::read_message(&mut read_lock, &mut buffer).await?.0;

            match read_message.msg_type {
                S2CMessage::Ip(_) => unreachable!(),
                S2CMessage::PassMessage {
                    from,
                    data,
                    to,
                    protocol,
                } => {
                    let receive_socket = self.dormant.dir.resolve_socket(&to, Some(&from), Some(protocol));

                    if let Some(local_socket) = receive_socket {
                        let guard = self.packet_queue.guard();
                        let queue = self.get_or_create_queue(local_socket, Some(from), &guard);
                        tracing::debug!(?from, ?to, data_len=?data.len(), ?local_socket, "Received pass message");
                        queue.enqueue_data(from, data);
                    } else {
                        tracing::warn!(?from, ?to, "No queue available for packet, dropping");
                    }
                }
                S2CMessage::PassBroadcast { from, to, data } => {
                    tracing::debug!(?from, ?to, data_len=?data.len(), "Received broadcast message");
                    let receive_socket = self.dormant.dir.resolve_socket(&to, None, Some(Protocol::UDP));

                    if let Some(receive_socket) = receive_socket {
                        let guard = self.packet_queue.guard();
                        let queue = self.get_or_create_queue(receive_socket, Some(from), &guard);
                        queue.enqueue_data(from, data);
                    } else {
                        tracing::trace!(?to, "No broadcast receive socket associated with target address");
                    }
                }
                S2CMessage::DeadClient { client } => {
                    tracing::info!(?client, "Client disconnected");
                    // self.on_disconnect(client);
                }
                S2CMessage::Connect { from, to } => {
                    tracing::debug!(?from, accept_socket=?to, "Received connect request");
                    let socket = self.dormant.dir.resolve_socket(&to, None, Some(Protocol::TCP));

                    if let Some(socket) = socket {
                        if let Some(data) = self.accept_connect_request(to, from) {
                            tracing::info!(
                                "Accepted the connection request transparently, application will still have to accept"
                            );
                            let pin = self.accepted_queue.pin();
                            let queue = pin.get_or_insert_with(socket, Default::default);
                            queue.lock().unwrap().push_back(data);
                        } else {
                            tracing::warn!("Could not accept connection request")
                        }
                    } else {
                        tracing::warn!("Had to drop connect request as no TCP socket exists which matches")
                    }
                }
            }
        }
    }

    /// Return the stored (or discovered upon call) socket type.
    pub fn get_socket_opt(&self, socket: SOCKET) -> Option<SocketOption> {
        self.dormant.dir.get_or_create_socket_opt(socket)
    }

    /// Return the associated local address for this socket.
    pub fn get_local_address(&self, socket: SOCKET) -> Option<LocalAddress> {
        self.dormant.dir.get_local_port(socket).map(|port| LocalAddress {
            ip: self.fictional_ip.octets(),
            port,
        })
    }

    /// Retrieve the associated [RemoteAddress] for a given TCP socket.
    ///
    /// If a UDP socket was passed, or the TCP socket has no connection, [None] is returned.
    pub fn get_associated_remote(&self, socket: SOCKET) -> Option<RemoteAddress> {
        self.dormant
            .dir
            .tcp_sockets
            .remote_addr_mapping
            .pin()
            .get(&socket)
            .copied()
    }

    pub async fn write_message<T: Encode + Debug>(&self, msg: T) -> eyre::Result<()> {
        tracing::trace!(?msg, "Sending message");
        let mut lock = self.write.lock().await;
        let _ = gbe_proxy_common::write_message(&mut lock, msg).await?;
        Ok(())
    }

    /// Update the internal state to send a connect request to a different fictional client to the server.
    ///
    /// Expects to only be called for addresses where `to.is_fictional()` holds.
    /// Returns the local address of this socket
    pub fn on_connect(&self, socket: SOCKET, to: RemoteAddress) -> LocalAddress {
        let local_port = self.dormant.get_or_create_address(socket, None);
        self.dormant.dir.tcp_sockets.bind_to_address(socket, local_port);
        self.dormant.dir.tcp_sockets.connect(socket, to);
        // Create a queue pre-emptively
        let _ = self.get_or_create_queue(socket, Some(to), &self.packet_queue.guard());
        LocalAddress {
            ip: self.fictional_ip.octets(),
            port: local_port,
        }
    }

    /// Handle an accept call on the given socket.
    ///
    /// If no Fictional clients wish to connect it simply returns [None]
    pub fn on_accept(&self, socket: SOCKET) -> Option<(SOCKET, RemoteAddress)> {
        let pin = self.accepted_queue.pin();
        let queue = pin.get_or_insert_with(socket, Default::default);
        let mut lock = queue.lock().unwrap();
        let (conn_socket, remote_addr) = lock.pop_front()?;
        tracing::info!(
            ?conn_socket,
            ?remote_addr,
            "Returning previously accepted fictitious request"
        );

        Some((conn_socket, remote_addr))
    }

    pub fn accept_connect_request(
        &self,
        listening_addr: LocalAddress,
        remote_addr: RemoteAddress,
    ) -> Option<(SOCKET, RemoteAddress)> {
        tracing::info!(
            ?listening_addr,
            ?remote_addr,
            "Accepting new fictive connection request"
        );

        let phantom_socket = unsafe { _SOCKET.call(23, SOCK_STREAM, IPPROTO_TCP) };
        self.on_socket_create(phantom_socket, SocketOption::TCP);
        self.accept_connection(phantom_socket, remote_addr, listening_addr);

        Some((phantom_socket, remote_addr))
    }

    /// # Arguments
    /// * `new_socket` - A fresh socket to represent the send/receive queues for this connection
    /// * `from` - The remote address of the client trying to connect
    /// * `to` - The local address of the socket which is in `listen` mode.
    fn accept_connection(&self, new_socket: SOCKET, from: RemoteAddress, to: LocalAddress) {
        // The 'source' address will always be the same port as we accepted from, no new address is needed.
        self.dormant
            .dir
            .tcp_sockets
            .accept_on_address(new_socket, to.port, from);
        let guard = self.packet_queue.guard();
        let _ = self.get_or_create_queue(new_socket, Some(from), &guard);
    }

    /// Handle the manual closure of a [SOCKET].
    pub fn on_close(&self, socket: SOCKET) {
        self.dormant.on_close(socket);
        self.packet_queue.pin().remove(&socket);
    }

    pub fn on_socket_bind(&self, socket: SOCKET, bind: SocketAddrEncodable) {
        self.dormant.on_socket_bind(socket, bind);
    }

    pub fn on_socket_create(&self, socket: SOCKET, sock_type: SocketOption) {
        self.dormant.on_socket_create(socket, sock_type);
    }

    pub async fn shutdown(self) -> eyre::Result<()> {
        std::mem::drop(self.connection);
        self.endpoint.wait_idle().await;
        Ok(())
    }

    /// Retrieve a current packet queue for the socket, or create a new one if possible.
    ///
    /// If the `socket` is a TCP socket then `remote_addr` is mandatory to avoid a panic.
    fn get_or_create_queue<'g>(
        &self,
        socket: SOCKET,
        remote_addr: Option<RemoteAddress>,
        pin: &'g impl Guard,
    ) -> &'g PacketSocketQueue {
        self.packet_queue.get_or_insert_with(
            socket,
            || {
                let queue_type = self.dormant.dir.get_or_create_socket_opt(socket).expect("Impossible");
                tracing::trace!(?socket, ?queue_type, "Creating new queue for socket with type");

                match queue_type {
                    SocketOption::UDP => PacketSocketQueue::UDP(Default::default()),
                    SocketOption::TCP => {
                        if let Some(remote) = remote_addr {
                            PacketSocketQueue::TCP(PacketQueue::new(remote))
                        } else {
                            tracing::error!("Could not find a local address for a TCP queue to bind to");
                            panic!("Expected local address")
                        }
                    }
                }
            },
            pin,
        )
    }
}

/// Dummy certificate verifier that treats any certificate as valid.
/// NOTE, such verification is vulnerable to MITM attacks, but convenient for testing.
#[derive(Debug)]
struct SkipServerVerification(Arc<rustls::crypto::CryptoProvider>);

impl SkipServerVerification {
    fn new() -> Arc<Self> {
        Arc::new(Self(Arc::new(rustls::crypto::ring::default_provider())))
    }
}

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}
