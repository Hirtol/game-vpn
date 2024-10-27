use crate::quic_conn::{DormantClientState, LocalAddress, QuicClient, RemoteAddress};
use gbe_proxy_common::{bincode::Encode, C2SHeader, C2SMessage, Protocol, SocketAddrEncodable};
use std::{
    fmt::Debug,
    sync::{Arc},
};
use std::sync::OnceLock;
use arc_swap::ArcSwap;
use windows_sys::Win32::Networking::WinSock::{FIONREAD, IN_ADDR, IPPROTO_TCP, IPPROTO_UDP, SEND_RECV_FLAGS, SOCKADDR, SOCKADDR_IN, SOCKET, SOCKET_ERROR, SO_BROADCAST, WINSOCK_SHUTDOWN_HOW, WINSOCK_SOCKET_TYPE};
use crate::socket_directory::{SocketOption};

pub static PROXY_MAN: OnceLock<ProxyManager> = OnceLock::new();

retour::static_detour! {
    pub static _ACCEPT: unsafe extern "system" fn (SOCKET, *mut SOCKADDR, *mut i32) -> SOCKET;
    pub static _BIND: unsafe extern "system" fn (SOCKET, *const SOCKADDR, i32) -> i32;
    pub static _CLOSESOCKET: unsafe extern "system" fn (SOCKET) -> i32;
    pub static _CONNECT: unsafe extern "system" fn (SOCKET, *const SOCKADDR, i32) -> i32;
    pub static _GETSOCKOPT: unsafe extern "system" fn (SOCKET, i32, i32, windows_sys::core::PSTR, *mut i32) -> i32;
    pub static _IOCTLSOCKET: unsafe extern "system" fn (SOCKET, i32, *mut u32) -> i32;
    pub static _LISTEN: unsafe extern "system" fn (SOCKET, i32) -> i32;
    pub static _RECV: unsafe extern "system" fn (SOCKET, windows_sys::core::PSTR, i32, SEND_RECV_FLAGS) -> i32;
    pub static _RECV_FROM: unsafe extern "system" fn (SOCKET, windows_sys::core::PSTR, i32, i32, *mut SOCKADDR, *mut i32) -> i32;
    pub static _SEND: unsafe extern "system" fn (SOCKET, windows_sys::core::PCSTR, i32, SEND_RECV_FLAGS) -> i32;
    pub static _SEND_TO: unsafe extern "system" fn (SOCKET, windows_sys::core::PCSTR, i32, i32, *const SOCKADDR, i32) -> i32;
    pub static _SETSOCKOPT: unsafe extern "system" fn (SOCKET, i32, i32, windows_sys::core::PCSTR, i32) -> i32;
    pub static _SHUTDOWN: unsafe extern "system" fn (SOCKET, WINSOCK_SHUTDOWN_HOW) -> i32;
    pub static _SOCKET: unsafe extern "system" fn (i32, WINSOCK_SOCKET_TYPE, i32) -> SOCKET;
}

pub enum ClientState {
    Ready(QuicClient),
    Dormant(Arc<DormantClientState>)
}

impl ClientState {
    pub fn as_client(&self) -> Option<&QuicClient> {
        match self {
            ClientState::Ready(client) => Some(client),
            ClientState::Dormant(_) => None
        }
    }

    pub fn on_socket_create(&self, socket: SOCKET, sock_type: SocketOption) {
        match self {
            ClientState::Ready(client) => {
                client.on_socket_create(socket, sock_type);
            }
            ClientState::Dormant(dormant) => {
                dormant.on_socket_create(socket, sock_type);
            }
        }
    }

    pub fn on_socket_bind(&self, socket: SOCKET, bind_addr: SocketAddrEncodable) {
        match self {
            ClientState::Ready(client) => {
                client.on_socket_bind(socket, bind_addr);
            }
            ClientState::Dormant(dormant) => {
                dormant.on_socket_bind(socket, bind_addr);
            }
        }
    }

    pub fn on_socket_close(&self, socket: SOCKET) {
        match self {
            ClientState::Ready(client) => {
                client.on_close(socket);
            }
            ClientState::Dormant(dormant) => {
                dormant.on_close(socket);
            }
        }
    }

    pub fn on_socket_accept(&self, socket: SOCKET) -> Option<(SOCKET, RemoteAddress)> {
        match self {
            ClientState::Ready(client) => {
                client.on_accept(socket)
            }
            ClientState::Dormant(_) => {
                None
            }
        }
    }
}

pub struct ProxyManager {
    client: Arc<ArcSwap<ClientState>>,
    rt: tokio::runtime::Handle,
}

impl ProxyManager {
    pub unsafe fn new(client: Arc<ArcSwap<ClientState>>, rt: tokio::runtime::Handle) -> eyre::Result<ProxyManager> {
        tracing::info!("Setting up hooks");

        _ACCEPT.initialize(windows_sys::Win32::Networking::WinSock::accept, accept_impl)?;
        _BIND.initialize(windows_sys::Win32::Networking::WinSock::bind, bind_impl)?;
        _CLOSESOCKET.initialize(windows_sys::Win32::Networking::WinSock::closesocket, closesocket_impl)?;
        _CONNECT.initialize(windows_sys::Win32::Networking::WinSock::connect, connect_impl)?;
        _GETSOCKOPT.initialize(windows_sys::Win32::Networking::WinSock::getsockopt, getsockopt_impl)?;
        _IOCTLSOCKET.initialize(windows_sys::Win32::Networking::WinSock::ioctlsocket, ioctlsocket_impl)?;
        _LISTEN.initialize(windows_sys::Win32::Networking::WinSock::listen, listen_impl)?;
        _RECV.initialize(windows_sys::Win32::Networking::WinSock::recv, recv_impl)?;
        _RECV_FROM.initialize(windows_sys::Win32::Networking::WinSock::recvfrom, recv_from_impl)?;
        _SEND.initialize(windows_sys::Win32::Networking::WinSock::send, send_impl)?;
        _SEND_TO.initialize(windows_sys::Win32::Networking::WinSock::sendto, send_to_impl)?;
        _SETSOCKOPT.initialize(windows_sys::Win32::Networking::WinSock::setsockopt, setsockopt_impl)?;
        _SHUTDOWN.initialize(windows_sys::Win32::Networking::WinSock::shutdown, shutdown_impl)?;
        _SOCKET.initialize(windows_sys::Win32::Networking::WinSock::socket, socket_impl)?;

        _ACCEPT.enable()?;
        _BIND.enable()?;
        _CLOSESOCKET.enable()?;
        _CONNECT.enable()?;
        _GETSOCKOPT.enable()?;
        _IOCTLSOCKET.enable()?;
        _LISTEN.enable()?;
        _RECV.enable()?;
        _RECV_FROM.enable()?;
        _SEND.enable()?;
        _SEND_TO.enable()?;
        _SETSOCKOPT.enable()?;
        _SHUTDOWN.enable()?;
        _SOCKET.enable()?;

        Ok(Self { client, rt })
    }

    #[tracing::instrument(skip_all, fields(socket))]
    pub fn on_socket_create(&self, socket: SOCKET, sock_type: SocketOption) {
        self.client.load().on_socket_create(socket, sock_type)
    }

    #[tracing::instrument(skip_all, fields(socket, bind_addr))]
    pub fn on_socket_bind(&self, socket: SOCKET, bind_addr: SocketAddrEncodable) {
        self.client.load().on_socket_bind(socket, bind_addr);
    }

    #[tracing::instrument(skip_all, fields(socket))]
    pub fn on_socket_close(&self, socket: SOCKET) {
        self.client.load().on_socket_close(socket)
    }

    #[tracing::instrument(skip(self))]
    pub fn on_connect(&self, socket: SOCKET, to: SocketAddrEncodable) -> bool {
        match &**self.client.load() {
            ClientState::Ready(client) if to.is_fictive() => {
                let local = client.on_connect(socket, to);

                let msg = C2SHeader {
                    msg_type: C2SMessage::Connect { from: local, to },
                };
                self.write_message(msg);
                tracing::info!("Connecting to fictive socket");
                true
            }
            _ => {
                false
            }
        }
    }

    /// See if there are any new Fictive IPs to accept
    ///
    /// Will return a phantom-socket associated with said IP
    #[tracing::instrument(skip(self))]
    pub fn on_accept(&self, socket: SOCKET) -> Option<(SOCKET, RemoteAddress)> {
        self.client.load().on_socket_accept(socket)
    }

    #[tracing::instrument(skip(self, buf))]
    pub fn on_send(
        &self,
        socket: SOCKET,
        buf: &[u8],
        flags: SEND_RECV_FLAGS,
        to: Option<SocketAddrEncodable>,
    ) -> eyre::Result<SendResult> {
        match &**self.client.load() {
            ClientState::Ready(client) => {
                let Some(local_addr) = client.get_local_address(socket) else {
                    return Ok(SendResult::Passthrough);
                };

                // First check if this socket exists and has a remote target (e.g., is fictive)
                if let Some(target) = client.get_associated_remote(socket) {
                    self.send_spawn(local_addr, target, buf, Protocol::TCP);
                    Ok(SendResult::SentData(buf.len() as i32))
                } else {
                    // Need to rely on the `to`
                    if let Some(to) = to {
                        if to.ip().is_broadcast() || to.is_fictive() {
                            let call_type = client.get_socket_opt(socket).unwrap_or(SocketOption::UDP);
                            self.send_spawn(local_addr, to, buf, call_type.into());
                            Ok(SendResult::SentData(buf.len() as i32))
                        } else {
                            tracing::trace!("Ignoring non-broadcast/fictive target");
                            Ok(SendResult::Passthrough)
                        }
                    } else {
                        tracing::warn!("No `to` address or fictive association found, passing through");
                        Ok(SendResult::Passthrough)
                    }
                }
            }
            ClientState::Dormant(_) => Ok(SendResult::Passthrough)
        }
    }

    fn send_spawn(&self, from: LocalAddress, target: RemoteAddress, buf: &[u8], protocol: Protocol) {
        let data = buf.to_vec();

        let msg = C2SHeader {
            msg_type: C2SMessage::PassMessage { from, to: target, data, protocol },
        };

        self.write_message(msg);
    }

    #[tracing::instrument(skip(self, buf, from))]
    pub fn on_receive(
        &self,
        socket: SOCKET,
        buf: &mut [u8],
        flags: SEND_RECV_FLAGS,
        from: Option<&mut SOCKADDR_IN>,
    ) -> eyre::Result<SendResult> {
        match &**self.client.load() {
            ClientState::Ready(client) => {
                let map = client.packet_queue.pin();
                if let Some(val) = map.get(&socket) {
                    let Some((received_from, written)) = val.read_data(buf) else {
                        return Ok(SendResult::Passthrough);
                    };
                    if let Some(from) = from {
                        received_from.write_to_sock_addr(from);
                    }

                    Ok(SendResult::SentData(written as i32))
                } else {
                    Ok(SendResult::Passthrough)
                }
            }
            ClientState::Dormant(_) => Ok(SendResult::Passthrough)
        }
    }

    #[tracing::instrument(skip_all, fields(socket))]
    pub fn query_pending_bytes(&self, socket: SOCKET) -> Option<usize> {
        match &**self.client.load() {
            ClientState::Ready(client) => {
                let packet = client.packet_queue.pin();
                Some(packet.get(&socket)?.pending_read())
            }
            ClientState::Dormant(_) => None
        }
    }

    fn write_message<T: Encode + Debug + Send + 'static>(&self, msg: T) {
        let client = self.client.load_full();
        self.rt.spawn(async move {
            match &*client {
                ClientState::Ready(client) => {
                    if let Err(e) = client.write_message(msg).await {
                        tracing::error!(?e, "Failed to send message")
                    }
                }
                ClientState::Dormant(_) => {
                    tracing::error!(?msg, "Tried to send a message with a dormant client!")
                }
            }
        });
    }
}

#[derive(Debug)]
enum SendResult {
    SentData(i32),
    Passthrough,
}

fn send_to_impl(
    s: SOCKET,
    buf: windows_sys::core::PCSTR,
    len: i32,
    flags: i32,
    to: *const SOCKADDR,
    tolen: i32,
) -> i32 {
    if buf.is_null() {
        tracing::error!("Received null pointer in send_to");
        return unsafe { _SEND_TO.call(s, buf, len, flags, to, tolen) };
    }

    let target = parse_socket_addr(to);
    let slice = unsafe { std::slice::from_raw_parts(buf, len as usize) };

    match get_proxy_man().on_send(s, slice, flags, Some(target)) {
        Ok(result) => match result {
            SendResult::SentData(bytes_written) => {
                tracing::info!(?s, ?target, ?slice, ?bytes_written, "SEND_TO CALL");
                bytes_written
            }
            SendResult::Passthrough => unsafe { _SEND_TO.call(s, buf, len, flags, to, tolen) },
        },
        Err(e) => {
            tracing::error!(?e, "Failed to send");
            0
        }
    }
}

fn send_impl(s: SOCKET, buf: windows_sys::core::PCSTR, len: i32, flags: i32) -> i32 {
    if buf.is_null() {
        tracing::error!("Received null pointer in send");
        return unsafe { _SEND.call(s, buf, len, flags) };
    }

    let slice = unsafe { std::slice::from_raw_parts(buf, len as usize) };
    match get_proxy_man().on_send(s, slice, flags, None) {
        Ok(result) => match result {
            SendResult::SentData(bytes_written) => {
                tracing::info!(?s, ?slice, ?bytes_written, "SEND CALL");
                bytes_written
            }
            SendResult::Passthrough => unsafe { _SEND.call(s, buf, len, flags) },
        },
        Err(e) => {
            tracing::error!(?e, "Failed to send");
            0
        }
    }
}

fn recv_from_impl(
    s: SOCKET,
    buf: windows_sys::core::PSTR,
    len: i32,
    flags: i32,
    from: *mut SOCKADDR,
    fromlen: *mut i32,
) -> i32 {
    unsafe {
        // Sanity check, happens more often than you'd think
        if buf.is_null() || len < 0 {
            return _RECV_FROM.call(s, buf, len, flags, from, fromlen);
        }

        let slice = unsafe { std::slice::from_raw_parts_mut(buf, len as usize) };
        let result = get_proxy_man().on_receive(
            s,
            slice,
            flags,
            Some(&mut *(from as *mut SOCKADDR_IN)),
        );

        match result {
            Ok(result) => match result {
                SendResult::SentData(bytes_written) if bytes_written > 0 => {
                    let from_s = parse_socket_addr(from);
                    tracing::trace!(?s, ?from_s, ?result, "RECV_FROM CALL");
                    bytes_written
                }
                SendResult::SentData(_) | SendResult::Passthrough => unsafe {
                    #[cfg(feature = "block_normal")]
                    return SOCKET_ERROR;
                    _RECV_FROM.call(s, buf, len, flags, from, fromlen)
                },
            },
            Err(e) => {
                tracing::error!(?e, "Failed to receive");
                // We pretend that everything is fine
                0
            }
        }
    }
}

fn recv_impl(s: SOCKET, buf: windows_sys::core::PSTR, len: i32, flags: i32) -> i32 {
    // Sanity check, happens more often than you'd think
    if buf.is_null() || len < 0 {
        unsafe {
            return _RECV.call(s, buf, len, flags);
        }
    }

    let slice = unsafe { std::slice::from_raw_parts_mut(buf, len as usize) };
    let result = get_proxy_man().on_receive(s, slice, flags, None);

    match result {
        Ok(result) => match result {
            SendResult::SentData(bytes_written) if bytes_written > 0 => {
                tracing::trace!(?s, ?result, "RECV CALL");
                bytes_written
            }
            SendResult::SentData(_) | SendResult::Passthrough => unsafe {
                #[cfg(feature = "block_normal")]
                return SOCKET_ERROR;
                _RECV.call(s, buf, len, flags)
            },
        },
        Err(e) => {
            tracing::error!(?e, "Failed to receive");
            // We pretend that everything is fine
            0
        }
    }
}

fn accept_impl(s: SOCKET, addr: *mut SOCKADDR, addrlen: *mut i32) -> SOCKET {
    if let Some((fict_socket, remote_addr)) = get_proxy_man().on_accept(s) {
        tracing::error!(?fict_socket, ?remote_addr, "Socket Accept");
        unsafe {
            let casted: *mut SOCKADDR_IN = addr.cast();
            remote_addr.write_to_sock_addr(&mut *casted);
        }

        fict_socket
    } else {
        unsafe {
            _ACCEPT.call(s, addr, addrlen)
        }
    }
}

fn bind_impl(s: SOCKET, name: *const SOCKADDR, namelen: i32) -> i32 {
    let address = parse_socket_addr(name);
    tracing::info!(?s, ?address, "BIND CALL");
    let result = unsafe { _BIND.call(s, name, namelen) };

    if result == 0 {
        get_proxy_man().on_socket_bind(s, address);
    } else {
        tracing::trace!(?s, "Not binding as main machine bind failed");
    }
    result
}

fn closesocket_impl(s: SOCKET) -> i32 {
    get_proxy_man().on_socket_close(s);

    unsafe { _CLOSESOCKET.call(s) }
}

fn connect_impl(s: SOCKET, name: *const SOCKADDR, namelen: i32) -> i32 {
    let connecting_to = parse_socket_addr(name);
    tracing::trace!(?s, ?namelen, ?connecting_to, "CONNECT CALL");

    // If our client handles the connect request we don't want to call the underlying connect functionality.
    if get_proxy_man().on_connect(s, connecting_to) {
        0
    } else {
        unsafe { _CONNECT.call(s, name, namelen) }
    }
}

fn getsockopt_impl(s: SOCKET, level: i32, optname: i32, optval: windows_sys::core::PSTR, optlen: *mut i32) -> i32 {
    unsafe { _GETSOCKOPT.call(s, level, optname, optval, optlen) }
}

fn ioctlsocket_impl(s: SOCKET, cmd: i32, argp: *mut u32) -> i32 {
    unsafe {
        match cmd {
            FIONREAD => {
                if let Some(awaiting) = get_proxy_man().query_pending_bytes(s) {
                    if awaiting == 0 {
                        // We ignore the result here, it might be invalid for our custom sockets!
                        let _ = _IOCTLSOCKET.call(s, cmd, argp);
                    } else {
                        argp.write(awaiting as u32);
                    }

                    0
                } else {
                    _IOCTLSOCKET.call(s, cmd, argp)
                }
            }
            _ => _IOCTLSOCKET.call(s, cmd, argp),
        }
    }
}

fn listen_impl(s: SOCKET, backlog: i32) -> i32 {
    unsafe { _LISTEN.call(s, backlog) }
}

fn setsockopt_impl(s: SOCKET, level: i32, optname: i32, optval: windows_sys::core::PCSTR, optlen: i32) -> i32 {
    if optname == SO_BROADCAST {
        tracing::info!(?s, "Is broadcast socket");
    }

    unsafe { _SETSOCKOPT.call(s, level, optname, optval, optlen) }
}

fn shutdown_impl(s: SOCKET, how: WINSOCK_SHUTDOWN_HOW) -> i32 {
    unsafe { _SHUTDOWN.call(s, how) }
}

fn socket_impl(af: i32, r#type: WINSOCK_SOCKET_TYPE, protocol: i32) -> SOCKET {
    let sock_type = match protocol {
        IPPROTO_TCP => SocketOption::TCP,
        IPPROTO_UDP => SocketOption::UDP,
        _ => return unsafe { _SOCKET.call(af, r#type, protocol) },
    };
    let socket = unsafe { _SOCKET.call(af, r#type, protocol) };

    get_proxy_man().on_socket_create(socket, sock_type);

    socket
}

// MISC FUNCTIONS

fn socket_addr_to_fic(inp: &SOCKADDR_IN) -> gbe_proxy_common::SocketAddrEncodable {
    SocketAddrEncodable {
        ip: inet_to_ipv4(inp.sin_addr),
        // Always received in BE format, when we want LE
        port: u16::from_be(inp.sin_port),
    }
}

fn inet_to_ipv4(in_addr: IN_ADDR) -> [u8; 4] {
    unsafe { std::mem::transmute(in_addr.S_un.S_un_b) }
}

fn get_proxy_man<'a>() -> &'a ProxyManager {
    PROXY_MAN.get().unwrap()
}

fn parse_socket_addr(inp: *const SOCKADDR) -> SocketAddrEncodable {
    let casted: *const SOCKADDR_IN = inp.cast();
    unsafe { socket_addr_to_fic(&*casted) }
}
