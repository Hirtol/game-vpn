//! Storage for easy access to the various states/mappings of ports to sockets and remote addresses.
//! 
//! Note that at the moment this is vulnerable to race conditions due to the fact that most maps are pinned independently.
use windows_sys::Win32::Networking::WinSock::{getsockname, getsockopt, IPPROTO_TCP, SOCKADDR, SOCKADDR_IN, SOCKET, SOL_SOCKET, SO_PROTOCOL_INFOW};
use gbe_proxy_common::Protocol;
use windows::Win32::Networking::WinSock::{SOCKADDR_STORAGE, WSAPROTOCOL_INFOW};
use crate::quic_conn::{LocalAddress, Port, RemoteAddress};

pub type LocalPort = Port;

pub struct SocketDirectory {
    pub tcp_sockets: TcpDirectory,
    pub udp_sockets: UdpDirectory,
    /// The known associations between a socket and if it's in the `UDP` or `TCP` directory
    pub socket_opt: papaya::HashMap<SOCKET, SocketOption>
}

impl SocketDirectory {
    pub fn new() -> Self {
        Self {
            tcp_sockets: Default::default(),
            udp_sockets: Default::default(),
            socket_opt: Default::default(),
        }
    }

    pub fn on_socket_create(&self, socket: SOCKET, sock_type: SocketOption) {
        tracing::trace!(?socket, ?sock_type, "Noted creation of new socket");
        self.socket_opt.pin().insert(socket, sock_type);
    }

    /// Properly close the given socket by removing all mappings.
    #[tracing::instrument(skip(self))]
    pub fn close_socket(&self, socket: SOCKET) {
        if let Some(opt) = self.socket_opt.pin().get(&socket) {
            match opt {
                SocketOption::UDP => {
                    self.udp_sockets.close_socket(socket);
                }
                SocketOption::TCP => {
                    self.tcp_sockets.close_socket(socket);
                }
            }
        } else {
            tracing::trace!("Ignoring socket close as the socket did not exist")
        }
    }

    /// Attempt to resolve a given [LocalAddress] and optional [RemoteAddress] to the respective TCP/UDP port.
    pub fn resolve_socket(&self, ours: &LocalAddress, theirs: Option<&RemoteAddress>, protocol: Option<Protocol>) -> Option<SOCKET> {
        if let Some(protocol) = protocol {
            match protocol {
                Protocol::UDP => {
                    // We know it _has_ to be a UDP socket, first try a specific match for our full address, or else drop down to
                    // just checking the port
                    self.udp_sockets.local_addr_mapping.pin().get(&ours.port).copied()
                }
                Protocol::TCP => {
                    if let Some(theirs) = theirs {
                        self.tcp_sockets.local_and_remote_mapping.pin().get(&(ours.port, *theirs)).copied()
                    } else {
                        // It can only be a listening TCP socket
                        self.tcp_sockets.local_addr_mapping.pin().get(&ours.port).copied()
                    }
                }
            }
        } else if let Some(theirs) = theirs {
            // We know it has to be a UDP socket
            if theirs.ip().is_broadcast() {
                // Just check the UDP ports
                self.udp_sockets.local_addr_mapping.pin().get(&ours.port).copied()
            } else {
                // First check if this `(ours, theirs)` pair can be resolved to a local TCP port
                // If not then it's likely that it was targeting a UDP port.
                self.tcp_sockets.local_and_remote_mapping.pin().get(&(ours.port, *theirs)).copied().or_else(|| {
                    self.udp_sockets.local_addr_mapping.pin().get(&ours.port).copied()
                })
            }
        } else {
            // We know it _has_ to be a UDP socket, first try a specific match for our full address, or else drop down to
            // just checking the port
            self.udp_sockets.local_addr_mapping.pin().get(&ours.port).copied()
        }
    }

    /// Retrieve the local address associated with this socket, if it exists.
    ///
    /// If the socket hasn't been bound/accepted this will return [None]
    pub fn get_local_port(&self, socket: SOCKET) -> Option<LocalPort> {
        let opt = self.get_or_create_socket_opt(socket)?;

        match opt {
            SocketOption::UDP => {
                self.udp_sockets.local_socket_addr_mapping.pin().get(&socket).copied()
            }
            SocketOption::TCP => {
                self.tcp_sockets.local_socket_addr_mapping.pin().get(&socket).copied()
            }
        }
    }

    /// Retrieve the associated [SocketOption] with this socket
    ///
    /// In case the socket was made before our hooks were in place the options will be discovered.
    #[tracing::instrument(skip(self))]
    pub fn get_or_create_socket_opt(&self, socket: SOCKET) -> Option<SocketOption> {
        let pin = self.socket_opt.pin();

        if let Some(protocol) = pin.get(&socket) {
            Some(*protocol)
        } else {
            tracing::trace!("Request for undiscovered socket");
            // This socket was made before we could inject, need to discover it
            let mut protocol_info = WSAPROTOCOL_INFOW::default();
            unsafe {
                let result = getsockopt(socket, SOL_SOCKET, SO_PROTOCOL_INFOW, &mut protocol_info as *mut WSAPROTOCOL_INFOW as *mut u8, &mut (std::mem::size_of::<WSAPROTOCOL_INFOW>() as i32));
                if result == 0 {
                    let out = if protocol_info.iProtocol == IPPROTO_TCP {
                        SocketOption::TCP
                    } else {
                        SocketOption::UDP
                    };

                    pin.insert(socket, out);

                    // Check for bound port
                    if let Some(bound) = self.sys_call_bound_address(socket) {
                        tracing::info!(?bound, "Found bound port for undiscovered socket");
                        match out {
                            SocketOption::UDP => {
                                self.udp_sockets.bind_to_port(socket, bound)
                            }
                            SocketOption::TCP => {
                                self.tcp_sockets.bind_to_address(socket, bound)
                            }
                        }
                    }


                    Some(out)
                } else {
                    None
                }
            }
        }
    }

    /// Attempt to recall what port (the address is assumed to be our fictional IP) the given socket was bound to.
    /// Will forcefully refresh our port cache by using a syscall.
    ///
    /// If it wasn't bound yet then `None` is returned.
    pub fn get_bound_port(&self, socket: SOCKET) -> Option<LocalPort> {
        let opt = self.get_or_create_socket_opt(socket)?;
        unsafe {
            if let Some(bound) = self.sys_call_bound_address(socket) {
                match opt {
                    SocketOption::UDP => {
                        self.udp_sockets.bind_to_port(socket, bound)
                    }
                    SocketOption::TCP => {
                        self.tcp_sockets.bind_to_address(socket, bound)
                    }
                }

                Some(bound)
            } else {
                None
            }
        }
    }

    /// Attempt to recall what port (the address is assumed to be our fictional IP) the given socket was bound to.
    ///
    /// If it wasn't bound yet then `None` is returned.
    unsafe fn sys_call_bound_address(&self, socket: SOCKET) -> Option<LocalPort> {
        let mut sock_addr = SOCKADDR_STORAGE::default();
        let real_sock_addr: &mut SOCKADDR_IN = std::mem::transmute(&mut sock_addr);
        let result = getsockname(socket, real_sock_addr as *mut SOCKADDR_IN as *mut SOCKADDR, &mut (std::mem::size_of::<SOCKADDR_IN>() as i32));
        
        if result == 0 {
            Some(u16::from_be(real_sock_addr.sin_port))
        } else {
            None
        }
    }
}

#[derive(Debug, Default)]
pub struct TcpDirectory {
    /// Mapping from socket to fictive port
    pub local_addr_mapping: papaya::HashMap<LocalPort, SOCKET>,
    pub local_socket_addr_mapping: papaya::HashMap<SOCKET, LocalPort>,
    /// Mapping from socket to TCP partner
    pub remote_addr_mapping: papaya::HashMap<SOCKET, RemoteAddress>,
    /// Mapping from a (local, remote) combination to route to the correct SOCKET.
    /// For reading.
    pub local_and_remote_mapping: papaya::HashMap<(LocalPort, RemoteAddress), SOCKET>,
    pub sock_local_and_remote_mapping: papaya::HashMap<SOCKET, (LocalPort, RemoteAddress)>,
}

impl TcpDirectory {

    /// Bind the given socket to the given address
    pub fn bind_to_address(&self, socket: SOCKET, address: LocalPort) {
        self.local_addr_mapping.pin().insert(address, socket);
        self.local_socket_addr_mapping.pin().insert(socket, address);
    }

    /// Accept a connection on the given local address. This will overlap with the listening port, and thus
    /// `local_addr_mapping` will _not_ be updated.
    pub fn accept_on_address(&self, socket: SOCKET, local_addr: LocalPort, remote: RemoteAddress) {
        self.local_socket_addr_mapping.pin().insert(socket, local_addr);
        self.connect(socket, remote);
    }

    /// Create a connection between the local socket and the remote fictive address
    ///
    /// The `socket` needs to have been used in a `bind_to_address` call.
    pub fn connect(&self, socket: SOCKET, to: RemoteAddress) {
        let local_addr = *self.local_socket_addr_mapping.pin().get(&socket)
            .expect("In order to connect the `bind_to_address` method needs to have been called");
        self.remote_addr_mapping.pin().insert(socket, to);
        self.local_and_remote_mapping.pin().insert((local_addr, to), socket);
        self.sock_local_and_remote_mapping.pin().insert(socket, (local_addr, to));
    }

    /// Strike the socket from the archives.
    pub fn close_socket(&self, socket: SOCKET) {
        let pin = self.local_addr_mapping.pin();
        if let Some((key, _))= pin.iter().find(|(_, sock)| **sock == socket) {
            pin.remove(key);
        }
        let pin = self.local_and_remote_mapping.pin();
        if let Some((key, _))= pin.iter().find(|(_, sock)| **sock == socket) {
            pin.remove(key);
        }
        self.local_socket_addr_mapping.pin().remove(&socket);
        self.remote_addr_mapping.pin().remove(&socket);
        self.sock_local_and_remote_mapping.pin().remove(&socket);
    }
}

#[derive(Debug, Default)]
pub struct UdpDirectory {
    /// Mapping from socket to fictive port
    pub local_addr_mapping: papaya::HashMap<LocalPort, SOCKET>,
    pub local_socket_addr_mapping: papaya::HashMap<SOCKET, LocalPort>,
}

impl UdpDirectory {
    /// Bind the given socket to the given address
    pub fn bind_to_port(&self, socket: SOCKET, address: LocalPort) {
        self.local_addr_mapping.pin().insert(address, socket);
        self.local_socket_addr_mapping.pin().insert(socket, address);
    }

    /// Strike the socket from the archives.
    pub fn close_socket(&self, socket: SOCKET) {
        let pin = self.local_addr_mapping.pin();
        if let Some((key, _))= pin.iter().find(|(_, sock)| **sock == socket) {
            pin.remove(key);
        }
        self.local_socket_addr_mapping.pin().remove(&socket);
    }
}

#[derive(Debug, Default, Copy, Clone)]
pub enum SocketOption {
    #[default]
    UDP,
    TCP
}

impl From<SocketOption> for Protocol {
    fn from(value: SocketOption) -> Self {
        match value {
            SocketOption::UDP => Self::UDP,
            SocketOption::TCP => Self::TCP,
        }
    }
}