use std::fmt::Debug;
use std::net::Ipv4Addr;
pub use bincode;
use quinn::{RecvStream, SendStream};
use windows_sys::Win32::Networking::WinSock::{AF_INET, SOCKADDR_IN};
use crate::subnet::is_fictive;

pub mod subnet;

pub type IpAddress = [u8; 4];

#[derive(Debug, bincode::Encode, bincode::Decode, Clone, Copy, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct SocketAddrEncodable {
    pub ip: IpAddress,
    pub port: u16,
}

impl SocketAddrEncodable {
    /// Write self to the network-byte order SOCKADDR_IN
    pub fn write_to_sock_addr(&self, addr: &mut SOCKADDR_IN) {
        addr.sin_port = self.port_be();
        addr.sin_addr.S_un.S_addr = self.ip_le_u32();
        addr.sin_family = AF_INET
    }

    /// Return the Big Endian format of the port, as the windows APIs expect that
    pub fn port_be(&self) -> u16 {
        self.port.rotate_left(8)
    }

    pub fn ip_le_u32(&self) -> u32 {
        u32::from_le_bytes(self.ip)
    }

    pub fn ip(&self) -> Ipv4Addr {
        self.ip.into()
    }

    pub fn is_fictive(&self) -> bool {
        is_fictive(self.ip())
    }
}


#[derive(Debug, Clone, Copy, bincode::Encode, bincode::Decode)]
pub enum Protocol {
    UDP,
    TCP
}

#[derive(Debug, bincode::Encode, bincode::Decode)]
pub struct C2SHeader {
    pub msg_type: C2SMessage
}

#[derive(Debug, bincode::Encode, bincode::Decode)]
pub enum C2SMessage {
    RequestIp,
    PassMessage {
        from: SocketAddrEncodable,
        to: SocketAddrEncodable,
        data: Vec<u8>,
        protocol: Protocol,
    },
    /// We called `connect()` for `to`
    Connect {
        from: SocketAddrEncodable,
        to: SocketAddrEncodable
    }
}

#[derive(Debug, bincode::Encode, bincode::Decode)]
pub struct S2CHeader {
    pub msg_type: S2CMessage
}

#[derive(Debug, bincode::Encode, bincode::Decode)]
pub enum S2CMessage {
    Ip(IpAddress),
    PassBroadcast {
        from: SocketAddrEncodable,
        to: SocketAddrEncodable,
        data: Vec<u8>
        // Broadcast can only be UDP
    },
    PassMessage {
        from: SocketAddrEncodable,
        to: SocketAddrEncodable,
        data: Vec<u8>,
        protocol: Protocol,
    },
    /// The `from` client sent a `connect()` request to us, in `accept()` we should assign this client.
    Connect {
        from: SocketAddrEncodable,
        to: SocketAddrEncodable,
    },
    /// When a fictive IP client no longer exists for the server
    DeadClient {
        client: SocketAddrEncodable
    }
}

pub async fn write_message<T: bincode::Encode + Debug>(write_msg: &mut SendStream, msg: T) -> eyre::Result<usize> {
    let encoded = bincode::encode_to_vec(msg, bincode::config::standard())?;
    // First write the length
    write_msg.write_all(&(encoded.len() as u32).to_le_bytes()).await?;
    // Then write the message
    write_msg.write_all(&encoded).await?;
    Ok(4 + encoded.len())
}

pub async fn read_message<T: bincode::Decode>(read_msg: &mut RecvStream, recv_buffer: &mut Vec<u8>) -> eyre::Result<(T, usize)> {
    let mut length = [0; 4];
    read_msg.read_exact(&mut length).await?;

    recv_buffer.resize(u32::from_le_bytes(length) as usize, 0);
    read_msg.read_exact(recv_buffer).await?;

    Ok(bincode::decode_from_slice(recv_buffer, bincode::config::standard())?)
}