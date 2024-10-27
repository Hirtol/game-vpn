use std::net::Ipv4Addr;

/// The subnet which we will mark as 'fictitious', aka, all traffic should be sent to our proxy server.
/// Selected at random.
/// 
/// This will obviously conflict with a client which has an actual address on this subnet
pub const SHARED_SUBNET: [u8; 2] = [10, 130];

/// Check whether the given IP address has the correct subnet.
pub fn is_fictive(ip: impl Into<Ipv4Addr>) -> bool {
    let ip = ip.into();
    ip.octets()[0..2] == SHARED_SUBNET
}

pub fn is_broadcast(ip: impl Into<Ipv4Addr>) -> bool {
    ip.into().is_broadcast()
}