//! Simple application for testing the basic hooks in a controlled environment
use std::net::{Ipv4Addr, SocketAddrV4};
use std::ptr;
use std::time::Duration;
use windows::core::imp::{LoadLibraryExA};
use windows::Win32::Networking::WinSock::{bind, htons, ioctlsocket, listen, recvfrom, sendto, setsockopt, socket, WSAStartup, AF_INET, FIONBIO, INADDR_BROADCAST, IPPROTO_TCP, IPPROTO_UDP, SOCKADDR, SOCKADDR_IN, SOCKADDR_STORAGE, SOCKET, SOCK_DGRAM, SOCK_STREAM, SOL_SOCKET, SO_BROADCAST, SO_RCVBUF, SO_SNDBUF, WSADATA};

fn main() -> eyre::Result<()> {
    unsafe {
        let mut data = WSADATA::default();
        WSAStartup((2 << 8) | 2, &mut data);
        std::thread::spawn(|| {
            LoadLibraryExA(windows::core::s!("gbe_proxy.dll").as_ptr(), ptr::null_mut(), 0);
        });
        std::thread::sleep(Duration::from_secs(1));
        
        unsafe_main()?;
    }

    Ok(())
}

struct Application {
    udp_broadcast: SOCKET,
    tcp_listen: SOCKET,
}

unsafe fn unsafe_main() -> eyre::Result<()> {
    let port = 49500;
    let udp_socket = setup_socket(SocketType::UDP, port)?;
    let tcp_listen = setup_socket(SocketType::TCP, port)?;

    // Setup listening
    listen(tcp_listen, 128);
    
    loop {
        send_broadcast(udp_socket, port);
        send_broadcast(udp_socket, port + 1);
        
        if let Some((addr, packet)) = receive_packet(udp_socket) {
            let data = String::from_utf8(packet).expect("Invalid broadcast");
            println!("Received a packet from: {addr:?}, with data: {data}");
        } else {
            println!("Did not receive a packet");
        }
        
        std::thread::sleep(Duration::from_secs(1));
    }

    Ok(())
}

#[derive(Debug, Clone, Copy)]
enum SocketType {
    UDP,
    TCP
}

unsafe fn receive_packet(sock: SOCKET) -> Option<(SocketAddrV4, Vec<u8>)> {
    let mut sock_addr = SOCKADDR_STORAGE {
        ss_family: Default::default(),
        __ss_pad1: [0; 6],
        __ss_align: 0,
        __ss_pad2: [0; 112],
    };
    let mut size = std::mem::size_of::<SOCKADDR_STORAGE>() as i32;
    let mut buf = vec![0; 16384];
    let returned = recvfrom(sock, &mut buf, 0, Some(&mut sock_addr as *mut SOCKADDR_STORAGE as *mut SOCKADDR), Some(&mut size));
    
    if returned >= 0 {
        let real_sock_addr: &mut SOCKADDR_IN = std::mem::transmute(&mut sock_addr);
        let real_socket = SocketAddrV4::new(Ipv4Addr::from(real_sock_addr.sin_addr), u16::from_be(real_sock_addr.sin_port));
        buf.truncate(returned as usize);
        
        Some((real_socket, buf))
    } else {
        None
    }
}

unsafe fn send_broadcast(sock: SOCKET, to_port: u16) {
    let data = format!("Hello from: {}", sock.0);
    let mut sock_addr = SOCKADDR_STORAGE {
        ss_family: Default::default(),
        __ss_pad1: [0; 6],
        __ss_align: 0,
        __ss_pad2: [0; 112],
    };
    let real_sock_addr: &mut SOCKADDR_IN = std::mem::transmute(&mut sock_addr);
    real_sock_addr.sin_family = AF_INET;
    real_sock_addr.sin_port = htons(to_port);
    real_sock_addr.sin_addr.S_un.S_addr = INADDR_BROADCAST;
    
    sendto(sock, data.as_bytes(), 0, real_sock_addr as *mut SOCKADDR_IN as *const SOCKADDR, std::mem::size_of::<SOCKADDR_IN>() as i32);
}

unsafe fn setup_socket(sock_type: SocketType, mut port: u16) -> eyre::Result<SOCKET> {
    let sock = create_socket(sock_type)?;

    // Set non-blocking
    ioctlsocket(sock, FIONBIO, &mut 1);
    match sock_type {
        SocketType::UDP => {
            setsockopt(sock, SOL_SOCKET, SO_BROADCAST, Some(&[1]));
        }
        SocketType::TCP => {}
    }

    set_buffer_size(sock);

    while !bind_socket(sock, port) {
        println!("Failed to bind socket port {port}, trying next");
        port += 1;
    }

    println!("Bound {sock_type:?} to port: {port}");
    
    Ok(sock)
}

unsafe fn bind_socket(sock: SOCKET, port: u16) -> bool {
    let mut sock_addr = SOCKADDR_STORAGE {
        ss_family: Default::default(),
        __ss_pad1: [0; 6],
        __ss_align: 0,
        __ss_pad2: [0; 112],
    };
    let real_sock_addr: &mut SOCKADDR_IN = std::mem::transmute(&mut sock_addr);
    real_sock_addr.sin_family = AF_INET;
    real_sock_addr.sin_port = htons(port);
    real_sock_addr.sin_addr.S_un.S_addr = 0;

    bind(sock, real_sock_addr as *mut SOCKADDR_IN as *const SOCKADDR, std::mem::size_of::<SOCKADDR_IN>() as i32) == 0
}

unsafe fn set_buffer_size(sock: SOCKET) {
    const SIZE: usize = 1024 * 1024;
    setsockopt(sock, SOL_SOCKET, SO_RCVBUF, Some(&SIZE.to_le_bytes()));
    setsockopt(sock, SOL_SOCKET, SO_SNDBUF, Some(&SIZE.to_le_bytes()));
}

unsafe fn create_socket(sock: SocketType) -> eyre::Result<SOCKET> {
    match sock {
        SocketType::UDP => {
            Ok(socket(AF_INET.0 as i32, SOCK_DGRAM, IPPROTO_UDP.0)?)
        }
        SocketType::TCP => {
            Ok(socket(AF_INET.0 as i32, SOCK_STREAM, IPPROTO_TCP.0)?)
        }
    }
}
