use std::{error::Error, net::SocketAddr, sync::Arc};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Mutex;
use quinn_proto::crypto::rustls::QuicClientConfig;
use quinn::{ClientConfig, Connection, Endpoint, RecvStream, SendStream};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use tracing_subscriber::util::SubscriberInitExt;
use client::ClientHandle;

mod common;
mod trace;
mod client;
use common::make_server_endpoint;

pub type FictionalIpv4 = Ipv4Addr;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
    trace::create_subscriber("INFO,gbe_proxy=TRACE,gbe_proxy_common=TRACE,gbe_proxy_server=TRACE").init();
    // server and client are running on the same thread asynchronously
    let addr = (Ipv4Addr::from_bits(0), 5000).into();
    tracing::trace!("Server is listening on: 0.0.0.0:5000");
    let server = Server::new(addr)?;
    
    server.run().await?;
    Ok(())
}

struct Server {
    endpoint: Endpoint,
    ip_assignments: Arc<papaya::HashMap<IpAddr, FictionalIpv4>>,
    clients: Arc<papaya::HashMap<Ipv4Addr, Arc<ClientHandle>>>,
    ip_provider: FictionalIpProvider,
}

impl Server {
    pub fn new(addr: SocketAddr) -> eyre::Result<Self> {
        Ok(Server {
            endpoint: make_server_endpoint(addr)?.0,
            ip_assignments: Arc::new(Default::default()),
            clients: Arc::new(Default::default()),
            ip_provider: FictionalIpProvider::new([10, 130]),
        })
    }

    pub async fn run(mut self) -> eyre::Result<()> {
        loop {
            let incoming_conn = self.endpoint.accept().await.unwrap();
            let conn = incoming_conn.await?;
            tracing::info!(
                "[server] connection accepted: addr={}",
                conn.remote_address()
            );
            
            let fictional_ip = self.ip_provider.next_ip();
            self.ip_assignments.pin().insert(conn.remote_address().ip(), fictional_ip);
            
            let client_handle = Arc::new(ClientHandle::new(fictional_ip, conn).await?);
            self.clients.pin().insert(fictional_ip, client_handle.clone());
            
            let clients_clone = self.clients.clone();
            tokio::task::spawn(async move {
                let clients_2 = clients_clone.clone();
                let finished = client_handle.run(clients_clone).await;
                
                if let Err(e) = finished {
                    clients_2.pin().remove(&fictional_ip);
                    tracing::error!(?e, "Finished client with error");
                } else {
                    clients_2.pin().remove(&fictional_ip);
                    tracing::info!(?fictional_ip, "Client shutdown");
                }
            });
        }
    }
}

struct FictionalIpProvider {
    subnet: [u8; 2],
    last_assigned: Option<Ipv4Addr>
}

impl FictionalIpProvider {
    pub fn new(subnet: [u8; 2]) -> Self {
        Self {
            subnet,
            last_assigned: None,
        }
    }

    pub fn next_ip(&mut self) -> Ipv4Addr {
        let Some(last) = self.last_assigned.take() else {
            let ip_addr = Ipv4Addr::new(self.subnet[0], self.subnet[1], 0, 0);
            self.last_assigned = Some(ip_addr);
            return ip_addr;
        };

        let [_, _, n, last] = last.octets();

        let next_ip = match last.overflowing_add(1) {
            (next_last, false) => {
                Ipv4Addr::new(self.subnet[0], self.subnet[1], n, next_last)
            },
            (next_last, true) => {
                let (next_n, overflowed) = n.overflowing_add(1);

                if overflowed {
                    panic!("Ran out of IPs!");
                } else {
                    Ipv4Addr::new(self.subnet[0], self.subnet[1], next_n, next_last)
                }
            }
        };

        self.last_assigned.replace(next_ip);

        next_ip
    }
}

