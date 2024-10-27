use std::{error::Error, net::SocketAddr, sync::Arc};
use std::collections::{HashSet};
use std::net::{Ipv4Addr};
use std::sync::Mutex;
use quinn::{Endpoint};
use tracing_subscriber::util::SubscriberInitExt;
use client::ClientHandle;

mod common;
mod trace;
mod client;
use common::make_server_endpoint;

pub type VirtualIpv4 = Ipv4Addr;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
    trace::create_subscriber("INFO,gbe_proxy=TRACE,gbe_proxy_common=TRACE,gbe_proxy_server=TRACE").init();
    // server and client are running on the same thread asynchronously
    let addr = (Ipv4Addr::from_bits(0), 5000).into();
    tracing::info!("Server is listening on: 0.0.0.0:5000");
    let server = Server::new(addr)?;
    
    server.run().await?;
    Ok(())
}

struct Server {
    endpoint: Endpoint,
    clients: Arc<papaya::HashMap<VirtualIpv4, Arc<ClientHandle>>>,
    ip_provider: Arc<Mutex<FictionalIpProvider>>,
}

impl Server {
    pub fn new(addr: SocketAddr) -> eyre::Result<Self> {
        Ok(Server {
            endpoint: make_server_endpoint(addr)?.0,
            clients: Arc::new(Default::default()),
            ip_provider: Arc::new(Mutex::new(FictionalIpProvider::new(gbe_proxy_common::subnet::SHARED_SUBNET))),
        })
    }

    pub async fn run(self) -> eyre::Result<()> {
        loop {
            let incoming_conn = self.endpoint.accept().await.unwrap();
            let conn = incoming_conn.await?;
            tracing::info!(addr=?conn.remote_address(),
                "Connection Accepted"
            );
            
            let virtual_ip = self.ip_provider.lock().unwrap().next_ip();

            tracing::info!(addr=?conn.remote_address(),?virtual_ip,
                "Assigned virtual IP address"
            );
            
            let client_handle = Arc::new(ClientHandle::new(virtual_ip, conn).await?);
            self.clients.pin().insert(virtual_ip, client_handle.clone());
            
            let clients_clone = self.clients.clone();
            let ip_provider_clone = self.ip_provider.clone();
            tokio::task::spawn(async move {
                let clients_2 = clients_clone.clone();
                let finished = client_handle.run(clients_clone).await;
                
                if let Err(e) = finished {
                    tracing::error!(?e, "Finished client with error");
                } else {
                    tracing::info!(?virtual_ip, "Client shutdown");
                }

                ip_provider_clone.lock().unwrap().free_ip(virtual_ip);
                clients_2.pin().remove(&virtual_ip);
            });
        }
    }
}

struct FictionalIpProvider {
    subnet: [u8; 2],
    ip_assignments: HashSet<VirtualIpv4>,
    last_assigned: Option<Ipv4Addr>
}

impl FictionalIpProvider {
    pub fn new(subnet: [u8; 2]) -> Self {
        Self {
            subnet,
            ip_assignments: Default::default(),
            last_assigned: None,
        }
    }
    
    pub fn free_ip(&mut self, ip: VirtualIpv4) {
        self.ip_assignments.remove(&ip);
    }

    pub fn next_ip(&mut self) -> Ipv4Addr {
        if self.ip_assignments.len() >= 65025 {
            panic!("Ran out of IP addresses")
        }
        
        let Some(last) = self.last_assigned.take() else {
            let ip_addr = Ipv4Addr::new(self.subnet[0], self.subnet[1], 0, 0);
            self.last_assigned = Some(ip_addr);
            return ip_addr;
        };

        let [_, _, n, last] = last.octets();
        
        let next_ip = loop {
            let next_ip = match last.overflowing_add(1) {
                (next_last, false) => {
                    Ipv4Addr::new(self.subnet[0], self.subnet[1], n, next_last)
                },
                (next_last, true) => {
                    let (next_n, _) = n.overflowing_add(1);
                    Ipv4Addr::new(self.subnet[0], self.subnet[1], next_n, next_last)
                }
            };
            
            if !self.ip_assignments.contains(&next_ip) {
                break next_ip;
            } else {
                tracing::trace!(existing=?next_ip, "Ip already exists, trying next...");
            }
        };

        self.last_assigned.replace(next_ip);
        self.ip_assignments.insert(next_ip);

        next_ip
    }
}

