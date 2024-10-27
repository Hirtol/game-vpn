use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use std::fmt::Debug;
use std::net::Ipv4Addr;
use quinn::{Connection, RecvStream, SendStream};
use tokio::io::AsyncReadExt;
use gbe_proxy_common::{bincode, C2SHeader, S2CMessage, S2CHeader, C2SMessage, SocketAddrEncodable};
use gbe_proxy_common::bincode::Encode;

pub struct ClientHandle {
    pub fictional_ip: Ipv4Addr,
    pub connection: Connection,
    pub read: tokio::sync::Mutex<RecvStream>,
    pub write: tokio::sync::Mutex<SendStream>,
}

impl ClientHandle {
    pub async fn new(fictional_ip: Ipv4Addr, conn: Connection) -> eyre::Result<Self> {
        let (write, read) = conn.accept_bi().await?;

        Ok(Self {
            fictional_ip,
            connection: conn,
            read: tokio::sync::Mutex::new(read),
            write: tokio::sync::Mutex::new(write),
        })
    }
    
    #[tracing::instrument(skip_all, fields(self.fictional_ip))]
    pub async fn run(&self, clients: Arc<papaya::HashMap<Ipv4Addr, Arc<ClientHandle>>>) -> eyre::Result<()> {
        const TO_READ: usize = std::mem::size_of::<gbe_proxy_common::C2SHeader>();
        tracing::info!(fictional_ip=?self.fictional_ip, real_ip=?self.connection.remote_address(), "Starting running for client");
        let mut header_buf = vec![0; TO_READ];
        
        loop {
            let mut lock = self.read.lock().await;
            let (header, bytes_read): (C2SHeader, usize) = gbe_proxy_common::read_message(&mut lock, &mut header_buf).await?;
            self.handle_message(header, &clients).await?;
        }
        
        Ok(())
    }
    
    async fn handle_message(&self, msg: C2SHeader, clients: &papaya::HashMap<Ipv4Addr, Arc<ClientHandle>>) -> eyre::Result<()> {
        match msg.msg_type {
            C2SMessage::RequestIp => {
                tracing::debug!("Received IP request");
                let response = S2CHeader {
                    msg_type: S2CMessage::Ip(self.fictional_ip.octets()),
                };
                self.write_message(response).await?;
            }
            C2SMessage::PassMessage { from, to, data, protocol } => {
                let clients = clients.pin_owned();
                
                if let Some(client) = clients.get(&to.ip()) {
                    let len = data.len();
                    let response = S2CHeader {
                        msg_type: S2CMessage::PassMessage {
                            from,
                            to,
                            data,
                            protocol,
                        },
                    };
                    tracing::debug!(?from, ?to, len, "Passing message");
                    client.write_message(response).await?;
                } else if to.ip().is_broadcast() {
                    tracing::debug!(?from, "Sending broadcast to all clients");
                    for (fictive_ip, client) in &clients {
                        // Sender also needs to receive it
                        // if *fictive_ip == self.fictional_ip {
                        //     continue;
                        // }
                        
                        let response = S2CHeader {
                            msg_type: S2CMessage::PassBroadcast {
                                from,
                                to,
                                data: data.clone(),
                            },
                        };
                        client.write_message(response).await?;
                    }
                } else {
                    let response = S2CHeader {
                        msg_type: S2CMessage::DeadClient {
                            client: to,
                        },
                    };
                    self.write_message(response).await?
                }
            }
            C2SMessage::Connect { from, to } => {
                tracing::debug!(?from, ?to, "Passing Connect request");
                let clients = clients.pin_owned();
                let response = S2CHeader {
                    msg_type: S2CMessage::Connect {
                        from,
                        to,
                    },
                };
                if let Some(client) = clients.get(&to.ip()) {
                    client.write_message(response).await?;
                }else {
                    let response = S2CHeader {
                        msg_type: S2CMessage::DeadClient {
                            client: to,
                        },
                    };
                    self.write_message(response).await?
                }
            }
        }
        
        Ok(())
    }

    pub async fn write_message<T: Encode + Debug>(&self, msg: T) -> eyre::Result<()> {
        let mut lock = self.write.lock().await;
        let _ = gbe_proxy_common::write_message(&mut lock, msg).await?;
        Ok(())
    }
}