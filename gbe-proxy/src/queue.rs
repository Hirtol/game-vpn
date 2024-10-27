use gbe_proxy_common::SocketAddrEncodable;
use std::sync::Mutex;
use std::collections::VecDeque;
use std::io::Write;
use crate::quic_conn::RemoteAddress;

#[derive(Debug)]
pub enum PacketSocketQueue {
    /// For UDP based sockets, we don't drop packets _ever_, but will drop remaining unread data
    UDP(Mutex<VecDeque<PacketQueue<Vec<u8>>>>),
    /// FOR TCP sockets with stream-emulation
    TCP(PacketQueue<Mutex<Vec<u8>>>)
}

impl PacketSocketQueue {
    pub fn enqueue_data(&self, from: SocketAddrEncodable, data: Vec<u8>) {
        match self {
            PacketSocketQueue::UDP(q) => {
                let mut lock = q.lock().unwrap();
                let pack = PacketQueue {
                    source: from,
                    queue: data,
                };
                lock.push_back(pack);
            }
            PacketSocketQueue::TCP(q) => {
                let mut lock = q.queue.lock().unwrap();
                lock.extend_from_slice(&data);
            }
        }
    }

    /// How many bytes are pending a read
    pub fn pending_read(&self) -> usize {
        match self {
            PacketSocketQueue::UDP(q) => {
                let lock = q.lock().unwrap();
                lock.get(0).map(|i| i.queue.len()).unwrap_or_default()
            }
            PacketSocketQueue::TCP(q) => {
                let lock = q.queue.lock().unwrap();
                lock.len()
            }
        }
    }

    /// Attempt to read data from the current queue
    ///
    /// If no data was available, `None` is returned, but this is _not_ an error.
    pub fn read_data(&self, mut buf: &mut [u8]) -> Option<(RemoteAddress, usize)> {
        match self {
            PacketSocketQueue::UDP(q) => {
                let mut lock = q.lock().unwrap();
                let packet = lock.pop_front()?;

                let written = buf.write(&packet.queue).expect("Should be infallible write");
                Some((packet.source, written))
            }
            PacketSocketQueue::TCP(q) => {
                let mut lock = q.queue.lock().unwrap();
                let written = buf.write(&lock).expect("Should be infallible write");
                lock.drain(0..written);

                Some((q.source, written))
            }
        }
    }
}

#[derive(Debug)]
pub struct PacketQueue<Q> {
    pub source: RemoteAddress,
    pub queue: Q
}

impl<Q: Default> PacketQueue<Q> {
    pub fn new(source: RemoteAddress) -> Self {
        Self {
            source,
            queue: Q::default(),
        }
    }
}