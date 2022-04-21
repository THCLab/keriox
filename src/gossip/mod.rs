#![cfg(feature = "gossip")]
//! Gossip server can be used to share some data across different program instances over the network.
//!
//! First create instance with some initial data and call [`Server::start`].
//! Then call [`Server::bootstrap`] to join a network.
//! You can use [`Server::update_data`] to update the local data and [`Server::get_peers`] to access data associated with other peers.

use std::{
    collections::{hash_map::Entry, HashMap},
    io,
    net::SocketAddr,
    ops::{Deref, DerefMut},
    sync::Arc,
    time::Duration,
};

use async_std::{
    net::UdpSocket,
    sync::{Mutex, MutexGuard, RwLock, RwLockReadGuard},
    task::sleep,
};
use rand::{prelude::IteratorRandom, Rng};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Gossip server instance.
pub struct Server<T: Clone> {
    socket: UdpSocket,
    network: Network<T>,
}

impl<T> Server<T>
where
    T: Clone + Send + Sync + Serialize + for<'de> Deserialize<'de>,
{
    /// Initializes a new Gossip server instance with initial local data.
    /// Opens a UDP socket immediately.
    pub async fn new(data: T, addr: impl Into<SocketAddr>) -> io::Result<Self> {
        let socket = UdpSocket::bind(addr.into()).await?;
        let network = Network::new(data);
        Ok(Self { socket, network })
    }

    /// Begins sending and receiving gossip messages.
    /// Stops when the future is dropped.
    pub async fn start(&self) -> Result<(), Error> {
        futures::future::select(Box::pin(self.recv_loop()), Box::pin(self.send_loop()))
            .await
            .factor_first()
            .0
    }

    /// Joins a gossip network.
    /// Requires an address of one other participant.
    pub async fn bootstrap(&self, peer_addr: SocketAddr) -> Result<(), Error> {
        self.send(peer_addr).await
    }

    /// Returns local listening address
    pub fn addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// Returns data about all the known peers.
    /// Can include data about local peer too.
    pub async fn peers(&self) -> RwLockReadGuard<'_, PeerMap<T>> {
        self.network.peers.read().await
    }

    /// Returns the data associated with local peer.
    pub async fn data(&self) -> MutexGuard<'_, Data<T>> {
        self.network.data.lock().await
    }

    /// Returns ID of the local peer.
    pub async fn id(&self) -> Uuid {
        self.network.id
    }

    /// Starts the receiving loop.
    async fn recv_loop(&self) -> Result<(), Error> {
        let mut buf = Box::new([0; 2048]);

        loop {
            let (len, peer_addr) = self.socket.recv_from(&mut buf[..]).await?;
            log::info!("{} receiving from {}", self.network.id, peer_addr);
            let buf = &buf[..len];
            let msg = bincode::deserialize::<Message<T>>(buf)?;
            self.recv(msg, peer_addr).await?;
        }
    }

    /// Handles a single incoming message.
    async fn recv(&self, msg: Message<T>, remote_addr: SocketAddr) -> Result<(), Error> {
        match msg {
            Message::Sync {
                id: sender_id,
                data: sender_data,
                peers: mut sender_peers,
            } => {
                // add sender of the message to the new peer list too
                sender_peers.insert(
                    sender_id,
                    Peer {
                        addr: remote_addr,
                        data: sender_data,
                    },
                );

                log::info!(
                    "{} received {} peers from {}",
                    self.network.id,
                    sender_peers.len(),
                    remote_addr
                );

                let mut local_peers = self.network.peers.write().await;

                // update our peer list with new data
                for (new_peer_id, new_peer) in &sender_peers {
                    match local_peers.entry(*new_peer_id) {
                        Entry::Vacant(entry) => {
                            entry.insert(new_peer.clone());
                        }
                        Entry::Occupied(mut entry) => {
                            if new_peer.data.version > entry.get().data.version {
                                *entry.get_mut() = new_peer.clone();
                            }
                        }
                    }
                }

                // check if the sender needs updating
                let mut remote_needs_update = false;
                for (peer_id, peer) in &*local_peers {
                    let remote_peer = sender_peers.get(&peer_id);
                    if let Some(remote_peer) = remote_peer {
                        if remote_peer.data.version >= peer.data.version {
                            continue;
                        }
                    }
                    remote_needs_update = true;
                    break;
                }

                drop(local_peers);

                // if we have more data then update the other peer too
                if remote_needs_update {
                    log::info!("{} reply to {}", self.network.id, remote_addr);
                    if let Err(err) = self.send(remote_addr).await {
                        log::error!("{} reply failed: {}", self.network.id, err);
                    };
                }
            }
        }

        Ok(())
    }

    /// Starts the sending loop
    async fn send_loop(&self) -> Result<(), Error> {
        let mut rng = rand::thread_rng();
        loop {
            // delay between sends
            sleep(Duration::from_millis(rng.gen_range(3000, 4000))).await;

            // select 3 random peers
            let recipients = self
                .network
                .peers
                .read()
                .await
                .iter()
                .map(|(_, peer)| peer.addr)
                .choose_multiple(&mut rng, 3);

            log::info!("{} sending to {} peers", self.network.id, recipients.len());

            // send
            // TODO: use try_join_all
            for addr in recipients {
                if let Err(err) = self.send(addr).await {
                    log::error!("{} sending failed: {}", self.network.id, err);
                };
            }
        }
    }

    /// Sends a single message to a single peer.
    async fn send(&self, recipient_addr: SocketAddr) -> Result<(), Error> {
        // prepare message
        let peers = self.network.peers.read().await.clone();
        log::info!(
            "{} sending {} peers to {}",
            self.network.id,
            peers.len(),
            recipient_addr
        );
        let msg = Message::Sync {
            id: self.network.id,
            data: self.network.data.lock().await.clone(),
            peers,
        };
        let msg = bincode::serialize(&msg)?;

        // send
        self.socket.send_to(&msg, recipient_addr).await?;

        Ok(())
    }
}

/// The network state as known to a single peer
struct Network<T: Clone> {
    id: Uuid,
    data: Arc<Mutex<Data<T>>>,
    peers: Arc<RwLock<PeerMap<T>>>,
}

impl<T> Network<T>
where
    T: Clone + Send + Sync + Serialize + for<'de> Deserialize<'de>,
{
    pub fn new(data: T) -> Self {
        Self {
            id: Uuid::new_v4(),
            data: Arc::new(Mutex::new(Data {
                value: data,
                version: 0,
            })),
            peers: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

/// Message that can be sent between peers.
#[derive(Debug, Clone, Serialize, Deserialize)]
enum Message<T: Clone> {
    /// Sent to another peer to update its state.
    /// If the receiver detects that it has some newer data it should reply with another Sync.
    Sync {
        /// Sender ID
        id: Uuid,
        /// Sender data
        data: Data<T>,
        /// Other peers known to sender.
        /// Can include the sender data too.
        peers: PeerMap<T>,
    },
}

type PeerMap<T> = HashMap<Uuid, Peer<T>>;

/// Snapshot of other peer's state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Peer<T: Clone> {
    addr: SocketAddr,
    data: Data<T>,
}

/// Snapshot of other peer's data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Data<T: Clone> {
    version: u32,
    value: T,
}

impl<T> Data<T>
where
    T: Clone + Send + Sync + Serialize + for<'de> Deserialize<'de>,
{
    pub fn new(value: T) -> Self {
        Self { value, version: 0 }
    }
}

impl<T: Clone> Deref for Data<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.value
    }
}

impl<T: Clone> DerefMut for Data<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.version += 1;
        &mut self.value
    }
}

/// Gossip server error.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
    #[error("bincode error: {0}")]
    Bincode(#[from] bincode::Error),
}
