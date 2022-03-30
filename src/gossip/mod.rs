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
    sync::Arc,
    time::Duration,
};

use async_std::{net::UdpSocket, sync::Mutex, task::sleep};
use rand::prelude::IteratorRandom;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Gossip server instance.
pub struct Server<T: Clone> {
    socket: UdpSocket,
    network: Arc<Mutex<Network<T>>>,
}

impl<T> Server<T>
where
    T: Clone + Send + Sync + Serialize + for<'de> Deserialize<'de>,
{
    /// Initializes a new Gossip server instance with initial local data.
    /// Opens a UDP socket immediately.
    pub async fn new(data: T) -> io::Result<Self> {
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        let network = Arc::new(Mutex::new(Network::new(data)));
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

    /// Modifies the data associated with local peer.
    pub async fn update_data(&self, update_fn: impl FnOnce(&mut T)) {
        let mut network = self.network.lock().await;
        network.local_version += 1;
        update_fn(&mut network.local_data);
    }

    /// Returns data about all the peers including local peer.
    pub async fn get_peers(&self) -> PeerMap<T> {
        let network = self.network.lock().await;
        network.peers.clone()
    }

    /// Returns the data associated with local peer.
    pub async fn get_data(&self) -> T {
        let network = self.network.lock().await;
        network.local_data.clone()
    }

    /// Returns ID of the local peer.
    pub async fn get_id(&self) -> Uuid {
        let network = self.network.lock().await;
        network.local_id
    }

    /// Starts the receiving loop.
    async fn recv_loop(&self) -> Result<(), Error> {
        let mut buf = Box::new([0; 2048]);

        loop {
            let (len, peer_addr) = self.socket.recv_from(&mut buf[..]).await?;
            let msg = &buf[..len];
            let msg: Message<T> = bincode::deserialize(msg)?;
            self.recv(msg, peer_addr).await?;
        }
    }

    /// Handles a single incoming message.
    async fn recv(&self, msg: Message<T>, peer_addr: SocketAddr) -> Result<(), Error> {
        let mut network = self.network.lock().await;

        match msg {
            Message::Sync { state } => {
                let mut new_peers = state.peers;

                // check if we have some data that the other peer doesn't
                let has_more = network
                    .peers
                    .iter()
                    .any(|peer| !new_peers.contains_key(peer.0));

                // add sender of the message to the new peer list too
                new_peers.insert(
                    state.local_id,
                    Peer {
                        id: state.local_id,
                        addr: peer_addr,
                        version: state.local_version,
                        data: state.local_data,
                    },
                );

                // update our peer list with new data
                for (new_peer_id, new_peer) in new_peers {
                    match network.peers.entry(new_peer_id) {
                        Entry::Vacant(entry) => {
                            entry.insert(new_peer);
                        }
                        Entry::Occupied(mut entry) => {
                            if new_peer.version > entry.get().version {
                                *entry.get_mut() = new_peer;
                            }
                        }
                    }
                }

                // if we have more data then update the other peer too
                if has_more {
                    self.send(peer_addr).await?;
                }
            }
        }

        Ok(())
    }

    /// Starts the sending loop
    async fn send_loop(&self) -> Result<(), Error> {
        loop {
            // delay between sends
            sleep(Duration::from_secs(5)).await;

            // select 3 random peers
            let recipients = {
                let mut rng = rand::thread_rng();
                let network = self.network.lock().await;
                network
                    .peers
                    .iter()
                    .map(|(_, peer)| peer.addr)
                    .choose_multiple(&mut rng, 3)
            };

            // send
            // TODO: use try_join_all
            for addr in recipients {
                self.send(addr).await?;
            }
        }
    }

    /// Sends a single message to a single peer.
    async fn send(&self, recipient_addr: SocketAddr) -> Result<(), Error> {
        // prepare message
        let msg = Message::Sync {
            state: (self.network.lock().await).clone(),
        };
        let msg = bincode::serialize(&msg)?;

        // send
        self.socket.send_to(&msg, recipient_addr).await?;

        Ok(())
    }
}

/// The network state as known to a single peer
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Network<T: Clone> {
    local_id: Uuid,
    local_version: u32,
    local_data: T,
    peers: PeerMap<T>,
}

impl<T> Network<T>
where
    T: Clone + Send + Sync + Serialize + for<'de> Deserialize<'de>,
{
    pub fn new(data: T) -> Self {
        Self {
            local_id: Uuid::new_v4(),
            local_data: data,
            local_version: 0,
            peers: HashMap::new(),
        }
    }
}

/// Message that can be sent between peers.
#[derive(Debug, Clone, Serialize, Deserialize)]
enum Message<T: Clone> {
    Sync { state: Network<T> },
}

type PeerMap<T> = HashMap<Uuid, Peer<T>>;

/// Snapshot of other peer's state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Peer<T: Clone> {
    id: Uuid,
    addr: SocketAddr,
    version: u32,
    data: T,
}

/// Gossip server error.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
    #[error("bincode error: {0}")]
    Bincode(#[from] bincode::Error),
}
