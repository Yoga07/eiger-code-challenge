use crate::comms::{Comms, CHANNEL_SIZE};
use crate::error::{Error, Result};
use crate::event::{Event, LocalEvent};
use crate::CommsError;
use bincode::serialize;
use blsttc::{PublicKey, SecretKey};
use bytes::Bytes;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tokio::sync::RwLock;
use tracing::{info, trace};
// use tracing::error;

#[derive(Clone)]
pub struct Node {
    addr: SocketAddr,
    bootstrap_nodes: Vec<SocketAddr>,
    // pub(crate) handshake_handler: Arc<RwLock<HandshakeHandler>>,
    comms: Arc<RwLock<Comms>>,
    pub(crate) event_tx: Sender<(SocketAddr, Event)>,
    event_rx: Arc<RwLock<Receiver<(SocketAddr, Event)>>>,
}

impl Node {
    pub async fn new(our_addr: SocketAddr, bootstrap_nodes: Vec<SocketAddr>) -> Result<Self> {
        let (event_tx, event_rx) = channel::<(SocketAddr, Event)>(CHANNEL_SIZE);

        let comms = Comms::new_node(our_addr, event_tx.clone())
            .await
            .map_err(Error::Comms)?;

        info!("Started node at {}", comms.our_address().await?);

        for node_addr in &bootstrap_nodes {
            comms.connect_to(node_addr).await?;
        }

        let node = Node {
            addr: our_addr,
            bootstrap_nodes,
            // handshake_handler: Arc::new(RwLock::new(hs_handler)),
            comms: Arc::new(RwLock::new(comms)),
            event_tx,
            event_rx: Arc::new(RwLock::new(event_rx)),
        };

        Ok(node)
    }

    pub fn our_address(&self) -> SocketAddr {
        self.addr
    }

    pub async fn connect_to(&mut self, addr: SocketAddr) -> Result<()> {
        self.comms
            .write()
            .await
            .connect_to(&addr)
            .await
            .map_err(Error::Comms)
    }

    pub async fn send_event_to(&self, addr: SocketAddr, msg: Event) -> Result<()> {
        info!("Trying to send a message to {addr:?}");
        let serialized = serialize(&msg)?;
        self.comms
            .write()
            .await
            .send_message_to(addr, Bytes::from(serialized))
            .await?;
        info!("Sent a message to {addr:?}");
        Ok(())
    }

    pub async fn start_event_loop(&self) {
        // let node = self.clone();
        let event_rx = self.event_rx.clone();
        let _handle = tokio::spawn(async move {
            while let Some((peer, event)) = event_rx.write().await.recv().await {
                println!("Received {event:?} from {peer:?}");
                match event {
                    Event::Generic(message) => println!("Received string message {message:?}"),
                    // Event::LocalEvent(local_msg) => {
                    //     if let Err(e) = node.handle_local_event(local_msg).await {
                    //         println!("Error handling local event {e:?}");
                    //     }
                    // }
                }
            }
        });
    }

    // pub async fn handle_local_event(&self, event: LocalEvent) -> Result<()> {
    //     match event {
    //         LocalEvent::SendEventTo(peer, event) => self.send_event_to(peer, *event).await,
    //     }
    // }
}
