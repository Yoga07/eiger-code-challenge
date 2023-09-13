use crate::comms::{Comms, CHANNEL_SIZE};
use crate::error::{Error, Result};
use crate::event::Event;
use crate::handshake::HandshakeHandler;
use bincode::serialize;
use blsttc::{PublicKey, SecretKey};
use bytes::Bytes;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::mpsc::{channel, Receiver};
use tokio::sync::RwLock;
// use tracing::error;

#[derive(Clone)]
pub struct Node {
    addr: SocketAddr,
    static_key: (PublicKey, SecretKey),
    bootstrap_nodes: Vec<SocketAddr>,
    pub(crate) handshake_handler: Arc<RwLock<HandshakeHandler>>,
    comms: Arc<RwLock<Comms>>,
    event_rx: Arc<RwLock<Receiver<Event>>>,
}

impl Node {
    pub async fn new(addr: SocketAddr, bootstrap_nodes: Vec<SocketAddr>) -> Result<Self> {
        let (event_tx, event_rx) = channel::<Event>(CHANNEL_SIZE);
        let sk = blsttc::SecretKey::random();
        let pk = sk.public_key();

        let mut comms = Comms::new_node(addr, event_tx)
            .await
            .map_err(|e| Error::CommsError(e))?;

        println!("Started node at {}", comms.local_address()?);

        let addr = comms.local_address()?;
        let hs_handler = HandshakeHandler::new();

        for node_addr in &bootstrap_nodes {
            comms.new_connection(node_addr).await;
        }

        let node = Node {
            addr,
            static_key: (pk, sk),
            bootstrap_nodes,
            handshake_handler: Arc::new(RwLock::new(hs_handler)),
            comms: Arc::new(RwLock::new(comms)),
            event_rx: Arc::new(RwLock::new(event_rx)),
        };

        Ok(node)
    }

    pub async fn connect_to(&mut self, addr: SocketAddr) {
        self.comms.write().await.new_connection(&addr).await
    }

    pub async fn send_event_to(&self, addr: SocketAddr, msg: Event) -> Result<()> {
        println!("Trying to send a message to {addr:?}");
        let serialized = serialize(&msg)?;
        self.comms
            .read()
            .await
            .send_message_to(addr, Bytes::from(serialized))
            .await?;
        println!("Sent a message to {addr:?}");
        Ok(())
    }

    pub async fn start_event_loop(&self) {
        let node = self.clone();
        let event_rx = self.event_rx.clone();
        let hand_shaker = self.handshake_handler.clone();
        let _handle = tokio::spawn(async move {
            while let Some(event) = event_rx.write().await.recv().await {
                match event {
                    Event::Generic(message) => println!("Received string message {message:?}"),
                    Event::Handshake(message) => node.handle_handshake(message).await,
                }
            }
        });
    }
}
