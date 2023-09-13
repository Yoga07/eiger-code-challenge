use crate::comms::{Comms, CHANNEL_SIZE};
use crate::error::{Error, Result};
use crate::message::Event;
use bytes::Bytes;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::mpsc::{channel, Receiver};
use tokio::sync::RwLock;
// use tracing::error;

pub struct Node {
    addr: SocketAddr,
    comms: Arc<RwLock<Comms>>,
    event_rx: Arc<RwLock<Receiver<Event>>>,
}

impl Node {
    pub async fn new(addr: SocketAddr) -> Result<Self> {
        let (event_tx, event_rx) = channel::<Event>(CHANNEL_SIZE);

        let comms = Comms::new_node(addr, event_tx)
            .await
            .map_err(|e| Error::CommsError(e))?;
        println!("Started node at {}", comms.local_address()?);

        let addr = comms.local_address()?;

        let node = Node {
            addr,
            comms: Arc::new(RwLock::new(comms)),
            event_rx: Arc::new(RwLock::new(event_rx)),
        };

        Ok(node)
    }

    pub async fn connect_to(&mut self, addr: SocketAddr) {
        self.comms.write().await.new_connection(&addr).await
    }

    pub async fn send_message_to(&self, addr: SocketAddr, msg: Bytes) -> Result<()> {
        println!("Trying to send a message to {addr:?}");
        self.comms.read().await.send_message_to(addr, msg).await?;
        println!("Sent a message to {addr:?}");
        Ok(())
    }

    pub async fn start_event_loop(&self) {
        let event_rx = self.event_rx.clone();
        while let Some(event) = event_rx.write().await.recv().await {
            println!("Received an EVENT!");
            println!("{event:?}");
        }
    }
}
