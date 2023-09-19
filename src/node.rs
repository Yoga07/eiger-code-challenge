use crate::casper_types::chainspec::Chainspec;
use crate::casper_types::message::{Message, Payload};
use crate::casper_types::ser_deser::MessagePackFormat;
use crate::comms::{Comms, CHANNEL_SIZE};
use crate::error::{Error, Result};
use crate::utils::setup_logging;
use casper_types::ProtocolVersion;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use tokio::sync::mpsc::{channel, Receiver};
use tokio::sync::RwLock;
use tokio_serde::Serializer;
use tracing::{info, trace};

// Placeholder for the casper_types::message::Message's generic.
// Required by the event loop channels
impl Payload for Vec<u8> {}

type EventReceiver = Receiver<(SocketAddr, Message<Vec<u8>>)>;

#[derive(Clone)]
pub struct Node {
    addr: SocketAddr,
    comms: Arc<RwLock<Comms>>,
    event_rx: Arc<RwLock<EventReceiver>>,
}

impl Node {
    pub async fn new(
        our_addr: SocketAddr,
        chainspec_path: PathBuf,
        log_to_file: bool,
    ) -> Result<Self> {
        // We'll be logging to console by default.
        // Update this in case we choose to have a config file.
        setup_logging(log_to_file);

        // Channels for event loop
        let (event_tx, event_rx) = channel(CHANNEL_SIZE);

        // Read chainspec to match chainspec of Casper
        let chainspec = Chainspec::from_path(chainspec_path)?;

        // Initialize communications
        let comms = Comms::new_node(our_addr, event_tx, chainspec)
            .await
            .map_err(Error::Comms)?;

        info!("Started node at {:?}", comms.our_address());

        let node = Node {
            addr: our_addr,
            comms: Arc::new(RwLock::new(comms)),
            event_rx: Arc::new(RwLock::new(event_rx)),
        };

        Ok(node)
    }

    pub fn our_address(&self) -> SocketAddr {
        self.addr
    }

    pub async fn connect_to(&self, addr: SocketAddr) -> Result<()> {
        self.comms
            .write()
            .await
            .connect_to(&addr)
            .await
            .map_err(Error::Comms)
    }

    pub async fn send_handshake_to<P: Payload>(&self, addr: SocketAddr) -> Result<()> {
        let mut encoder = MessagePackFormat;
        let hs: Message<P> = Message::Handshake {
            network_name: "casper-example".to_string(),
            public_addr: self.our_address(),
            protocol_version: ProtocolVersion::V1_0_0,
            consensus_certificate: None,
            is_syncing: false,
            chainspec_hash: None,
        };
        let serialized_handshake_message = Pin::new(&mut encoder)
            .serialize(&Arc::new(hs))
            .map_err(|_| Error::HandShake("Could Not Encode Our Handshake".to_string()))?;

        info!("Trying to send a message to {addr:?}");
        println!("Trying to send a message to {addr:?}");
        self.comms
            .write()
            .await
            .send_message_to(addr, serialized_handshake_message)
            .await?;
        info!("Sent a message to {addr:?}");
        Ok(())
    }

    pub async fn start_event_loop(&self) {
        let event_rx = self.event_rx.clone();
        info!("Starting event loop for node");
        while let Some((peer, message)) = event_rx.write().await.recv().await {
            match message {
                Message::Handshake { .. } => {
                    // Just log it, we are not going to process it here.
                    // Comms module takes care of the replying since it is a protocol level message.
                    info!("Received a Handshake from Peer {peer:?}!");
                    trace!("{message:?}");
                }
                Message::Ping { .. } => {
                    info!("Received a Ping from Casper. Not going to send a Pong!");
                    trace!("{message:?}");
                }
                _ => info!("Received a different message {message:?}!"),
            }
        }
    }
}
