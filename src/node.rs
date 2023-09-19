use crate::casper_types::chainspec::Chainspec;
use crate::casper_types::message::{Message, Payload};
use crate::comms::{Comms, CHANNEL_SIZE};
use crate::error::{Error, Result};
use crate::utils::setup_logging;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::mpsc::{channel, Receiver};
use tokio::sync::RwLock;
use tracing::{error, info};

// Placeholder for the casper_types::message::Message's generic.
// Required by the event loop channels
impl Payload for Vec<u8> {}

type EventReceiver = Receiver<(SocketAddr, Message<Vec<u8>>)>;

#[derive(Clone)]
pub struct Node {
    comms: Arc<RwLock<Comms>>,
    event_rx: Arc<RwLock<EventReceiver>>,
    bootstrap_test_addr: Option<SocketAddr>,
}

impl Node {
    pub async fn new(
        our_addr: SocketAddr,
        bootstrap_nodes: Vec<SocketAddr>,
        chainspec_path: PathBuf,
        log_to_file: bool,
    ) -> Result<Self> {
        setup_logging(log_to_file);
        // Channels for event loop
        let (event_tx, event_rx) = channel(CHANNEL_SIZE);

        // Read chainspec to match chainspec of Casper
        let chainspec = Chainspec::from_path(chainspec_path)?;

        // Initialize communications
        let comms = Comms::new_node(our_addr, event_tx, chainspec)
            .await
            .map_err(Error::Comms)?;

        let bootstrap_test_addr = bootstrap_nodes.first().cloned();
        for peer in bootstrap_nodes {
            comms.connect_to(&peer).await?;
            comms.send_handshake_to::<Vec<u8>>(peer).await?;
        }

        info!("Started node at {:?}", comms.our_address());

        let node = Node {
            comms: Arc::new(RwLock::new(comms)),
            event_rx: Arc::new(RwLock::new(event_rx)),
            bootstrap_test_addr,
        };

        Ok(node)
    }

    pub async fn start_event_loop(&self) {
        let event_rx = self.event_rx.clone();
        let comms = self.comms.clone();
        let bootstrap_test_addr = self.bootstrap_test_addr;
        info!("Starting event loop for node");
        while let Some((peer, message)) = event_rx.write().await.recv().await {
            match message {
                Message::Handshake { .. } => {
                    // Just log it, we are not going to process it here.
                    // Comms module takes care of the replying since it is a protocol level message.
                    info!("Received a Handshake from Peer {peer:?} \n {message:?}! ");

                    // Test Handshake
                    // NOTE: We cannot reply to the incoming peer address because it is always different to the listening address of the same peer
                    // Therefore we'll test a random peer for Ping/Pong
                    if let Some(test_addr) = bootstrap_test_addr {
                        if let Err(e) = comms.write().await.send_ping_to::<Vec<u8>>(test_addr).await
                        {
                            error!("Error {e:?} sending ping to {peer:?}");
                        }
                    }
                }
                Message::Ping { .. } => {
                    info!("Received a {message:?} from Casper. Not going to send a Pong!");
                }
                Message::Pong { .. } => {
                    info!("Received a {message:?} from {peer:?}");
                }
                _ => info!("Received a different message {message:?}!"),
            }
        }
    }
}
