mod builder;
mod error;
mod message;

use quinn::{Connection, TransportConfig};
use tokio::sync::mpsc::Receiver;

pub struct Comms {
    quinn_endpoint: quinn::Endpoint,
}

/// Channel on which incoming connections are notified on
#[derive(Debug)]
pub struct IncomingConnections(pub(crate) Receiver<(Connection, COnnection)>);

impl IncomingConnections {
    /// Blocks until there is an incoming connection and returns the address of the
    /// connecting peer
    pub async fn next(&mut self) -> Option<(Connection, ConnectionIncoming)> {
        self.0.recv().await
    }

    /// Non-blocking method to receive the next incoming connection if present.
    /// See tokio::sync::mpsc::Receiver::try_recv()
    pub fn try_recv(&mut self) -> Result<(Connection, ConnectionIncoming), TryRecvError> {
        self.0.try_recv()
    }
}

impl Comms {
    fn new_node() -> Self {

        let transport_cfg = TransportConfig::default();

        let ep = quinn::EndpointConfig::new()

    }
}