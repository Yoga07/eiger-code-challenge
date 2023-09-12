mod builder;
mod error;
mod message;

use crate::comms::builder::{Builder, SERVER_NAME};
use crate::comms::error::CommsError;
use crate::comms::message::CommsMessage;
use quinn::{Connection, RecvStream, SendStream};
use std::collections::BTreeMap;
use std::net::SocketAddr;
use tokio::sync::mpsc::{Receiver, Sender};
use tracing::{error, trace};

/// Channel bounds
pub(crate) const CHANNEL_SIZE: usize = 10_000;

pub struct Comms {
    quinn_endpoint: quinn::Endpoint,
    incoming_conns: IncomingConnections,
    connection_pool: BTreeMap<usize, (Connection, Receiver<IncomingMsg>)>,
}

type IncomingMsg = Result<(CommsMessage, Option<SendStream>), CommsError>;

/// Channel on which incoming connections are notified on
#[derive(Debug)]
pub struct IncomingConnections(pub(crate) Receiver<(Connection, Receiver<IncomingMsg>)>);

impl IncomingConnections {
    /// Blocks until there is an incoming connection and returns the address of the
    /// connecting peer
    pub async fn next(&mut self) -> Option<(Connection, Receiver<IncomingMsg>)> {
        self.0.recv().await
    }

    /// Non-blocking method to receive the next incoming connection if present.
    /// See tokio::sync::mpsc::Receiver::try_recv()
    pub fn try_recv(&mut self) -> Result<(Connection, Receiver<IncomingMsg>), CommsError> {
        self.0
            .try_recv()
            .map_err(|e| CommsError::RecvFailed(e.to_string()))
    }
}

impl Comms {
    pub fn new_node() -> Result<Self, CommsError> {
        let (endpoint, incoming_conns) = Builder::new().server()?;

        Ok(Comms {
            quinn_endpoint: endpoint,
            incoming_conns,
            connection_pool: BTreeMap::new(),
        })
    }

    /// Attempt a connection to a node_addr.
    ///
    /// It will always try to open a new connection.
    async fn new_connection(&mut self, node_addr: &SocketAddr) {
        trace!("Attempting to connect to {:?}", node_addr);
        let connecting = match self.quinn_endpoint.connect(*node_addr, SERVER_NAME) {
            Err(error) => {
                error!(
                    "Connection attempt to {node_addr:?} failed due to {:?}",
                    error
                );
                return;
            }
            Ok(conn) => conn,
        };

        match connecting.await {
            Ok(new_conn) => {
                let conn_id = new_conn.stable_id();
                let (peer_connection_tx, peer_connection_rx) = tokio::sync::mpsc::channel::<
                    Result<(CommsMessage, Option<SendStream>), CommsError>,
                >(CHANNEL_SIZE);
                listen_on_bi_streams(new_conn.clone(), peer_connection_tx);

                trace!(
                    "Successfully connected to peer {node_addr}, conn_id={}",
                    new_conn.stable_id()
                );

                // Add this connection to the pool
                self.connection_pool
                    .insert(conn_id, (new_conn, peer_connection_rx));
            }
            Err(error) => error!("Error {error:?} when connecting to given address {node_addr:?}"),
        }
    }

    /// Open a bidirectional stream to the peer.
    ///
    /// Bidirectional streams allow messages to be sent in both directions. This can be useful to
    /// automatically correlate response messages, for example.
    ///
    /// Messages sent over the stream will arrive at the peer in the order they were sent.
    pub async fn open_bi(&self, peer_id: usize) -> Result<(SendStream, RecvStream), CommsError> {
        let peer_connection = self
            .connection_pool
            .get(&peer_id)
            .ok_or(CommsError::PeerNotFound)?;
        let (send_stream, recv_stream) = peer_connection
            .0
            .open_bi()
            .await
            .map_err(|e| CommsError::BiConnectFailed(e.to_string()))?;
        Ok((send_stream, recv_stream))
    }
}

pub fn listen_on_bi_streams(connection: Connection, tx: Sender<IncomingMsg>) {
    let conn_id = connection.stable_id();

    let _handle = tokio::spawn(async move {
        trace!("Connection {conn_id}: listening for incoming bi-streams");

        loop {
            // Wait for an incoming stream.
            let bi = connection
                .accept_bi()
                .await
                .map_err(|e| CommsError::BiConnectFailed(e.to_string()));
            let (send, recv) = match bi {
                Ok(recv) => recv,
                Err(err) => {
                    // In case of a connection error, there is not much we can do.
                    trace!("Connection failure when awaiting incoming bi-streams: {err:?}");
                    break;
                }
            };
            trace!("Connection {conn_id}: incoming bi-stream accepted");

            let tx = tx.clone();

            // Make sure we are able to process multiple streams in parallel.
            let _handle = tokio::spawn(async move {
                let reserved_sender = match tx.reserve().await {
                    Ok(p) => p,
                    Err(error) => {
                        tracing::error!(
                            "Could not reserve sender for new conn msg read: {error:?}"
                        );
                        return;
                    }
                };
                let msg = CommsMessage::recv_from_stream(recv).await;

                // Pass the stream, so it can be used to respond to the user message.
                let msg = msg.map(|msg| (msg, Some(send)));
                // Send away the msg or error
                reserved_sender.send(msg);
                trace!("Upper layer notified of new messages");
            });
        }

        trace!("Connection {conn_id}: stopped listening for bi-streams");
    });
}
