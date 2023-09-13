mod builder;
mod error;
mod message;

pub use error::CommsError;

use crate::comms::builder::{Builder, SERVER_NAME};
use crate::comms::message::CommsMessage;
use crate::message::NodeMessage;
use bytes::Bytes;
use quinn::{Connection, RecvStream, SendStream};
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::sync::{Mutex, RwLock, RwLockWriteGuard};
use tokio::task::JoinHandle;
use tokio::time::{sleep, Duration};
use tracing::{error, trace};

/// Channel bounds
pub(crate) const CHANNEL_SIZE: usize = 10_000;

pub(crate) const IDLE_TIMEOUT: usize = 60 * 60 * 1_000; // 3600s

pub struct Comms {
    quinn_endpoint: quinn::Endpoint,
    incoming_conns: Arc<Mutex<IncomingConnections>>,
    connection_pool: Arc<Mutex<BTreeMap<SocketAddr, (Connection, Receiver<IncomingMsg>)>>>,
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
    pub async fn new_node(
        addr: SocketAddr,
        event_tx: Sender<NodeMessage>,
    ) -> Result<Self, CommsError> {
        let (endpoint, incoming_connections) = Builder::new()
            .addr(addr)
            .idle_timeout(IDLE_TIMEOUT as u32)
            .server()?;

        let incoming_arced = Arc::new(Mutex::new(incoming_connections));

        let comms = Comms {
            quinn_endpoint: endpoint,
            incoming_conns: incoming_arced,
            connection_pool: Arc::new(Mutex::new(BTreeMap::new())),
        };

        comms.listen_on_endpoint(event_tx.clone()).await;

        comms.listen_to_connection_pool(event_tx).await;

        Ok(comms)
    }

    pub fn local_address(&self) -> Result<SocketAddr, CommsError> {
        self.quinn_endpoint
            .local_addr()
            .map_err(|e| CommsError::Io(e.to_string()))
    }

    pub async fn listen_on_endpoint(&self, event_tx: Sender<NodeMessage>) {
        let mut incoming_conns = self.incoming_conns.clone();
        let mut connection_pool = self.connection_pool.clone();
        println!("Starting to listen!");
        let _handle = tokio::spawn(async move {
            println!("Awaiting message!");
            while let Some((connection, mut incoming_msg)) =
                incoming_conns.lock().await.next().await
            {
                println!("New connection received!");

                // insert into connection pool
                connection_pool
                    .lock()
                    .await
                    .insert(connection.remote_address(), (connection, incoming_msg));
                println!("Inserted new conn!");
            }
        });
    }

    pub async fn listen_to_connection_pool(&self, event_tx: Sender<NodeMessage>) {
        let all_receivers = self.connection_pool.clone();
        let _handle = tokio::spawn(async move {
            loop {
                for (conns, ref mut receiver) in all_receivers.lock().await.values_mut() {
                    println!("Iterating receiver for addr: {:?}", conns.remote_address());
                    let msg = match receiver.recv().await {
                        Some(msg) => {
                            println!("Recevied new msg on connection pool!");
                            msg
                        }
                        None => {
                            println!("Received error when reading message");
                            continue;
                        }
                    };

                    match msg {
                        Ok((comms_message, resp_stream)) => {
                            let payload = comms_message.get_payload();
                            let message = String::from_utf8(payload.to_vec()).unwrap();
                            println!("Received string {message:?}");
                            let event = NodeMessage::String(message);
                            event_tx.send(event).await.unwrap();
                            continue;
                        }
                        Err(e) => {
                            println!("Received error when opening reading message");
                        }
                    }
                }

                // Polling interval
                sleep(Duration::from_secs(1)).await;
            }
        });
    }

    /// Attempt a connection to a node_addr.
    ///
    /// It will always try to open a new connection.
    pub async fn new_connection(&mut self, node_addr: &SocketAddr) {
        println!("Attempting to connect to {:?}", node_addr);
        let connecting = match self.quinn_endpoint.connect(*node_addr, SERVER_NAME) {
            Err(error) => {
                println!(
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
                println!(
                    "Successfully connected to peer {node_addr}, conn_id={}",
                    new_conn.stable_id()
                );

                // Add this connection to the pool
                self.connection_pool
                    .lock()
                    .await
                    .insert(new_conn.remote_address(), (new_conn, peer_connection_rx));
            }
            Err(error) => {
                println!("Error {error:?} when connecting to given address {node_addr:?}")
            }
        }
    }

    pub async fn send_message_to(
        &self,
        addr: SocketAddr,
        payload: Bytes,
    ) -> Result<(), CommsError> {
        let (mut send_str, recv_str) = self.open_bi(addr).await?;
        let message = CommsMessage::new(payload)?;
        message.write_to_stream(&mut send_str).await
    }

    /// Open a bidirectional stream to the peer.
    ///
    /// Bidirectional streams allow messages to be sent in both directions. This can be useful to
    /// automatically correlate response messages, for example.
    ///
    /// Messages sent over the stream will arrive at the peer in the order they were sent.
    pub async fn open_bi(&self, addr: SocketAddr) -> Result<(SendStream, RecvStream), CommsError> {
        let conn_pool = self.connection_pool.lock().await;

        let peer_connection = conn_pool.get(&addr).ok_or(CommsError::PeerNotFound)?;
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
