mod builder;
mod error;
mod message;
mod tls_utils;

pub use error::CommsError;
use std::collections::btree_map::BTreeMap;

use crate::comms::builder::{Builder, SERVER_NAME};
use crate::comms::error::{SslResult, TLSError};
use crate::comms::message::CommsMessage;
use crate::comms::tls_utils::{
    generate_node_cert, validate_self_signed_cert, with_generated_certs, Identity,
};
use crate::event::Event;
use bincode::deserialize;
use bytes::Bytes;
use openssl::pkey::{PKeyRef, Private};
use openssl::ssl::{SslConnector, SslMethod};
use openssl::x509::X509Ref;
use quinn::{Connection, RecvStream, SendStream};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::sync::Mutex;
use tokio::time::{sleep, timeout, Duration};
use tokio_openssl::SslStream;
use tracing::{debug, error, trace};

/// Channel bounds
pub(crate) const CHANNEL_SIZE: usize = 10_000;

pub(crate) const IDLE_TIMEOUT: usize = 60 * 60 * 1_000; // 3600s

pub struct Comms {
    quinn_endpoint: quinn::Endpoint,
    incoming_conns: Arc<Mutex<IncomingConnections>>,
    #[allow(clippy::type_complexity)]
    connection_pool: Arc<Mutex<BTreeMap<SocketAddr, (Connection, Receiver<IncomingMsg>)>>>,
    tcp_ep: TcpListener,
    identity: Identity,
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
        event_tx: Sender<(SocketAddr, Event)>,
    ) -> Result<Self, CommsError> {
        let (endpoint, incoming_connections) = Builder::new()
            .addr(addr)
            .idle_timeout(IDLE_TIMEOUT as u32)
            .server()?;

        let listener =
            TcpListener::bind(bind_address).map_err(|error| CommsError::ListenerCreation(error))?;

        // We must set non-blocking to `true` or else the tokio task hangs forever.
        listener
            .set_nonblocking(true)
            .map_err(CommsError::ListenerSetNonBlocking)?;

        let tcp_ep =
            tokio::net::TcpListener::from_std(listener).map_err(CommsError::ListenerConversion)?;

        let incoming_arced = Arc::new(Mutex::new(incoming_connections));

        let new_identity = with_generated_certs()?;

        let comms = Comms {
            quinn_endpoint: endpoint,
            incoming_conns: incoming_arced,
            connection_pool: Arc::new(Mutex::new(BTreeMap::new())),
            tcp_ep,
            identity: new_identity,
        };

        comms.listen_on_endpoint().await;

        comms.listen_to_connection_pool(event_tx).await;

        Ok(comms)
    }

    pub(crate) async fn connect_to(addr: SocketAddr) -> Result<(), CommsError> {
        let stream = TcpStream::connect(peer_addr)
            .await
            .map_err(TLSError::TcpConnection)?;

        stream.set_nodelay(true).map_err(TLSError::TcpNoDelay)?;

        let mut transport =
            Self::create_tls_connector(context.our_cert.as_x509(), &context.secret_key)
                .and_then(|connector| connector.configure())
                .and_then(|mut config| {
                    config.set_verify_hostname(false);
                    config.into_ssl("this-will-not-be-checked.example.com")
                })
                .and_then(|ssl| SslStream::new(ssl, stream))
                .map_err(TLSError::TlsInitialization)?;

        let peer_cert = transport
            .ssl()
            .peer_certificate()
            .ok_or(TLSError::NoPeerCertificate)?;

        // We'll validate them just as Casper does to maintain integrity
        let validated_peer_cert =
            validate_self_signed_cert(peer_cert).map_err(TLSError::PeerCertificateInvalid)?;

        Ok(())
    }
    /// Creates a TLS acceptor for a client.
    ///
    /// A connector compatible with the acceptor created using `create_tls_acceptor`. Server
    /// certificates must always be validated using `validate_cert` after connecting.
    pub(crate) fn create_tls_connector(
        cert: &X509Ref,
        private_key: &PKeyRef<Private>,
    ) -> SslResult<SslConnector> {
        let mut builder = SslConnector::builder(SslMethod::tls_client())?;
        set_context_options(&mut builder, cert, private_key)?;

        Ok(builder.build())
    }

    pub fn local_address(&self) -> Result<SocketAddr, CommsError> {
        self.quinn_endpoint
            .local_addr()
            .map_err(|e| CommsError::Io(e.to_string()))
    }

    pub async fn listen_on_endpoint(&self) {
        let incoming_conns = self.incoming_conns.clone();
        let connection_pool = self.connection_pool.clone();
        trace!("Starting to listen!");
        let _handle = tokio::spawn(async move {
            while let Some((connection, incoming_msg)) = incoming_conns.lock().await.next().await {
                trace!("New connection received!");

                // insert into connection pool
                connection_pool
                    .lock()
                    .await
                    .insert(connection.remote_address(), (connection, incoming_msg));
                trace!("Inserted new conn!");
            }
        });
    }

    pub async fn listen_to_connection_pool(&self, event_tx: Sender<(SocketAddr, Event)>) {
        let all_receivers = self.connection_pool.clone();
        let _handle = tokio::spawn(async move {
            loop {
                for (connection, ref mut receiver) in all_receivers.lock().await.values_mut() {
                    let msg =
                        if let Ok(msg) = timeout(Duration::from_millis(1), receiver.recv()).await {
                            match msg {
                                Some(msg) => {
                                    debug!("Recevied new msg on connection pool!");
                                    msg
                                }
                                None => {
                                    error!("Received error when reading message");
                                    continue;
                                }
                            }
                        } else {
                            continue;
                        };

                    match msg {
                        Ok((comms_message, _resp_stream)) => {
                            let payload = comms_message.get_payload();
                            let peer_addr = connection.remote_address();
                            let event: Event = deserialize(&payload).unwrap();
                            event_tx.send((peer_addr, event)).await.unwrap();
                            continue;
                        }
                        Err(e) => {
                            error!("Received error when opening message {e:?}");
                        }
                    }
                }

                // Polling interval
                sleep(Duration::from_millis(5)).await;
            }
        });
    }

    /// Attempt a connection to a node_addr.
    ///
    /// It will always try to open a new connection.
    pub async fn new_connection(&mut self, node_addr: &SocketAddr) {
        debug!("Attempting to connect to {:?}", node_addr);
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
                debug!("Successfully connected to peer {node_addr}, conn_id={conn_id}",);

                // Add this connection to the pool
                self.connection_pool
                    .lock()
                    .await
                    .insert(new_conn.remote_address(), (new_conn, peer_connection_rx));
            }
            Err(error) => {
                error!("Error {error:?} when connecting to given address {node_addr:?}")
            }
        }
    }

    pub async fn send_message_to(
        &self,
        addr: SocketAddr,
        payload: Bytes,
    ) -> Result<(), CommsError> {
        let (mut send_str, _recv_str) = self.open_bi(addr).await?;
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
        debug!("Opening bi stream to {addr:?}");
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

            // Polling interval
            sleep(Duration::from_millis(5)).await;
        }

        trace!("Connection {conn_id}: stopped listening for bi-streams");
    });
}
