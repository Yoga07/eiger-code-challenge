mod error;
mod message;
mod tls_utils;

pub use error::CommsError;
use std::collections::btree_map::BTreeMap;

use crate::comms::error::{SslResult, TLSError};
use crate::comms::message::CommsMessage;
use crate::comms::tls_utils::{
    generate_node_cert, set_context_options, validate_self_signed_cert, with_generated_certs,
    Identity,
};
use crate::event::Event;
use bincode::deserialize;
use bytes::Bytes;
use openssl::pkey::{PKeyRef, Private};
use openssl::ssl::{Ssl, SslAcceptor, SslConnector, SslMethod};
use openssl::x509::X509Ref;
use quinn::{Connection, RecvStream, SendStream};
use serde_big_array::big_array;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::sync::Mutex;
use tokio::time::{sleep, timeout, Duration};
use tokio_openssl::SslStream;
use tracing::{debug, error, info, trace};

/// Channel bounds
pub(crate) const CHANNEL_SIZE: usize = 10_000;

pub(crate) const IDLE_TIMEOUT: usize = 60 * 60 * 1_000; // 3600s

pub struct Comms {
    #[allow(clippy::type_complexity)]
    tcp_ep: Arc<Mutex<TcpListener>>,
    identity: Identity,
    connection_pool: Arc<Mutex<BTreeMap<SocketAddr, SslStream<TcpStream>>>>,
}

impl Comms {
    pub async fn new_node(
        addr: SocketAddr,
        event_tx: Sender<(SocketAddr, Event)>,
    ) -> Result<Self, CommsError> {
        println!("[{addr:?}] Starting std::tcp listener");
        let listener = std::net::TcpListener::bind(addr)
            .map_err(|error| CommsError::ListenerCreation(error))?;

        // We must set non-blocking to `true` or else the tokio task hangs forever.
        listener
            .set_nonblocking(true)
            .map_err(|_| CommsError::ListenerSetNonBlocking)?;

        println!("[{addr:?}] Converting std::tcp listener to tokio");
        let tcp_ep = TcpListener::from_std(listener).map_err(|_| CommsError::ListenerConversion)?;
        let new_identity = with_generated_certs()?;

        let comms = Comms {
            connection_pool: Arc::new(Mutex::new(BTreeMap::new())),
            tcp_ep: Arc::new(Mutex::new(tcp_ep)),
            identity: new_identity,
        };

        println!("[{addr:?}] Created comms!");

        comms.listen_on_endpoint().await;

        comms.listen_to_connection_pool(event_tx).await;

        Ok(comms)
    }

    pub async fn our_address(&self) -> Result<SocketAddr, CommsError> {
        self.tcp_ep
            .lock()
            .await
            .local_addr()
            .map_err(|e| CommsError::Io(e.to_string()))
    }

    pub async fn connect_to(&self, peer_addr: &SocketAddr) -> Result<(), CommsError> {
        println!("Connecting to Peer {peer_addr:?}");
        let stream = TcpStream::connect(peer_addr)
            .await
            .map_err(|e| TLSError::TcpConnection(e))?;

        stream.set_nodelay(true).map_err(|e| TLSError::TcpNoDelay)?;

        let transport =
            Self::create_tls_connector(&self.identity.tls_certificate, &self.identity.secret_key)
                .and_then(|connector| connector.configure())
                .and_then(|mut config| {
                    config.set_verify_hostname(false);
                    config.into_ssl("this-will-not-be-checked.example.com")
                })
                .and_then(|ssl| SslStream::new(ssl, stream))
                .map_err(|e| TLSError::TlsInitialization(e.to_string()))?;

        let peer_cert = transport
            .ssl()
            .peer_certificate()
            .ok_or(TLSError::NoPeerCertificate)?;

        // We'll validate them just as Casper does to maintain integrity
        let _validated_peer_cert = validate_self_signed_cert(peer_cert)?;

        info!("Validated Peer Cert");

        self.connection_pool
            .lock()
            .await
            .insert(peer_addr.clone(), transport);
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

    /// Creates a TLS acceptor for a server.
    ///
    /// The acceptor will restrict TLS parameters to secure one defined in this crate that are
    /// compatible with connectors built with `create_tls_connector`.
    ///
    /// Incoming certificates must still be validated using `validate_cert`.
    pub(crate) fn create_tls_acceptor(
        cert: &X509Ref,
        private_key: &PKeyRef<Private>,
    ) -> SslResult<SslAcceptor> {
        let mut builder = SslAcceptor::mozilla_modern_v5(SslMethod::tls_server())?;
        set_context_options(&mut builder, cert, private_key)?;

        Ok(builder.build())
    }

    pub async fn listen_on_endpoint(&self) {
        let connection_pool = self.connection_pool.clone();
        let identity = self.identity.clone();
        let tcp_ep = self.tcp_ep.clone();
        trace!("Starting to listen!");
        println!("Starting to listen!");
        let _handle = tokio::spawn(async move {
            println!("Started ep listener thread");
            while let Ok((stream, peer_addr)) = tcp_ep.lock().await.accept().await {
                println!("New connection received!");
                trace!("New connection received!");

                let mut transport: SslStream<TcpStream> = match Self::create_tls_acceptor(
                    identity.tls_certificate.as_ref(),
                    identity.secret_key.as_ref(),
                )
                .and_then(|ssl_acceptor| Ssl::new(ssl_acceptor.context()))
                .and_then(|ssl| SslStream::new(ssl, stream))
                .map_err(|e| CommsError::Tls(TLSError::TlsInitialization(e.to_string())))
                {
                    Ok(stream) => stream,
                    Err(e) => {
                        println!("Error accepting connection at endpoint {e:?}");
                        error!("Error accepting connection at endpoint {e:?}");
                        continue;
                    }
                };

                if let Err(e) = SslStream::accept(Pin::new(&mut transport))
                    .await
                    .map_err(|e| CommsError::Tls(TLSError::TlsHandshake(e.to_string())))
                {
                    error!("Error accepting connection at endpoint {e:?}");
                    println!("Error accepting connection at endpoint {e:?}");
                    continue;
                }

                let peer_cert = match transport
                    .ssl()
                    .peer_certificate()
                    .ok_or(TLSError::NoPeerCertificate)
                {
                    Ok(cert) => cert,
                    Err(e) => {
                        error!("Error accepting connection at endpoint {e:?}");
                        continue;
                    }
                };

                // We'll validate them just as Casper does to maintain integrity
                let _validated_peer_cert = match validate_self_signed_cert(peer_cert) {
                    Ok(peer_cert) => peer_cert,
                    Err(e) => {
                        error!("Error accepting connection at endpoint {e:?}");
                        println!("Error accepting connection at endpoint {e:?}");
                        continue;
                    }
                };

                // insert into connection pool
                let _ = connection_pool.lock().await.insert(peer_addr, transport);
                trace!("Inserted new conn!");
                println!("Inserted new conn!");
            }
        });
    }

    pub async fn listen_to_connection_pool(&self, event_tx: Sender<(SocketAddr, Event)>) {
        println!("Starting conn pool listener thread");
        let all_receivers = self.connection_pool.clone();
        let _handle = tokio::spawn(async move {
            println!("Starteddddd conn pool listener thread");
            loop {
                for stream in all_receivers.lock().await.values_mut() {
                    let (mut reader, _writer) = tokio::io::split(stream);
                    // Create a buffer to read incoming data
                    let mut buffer = [0u8; 1024 * 1024]; // 1 MB buffer
                    println!("reading with buffer");
                    if let Ok(msg) =
                        timeout(Duration::from_millis(1), reader.read(&mut buffer)).await
                    {
                        match msg {
                            Ok(bytes_read) => {
                                if bytes_read == 0 {
                                    // The client has disconnected
                                    println!("Disconnected.");
                                }

                                // Handle the data received from the client
                                let data = &buffer[..bytes_read];
                                println!("Received DATA FROM CASPER!: {:?}", data);
                            }
                            Err(e) => {
                                println!("Error reading from client: {:?}", e);
                            }
                        }
                    }

                    // Polling interval
                    sleep(Duration::from_millis(5)).await;
                }
            }
        });
    }

    pub async fn send_message_to(
        &self,
        addr: SocketAddr,
        payload: Bytes,
    ) -> Result<(), CommsError> {
        let mut conn_pool = self.connection_pool.lock().await;

        let peer_connection = conn_pool.get_mut(&addr).ok_or(CommsError::PeerNotFound)?;
        let message = CommsMessage::new(payload)?;
        message.write_to_stream(peer_connection).await
    }
}
