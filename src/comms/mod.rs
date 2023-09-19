mod error;
mod message;
mod tls_utils;

pub use error::CommsError;
use std::collections::btree_map::BTreeMap;
use std::io;

use crate::casper_types::bincode_format::BincodeFormat;
use crate::casper_types::chainspec::Chainspec;
use crate::casper_types::message::{Message, Payload};
use crate::casper_types::ser_deser::MessagePackFormat;
use crate::comms::error::{SslResult, TLSError};
use crate::comms::message::CommsMessage;
use crate::comms::tls_utils::{
    set_context_options, validate_self_signed_cert, with_generated_certs, Identity,
};
use bytes::Bytes;
use futures::{SinkExt, StreamExt};
use openssl::pkey::{PKeyRef, Private};
use openssl::ssl::{Ssl, SslAcceptor, SslConnector, SslMethod};
use openssl::x509::X509Ref;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc::Sender;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio::time::{interval, timeout, Duration};
use tokio_openssl::SslStream;
use tokio_serde::{Deserializer, Serializer};
use tokio_util::codec::LengthDelimitedCodec;
use tracing::{debug, error, info, trace, warn};

/// Channel bounds
pub(crate) const CHANNEL_SIZE: usize = 10_000;

/// Maximum frame length to be decoded from incoming stream
pub const MAX_FRAME_LEN: usize = 25165824; // 25 MB as Bytes

/// Connection Pool polling rate
pub const POLLING_RATE: u64 = 1; // 1 ms

pub type FramedTransport = tokio_util::codec::Framed<SslStream<TcpStream>, LengthDelimitedCodec>;

pub struct Comms {
    our_address: SocketAddr,
    tcp_ep: Arc<Mutex<TcpListener>>,
    identity: Identity,
    chainspec: Chainspec,
    connection_pool: Arc<Mutex<BTreeMap<SocketAddr, FramedTransport>>>,
    endpoint_listener_handle: Option<JoinHandle<()>>,
    conn_pool_listener_handle: Option<JoinHandle<()>>,
}

impl Comms {
    pub async fn new_node<P: Payload>(
        addr: SocketAddr,
        event_tx: Sender<(SocketAddr, Message<P>)>,
        chainspec: Chainspec,
    ) -> Result<Self, CommsError> {
        debug!("Starting Tokio::net::TcpListener");
        let tcp_ep = TcpListener::bind(addr)
            .await
            .map_err(|_| CommsError::ListenerConversion)?;
        let new_identity = with_generated_certs()?;

        let mut comms = Comms {
            our_address: addr,
            connection_pool: Arc::new(Mutex::new(BTreeMap::new())),
            tcp_ep: Arc::new(Mutex::new(tcp_ep)),
            identity: new_identity,
            endpoint_listener_handle: None,
            conn_pool_listener_handle: None,
            chainspec,
        };

        let endpoint_listener_handle = comms.listen_on_endpoint().await;
        let conn_pool_listener_handle = comms.listen_to_connection_pool(event_tx).await;

        comms.endpoint_listener_handle = Some(endpoint_listener_handle);
        comms.conn_pool_listener_handle = Some(conn_pool_listener_handle);

        info!("Network communications started!");
        trace!("Waiting for incoming connections...");

        Ok(comms)
    }

    pub fn our_address(&self) -> SocketAddr {
        self.our_address
    }

    pub async fn connect_to(&self, peer_addr: &SocketAddr) -> Result<(), CommsError> {
        println!("Connecting to Peer {peer_addr:?}");
        let stream = TcpStream::connect(peer_addr)
            .await
            .map_err(TLSError::TcpConnection)?;

        stream.set_nodelay(true).map_err(|_| TLSError::TcpNoDelay)?;

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
        //
        // // We'll validate them just as Casper does to maintain integrity
        let _validated_peer_cert = validate_self_signed_cert(peer_cert)?;

        info!("Validated Peer Cert");
        // Frame the transport
        let framed_transport = tokio_util::codec::Framed::new(
            transport,
            LengthDelimitedCodec::builder()
                .max_frame_length(MAX_FRAME_LEN)
                .new_codec(),
        );

        self.connection_pool
            .lock()
            .await
            .insert(*peer_addr, framed_transport);
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

    pub async fn listen_on_endpoint(&self) -> JoinHandle<()> {
        let connection_pool = self.connection_pool.clone();
        let identity = self.identity.clone();
        let tcp_ep = self.tcp_ep.clone();
        info!("Starting to listen on TCP Endpoint for incoming connections");
        tokio::spawn(async move {
            while let Ok((stream, peer_addr)) = tcp_ep.lock().await.accept().await {
                info!("New connection received!");

                info!("Setting up TLS with connected peer");
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
                        error!("Error accepting connection at endpoint {e:?}");
                        continue;
                    }
                };

                info!("Starting TLS level handshake");
                if let Err(e) = SslStream::accept(Pin::new(&mut transport))
                    .await
                    .map_err(|e| CommsError::Tls(TLSError::TlsHandshake(e.to_string())))
                {
                    error!("Error accepting connection to endpoint {e:?}");
                    continue;
                }

                info!("Receiving peer's Ssl certificates");
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

                info!("Verifying peer's certificates for sanity");
                // We'll validate them just as Casper does to maintain integrity
                // We won't be storing them as we won't be holding connections after handshake
                let _validated_peer_cert = match validate_self_signed_cert(peer_cert) {
                    Ok(peer_cert) => peer_cert,
                    Err(e) => {
                        error!("Error accepting connection at endpoint {e:?}");
                        continue;
                    }
                };

                info!("Framing the stream to match Casper's encoding");
                // Frame the transport
                let framed_transport = tokio_util::codec::Framed::new(
                    transport,
                    LengthDelimitedCodec::builder()
                        .max_frame_length(MAX_FRAME_LEN)
                        .new_codec(),
                );

                info!("Inserting stream into our connection pool");
                // insert into connection pool
                let _ = connection_pool
                    .lock()
                    .await
                    .insert(peer_addr, framed_transport);
            }
        })
    }

    pub async fn listen_to_connection_pool<P: Payload>(
        &self,
        event_tx: Sender<(SocketAddr, Message<P>)>,
    ) -> JoinHandle<()> {
        info!("Starting connection pool listener thread");
        let our_addr = self.our_address();
        let all_receivers = self.connection_pool.clone();
        let chainspec = self.chainspec.clone();
        tokio::spawn(async move {
            // Polling interval
            let mut interval = interval(Duration::from_millis(POLLING_RATE));

            loop {
                // Wait for the polling to happen
                interval.tick().await;

                for (addr, stream) in all_receivers.lock().await.iter_mut() {
                    // Split into a bi-directional stream
                    let (mut writer, mut reader) = stream.split();

                    if let Ok(Some(msg)) =
                        timeout(Duration::from_millis(POLLING_RATE), reader.next()).await
                    {
                        match msg {
                            Ok(bytes_read) => {
                                let mut encoder = MessagePackFormat;
                                let remote_message: Result<Message<P>, io::Error> =
                                    Pin::new(&mut encoder).deserialize(&bytes_read);

                                if let Ok(msg) = remote_message {
                                    match msg {
                                        Message::Handshake { .. } => {
                                            // Notify the event loop
                                            let _ = event_tx.send((*addr, msg)).await;

                                            // Send back a handshake message on the same stream
                                            let hs: Message<P> = Message::Handshake {
                                                network_name: chainspec.network_config.name.clone(),
                                                public_addr: our_addr,
                                                protocol_version: chainspec.protocol_version(),
                                                consensus_certificate: None, // not required
                                                is_syncing: false,           // not required
                                                chainspec_hash: Some(chainspec.hash()),
                                            };

                                            info!("Sending Handshake to Casper");
                                            trace!("{hs:?}");

                                            // Serialize our handshake
                                            match Pin::new(&mut encoder)
                                                .serialize(&Arc::new(hs))
                                                .map_err(|e| {
                                                    CommsError::CouldNotEncodeOurHandshake(
                                                        e.to_string(),
                                                    )
                                                }) {
                                                Ok(bytes) => {
                                                    if let Err(e) = writer.send(bytes).await {
                                                        error!(
                                                            "Error sending handshake to CASPER!: {e:?}"
                                                        );
                                                    }
                                                }
                                                Err(e) => {
                                                    error!("Error serializing handshake for Casper!: {e:?}");
                                                    continue;
                                                }
                                            }
                                        }
                                        _ => {
                                            info!("Ignoring post-handshake traffic from Casper");
                                            println!("Ignoring post-handshake traffic from Casper");
                                        }
                                    }
                                } else {
                                    // NOTE: This block is just done for demonstration purpose
                                    // This proves that the serialization format has changed since handshake was a success.
                                    trace!("BYTES FROM CASPER {bytes_read:?}");

                                    let mut bincode_fmt = BincodeFormat::default();

                                    let _: Message<P> = match Pin::new(&mut bincode_fmt)
                                        .deserialize(&bytes_read)
                                    {
                                        Ok(message) => {
                                            let _ = event_tx.send((*addr, message.clone())).await;
                                            message
                                        }
                                        Err(e) => {
                                            warn!("Error deserializing {e:?}");
                                            warn!("Received an internal message from Casper. Ignoring the deserialization error");
                                            continue;
                                        }
                                    };
                                }
                            }
                            Err(e) => {
                                error!("Error reading from client: {:?}", e);
                            }
                        }
                    }
                }
            }
        })
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
