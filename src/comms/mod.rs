mod error;
mod message;
mod tls_utils;

pub use error::CommsError;
use std::collections::btree_map::BTreeMap;

use crate::casper_types::message::{Message, Payload};
use crate::casper_types::ser_deser::MessagePackFormat;
use crate::casper_types::Nonce;
use crate::comms::error::{SslResult, TLSError};
use crate::comms::message::CommsMessage;
use crate::comms::tls_utils::{
    set_context_options, validate_self_signed_cert, with_generated_certs, Identity,
};
use bytes::{Bytes, BytesMut};
use casper_hashing::Digest;
use casper_types::ProtocolVersion;
use futures::{SinkExt, StreamExt};
use openssl::pkey::{PKeyRef, Private};
use openssl::ssl::{Ssl, SslAcceptor, SslConnector, SslMethod};
use openssl::x509::X509Ref;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt, WriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc::Sender;
use tokio::sync::Mutex;
use tokio::time::{sleep, timeout, Duration};
use tokio_openssl::SslStream;
use tokio_serde::{Deserializer, Serializer};
use tokio_util::codec::LengthDelimitedCodec;
use tracing::{error, info, trace};

/// Channel bounds
pub(crate) const CHANNEL_SIZE: usize = 10_000;

pub(crate) const IDLE_TIMEOUT: usize = 60 * 60 * 1_000; // 3600s

pub type FramedTransport = tokio_util::codec::Framed<SslStream<TcpStream>, LengthDelimitedCodec>;

pub struct Comms {
    our_address: SocketAddr,
    tcp_ep: Arc<Mutex<TcpListener>>,
    identity: Identity,
    connection_pool: Arc<Mutex<BTreeMap<SocketAddr, FramedTransport>>>,
}

impl Comms {
    pub async fn new_node<P: Payload>(
        addr: SocketAddr,
        event_tx: Sender<(SocketAddr, Message<P>)>,
        chainspec_hash: Digest,
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
            our_address: addr,
            connection_pool: Arc::new(Mutex::new(BTreeMap::new())),
            tcp_ep: Arc::new(Mutex::new(tcp_ep)),
            identity: new_identity,
        };

        println!("[{addr:?}] Created comms!");

        comms.listen_on_endpoint().await;

        comms
            .listen_to_connection_pool(event_tx, chainspec_hash)
            .await;

        Ok(comms)
    }

    pub fn our_address(&self) -> SocketAddr {
        self.our_address
    }

    pub async fn connect_to(&self, peer_addr: &SocketAddr) -> Result<(), CommsError> {
        println!("Connecting to Peer {peer_addr:?}");
        let stream = TcpStream::connect(peer_addr)
            .await
            .map_err(|e| TLSError::TcpConnection(e))?;

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

        // We'll validate them just as Casper does to maintain integrity
        let _validated_peer_cert = validate_self_signed_cert(peer_cert)?;

        info!("Validated Peer Cert");

        // Frame the transport
        let framed_transport = tokio_util::codec::Framed::new(
            transport,
            LengthDelimitedCodec::builder()
                .max_frame_length(25165824 as usize)
                .new_codec(),
        );

        self.connection_pool
            .lock()
            .await
            .insert(peer_addr.clone(), framed_transport);
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

                // Frame the transport
                let framed_transport = tokio_util::codec::Framed::new(
                    transport,
                    LengthDelimitedCodec::builder()
                        .max_frame_length(25165824 as usize)
                        .new_codec(),
                );

                // insert into connection pool
                let _ = connection_pool
                    .lock()
                    .await
                    .insert(peer_addr, framed_transport);
                trace!("Inserted new conn!");
                println!("Inserted new conn!");
            }
        });
    }

    pub async fn listen_to_connection_pool<P: Payload>(
        &self,
        event_tx: Sender<(SocketAddr, Message<P>)>,
        chainspec_hash: Digest,
    ) {
        println!("Starting conn pool listener thread");
        let our_addr = self.our_address();
        let all_receivers = self.connection_pool.clone();
        let _handle = tokio::spawn(async move {
            loop {
                for (addr, stream) in all_receivers.lock().await.iter_mut() {
                    // let (mut reader, mut writer) = tokio::io::split(stream);

                    let (mut writer, mut reader) = stream.split();
                    // Create a buffer to read incoming data
                    // let mut buffer = [0u8; 1024 * 1024]; // 1 MB buffer
                    if let Ok(Some(msg)) = timeout(Duration::from_millis(1), reader.next()).await {
                        match msg {
                            Ok(bytes_read) => {
                                // if bytes_read == 0 {
                                //     // The client has disconnected
                                //     println!("Peer {addr:?} has disconnected.");
                                //     println!("Removing them from connection pool.");
                                //
                                //     // Remove them from our conn pool
                                //     let _ = all_receivers.lock().await.remove(addr);
                                // }

                                // Handle the data received from the client
                                // let data = &buffer[4..bytes_read]; // remove appended data
                                // let bytes = BytesMut::from(data);

                                println!("Data from Casper {bytes_read:?}");

                                let mut encoder = MessagePackFormat;

                                let remote_message: Message<P> = match Pin::new(&mut encoder)
                                    .deserialize(&bytes_read)
                                    .map_err(|e| {
                                        CommsError::InvalidRemoteHandshakeMessage(e.to_string())
                                    }) {
                                    Ok(x) => x,
                                    Err(e) => {
                                        println!("Error deserializing DATA FROM CASPER!: {e:?}");
                                        continue;
                                    }
                                };

                                // Notify the event loop
                                let _ = event_tx.send((addr.clone(), remote_message.clone())).await;

                                // Send back a handshake message
                                let hs: Message<P> = Message::Handshake {
                                    network_name: "casper-example".to_string(),
                                    public_addr: our_addr,
                                    protocol_version: ProtocolVersion::V1_0_0,
                                    consensus_certificate: None,
                                    is_syncing: false,
                                    chainspec_hash: Some(chainspec_hash),
                                };

                                // let ping: Message<P> = Message::Ping { nonce: Nonce::new(5 as u64) };

                                match Pin::new(&mut encoder)
                                    .serialize(&Arc::new(hs))
                                    .map_err(|e| {
                                        CommsError::CouldNotEncodeOurHandshake(e.to_string())
                                    }) {
                                    Ok(bytes) => {
                                        println!("BYTES TO BE SENT TO CASPER {bytes:?}");
                                        if let Err(e) = writer.send(bytes).await {
                                            println!("Error sending data to CASPER!: {e:?}");
                                            continue;
                                        }

                                        println!("Sent message to CASPER!");
                                    }
                                    Err(e) => {
                                        println!("Error serializing handshake for Casper!: {e:?}");
                                        continue;
                                    }
                                }
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
