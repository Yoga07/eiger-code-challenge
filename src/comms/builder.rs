use crate::comms::error::CommsError;
use crate::comms::message::CommsMessage;
use crate::comms::{listen_on_bi_streams, IncomingConnections, IncomingMsg, CHANNEL_SIZE};
use quinn::{Connection, Endpoint, IdleTimeout, SendStream, TransportConfig, VarInt};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tracing::{trace, warn};

pub(crate) const DEFAULT_IDLE_TIMEOUT: u32 = 10_000; // 10s

/// Hard-coded server name for self-signed certificates.
pub(crate) const SERVER_NAME: &str = "eiger.test";

/// Build a [`crate::Comms`]
#[allow(missing_debug_implementations)]
pub struct Builder {
    addr: SocketAddr,
    max_idle_timeout: Option<IdleTimeout>,
    max_concurrent_bidi_streams: VarInt,
    max_concurrent_uni_streams: VarInt,
    keep_alive_interval: Option<Duration>,
}

impl Default for Builder {
    fn default() -> Self {
        Self {
            addr: SocketAddr::from(([0, 0, 0, 0], 0)),
            max_idle_timeout: Some(IdleTimeout::from(VarInt::from_u32(DEFAULT_IDLE_TIMEOUT))),
            max_concurrent_bidi_streams: 100u32.into(),
            max_concurrent_uni_streams: 100u32.into(),
            keep_alive_interval: None,
        }
    }
}

impl Builder {
    /// Instantiate a builder with default parameters.
    /// See source of [`Self::default`] for default values.
    pub fn new() -> Self {
        Self::default()
    }

    /// Local address passed to [`quinn::Endpoint::server`].
    pub fn addr(mut self, addr: impl Into<SocketAddr>) -> Self {
        self.addr = addr.into();
        self
    }

    /// Maximum time before timeout. Takes time in milliseconds.
    ///
    /// Maps to [`quinn::TransportConfig::max_idle_timeout`].
    pub fn idle_timeout(mut self, to: impl Into<Option<u32>>) -> Self {
        self.max_idle_timeout = to.into().map(|v| IdleTimeout::from(VarInt::from_u32(v)));
        self
    }

    /// Takes time in milliseconds.
    ///
    /// Maps to [`quinn::TransportConfig::max_concurrent_bidi_streams`].
    pub fn max_concurrent_bidi_streams(mut self, max: u32) -> Self {
        self.max_concurrent_bidi_streams = VarInt::from_u32(max);
        self
    }

    /// Takes time in milliseconds.
    ///
    /// Maps to [`quinn::TransportConfig::max_concurrent_uni_streams`].
    pub fn max_concurrent_uni_streams(mut self, max: u32) -> Self {
        self.max_concurrent_uni_streams = VarInt::from_u32(max);
        self
    }

    /// Maps to [`quinn::TransportConfig::keep_alive_interval`].
    pub fn keep_alive_interval(mut self, interval: impl Into<Option<Duration>>) -> Self {
        self.keep_alive_interval = interval.into();
        self
    }

    /// Instantiate a server (peer) [`quinn::Endpoint`] using the parameters passed to this builder.
    pub fn server(self) -> Result<(Endpoint, IncomingConnections), CommsError> {
        let (cfg_srv, cfg_cli) = self.config()?;

        let mut endpoint = quinn::Endpoint::server(cfg_srv, self.addr)
            .map_err(|e| CommsError::Generic(e.to_string()))?;
        endpoint.set_default_client_config(cfg_cli);

        let (connection_tx, connection_rx) = channel(CHANNEL_SIZE);
        listen_for_incoming_connections(endpoint.clone(), connection_tx);

        Ok((endpoint, IncomingConnections(connection_rx)))
    }

    /// Helper to construct a [`TransportConfig`] from our parameters.
    fn transport_config(&self) -> TransportConfig {
        let mut config = TransportConfig::default();
        let _ = config.max_idle_timeout(self.max_idle_timeout);
        let _ = config.keep_alive_interval(self.keep_alive_interval);
        let _ = config.max_concurrent_bidi_streams(self.max_concurrent_bidi_streams);
        let _ = config.max_concurrent_uni_streams(self.max_concurrent_uni_streams);

        config
    }

    pub(crate) fn config(&self) -> Result<(quinn::ServerConfig, quinn::ClientConfig), CommsError> {
        let transport = Arc::new(self.transport_config());

        let (mut server, mut client) = config()?;
        let _ = server.transport_config(Arc::clone(&transport));
        let _ = client.transport_config(Arc::clone(&transport));

        Ok((server, client))
    }
}

fn config() -> Result<(quinn::ServerConfig, quinn::ClientConfig), CommsError> {
    let mut roots = rustls::RootCertStore::empty();
    let (cert, key) = generate_cert().map_err(|e| CommsError::BadCertificate(e.to_string()))?;
    roots
        .add(&cert)
        .map_err(|e| CommsError::BadCertificate(e.to_string()))?;

    let mut client_crypto = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(roots)
        .with_no_client_auth();

    // NOTE: This is just a placeholder
    // allow client to connect to unknown certificates, eg those generated above
    client_crypto
        .dangerous()
        .set_certificate_verifier(Arc::new(SkipServerVerification));

    let server = quinn::ServerConfig::with_single_cert(vec![cert], key)
        .map_err(|e| CommsError::BadCertificate(e.to_string()))?;
    let client = quinn::ClientConfig::new(Arc::new(client_crypto));

    Ok((server, client))
}

fn generate_cert() -> Result<(rustls::Certificate, rustls::PrivateKey), rcgen::RcgenError> {
    let cert = rcgen::generate_simple_self_signed(vec![SERVER_NAME.to_string()])?;

    let key = cert.serialize_private_key_der();
    let cert = cert.serialize_der().unwrap();

    let key = rustls::PrivateKey(key);
    let cert = rustls::Certificate(cert);
    Ok((cert, key))
}

// Implementation of `ServerCertVerifier` that verifies everything as trustworthy.
struct SkipServerVerification;

impl rustls::client::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::Certificate,
        _intermediates: &[rustls::Certificate],
        _server_name: &rustls::ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: std::time::SystemTime,
    ) -> Result<rustls::client::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::ServerCertVerified::assertion())
    }
}

fn listen_for_incoming_connections(
    quinn_endpoint: quinn::Endpoint,
    connection_tx: Sender<(Connection, Receiver<IncomingMsg>)>,
) {
    let _handle = tokio::spawn(async move {
        while let Some(quinn_conn) = quinn_endpoint.accept().await {
            let conn_sender = connection_tx.clone();
            // move incoming conn waiting off thread so as not to block us
            let _handle = tokio::spawn(async move {
                match quinn_conn.await {
                    Ok(connection) => {
                        let conn_id = connection.stable_id();
                        let (peer_connection_tx, peer_connection_rx) =
                            channel::<Result<(CommsMessage, Option<SendStream>), CommsError>>(
                                CHANNEL_SIZE,
                            );
                        listen_on_bi_streams(connection.clone(), peer_connection_tx);
                        println!("Incoming new connection conn_id={conn_id}");
                        if conn_sender
                            .send((connection, peer_connection_rx))
                            .await
                            .is_err()
                        {
                            println!("Dropping incoming connection conn_id={conn_id}, because receiver was dropped");
                        }
                    }
                    Err(err) => {
                        println!("An incoming connection failed because of: {:?}", err);
                    }
                }
            });
        }

        println!(
            "quinn::Endpoint::accept() returned None. There will be no more incoming connections"
        );
    });
}
