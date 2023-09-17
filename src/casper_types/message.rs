use crate::casper_types::crypto::ConsensusCertificate;
use crate::casper_types::Nonce;
use casper_hashing::Digest;
use casper_types::ProtocolVersion;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::fmt::{Debug, Display, Formatter};
use std::net::SocketAddr;
use strum::EnumDiscriminants;

#[derive(Clone, Debug, Deserialize, Serialize, EnumDiscriminants)]
#[strum_discriminants(derive(strum::EnumIter))]
#[allow(clippy::large_enum_variant)]
pub enum Message<P> {
    Handshake {
        /// Network we are connected to.
        network_name: String,
        /// The public address of the node connecting.
        public_addr: SocketAddr,
        /// Protocol version the node is speaking.
        #[serde(default = "default_protocol_version")]
        protocol_version: ProtocolVersion,
        /// A self-signed certificate indicating validator status.
        #[serde(default)]
        consensus_certificate: Option<ConsensusCertificate>,
        /// True if the node is syncing.
        #[serde(default)]
        is_syncing: bool,
        /// Hash of the chainspec the node is running.
        #[serde(default)]
        chainspec_hash: Option<Digest>,
    },
    /// A ping request.
    Ping {
        /// The nonce to be returned with the pong.
        nonce: Nonce,
    },
    /// A pong response.
    Pong {
        /// Nonce to match pong to ping.
        nonce: Nonce,
    },
    Payload(P),
}

/// The default protocol version to use in absence of one in the protocol version field.
#[inline]
fn default_protocol_version() -> ProtocolVersion {
    ProtocolVersion::V1_0_0
}

/// Network message payload.
///
/// Payloads are what is transferred across the network outside of control messages from the
/// networking component itself.
pub trait Payload: Serialize + DeserializeOwned + Clone + Debug + Send + Sync + 'static {}

impl<P: Payload> Message<P> {}
