// TODO - remove once schemars stops causing warning.
#![allow(clippy::field_reassign_with_default)]

use std::str::FromStr;

use datasize::DataSize;
use serde::{Deserialize, Serialize};

use casper_types::{
    bytesrepr::{self, FromBytes, ToBytes},
    ProtocolVersion,
};

use super::{ActivationPoint, GlobalStateUpdate};

/// Configuration values associated with the protocol.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, DataSize, Debug)]
pub struct ProtocolConfig {
    /// Protocol version.
    #[data_size(skip)]
    pub version: ProtocolVersion,
    /// Whether we need to clear latest blocks back to the switch block just before the activation
    /// point or not.
    pub hard_reset: bool,
    /// This protocol config applies starting at the era specified in the activation point.
    pub activation_point: ActivationPoint,
    /// Any arbitrary updates we might want to make to the global state at the start of the era
    /// specified in the activation point.
    pub global_state_update: Option<GlobalStateUpdate>,
}

impl ToBytes for ProtocolConfig {
    fn to_bytes(&self) -> Result<Vec<u8>, bytesrepr::Error> {
        let mut buffer = bytesrepr::allocate_buffer(self)?;
        buffer.extend(self.version.to_string().to_bytes()?);
        buffer.extend(self.hard_reset.to_bytes()?);
        buffer.extend(self.activation_point.to_bytes()?);
        buffer.extend(self.global_state_update.to_bytes()?);
        Ok(buffer)
    }

    fn serialized_length(&self) -> usize {
        self.version.to_string().serialized_length()
            + self.hard_reset.serialized_length()
            + self.activation_point.serialized_length()
            + self.global_state_update.serialized_length()
    }
}

impl FromBytes for ProtocolConfig {
    fn from_bytes(bytes: &[u8]) -> Result<(Self, &[u8]), bytesrepr::Error> {
        let (protocol_version_string, remainder) = String::from_bytes(bytes)?;
        let version = ProtocolVersion::from_str(&protocol_version_string)
            .map_err(|_| bytesrepr::Error::Formatting)?;
        let (hard_reset, remainder) = bool::from_bytes(remainder)?;
        let (activation_point, remainder) = ActivationPoint::from_bytes(remainder)?;
        let (global_state_update, remainder) = Option::<GlobalStateUpdate>::from_bytes(remainder)?;
        let protocol_config = ProtocolConfig {
            version,
            hard_reset,
            activation_point,
            global_state_update,
        };
        Ok((protocol_config, remainder))
    }
}
