//! The chainspec is a set of configuration options for the network.  All validators must apply the
//! same set of options in order to join and act as a peer in a given network.

mod accounts_config;
mod activation_point;
mod core_config;
mod deploy_config;
mod error;
mod global_state_update;
mod highway_config;
mod network_config;
mod parse_toml;
mod protocol_config;
mod system_config;
mod wasm_config;

use std::{fmt::Debug, path::Path, sync::Arc};

use datasize::DataSize;
use serde::Serialize;
use tracing::{error, info, warn};

use casper_hashing::Digest;
use casper_types::{
    bytesrepr::{self, FromBytes, ToBytes},
    EraId, ProtocolVersion,
};

pub use self::{
    activation_point::ActivationPoint,
    core_config::{ConsensusProtocolName, CoreConfig, LegacyRequiredFinality},
    deploy_config::DeployConfig,
    error::Error,
    global_state_update::GlobalStateUpdate,
    highway_config::HighwayConfig,
    network_config::NetworkConfig,
    protocol_config::ProtocolConfig,
};
use crate::casper_types::chainspec::system_config::SystemConfig;
use crate::casper_types::chainspec::wasm_config::WasmConfig;
use crate::casper_types::chainspec::Error as ChainspecError;

/// The name of the chainspec file on disk.
pub const CHAINSPEC_FILENAME: &str = "chainspec.toml";

// Additional overhead accounted for (eg. lower level networking packet encapsulation).
const CHAINSPEC_NETWORK_MESSAGE_SAFETY_MARGIN: usize = 256;

/// A collection of configuration settings describing the state of the system at genesis and after
/// upgrades to basic system functionality occurring after genesis.
#[derive(DataSize, PartialEq, Eq, Serialize, Debug, Clone)]
pub struct Chainspec {
    /// Protocol config.
    #[serde(rename = "protocol")]
    pub protocol_config: ProtocolConfig,

    /// Network config.
    #[serde(rename = "network")]
    pub network_config: NetworkConfig,

    /// Core config.
    #[serde(rename = "core")]
    pub core_config: CoreConfig,

    /// Highway config.
    #[serde(rename = "highway")]
    pub highway_config: HighwayConfig,

    /// Deploy Config.
    #[serde(rename = "deploys")]
    pub deploy_config: DeployConfig,

    /// Wasm config.
    #[serde(rename = "wasm")]
    pub wasm_config: WasmConfig,

    /// System costs config.
    #[serde(rename = "system_costs")]
    pub system_costs_config: SystemConfig,
}

impl Chainspec {
    pub fn from_path<P: AsRef<Path>>(path: P) -> Result<Self, ChainspecError> {
        parse_toml::parse_toml(path.as_ref())
    }

    /// Serializes `self` and hashes the resulting bytes.
    pub fn hash(&self) -> Digest {
        let serialized_chainspec = self.to_bytes().unwrap_or_else(|error| {
            error!(%error, "failed to serialize chainspec");
            vec![]
        });
        Digest::hash(serialized_chainspec)
    }

    /// Returns the protocol version of the chainspec.
    pub fn protocol_version(&self) -> ProtocolVersion {
        self.protocol_config.version
    }
}

impl ToBytes for Chainspec {
    fn to_bytes(&self) -> Result<Vec<u8>, bytesrepr::Error> {
        let mut buffer = bytesrepr::allocate_buffer(self)?;
        buffer.extend(self.protocol_config.to_bytes()?);
        buffer.extend(self.network_config.to_bytes()?);
        buffer.extend(self.core_config.to_bytes()?);
        buffer.extend(self.highway_config.to_bytes()?);
        buffer.extend(self.deploy_config.to_bytes()?);
        buffer.extend(self.wasm_config.to_bytes()?);
        buffer.extend(self.system_costs_config.to_bytes()?);
        Ok(buffer)
    }

    fn serialized_length(&self) -> usize {
        self.protocol_config.serialized_length()
            + self.network_config.serialized_length()
            + self.core_config.serialized_length()
            + self.highway_config.serialized_length()
            + self.deploy_config.serialized_length()
            + self.wasm_config.serialized_length()
            + self.system_costs_config.serialized_length()
    }
}

impl FromBytes for Chainspec {
    fn from_bytes(bytes: &[u8]) -> Result<(Self, &[u8]), bytesrepr::Error> {
        let (protocol_config, remainder) = ProtocolConfig::from_bytes(bytes)?;
        let (network_config, remainder) = NetworkConfig::from_bytes(remainder)?;
        let (core_config, remainder) = CoreConfig::from_bytes(remainder)?;
        let (highway_config, remainder) = HighwayConfig::from_bytes(remainder)?;
        let (deploy_config, remainder) = DeployConfig::from_bytes(remainder)?;
        let (wasm_config, remainder) = WasmConfig::from_bytes(remainder)?;
        let (system_costs_config, remainder) = SystemConfig::from_bytes(remainder)?;
        let chainspec = Chainspec {
            protocol_config,
            network_config,
            core_config,
            highway_config,
            deploy_config,
            wasm_config,
            system_costs_config,
        };
        Ok((chainspec, remainder))
    }
}
