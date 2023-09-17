// TODO - remove once schemars stops causing warning.
#![allow(clippy::field_reassign_with_default)]

use std::{collections::BTreeMap, str::FromStr};

use datasize::DataSize;
use serde::{Deserialize, Serialize};

use casper_types::{
    bytesrepr::{self, FromBytes, ToBytes},
    Key, ProtocolVersion, StoredValue,
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

impl ProtocolConfig {
    /// The mapping of [`Key`]s to [`StoredValue`]s we will use to update global storage in the
    /// event of an emergency update.
    pub(crate) fn get_update_mapping(
        &self,
    ) -> Result<BTreeMap<Key, StoredValue>, bytesrepr::Error> {
        let state_update = match &self.global_state_update {
            Some(GlobalStateUpdate { entries, .. }) => entries,
            None => return Ok(BTreeMap::default()),
        };
        let mut update_mapping = BTreeMap::new();
        for (key, stored_value_bytes) in state_update {
            let stored_value = bytesrepr::deserialize(stored_value_bytes.clone().into())?;
            update_mapping.insert(*key, stored_value);
        }
        Ok(update_mapping)
    }

    /// Checks whether the values set in the config make sense and returns `false` if they don't.
    pub(super) fn is_valid(&self) -> bool {
        true
    }
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
