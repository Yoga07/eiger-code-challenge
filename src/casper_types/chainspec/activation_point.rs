// TODO - remove once schemars stops causing warning.
#![allow(clippy::field_reassign_with_default)]

use std::fmt::{self, Display, Formatter};

use datasize::DataSize;
use serde::{Deserialize, Serialize};

use casper_types::{
    bytesrepr::{self, FromBytes, ToBytes, U8_SERIALIZED_LENGTH},
    EraId, Timestamp,
};

const ERA_ID_TAG: u8 = 0;
const GENESIS_TAG: u8 = 1;

/// The first era to which the associated protocol version applies.
#[derive(Copy, Clone, DataSize, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[serde(untagged)]
pub enum ActivationPoint {
    /// Era id.
    EraId(EraId),
    /// Genesis timestamp.
    Genesis(Timestamp),
}

impl Display for ActivationPoint {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            ActivationPoint::EraId(era_id) => write!(formatter, "activation point {}", era_id),
            ActivationPoint::Genesis(timestamp) => {
                write!(formatter, "activation point {}", timestamp)
            }
        }
    }
}

impl ToBytes for ActivationPoint {
    fn to_bytes(&self) -> Result<Vec<u8>, bytesrepr::Error> {
        match self {
            ActivationPoint::EraId(era_id) => {
                let mut buffer = vec![ERA_ID_TAG];
                buffer.extend(era_id.to_bytes()?);
                Ok(buffer)
            }
            ActivationPoint::Genesis(timestamp) => {
                let mut buffer = vec![GENESIS_TAG];
                buffer.extend(timestamp.to_bytes()?);
                Ok(buffer)
            }
        }
    }

    fn serialized_length(&self) -> usize {
        U8_SERIALIZED_LENGTH
            + match self {
                ActivationPoint::EraId(era_id) => era_id.serialized_length(),
                ActivationPoint::Genesis(timestamp) => timestamp.serialized_length(),
            }
    }
}

impl FromBytes for ActivationPoint {
    fn from_bytes(bytes: &[u8]) -> Result<(Self, &[u8]), bytesrepr::Error> {
        let (tag, remainder) = u8::from_bytes(bytes)?;
        match tag {
            ERA_ID_TAG => {
                let (era_id, remainder) = EraId::from_bytes(remainder)?;
                Ok((ActivationPoint::EraId(era_id), remainder))
            }
            GENESIS_TAG => {
                let (timestamp, remainder) = Timestamp::from_bytes(remainder)?;
                Ok((ActivationPoint::Genesis(timestamp), remainder))
            }
            _ => Err(bytesrepr::Error::Formatting),
        }
    }
}
