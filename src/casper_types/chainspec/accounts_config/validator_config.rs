use datasize::DataSize;
use num::Zero;
use serde::{Deserialize, Serialize};

use casper_types::{
    bytesrepr::{self, FromBytes, ToBytes},
    system::auction::DelegationRate,
    Motes,
};
#[cfg(test)]
use casper_types::{testing::TestRng, U512};

/// Validator account configuration.
#[derive(PartialEq, Eq, Ord, PartialOrd, Serialize, Deserialize, DataSize, Debug, Copy, Clone)]
pub struct ValidatorConfig {
    bonded_amount: Motes,
    #[serde(default = "DelegationRate::zero")]
    delegation_rate: DelegationRate,
}

impl ValidatorConfig {
    /// Creates a new `ValidatorConfig`.
    pub fn new(bonded_amount: Motes, delegation_rate: DelegationRate) -> Self {
        Self {
            bonded_amount,
            delegation_rate,
        }
    }

    /// Delegation rate.
    pub fn delegation_rate(&self) -> DelegationRate {
        self.delegation_rate
    }

    /// Bonded amount.
    pub fn bonded_amount(&self) -> Motes {
        self.bonded_amount
    }
}

impl ToBytes for ValidatorConfig {
    fn to_bytes(&self) -> Result<Vec<u8>, bytesrepr::Error> {
        let mut buffer = bytesrepr::allocate_buffer(self)?;
        buffer.extend(self.bonded_amount.to_bytes()?);
        buffer.extend(self.delegation_rate.to_bytes()?);
        Ok(buffer)
    }

    fn serialized_length(&self) -> usize {
        self.bonded_amount.serialized_length() + self.delegation_rate.serialized_length()
    }
}

impl FromBytes for ValidatorConfig {
    fn from_bytes(bytes: &[u8]) -> Result<(Self, &[u8]), bytesrepr::Error> {
        let (bonded_amount, remainder) = FromBytes::from_bytes(bytes)?;
        let (delegation_rate, remainder) = FromBytes::from_bytes(remainder)?;
        let account_config = ValidatorConfig {
            bonded_amount,
            delegation_rate,
        };
        Ok((account_config, remainder))
    }
}
