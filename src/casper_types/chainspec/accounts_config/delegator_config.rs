use datasize::DataSize;
use serde::{Deserialize, Serialize};

use casper_types::{
    bytesrepr::{self, FromBytes, ToBytes},
    Motes, PublicKey,
};

/// Configuration values related to a delegator.
#[derive(PartialEq, Ord, PartialOrd, Eq, Serialize, Deserialize, DataSize, Debug, Clone)]
pub struct DelegatorConfig {
    /// Validator public key.
    pub validator_public_key: PublicKey,
    /// Delegator public key.
    pub delegator_public_key: PublicKey,
    /// Balance for this delegator in Motes.
    pub balance: Motes,
    /// Delegated amount in Motes.
    pub delegated_amount: Motes,
}

impl DelegatorConfig {
    /// Creates a new DelegatorConfig.
    pub fn new(
        validator_public_key: PublicKey,
        delegator_public_key: PublicKey,
        balance: Motes,
        delegated_amount: Motes,
    ) -> Self {
        Self {
            validator_public_key,
            delegator_public_key,
            balance,
            delegated_amount,
        }
    }
}

impl ToBytes for DelegatorConfig {
    fn to_bytes(&self) -> Result<Vec<u8>, bytesrepr::Error> {
        let mut buffer = bytesrepr::allocate_buffer(self)?;
        buffer.extend(self.validator_public_key.to_bytes()?);
        buffer.extend(self.delegator_public_key.to_bytes()?);
        buffer.extend(self.balance.to_bytes()?);
        buffer.extend(self.delegated_amount.to_bytes()?);
        Ok(buffer)
    }

    fn serialized_length(&self) -> usize {
        self.validator_public_key.serialized_length()
            + self.delegator_public_key.serialized_length()
            + self.balance.serialized_length()
            + self.delegated_amount.serialized_length()
    }
}

impl FromBytes for DelegatorConfig {
    fn from_bytes(bytes: &[u8]) -> Result<(Self, &[u8]), bytesrepr::Error> {
        let (validator_public_key, remainder) = FromBytes::from_bytes(bytes)?;
        let (delegator_public_key, remainder) = FromBytes::from_bytes(remainder)?;
        let (balance, remainder) = FromBytes::from_bytes(remainder)?;
        let (delegated_amount, remainder) = FromBytes::from_bytes(remainder)?;
        let delegator_config = DelegatorConfig {
            validator_public_key,
            delegator_public_key,
            balance,
            delegated_amount,
        };
        Ok((delegator_config, remainder))
    }
}
