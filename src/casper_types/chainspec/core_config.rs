use std::collections::BTreeSet;

use tracing::{error, warn};

use casper_types::{
    bytesrepr::{self, FromBytes, ToBytes},
    PublicKey,
};

use datasize::DataSize;
use num::rational::Ratio;

use serde::{
    de::{Deserializer, Error as DeError},
    Deserialize, Serialize, Serializer,
};

use casper_types::{system::auction::VESTING_SCHEDULE_LENGTH_MILLIS, ProtocolVersion, TimeDiff};

/// Configuration values associated with the core protocol.
#[derive(Clone, DataSize, PartialEq, Eq, Serialize, Deserialize, Debug)]
// Disallow unknown fields to ensure config files and command-line overrides contain valid keys.
#[serde(deny_unknown_fields)]
pub struct CoreConfig {
    /// Duration of an era.
    pub era_duration: TimeDiff,

    /// Minimum era height.
    pub minimum_era_height: u64,

    /// Minimum block time.
    pub minimum_block_time: TimeDiff,

    /// Validator slots.
    pub validator_slots: u32,

    /// Finality threshold fraction.
    #[data_size(skip)]
    pub finality_threshold_fraction: Ratio<u64>,

    /// Protocol version from which nodes are required to hold strict finality signatures.
    pub start_protocol_version_with_strict_finality_signatures_required: ProtocolVersion,

    /// Which finality is required for legacy blocks.
    /// Used to determine finality sufficiency for new joiners syncing blocks created
    /// in a protocol version before
    /// `start_protocol_version_with_strict_finality_signatures_required`.
    pub legacy_required_finality: LegacyRequiredFinality,

    /// Number of eras before an auction actually defines the set of validators.
    /// If you bond with a sufficient bid in era N, you will be a validator in era N +
    /// auction_delay + 1
    pub auction_delay: u64,

    /// The period after genesis during which a genesis validator's bid is locked.
    pub locked_funds_period: TimeDiff,

    /// The period in which genesis validator's bid is released over time after it's unlocked.
    pub vesting_schedule_period: TimeDiff,

    /// The delay in number of eras for paying out the the unbonding amount.
    pub unbonding_delay: u64,

    /// Round seigniorage rate represented as a fractional number.
    #[data_size(skip)]
    pub round_seigniorage_rate: Ratio<u64>,

    /// Maximum number of associated keys for a single account.
    pub max_associated_keys: u32,

    /// Maximum height of contract runtime call stack.
    pub max_runtime_call_stack_height: u32,

    /// The minimum bound of motes that can be delegated to a validator.
    pub minimum_delegation_amount: u64,

    /// Global state prune batch size (0 means the feature is off in the current protocol version).
    pub prune_batch_size: u64,

    /// Enables strict arguments checking when calling a contract.
    pub strict_argument_checking: bool,

    /// How many peers to simultaneously ask when sync leaping.
    pub simultaneous_peer_requests: u8,

    /// Which consensus protocol to use.
    pub consensus_protocol: ConsensusProtocolName,

    /// The maximum amount of delegators per validator.
    /// if the value is 0, there is no maximum capacity.
    pub max_delegators_per_validator: u32,
    /// Auction entrypoints such as "add_bid" or "delegate" are disabled if this flag is set to
    /// `false`. Setting up this option makes sense only for private chains where validator set
    /// rotation is unnecessary.
    pub(crate) allow_auction_bids: bool,
    /// Allows unrestricted transfers between users.
    pub(crate) allow_unrestricted_transfers: bool,
    /// If set to false then consensus doesn't compute rewards and always uses 0.
    pub(crate) compute_rewards: bool,
    /// Administrative accounts are valid option for for a private chain only.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub(crate) administrators: BTreeSet<PublicKey>,
    /// Refund handling.
    #[data_size(skip)]
    pub(crate) refund_handling: RefundHandling,
    /// Fee handling.
    pub(crate) fee_handling: FeeHandling,
}

impl CoreConfig {
    /// The number of eras that have already started and whose validators are still bonded.
    pub fn recent_era_count(&self) -> u64 {
        // Safe to use naked `-` operation assuming `CoreConfig::is_valid()` has been checked.
        self.unbonding_delay - self.auction_delay
    }

    /// Returns `false` if unbonding delay is not greater than auction delay to ensure
    /// that `recent_era_count()` yields a value of at least 1.
    pub fn is_valid(&self) -> bool {
        if self.unbonding_delay <= self.auction_delay {
            warn!(
                unbonding_delay = self.unbonding_delay,
                auction_delay = self.auction_delay,
                "unbonding delay should be greater than auction delay",
            );
            return false;
        }

        // If the era duration is set to zero, we will treat it as explicitly stating that eras
        // should be defined by height only.  Warn only.
        if self.era_duration.millis() > 0
            && self.era_duration.millis()
                < self.minimum_era_height * self.minimum_block_time.millis()
        {
            warn!("era duration is less than minimum era height * round length!");
        }

        if self.finality_threshold_fraction <= Ratio::new(0, 1)
            || self.finality_threshold_fraction >= Ratio::new(1, 1)
        {
            error!(
                ftf = %self.finality_threshold_fraction,
                "finality threshold fraction is not in the range (0, 1)",
            );
            return false;
        }

        if self.vesting_schedule_period > TimeDiff::from_millis(VESTING_SCHEDULE_LENGTH_MILLIS) {
            error!(
                vesting_schedule_millis = self.vesting_schedule_period.millis(),
                max_millis = VESTING_SCHEDULE_LENGTH_MILLIS,
                "vesting schedule period too long",
            );
            return false;
        }

        true
    }
}

impl ToBytes for CoreConfig {
    fn to_bytes(&self) -> Result<Vec<u8>, bytesrepr::Error> {
        let mut buffer = bytesrepr::allocate_buffer(self)?;
        buffer.extend(self.era_duration.to_bytes()?);
        buffer.extend(self.minimum_era_height.to_bytes()?);
        buffer.extend(self.minimum_block_time.to_bytes()?);
        buffer.extend(self.validator_slots.to_bytes()?);
        buffer.extend(self.finality_threshold_fraction.to_bytes()?);
        buffer.extend(
            self.start_protocol_version_with_strict_finality_signatures_required
                .to_bytes()?,
        );
        buffer.extend(self.legacy_required_finality.to_bytes()?);
        buffer.extend(self.auction_delay.to_bytes()?);
        buffer.extend(self.locked_funds_period.to_bytes()?);
        buffer.extend(self.vesting_schedule_period.to_bytes()?);
        buffer.extend(self.unbonding_delay.to_bytes()?);
        buffer.extend(self.round_seigniorage_rate.to_bytes()?);
        buffer.extend(self.max_associated_keys.to_bytes()?);
        buffer.extend(self.max_runtime_call_stack_height.to_bytes()?);
        buffer.extend(self.minimum_delegation_amount.to_bytes()?);
        buffer.extend(self.prune_batch_size.to_bytes()?);
        buffer.extend(self.strict_argument_checking.to_bytes()?);
        buffer.extend(self.simultaneous_peer_requests.to_bytes()?);
        buffer.extend(self.consensus_protocol.to_bytes()?);
        buffer.extend(self.max_delegators_per_validator.to_bytes()?);
        buffer.extend(self.allow_auction_bids.to_bytes()?);
        buffer.extend(self.allow_unrestricted_transfers.to_bytes()?);
        buffer.extend(self.compute_rewards.to_bytes()?);
        buffer.extend(self.administrators.to_bytes()?);
        buffer.extend(self.refund_handling.to_bytes()?);
        buffer.extend(self.fee_handling.to_bytes()?);
        Ok(buffer)
    }

    fn serialized_length(&self) -> usize {
        self.era_duration.serialized_length()
            + self.minimum_era_height.serialized_length()
            + self.minimum_block_time.serialized_length()
            + self.validator_slots.serialized_length()
            + self.finality_threshold_fraction.serialized_length()
            + self
                .start_protocol_version_with_strict_finality_signatures_required
                .serialized_length()
            + self.legacy_required_finality.serialized_length()
            + self.auction_delay.serialized_length()
            + self.locked_funds_period.serialized_length()
            + self.vesting_schedule_period.serialized_length()
            + self.unbonding_delay.serialized_length()
            + self.round_seigniorage_rate.serialized_length()
            + self.max_associated_keys.serialized_length()
            + self.max_runtime_call_stack_height.serialized_length()
            + self.minimum_delegation_amount.serialized_length()
            + self.prune_batch_size.serialized_length()
            + self.strict_argument_checking.serialized_length()
            + self.simultaneous_peer_requests.serialized_length()
            + self.consensus_protocol.serialized_length()
            + self.max_delegators_per_validator.serialized_length()
            + self.allow_auction_bids.serialized_length()
            + self.allow_unrestricted_transfers.serialized_length()
            + self.compute_rewards.serialized_length()
            + self.administrators.serialized_length()
            + self.refund_handling.serialized_length()
            + self.fee_handling.serialized_length()
    }
}

impl FromBytes for CoreConfig {
    fn from_bytes(bytes: &[u8]) -> Result<(Self, &[u8]), bytesrepr::Error> {
        let (era_duration, remainder) = TimeDiff::from_bytes(bytes)?;
        let (minimum_era_height, remainder) = u64::from_bytes(remainder)?;
        let (minimum_block_time, remainder) = TimeDiff::from_bytes(remainder)?;
        let (validator_slots, remainder) = u32::from_bytes(remainder)?;
        let (finality_threshold_fraction, remainder) = Ratio::<u64>::from_bytes(remainder)?;
        let (start_protocol_version_with_strict_finality_signatures_required, remainder) =
            ProtocolVersion::from_bytes(remainder)?;
        let (legacy_required_finality, remainder) = LegacyRequiredFinality::from_bytes(remainder)?;
        let (auction_delay, remainder) = u64::from_bytes(remainder)?;
        let (locked_funds_period, remainder) = TimeDiff::from_bytes(remainder)?;
        let (vesting_schedule_period, remainder) = TimeDiff::from_bytes(remainder)?;
        let (unbonding_delay, remainder) = u64::from_bytes(remainder)?;
        let (round_seigniorage_rate, remainder) = Ratio::<u64>::from_bytes(remainder)?;
        let (max_associated_keys, remainder) = u32::from_bytes(remainder)?;
        let (max_runtime_call_stack_height, remainder) = u32::from_bytes(remainder)?;
        let (minimum_delegation_amount, remainder) = u64::from_bytes(remainder)?;
        let (prune_batch_size, remainder) = u64::from_bytes(remainder)?;
        let (strict_argument_checking, remainder) = bool::from_bytes(remainder)?;
        let (simultaneous_peer_requests, remainder) = u8::from_bytes(remainder)?;
        let (consensus_protocol, remainder) = ConsensusProtocolName::from_bytes(remainder)?;
        let (max_delegators_per_validator, remainder) = FromBytes::from_bytes(remainder)?;
        let (allow_auction_bids, remainder) = FromBytes::from_bytes(remainder)?;
        let (allow_unrestricted_transfers, remainder) = FromBytes::from_bytes(remainder)?;
        let (compute_rewards, remainder) = bool::from_bytes(remainder)?;
        let (administrative_accounts, remainder) = FromBytes::from_bytes(remainder)?;
        let (refund_handling, remainder) = FromBytes::from_bytes(remainder)?;
        let (fee_handling, remainder) = FromBytes::from_bytes(remainder)?;
        let config = CoreConfig {
            era_duration,
            minimum_era_height,
            minimum_block_time,
            validator_slots,
            finality_threshold_fraction,
            start_protocol_version_with_strict_finality_signatures_required,
            legacy_required_finality,
            auction_delay,
            locked_funds_period,
            vesting_schedule_period,
            unbonding_delay,
            round_seigniorage_rate,
            max_associated_keys,
            max_runtime_call_stack_height,
            minimum_delegation_amount,
            prune_batch_size,
            strict_argument_checking,
            simultaneous_peer_requests,
            consensus_protocol,
            max_delegators_per_validator,
            allow_auction_bids,
            allow_unrestricted_transfers,
            compute_rewards,
            administrators: administrative_accounts,
            refund_handling,
            fee_handling,
        };
        Ok((config, remainder))
    }
}

/// Consensus protocol name.
#[derive(Copy, Clone, DataSize, PartialEq, Eq, Debug)]
pub enum ConsensusProtocolName {
    /// Highway.
    Highway,
    /// Zug.
    Zug,
}

impl Serialize for ConsensusProtocolName {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            ConsensusProtocolName::Highway => "Highway",
            ConsensusProtocolName::Zug => "Zug",
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ConsensusProtocolName {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        match String::deserialize(deserializer)?.to_lowercase().as_str() {
            "highway" => Ok(ConsensusProtocolName::Highway),
            "zug" => Ok(ConsensusProtocolName::Zug),
            _ => Err(DeError::custom("unknown consensus protocol name")),
        }
    }
}

const CONSENSUS_HIGHWAY_TAG: u8 = 0;
const CONSENSUS_ZUG_TAG: u8 = 1;

impl ToBytes for ConsensusProtocolName {
    fn to_bytes(&self) -> Result<Vec<u8>, bytesrepr::Error> {
        let tag = match self {
            ConsensusProtocolName::Highway => CONSENSUS_HIGHWAY_TAG,
            ConsensusProtocolName::Zug => CONSENSUS_ZUG_TAG,
        };
        Ok(vec![tag])
    }

    fn serialized_length(&self) -> usize {
        1
    }
}

impl FromBytes for ConsensusProtocolName {
    fn from_bytes(bytes: &[u8]) -> Result<(Self, &[u8]), bytesrepr::Error> {
        let (tag, remainder) = u8::from_bytes(bytes)?;
        let name = match tag {
            CONSENSUS_HIGHWAY_TAG => ConsensusProtocolName::Highway,
            CONSENSUS_ZUG_TAG => ConsensusProtocolName::Zug,
            _ => return Err(bytesrepr::Error::Formatting),
        };
        Ok((name, remainder))
    }
}

/// Which finality a legacy block needs during a fast sync.
#[derive(Copy, Clone, DataSize, PartialEq, Eq, Debug)]
pub enum LegacyRequiredFinality {
    /// Strict finality: more than 2/3rd of validators.
    Strict,
    /// Weak finality: more than 1/3rd of validators.
    Weak,
    /// Finality always valid.
    Any,
}

impl Serialize for LegacyRequiredFinality {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            LegacyRequiredFinality::Strict => "Strict",
            LegacyRequiredFinality::Weak => "Weak",
            LegacyRequiredFinality::Any => "Any",
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for LegacyRequiredFinality {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        match String::deserialize(deserializer)?.to_lowercase().as_str() {
            "strict" => Ok(LegacyRequiredFinality::Strict),
            "weak" => Ok(LegacyRequiredFinality::Weak),
            "any" => Ok(LegacyRequiredFinality::Any),
            _ => Err(DeError::custom("unknown legacy required finality")),
        }
    }
}

const LEGACY_REQUIRED_FINALITY_STRICT_TAG: u8 = 0;
const LEGACY_REQUIRED_FINALITY_WEAK_TAG: u8 = 1;
const LEGACY_REQUIRED_FINALITY_ANY_TAG: u8 = 2;

impl ToBytes for LegacyRequiredFinality {
    fn to_bytes(&self) -> Result<Vec<u8>, bytesrepr::Error> {
        let tag = match self {
            LegacyRequiredFinality::Strict => LEGACY_REQUIRED_FINALITY_STRICT_TAG,
            LegacyRequiredFinality::Weak => LEGACY_REQUIRED_FINALITY_WEAK_TAG,
            LegacyRequiredFinality::Any => LEGACY_REQUIRED_FINALITY_ANY_TAG,
        };
        Ok(vec![tag])
    }

    fn serialized_length(&self) -> usize {
        1
    }
}

impl FromBytes for LegacyRequiredFinality {
    fn from_bytes(bytes: &[u8]) -> Result<(Self, &[u8]), bytesrepr::Error> {
        let (tag, remainder) = u8::from_bytes(bytes)?;
        match tag {
            LEGACY_REQUIRED_FINALITY_STRICT_TAG => Ok((LegacyRequiredFinality::Strict, remainder)),
            LEGACY_REQUIRED_FINALITY_WEAK_TAG => Ok((LegacyRequiredFinality::Weak, remainder)),
            LEGACY_REQUIRED_FINALITY_ANY_TAG => Ok((LegacyRequiredFinality::Any, remainder)),
            _ => Err(bytesrepr::Error::Formatting),
        }
    }
}

const FEE_HANDLING_PROPOSER_TAG: u8 = 0;
const FEE_HANDLING_ACCUMULATE_TAG: u8 = 1;
const FEE_HANDLING_BURN_TAG: u8 = 2;

/// Defines how fees are handled in the system.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize, DataSize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum FeeHandling {
    /// Transaction fees are paid to the block proposer.
    ///
    /// This is the default option for public chains.
    PayToProposer,
    /// Transaction fees are accumulated in a special purse and then distributed during end of era
    /// processing evenly among all administrator accounts.
    ///
    /// This setting is applicable for some private chains (but not all).
    Accumulate,
    /// Burn the fees.
    Burn,
}

impl ToBytes for FeeHandling {
    fn to_bytes(&self) -> Result<Vec<u8>, bytesrepr::Error> {
        match self {
            FeeHandling::PayToProposer => Ok(vec![FEE_HANDLING_PROPOSER_TAG]),
            FeeHandling::Accumulate => Ok(vec![FEE_HANDLING_ACCUMULATE_TAG]),
            FeeHandling::Burn => Ok(vec![FEE_HANDLING_BURN_TAG]),
        }
    }

    fn serialized_length(&self) -> usize {
        1
    }
}

impl FromBytes for FeeHandling {
    fn from_bytes(bytes: &[u8]) -> Result<(Self, &[u8]), bytesrepr::Error> {
        let (tag, rem) = u8::from_bytes(bytes)?;
        match tag {
            FEE_HANDLING_PROPOSER_TAG => Ok((FeeHandling::PayToProposer, rem)),
            FEE_HANDLING_ACCUMULATE_TAG => Ok((FeeHandling::Accumulate, rem)),
            FEE_HANDLING_BURN_TAG => Ok((FeeHandling::Burn, rem)),
            _ => Err(bytesrepr::Error::Formatting),
        }
    }
}

const REFUND_HANDLING_REFUND_TAG: u8 = 0;
const REFUND_HANDLING_BURN_TAG: u8 = 1;

/// Defines how refunds are calculated.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RefundHandling {
    /// Refund of excess payment amount goes to either a pre-defined purse, or back to the sender
    /// and the rest of the payment amount goes to the block proposer.
    Refund {
        /// Computes how much refund goes back to the user after deducting gas spent from the paid
        /// amount.
        ///
        /// user_part = (payment_amount - gas_spent_amount) * refund_ratio
        /// validator_part = payment_amount - user_part
        ///
        /// Any dust amount that was a result of multiplying by refund_ratio goes back to user.
        refund_ratio: Ratio<u64>,
    },
    /// Burns the refund amount.
    Burn {
        /// Computes how much of the refund amount is burned after deducting gas spent from the
        /// paid amount.
        refund_ratio: Ratio<u64>,
    },
}

impl ToBytes for RefundHandling {
    fn to_bytes(&self) -> Result<Vec<u8>, bytesrepr::Error> {
        let mut buffer = bytesrepr::allocate_buffer(self)?;

        match self {
            RefundHandling::Refund { refund_ratio } => {
                buffer.push(REFUND_HANDLING_REFUND_TAG);
                buffer.extend(refund_ratio.to_bytes()?);
            }
            RefundHandling::Burn { refund_ratio } => {
                buffer.push(REFUND_HANDLING_BURN_TAG);
                buffer.extend(refund_ratio.to_bytes()?);
            }
        }

        Ok(buffer)
    }

    fn serialized_length(&self) -> usize {
        1 + match self {
            RefundHandling::Refund { refund_ratio } => refund_ratio.serialized_length(),
            RefundHandling::Burn { refund_ratio } => refund_ratio.serialized_length(),
        }
    }
}

impl FromBytes for RefundHandling {
    fn from_bytes(bytes: &[u8]) -> Result<(Self, &[u8]), bytesrepr::Error> {
        let (tag, rem) = u8::from_bytes(bytes)?;
        match tag {
            REFUND_HANDLING_REFUND_TAG => {
                let (refund_ratio, rem) = FromBytes::from_bytes(rem)?;
                Ok((RefundHandling::Refund { refund_ratio }, rem))
            }
            REFUND_HANDLING_BURN_TAG => {
                let (refund_ratio, rem) = FromBytes::from_bytes(rem)?;
                Ok((RefundHandling::Burn { refund_ratio }, rem))
            }
            _ => Err(bytesrepr::Error::Formatting),
        }
    }
}
