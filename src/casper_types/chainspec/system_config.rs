//! Definition of the costs of running code in the system.
use datasize::DataSize;
use serde::{Deserialize, Serialize};

use casper_types::bytesrepr::{self, FromBytes, ToBytes};

/// Default gas cost for a wasmless transfer.
pub const DEFAULT_WASMLESS_TRANSFER_COST: u32 = 100_000_000;

/// Definition of costs in the system.
///
/// This structure contains the costs of all the system contract's entry points and, additionally,
/// it defines a wasmless transfer cost.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug, DataSize)]
#[serde(deny_unknown_fields)]
pub struct SystemConfig {
    /// Wasmless transfer cost expressed in gas.
    wasmless_transfer_cost: u32,

    /// Configuration of auction entrypoint costs.
    auction_costs: AuctionCosts,

    /// Configuration of mint entrypoint costs.
    mint_costs: MintCosts,

    /// Configuration of handle payment entrypoint costs.
    handle_payment_costs: HandlePaymentCosts,

    /// Configuration of standard payment costs.
    standard_payment_costs: StandardPaymentCosts,
}

impl SystemConfig {
    /// Creates new system config instance.
    pub fn new(
        wasmless_transfer_cost: u32,
        auction_costs: AuctionCosts,
        mint_costs: MintCosts,
        handle_payment_costs: HandlePaymentCosts,
        standard_payment_costs: StandardPaymentCosts,
    ) -> Self {
        Self {
            wasmless_transfer_cost,
            auction_costs,
            mint_costs,
            handle_payment_costs,
            standard_payment_costs,
        }
    }

    /// Returns wasmless transfer cost.
    pub fn wasmless_transfer_cost(&self) -> u32 {
        self.wasmless_transfer_cost
    }

    /// Returns the costs of executing auction entry points.
    pub fn auction_costs(&self) -> &AuctionCosts {
        &self.auction_costs
    }

    /// Returns the costs of executing mint entry points.
    pub fn mint_costs(&self) -> &MintCosts {
        &self.mint_costs
    }

    /// Returns the costs of executing `handle_payment` entry points.
    pub fn handle_payment_costs(&self) -> &HandlePaymentCosts {
        &self.handle_payment_costs
    }

    /// Returns the costs of executing `standard_payment` entry points.
    pub fn standard_payment_costs(&self) -> &StandardPaymentCosts {
        &self.standard_payment_costs
    }
}

impl Default for SystemConfig {
    fn default() -> Self {
        Self {
            wasmless_transfer_cost: DEFAULT_WASMLESS_TRANSFER_COST,
            auction_costs: AuctionCosts::default(),
            mint_costs: MintCosts::default(),
            handle_payment_costs: HandlePaymentCosts::default(),
            standard_payment_costs: StandardPaymentCosts::default(),
        }
    }
}

impl ToBytes for SystemConfig {
    fn to_bytes(&self) -> Result<Vec<u8>, casper_types::bytesrepr::Error> {
        let mut ret = bytesrepr::unchecked_allocate_buffer(self);

        ret.append(&mut self.wasmless_transfer_cost.to_bytes()?);
        ret.append(&mut self.auction_costs.to_bytes()?);
        ret.append(&mut self.mint_costs.to_bytes()?);
        ret.append(&mut self.handle_payment_costs.to_bytes()?);
        ret.append(&mut self.standard_payment_costs.to_bytes()?);

        Ok(ret)
    }

    fn serialized_length(&self) -> usize {
        self.wasmless_transfer_cost.serialized_length()
            + self.auction_costs.serialized_length()
            + self.mint_costs.serialized_length()
            + self.handle_payment_costs.serialized_length()
            + self.standard_payment_costs.serialized_length()
    }
}

impl FromBytes for SystemConfig {
    fn from_bytes(bytes: &[u8]) -> Result<(Self, &[u8]), casper_types::bytesrepr::Error> {
        let (wasmless_transfer_cost, rem) = FromBytes::from_bytes(bytes)?;
        let (auction_costs, rem) = FromBytes::from_bytes(rem)?;
        let (mint_costs, rem) = FromBytes::from_bytes(rem)?;
        let (handle_payment_costs, rem) = FromBytes::from_bytes(rem)?;
        let (standard_payment_costs, rem) = FromBytes::from_bytes(rem)?;
        Ok((
            SystemConfig::new(
                wasmless_transfer_cost,
                auction_costs,
                mint_costs,
                handle_payment_costs,
                standard_payment_costs,
            ),
            rem,
        ))
    }
}

/// Default cost of the `get_era_validators` auction entry point.
pub const DEFAULT_GET_ERA_VALIDATORS_COST: u32 = 10_000;
/// Default cost of the `read_seigniorage_recipients` auction entry point.
pub const DEFAULT_READ_SEIGNIORAGE_RECIPIENTS_COST: u32 = 10_000;
/// Default cost of the `add_bid` auction entry point.
pub const DEFAULT_ADD_BID_COST: u32 = 2_500_000_000;
/// Default cost of the `withdraw_bid` auction entry point.
pub const DEFAULT_WITHDRAW_BID_COST: u32 = 2_500_000_000;
/// Default cost of the `delegate` auction entry point.
pub const DEFAULT_DELEGATE_COST: u32 = 2_500_000_000;
/// Default cost of the `redelegate` auction entry point.
pub const DEFAULT_REDELEGATE_COST: u32 = 2_500_000_000;
/// Default cost of the `undelegate` auction entry point.
pub const DEFAULT_UNDELEGATE_COST: u32 = 2_500_000_000;
/// Default cost of the `run_auction` auction entry point.
pub const DEFAULT_RUN_AUCTION_COST: u32 = 10_000;
/// Default cost of the `slash` auction entry point.
pub const DEFAULT_SLASH_COST: u32 = 10_000;
/// Default cost of the `distribute` auction entry point.
pub const DEFAULT_DISTRIBUTE_COST: u32 = 10_000;
/// Default cost of the `withdraw_delegator_reward` auction entry point.
pub const DEFAULT_WITHDRAW_DELEGATOR_REWARD_COST: u32 = 10_000;
/// Default cost of the `withdraw_validator_reward` auction entry point.
pub const DEFAULT_WITHDRAW_VALIDATOR_REWARD_COST: u32 = 10_000;
/// Default cost of the `read_era_id` auction entry point.
pub const DEFAULT_READ_ERA_ID_COST: u32 = 10_000;
/// Default cost of the `activate_bid` auction entry point.
pub const DEFAULT_ACTIVATE_BID_COST: u32 = 10_000;

/// Description of the costs of calling auction entrypoints.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug, DataSize)]
#[serde(deny_unknown_fields)]
pub struct AuctionCosts {
    /// Cost of calling the `get_era_validators` entry point.
    pub get_era_validators: u32,
    /// Cost of calling the `read_seigniorage_recipients` entry point.
    pub read_seigniorage_recipients: u32,
    /// Cost of calling the `add_bid` entry point.
    pub add_bid: u32,
    /// Cost of calling the `withdraw_bid` entry point.
    pub withdraw_bid: u32,
    /// Cost of calling the `delegate` entry point.
    pub delegate: u32,
    /// Cost of calling the `undelegate` entry point.
    pub undelegate: u32,
    /// Cost of calling the `run_auction` entry point.
    pub run_auction: u32,
    /// Cost of calling the `slash` entry point.
    pub slash: u32,
    /// Cost of calling the `distribute` entry point.
    pub distribute: u32,
    /// Cost of calling the `withdraw_delegator_reward` entry point.
    pub withdraw_delegator_reward: u32,
    /// Cost of calling the `withdraw_validator_reward` entry point.
    pub withdraw_validator_reward: u32,
    /// Cost of calling the `read_era_id` entry point.
    pub read_era_id: u32,
    /// Cost of calling the `activate_bid` entry point.
    pub activate_bid: u32,
    /// Cost of calling the `redelegate` entry point.
    pub redelegate: u32,
}

impl Default for AuctionCosts {
    fn default() -> Self {
        Self {
            get_era_validators: DEFAULT_GET_ERA_VALIDATORS_COST,
            read_seigniorage_recipients: DEFAULT_READ_SEIGNIORAGE_RECIPIENTS_COST,
            add_bid: DEFAULT_ADD_BID_COST,
            withdraw_bid: DEFAULT_WITHDRAW_BID_COST,
            delegate: DEFAULT_DELEGATE_COST,
            undelegate: DEFAULT_UNDELEGATE_COST,
            run_auction: DEFAULT_RUN_AUCTION_COST,
            slash: DEFAULT_SLASH_COST,
            distribute: DEFAULT_DISTRIBUTE_COST,
            withdraw_delegator_reward: DEFAULT_WITHDRAW_DELEGATOR_REWARD_COST,
            withdraw_validator_reward: DEFAULT_WITHDRAW_VALIDATOR_REWARD_COST,
            read_era_id: DEFAULT_READ_ERA_ID_COST,
            activate_bid: DEFAULT_ACTIVATE_BID_COST,
            redelegate: DEFAULT_REDELEGATE_COST,
        }
    }
}

impl ToBytes for AuctionCosts {
    fn to_bytes(&self) -> Result<Vec<u8>, casper_types::bytesrepr::Error> {
        let mut ret = bytesrepr::unchecked_allocate_buffer(self);

        let Self {
            get_era_validators,
            read_seigniorage_recipients,
            add_bid,
            withdraw_bid,
            delegate,
            undelegate,
            run_auction,
            slash,
            distribute,
            withdraw_delegator_reward,
            withdraw_validator_reward,
            read_era_id,
            activate_bid,
            redelegate,
        } = self;

        ret.append(&mut get_era_validators.to_bytes()?);
        ret.append(&mut read_seigniorage_recipients.to_bytes()?);
        ret.append(&mut add_bid.to_bytes()?);
        ret.append(&mut withdraw_bid.to_bytes()?);
        ret.append(&mut delegate.to_bytes()?);
        ret.append(&mut undelegate.to_bytes()?);
        ret.append(&mut run_auction.to_bytes()?);
        ret.append(&mut slash.to_bytes()?);
        ret.append(&mut distribute.to_bytes()?);
        ret.append(&mut withdraw_delegator_reward.to_bytes()?);
        ret.append(&mut withdraw_validator_reward.to_bytes()?);
        ret.append(&mut read_era_id.to_bytes()?);
        ret.append(&mut activate_bid.to_bytes()?);
        ret.append(&mut redelegate.to_bytes()?);

        Ok(ret)
    }

    fn serialized_length(&self) -> usize {
        let Self {
            get_era_validators,
            read_seigniorage_recipients,
            add_bid,
            withdraw_bid,
            delegate,
            undelegate,
            run_auction,
            slash,
            distribute,
            withdraw_delegator_reward,
            withdraw_validator_reward,
            read_era_id,
            activate_bid,
            redelegate,
        } = self;

        get_era_validators.serialized_length()
            + read_seigniorage_recipients.serialized_length()
            + add_bid.serialized_length()
            + withdraw_bid.serialized_length()
            + delegate.serialized_length()
            + undelegate.serialized_length()
            + run_auction.serialized_length()
            + slash.serialized_length()
            + distribute.serialized_length()
            + withdraw_delegator_reward.serialized_length()
            + withdraw_validator_reward.serialized_length()
            + read_era_id.serialized_length()
            + activate_bid.serialized_length()
            + redelegate.serialized_length()
    }
}

impl FromBytes for AuctionCosts {
    fn from_bytes(bytes: &[u8]) -> Result<(Self, &[u8]), casper_types::bytesrepr::Error> {
        let (get_era_validators, rem) = FromBytes::from_bytes(bytes)?;
        let (read_seigniorage_recipients, rem) = FromBytes::from_bytes(rem)?;
        let (add_bid, rem) = FromBytes::from_bytes(rem)?;
        let (withdraw_bid, rem) = FromBytes::from_bytes(rem)?;
        let (delegate, rem) = FromBytes::from_bytes(rem)?;
        let (undelegate, rem) = FromBytes::from_bytes(rem)?;
        let (run_auction, rem) = FromBytes::from_bytes(rem)?;
        let (slash, rem) = FromBytes::from_bytes(rem)?;
        let (distribute, rem) = FromBytes::from_bytes(rem)?;
        let (withdraw_delegator_reward, rem) = FromBytes::from_bytes(rem)?;
        let (withdraw_validator_reward, rem) = FromBytes::from_bytes(rem)?;
        let (read_era_id, rem) = FromBytes::from_bytes(rem)?;
        let (activate_bid, rem) = FromBytes::from_bytes(rem)?;
        let (redelegate, rem) = FromBytes::from_bytes(rem)?;
        Ok((
            Self {
                get_era_validators,
                read_seigniorage_recipients,
                add_bid,
                withdraw_bid,
                delegate,
                undelegate,
                run_auction,
                slash,
                distribute,
                withdraw_delegator_reward,
                withdraw_validator_reward,
                read_era_id,
                activate_bid,
                redelegate,
            },
            rem,
        ))
    }
}

/// Default cost of the `mint` mint entry point.
pub const DEFAULT_MINT_COST: u32 = 2_500_000_000;
/// Default cost of the `reduce_total_supply` mint entry point.
pub const DEFAULT_REDUCE_TOTAL_SUPPLY_COST: u32 = 10_000;
/// Default cost of the `create` mint entry point.
pub const DEFAULT_CREATE_COST: u32 = 2_500_000_000;
/// Default cost of the `balance` mint entry point.
pub const DEFAULT_BALANCE_COST: u32 = 10_000;
/// Default cost of the `transfer` mint entry point.
pub const DEFAULT_TRANSFER_COST: u32 = 10_000;
/// Default cost of the `read_base_round_reward` mint entry point.
pub const DEFAULT_READ_BASE_ROUND_REWARD_COST: u32 = 10_000;
/// Default cost of the `mint_into_existing_purse` mint entry point.
pub const DEFAULT_MINT_INTO_EXISTING_PURSE_COST: u32 = 2_500_000_000;

/// Description of the costs of calling mint entry points.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug, DataSize)]
#[serde(deny_unknown_fields)]
pub struct MintCosts {
    /// Cost of calling the `mint` entry point.
    pub mint: u32,
    /// Cost of calling the `reduce_total_supply` entry point.
    pub reduce_total_supply: u32,
    /// Cost of calling the `create` entry point.
    pub create: u32,
    /// Cost of calling the `balance` entry point.
    pub balance: u32,
    /// Cost of calling the `transfer` entry point.
    pub transfer: u32,
    /// Cost of calling the `read_base_round_reward` entry point.
    pub read_base_round_reward: u32,
    /// Cost of calling the `mint_into_existing_purse` entry point.
    pub mint_into_existing_purse: u32,
}

impl Default for MintCosts {
    fn default() -> Self {
        Self {
            mint: DEFAULT_MINT_COST,
            reduce_total_supply: DEFAULT_REDUCE_TOTAL_SUPPLY_COST,
            create: DEFAULT_CREATE_COST,
            balance: DEFAULT_BALANCE_COST,
            transfer: DEFAULT_TRANSFER_COST,
            read_base_round_reward: DEFAULT_READ_BASE_ROUND_REWARD_COST,
            mint_into_existing_purse: DEFAULT_MINT_INTO_EXISTING_PURSE_COST,
        }
    }
}

impl ToBytes for MintCosts {
    fn to_bytes(&self) -> Result<Vec<u8>, casper_types::bytesrepr::Error> {
        let mut ret = bytesrepr::unchecked_allocate_buffer(self);

        let Self {
            mint,
            reduce_total_supply,
            create,
            balance,
            transfer,
            read_base_round_reward,
            mint_into_existing_purse,
        } = self;

        ret.append(&mut mint.to_bytes()?);
        ret.append(&mut reduce_total_supply.to_bytes()?);
        ret.append(&mut create.to_bytes()?);
        ret.append(&mut balance.to_bytes()?);
        ret.append(&mut transfer.to_bytes()?);
        ret.append(&mut read_base_round_reward.to_bytes()?);
        ret.append(&mut mint_into_existing_purse.to_bytes()?);

        Ok(ret)
    }

    fn serialized_length(&self) -> usize {
        let Self {
            mint,
            reduce_total_supply,
            create,
            balance,
            transfer,
            read_base_round_reward,
            mint_into_existing_purse,
        } = self;

        mint.serialized_length()
            + reduce_total_supply.serialized_length()
            + create.serialized_length()
            + balance.serialized_length()
            + transfer.serialized_length()
            + read_base_round_reward.serialized_length()
            + mint_into_existing_purse.serialized_length()
    }
}

impl FromBytes for MintCosts {
    fn from_bytes(bytes: &[u8]) -> Result<(Self, &[u8]), casper_types::bytesrepr::Error> {
        let (mint, rem) = FromBytes::from_bytes(bytes)?;
        let (reduce_total_supply, rem) = FromBytes::from_bytes(rem)?;
        let (create, rem) = FromBytes::from_bytes(rem)?;
        let (balance, rem) = FromBytes::from_bytes(rem)?;
        let (transfer, rem) = FromBytes::from_bytes(rem)?;
        let (read_base_round_reward, rem) = FromBytes::from_bytes(rem)?;
        let (mint_into_existing_purse, rem) = FromBytes::from_bytes(rem)?;

        Ok((
            Self {
                mint,
                reduce_total_supply,
                create,
                balance,
                transfer,
                read_base_round_reward,
                mint_into_existing_purse,
            },
            rem,
        ))
    }
}

/// Default cost of the `get_payment_purse` `handle_payment` entry point.
pub const DEFAULT_GET_PAYMENT_PURSE_COST: u32 = 10_000;
/// Default cost of the `set_refund_purse` `handle_payment` entry point.
pub const DEFAULT_SET_REFUND_PURSE_COST: u32 = 10_000;
/// Default cost of the `get_refund_purse` `handle_payment` entry point.
pub const DEFAULT_GET_REFUND_PURSE_COST: u32 = 10_000;
/// Default cost of the `finalize_payment` `handle_payment` entry point.
pub const DEFAULT_FINALIZE_PAYMENT_COST: u32 = 10_000;

/// Description of the costs of calling `handle_payment` entrypoints.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug, DataSize)]
#[serde(deny_unknown_fields)]
pub struct HandlePaymentCosts {
    /// Cost of calling the `get_payment_purse` entry point.
    pub get_payment_purse: u32,
    /// Cost of calling the `set_refund_purse` entry point.
    pub set_refund_purse: u32,
    /// Cost of calling the `get_refund_purse` entry point.
    pub get_refund_purse: u32,
    /// Cost of calling the `finalize_payment` entry point.
    pub finalize_payment: u32,
}

impl Default for HandlePaymentCosts {
    fn default() -> Self {
        Self {
            get_payment_purse: DEFAULT_GET_PAYMENT_PURSE_COST,
            set_refund_purse: DEFAULT_SET_REFUND_PURSE_COST,
            get_refund_purse: DEFAULT_GET_REFUND_PURSE_COST,
            finalize_payment: DEFAULT_FINALIZE_PAYMENT_COST,
        }
    }
}

impl ToBytes for HandlePaymentCosts {
    fn to_bytes(&self) -> Result<Vec<u8>, casper_types::bytesrepr::Error> {
        let mut ret = bytesrepr::unchecked_allocate_buffer(self);

        ret.append(&mut self.get_payment_purse.to_bytes()?);
        ret.append(&mut self.set_refund_purse.to_bytes()?);
        ret.append(&mut self.get_refund_purse.to_bytes()?);
        ret.append(&mut self.finalize_payment.to_bytes()?);

        Ok(ret)
    }

    fn serialized_length(&self) -> usize {
        self.get_payment_purse.serialized_length()
            + self.set_refund_purse.serialized_length()
            + self.get_refund_purse.serialized_length()
            + self.finalize_payment.serialized_length()
    }
}

impl FromBytes for HandlePaymentCosts {
    fn from_bytes(bytes: &[u8]) -> Result<(Self, &[u8]), casper_types::bytesrepr::Error> {
        let (get_payment_purse, rem) = FromBytes::from_bytes(bytes)?;
        let (set_refund_purse, rem) = FromBytes::from_bytes(rem)?;
        let (get_refund_purse, rem) = FromBytes::from_bytes(rem)?;
        let (finalize_payment, rem) = FromBytes::from_bytes(rem)?;

        Ok((
            Self {
                get_payment_purse,
                set_refund_purse,
                get_refund_purse,
                finalize_payment,
            },
            rem,
        ))
    }
}

/// Default cost of the `pay` standard payment entry point.
const DEFAULT_PAY_COST: u32 = 10_000;

/// Description of the costs of calling standard payment entry points.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug, DataSize)]
#[serde(deny_unknown_fields)]
pub struct StandardPaymentCosts {
    /// Cost of calling the `pay` entry point.
    pub pay: u32,
}

impl Default for StandardPaymentCosts {
    fn default() -> Self {
        Self {
            pay: DEFAULT_PAY_COST,
        }
    }
}

impl ToBytes for StandardPaymentCosts {
    fn to_bytes(&self) -> Result<Vec<u8>, casper_types::bytesrepr::Error> {
        let mut ret = bytesrepr::unchecked_allocate_buffer(self);
        ret.append(&mut self.pay.to_bytes()?);
        Ok(ret)
    }

    fn serialized_length(&self) -> usize {
        self.pay.serialized_length()
    }
}

impl FromBytes for StandardPaymentCosts {
    fn from_bytes(bytes: &[u8]) -> Result<(Self, &[u8]), casper_types::bytesrepr::Error> {
        let (pay, rem) = FromBytes::from_bytes(bytes)?;
        Ok((Self { pay }, rem))
    }
}
