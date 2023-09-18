//! Configuration of the Wasm execution engine.
use datasize::DataSize;
use serde::{Deserialize, Serialize};

use casper_types::bytesrepr::{self, FromBytes, ToBytes};

/// Default maximum number of pages of the Wasm memory.
pub const DEFAULT_WASM_MAX_MEMORY: u32 = 64;
/// Default maximum stack height.
pub const DEFAULT_MAX_STACK_HEIGHT: u32 = 500;

/// Configuration of the Wasm execution environment.
///
/// This structure contains various Wasm execution configuration options, such as memory limits,
/// stack limits and costs.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug, DataSize)]
#[serde(deny_unknown_fields)]
pub struct WasmConfig {
    /// Maximum amount of heap memory (represented in 64kB pages) each contract can use.
    pub max_memory: u32,
    /// Max stack height (native WebAssembly stack limiter).
    pub max_stack_height: u32,
    /// Wasm opcode costs table.
    opcode_costs: OpcodeCosts,
    /// Storage costs.
    storage_costs: StorageCosts,
    /// Host function costs table.
    host_function_costs: HostFunctionCosts,
}

impl WasmConfig {
    /// Creates new Wasm config.
    pub const fn new(
        max_memory: u32,
        max_stack_height: u32,
        opcode_costs: OpcodeCosts,
        storage_costs: StorageCosts,
        host_function_costs: HostFunctionCosts,
    ) -> Self {
        Self {
            max_memory,
            max_stack_height,
            opcode_costs,
            storage_costs,
            host_function_costs,
        }
    }

    /// Returns opcode costs.
    pub fn opcode_costs(&self) -> OpcodeCosts {
        self.opcode_costs
    }

    /// Returns storage costs.
    pub fn storage_costs(&self) -> StorageCosts {
        self.storage_costs
    }

    /// Returns host function costs and consumes this object.
    pub fn take_host_function_costs(self) -> HostFunctionCosts {
        self.host_function_costs
    }
}

impl Default for WasmConfig {
    fn default() -> Self {
        Self {
            max_memory: DEFAULT_WASM_MAX_MEMORY,
            max_stack_height: DEFAULT_MAX_STACK_HEIGHT,
            opcode_costs: OpcodeCosts::default(),
            storage_costs: StorageCosts::default(),
            host_function_costs: HostFunctionCosts::default(),
        }
    }
}

impl ToBytes for WasmConfig {
    fn to_bytes(&self) -> Result<Vec<u8>, bytesrepr::Error> {
        let mut ret = bytesrepr::unchecked_allocate_buffer(self);

        ret.append(&mut self.max_memory.to_bytes()?);
        ret.append(&mut self.max_stack_height.to_bytes()?);
        ret.append(&mut self.opcode_costs.to_bytes()?);
        ret.append(&mut self.storage_costs.to_bytes()?);
        ret.append(&mut self.host_function_costs.to_bytes()?);

        Ok(ret)
    }

    fn serialized_length(&self) -> usize {
        self.max_memory.serialized_length()
            + self.max_stack_height.serialized_length()
            + self.opcode_costs.serialized_length()
            + self.storage_costs.serialized_length()
            + self.host_function_costs.serialized_length()
    }
}

impl FromBytes for WasmConfig {
    fn from_bytes(bytes: &[u8]) -> Result<(Self, &[u8]), bytesrepr::Error> {
        let (max_memory, rem) = FromBytes::from_bytes(bytes)?;
        let (max_stack_height, rem) = FromBytes::from_bytes(rem)?;
        let (opcode_costs, rem) = FromBytes::from_bytes(rem)?;
        let (storage_costs, rem) = FromBytes::from_bytes(rem)?;
        let (host_function_costs, rem) = FromBytes::from_bytes(rem)?;

        Ok((
            WasmConfig {
                max_memory,
                max_stack_height,
                opcode_costs,
                storage_costs,
                host_function_costs,
            },
            rem,
        ))
    }
}

/// Default cost of the `bit` Wasm opcode.
pub const DEFAULT_BIT_COST: u32 = 300;
/// Default cost of the `add` Wasm opcode.
pub const DEFAULT_WASM_ADD_COST: u32 = 210;
/// Default cost of the `mul` Wasm opcode.
pub const DEFAULT_MUL_COST: u32 = 240;
/// Default cost of the `div` Wasm opcode.
pub const DEFAULT_DIV_COST: u32 = 320;
/// Default cost of the `load` Wasm opcode.
pub const DEFAULT_LOAD_COST: u32 = 2_500;
/// Default cost of the `store` Wasm opcode.
pub const DEFAULT_STORE_COST: u32 = 4_700;
/// Default cost of the `const` Wasm opcode.
pub const DEFAULT_CONST_COST: u32 = 110;
/// Default cost of the `local` Wasm opcode.
pub const DEFAULT_LOCAL_COST: u32 = 390;
/// Default cost of the `global` Wasm opcode.
pub const DEFAULT_GLOBAL_COST: u32 = 390;
/// Default cost of the `integer_comparison` Wasm opcode.
pub const DEFAULT_INTEGER_COMPARISON_COST: u32 = 250;
/// Default cost of the `conversion` Wasm opcode.
pub const DEFAULT_CONVERSION_COST: u32 = 420;
/// Default cost of the `unreachable` Wasm opcode.
pub const DEFAULT_UNREACHABLE_COST: u32 = 270;
/// Default cost of the `nop` Wasm opcode.
// TODO: This value is not researched.
pub const DEFAULT_NOP_COST: u32 = 200;
/// Default cost of the `current_memory` Wasm opcode.
pub const DEFAULT_CURRENT_MEMORY_COST: u32 = 290;
/// Default cost of the `grow_memory` Wasm opcode.
pub const DEFAULT_GROW_MEMORY_COST: u32 = 240_000;
/// Default cost of the `block` Wasm opcode.
pub const DEFAULT_CONTROL_FLOW_BLOCK_OPCODE: u32 = 440;
/// Default cost of the `loop` Wasm opcode.
pub const DEFAULT_CONTROL_FLOW_LOOP_OPCODE: u32 = 440;
/// Default cost of the `if` Wasm opcode.
pub const DEFAULT_CONTROL_FLOW_IF_OPCODE: u32 = 440;
/// Default cost of the `else` Wasm opcode.
pub const DEFAULT_CONTROL_FLOW_ELSE_OPCODE: u32 = 440;
/// Default cost of the `end` Wasm opcode.
pub const DEFAULT_CONTROL_FLOW_END_OPCODE: u32 = 440;
/// Default cost of the `br` Wasm opcode.
pub const DEFAULT_CONTROL_FLOW_BR_OPCODE: u32 = 440_000;
/// Default cost of the `br_if` Wasm opcode.
pub const DEFAULT_CONTROL_FLOW_BR_IF_OPCODE: u32 = 440_000;
/// Default cost of the `return` Wasm opcode.
pub const DEFAULT_CONTROL_FLOW_RETURN_OPCODE: u32 = 440;
/// Default cost of the `select` Wasm opcode.
pub const DEFAULT_CONTROL_FLOW_SELECT_OPCODE: u32 = 440;
/// Default cost of the `call` Wasm opcode.
pub const DEFAULT_CONTROL_FLOW_CALL_OPCODE: u32 = 140_000;
/// Default cost of the `call_indirect` Wasm opcode.
pub const DEFAULT_CONTROL_FLOW_CALL_INDIRECT_OPCODE: u32 = 140_000;
/// Default cost of the `drop` Wasm opcode.
pub const DEFAULT_CONTROL_FLOW_DROP_OPCODE: u32 = 440;
/// Default fixed cost of the `br_table` Wasm opcode.
pub const DEFAULT_CONTROL_FLOW_BR_TABLE_OPCODE: u32 = 440_000;
/// Default multiplier for the size of targets in `br_table` Wasm opcode.
pub const DEFAULT_CONTROL_FLOW_BR_TABLE_MULTIPLIER: u32 = 100;

/// Definition of a cost table for a Wasm `br_table` opcode.
///
/// Charge of a `br_table` opcode is calculated as follows:
///
/// ```text
/// cost + (len(br_table.targets) * size_multiplier)
/// ```
// This is done to encourage users to avoid writing code with very long `br_table`s.
#[derive(Copy, Clone, PartialEq, Eq, Serialize, Deserialize, Debug, DataSize)]
#[serde(deny_unknown_fields)]
pub struct BrTableCost {
    /// Fixed cost charge for `br_table` opcode.
    pub cost: u32,
    /// Multiplier for size of target labels in the `br_table` opcode.
    pub size_multiplier: u32,
}

impl Default for BrTableCost {
    fn default() -> Self {
        Self {
            cost: DEFAULT_CONTROL_FLOW_BR_TABLE_OPCODE,
            size_multiplier: DEFAULT_CONTROL_FLOW_BR_TABLE_MULTIPLIER,
        }
    }
}

impl ToBytes for BrTableCost {
    fn to_bytes(&self) -> Result<Vec<u8>, bytesrepr::Error> {
        let Self {
            cost,
            size_multiplier,
        } = self;

        let mut ret = bytesrepr::unchecked_allocate_buffer(self);

        ret.append(&mut cost.to_bytes()?);
        ret.append(&mut size_multiplier.to_bytes()?);

        Ok(ret)
    }

    fn serialized_length(&self) -> usize {
        let Self {
            cost,
            size_multiplier,
        } = self;

        cost.serialized_length() + size_multiplier.serialized_length()
    }
}

impl FromBytes for BrTableCost {
    fn from_bytes(bytes: &[u8]) -> Result<(Self, &[u8]), bytesrepr::Error> {
        let (cost, bytes): (_, &[u8]) = FromBytes::from_bytes(bytes)?;
        let (size_multiplier, bytes): (_, &[u8]) = FromBytes::from_bytes(bytes)?;
        Ok((
            Self {
                cost,
                size_multiplier,
            },
            bytes,
        ))
    }
}

/// Definition of a cost table for a Wasm control flow opcodes.
#[derive(Copy, Clone, PartialEq, Eq, Serialize, Deserialize, Debug, DataSize)]
#[serde(deny_unknown_fields)]
pub struct ControlFlowCosts {
    /// Cost for `block` opcode.
    pub block: u32,
    /// Cost for `loop` opcode.
    #[serde(rename = "loop")]
    pub op_loop: u32,
    /// Cost for `if` opcode.
    #[serde(rename = "if")]
    pub op_if: u32,
    /// Cost for `else` opcode.
    #[serde(rename = "else")]
    pub op_else: u32,
    /// Cost for `end` opcode.
    pub end: u32,
    /// Cost for `br` opcode.
    pub br: u32,
    /// Cost for `br_if` opcode.
    pub br_if: u32,
    /// Cost for `return` opcode.
    #[serde(rename = "return")]
    pub op_return: u32,
    /// Cost for `call` opcode.
    pub call: u32,
    /// Cost for `call_indirect` opcode.
    pub call_indirect: u32,
    /// Cost for `drop` opcode.
    pub drop: u32,
    /// Cost for `select` opcode.
    pub select: u32,
    /// Cost for `br_table` opcode.
    pub br_table: BrTableCost,
}

impl Default for ControlFlowCosts {
    fn default() -> Self {
        Self {
            block: DEFAULT_CONTROL_FLOW_BLOCK_OPCODE,
            op_loop: DEFAULT_CONTROL_FLOW_LOOP_OPCODE,
            op_if: DEFAULT_CONTROL_FLOW_IF_OPCODE,
            op_else: DEFAULT_CONTROL_FLOW_ELSE_OPCODE,
            end: DEFAULT_CONTROL_FLOW_END_OPCODE,
            br: DEFAULT_CONTROL_FLOW_BR_OPCODE,
            br_if: DEFAULT_CONTROL_FLOW_BR_IF_OPCODE,
            op_return: DEFAULT_CONTROL_FLOW_RETURN_OPCODE,
            call: DEFAULT_CONTROL_FLOW_CALL_OPCODE,
            call_indirect: DEFAULT_CONTROL_FLOW_CALL_INDIRECT_OPCODE,
            drop: DEFAULT_CONTROL_FLOW_DROP_OPCODE,
            select: DEFAULT_CONTROL_FLOW_SELECT_OPCODE,
            br_table: Default::default(),
        }
    }
}

impl ToBytes for ControlFlowCosts {
    fn to_bytes(&self) -> Result<Vec<u8>, bytesrepr::Error> {
        let mut ret = bytesrepr::unchecked_allocate_buffer(self);

        let Self {
            block,
            op_loop,
            op_if,
            op_else,
            end,
            br,
            br_if,
            op_return,
            call,
            call_indirect,
            drop,
            select,
            br_table,
        } = self;
        ret.append(&mut block.to_bytes()?);
        ret.append(&mut op_loop.to_bytes()?);
        ret.append(&mut op_if.to_bytes()?);
        ret.append(&mut op_else.to_bytes()?);
        ret.append(&mut end.to_bytes()?);
        ret.append(&mut br.to_bytes()?);
        ret.append(&mut br_if.to_bytes()?);
        ret.append(&mut op_return.to_bytes()?);
        ret.append(&mut call.to_bytes()?);
        ret.append(&mut call_indirect.to_bytes()?);
        ret.append(&mut drop.to_bytes()?);
        ret.append(&mut select.to_bytes()?);
        ret.append(&mut br_table.to_bytes()?);

        Ok(ret)
    }

    fn serialized_length(&self) -> usize {
        let Self {
            block,
            op_loop,
            op_if,
            op_else,
            end,
            br,
            br_if,
            op_return,
            call,
            call_indirect,
            drop,
            select,
            br_table,
        } = self;
        block.serialized_length()
            + op_loop.serialized_length()
            + op_if.serialized_length()
            + op_else.serialized_length()
            + end.serialized_length()
            + br.serialized_length()
            + br_if.serialized_length()
            + op_return.serialized_length()
            + call.serialized_length()
            + call_indirect.serialized_length()
            + drop.serialized_length()
            + select.serialized_length()
            + br_table.serialized_length()
    }
}

impl FromBytes for ControlFlowCosts {
    fn from_bytes(bytes: &[u8]) -> Result<(Self, &[u8]), bytesrepr::Error> {
        let (block, bytes): (_, &[u8]) = FromBytes::from_bytes(bytes)?;
        let (op_loop, bytes): (_, &[u8]) = FromBytes::from_bytes(bytes)?;
        let (op_if, bytes): (_, &[u8]) = FromBytes::from_bytes(bytes)?;
        let (op_else, bytes): (_, &[u8]) = FromBytes::from_bytes(bytes)?;
        let (end, bytes): (_, &[u8]) = FromBytes::from_bytes(bytes)?;
        let (br, bytes): (_, &[u8]) = FromBytes::from_bytes(bytes)?;
        let (br_if, bytes): (_, &[u8]) = FromBytes::from_bytes(bytes)?;
        let (op_return, bytes): (_, &[u8]) = FromBytes::from_bytes(bytes)?;
        let (call, bytes): (_, &[u8]) = FromBytes::from_bytes(bytes)?;
        let (call_indirect, bytes): (_, &[u8]) = FromBytes::from_bytes(bytes)?;
        let (drop, bytes): (_, &[u8]) = FromBytes::from_bytes(bytes)?;
        let (select, bytes): (_, &[u8]) = FromBytes::from_bytes(bytes)?;
        let (br_table, bytes): (_, &[u8]) = FromBytes::from_bytes(bytes)?;

        let control_flow_cost = ControlFlowCosts {
            block,
            op_loop,
            op_if,
            op_else,
            end,
            br,
            br_if,
            op_return,
            call,
            call_indirect,
            drop,
            select,
            br_table,
        };
        Ok((control_flow_cost, bytes))
    }
}

/// Definition of a cost table for Wasm opcodes.
///
/// This is taken (partially) from parity-ethereum.
#[derive(Copy, Clone, PartialEq, Eq, Serialize, Deserialize, Debug, DataSize)]
#[serde(deny_unknown_fields)]
pub struct OpcodeCosts {
    /// Bit operations multiplier.
    pub bit: u32,
    /// Arithmetic add operations multiplier.
    pub add: u32,
    /// Mul operations multiplier.
    pub mul: u32,
    /// Div operations multiplier.
    pub div: u32,
    /// Memory load operation multiplier.
    pub load: u32,
    /// Memory store operation multiplier.
    pub store: u32,
    /// Const operation multiplier.
    #[serde(rename = "const")]
    pub op_const: u32,
    /// Local operations multiplier.
    pub local: u32,
    /// Global operations multiplier.
    pub global: u32,
    /// Integer operations multiplier.
    pub integer_comparison: u32,
    /// Conversion operations multiplier.
    pub conversion: u32,
    /// Unreachable operation multiplier.
    pub unreachable: u32,
    /// Nop operation multiplier.
    pub nop: u32,
    /// Get current memory operation multiplier.
    pub current_memory: u32,
    /// Grow memory cost, per page (64kb)
    pub grow_memory: u32,
    /// Control flow operations multiplier.
    pub control_flow: ControlFlowCosts,
}

impl Default for OpcodeCosts {
    fn default() -> Self {
        OpcodeCosts {
            bit: DEFAULT_BIT_COST,
            add: DEFAULT_WASM_ADD_COST,
            mul: DEFAULT_MUL_COST,
            div: DEFAULT_DIV_COST,
            load: DEFAULT_LOAD_COST,
            store: DEFAULT_STORE_COST,
            op_const: DEFAULT_CONST_COST,
            local: DEFAULT_LOCAL_COST,
            global: DEFAULT_GLOBAL_COST,
            integer_comparison: DEFAULT_INTEGER_COMPARISON_COST,
            conversion: DEFAULT_CONVERSION_COST,
            unreachable: DEFAULT_UNREACHABLE_COST,
            nop: DEFAULT_NOP_COST,
            current_memory: DEFAULT_CURRENT_MEMORY_COST,
            grow_memory: DEFAULT_GROW_MEMORY_COST,
            control_flow: ControlFlowCosts::default(),
        }
    }
}

impl ToBytes for OpcodeCosts {
    fn to_bytes(&self) -> Result<Vec<u8>, bytesrepr::Error> {
        let mut ret = bytesrepr::unchecked_allocate_buffer(self);

        let Self {
            bit,
            add,
            mul,
            div,
            load,
            store,
            op_const,
            local,
            global,
            integer_comparison,
            conversion,
            unreachable,
            nop,
            current_memory,
            grow_memory,
            control_flow,
        } = self;

        ret.append(&mut bit.to_bytes()?);
        ret.append(&mut add.to_bytes()?);
        ret.append(&mut mul.to_bytes()?);
        ret.append(&mut div.to_bytes()?);
        ret.append(&mut load.to_bytes()?);
        ret.append(&mut store.to_bytes()?);
        ret.append(&mut op_const.to_bytes()?);
        ret.append(&mut local.to_bytes()?);
        ret.append(&mut global.to_bytes()?);
        ret.append(&mut integer_comparison.to_bytes()?);
        ret.append(&mut conversion.to_bytes()?);
        ret.append(&mut unreachable.to_bytes()?);
        ret.append(&mut nop.to_bytes()?);
        ret.append(&mut current_memory.to_bytes()?);
        ret.append(&mut grow_memory.to_bytes()?);
        ret.append(&mut control_flow.to_bytes()?);

        Ok(ret)
    }

    fn serialized_length(&self) -> usize {
        let Self {
            bit,
            add,
            mul,
            div,
            load,
            store,
            op_const,
            local,
            global,
            integer_comparison,
            conversion,
            unreachable,
            nop,
            current_memory,
            grow_memory,
            control_flow,
        } = self;
        bit.serialized_length()
            + add.serialized_length()
            + mul.serialized_length()
            + div.serialized_length()
            + load.serialized_length()
            + store.serialized_length()
            + op_const.serialized_length()
            + local.serialized_length()
            + global.serialized_length()
            + integer_comparison.serialized_length()
            + conversion.serialized_length()
            + unreachable.serialized_length()
            + nop.serialized_length()
            + current_memory.serialized_length()
            + grow_memory.serialized_length()
            + control_flow.serialized_length()
    }
}

impl FromBytes for OpcodeCosts {
    fn from_bytes(bytes: &[u8]) -> Result<(Self, &[u8]), bytesrepr::Error> {
        let (bit, bytes): (_, &[u8]) = FromBytes::from_bytes(bytes)?;
        let (add, bytes): (_, &[u8]) = FromBytes::from_bytes(bytes)?;
        let (mul, bytes): (_, &[u8]) = FromBytes::from_bytes(bytes)?;
        let (div, bytes): (_, &[u8]) = FromBytes::from_bytes(bytes)?;
        let (load, bytes): (_, &[u8]) = FromBytes::from_bytes(bytes)?;
        let (store, bytes): (_, &[u8]) = FromBytes::from_bytes(bytes)?;
        let (const_, bytes): (_, &[u8]) = FromBytes::from_bytes(bytes)?;
        let (local, bytes): (_, &[u8]) = FromBytes::from_bytes(bytes)?;
        let (global, bytes): (_, &[u8]) = FromBytes::from_bytes(bytes)?;
        let (integer_comparison, bytes): (_, &[u8]) = FromBytes::from_bytes(bytes)?;
        let (conversion, bytes): (_, &[u8]) = FromBytes::from_bytes(bytes)?;
        let (unreachable, bytes): (_, &[u8]) = FromBytes::from_bytes(bytes)?;
        let (nop, bytes): (_, &[u8]) = FromBytes::from_bytes(bytes)?;
        let (current_memory, bytes): (_, &[u8]) = FromBytes::from_bytes(bytes)?;
        let (grow_memory, bytes): (_, &[u8]) = FromBytes::from_bytes(bytes)?;
        let (control_flow, bytes): (_, &[u8]) = FromBytes::from_bytes(bytes)?;

        let opcode_costs = OpcodeCosts {
            bit,
            add,
            mul,
            div,
            load,
            store,
            op_const: const_,
            local,
            global,
            integer_comparison,
            conversion,
            unreachable,
            nop,
            current_memory,
            grow_memory,
            control_flow,
        };
        Ok((opcode_costs, bytes))
    }
}

/// Default gas cost per byte stored.
pub const DEFAULT_GAS_PER_BYTE_COST: u32 = 630_000;

/// Represents a cost table for storage costs.
#[derive(Copy, Clone, PartialEq, Eq, Serialize, Deserialize, Debug, DataSize)]
#[serde(deny_unknown_fields)]
pub struct StorageCosts {
    /// Gas charged per byte stored in the global state.
    gas_per_byte: u32,
}

impl StorageCosts {
    /// Creates new `StorageCosts`.
    pub const fn new(gas_per_byte: u32) -> Self {
        Self { gas_per_byte }
    }
}

impl Default for StorageCosts {
    fn default() -> Self {
        Self {
            gas_per_byte: DEFAULT_GAS_PER_BYTE_COST,
        }
    }
}

impl ToBytes for StorageCosts {
    fn to_bytes(&self) -> Result<Vec<u8>, bytesrepr::Error> {
        let mut ret = bytesrepr::unchecked_allocate_buffer(self);

        ret.append(&mut self.gas_per_byte.to_bytes()?);

        Ok(ret)
    }

    fn serialized_length(&self) -> usize {
        self.gas_per_byte.serialized_length()
    }
}

impl FromBytes for StorageCosts {
    fn from_bytes(bytes: &[u8]) -> Result<(Self, &[u8]), bytesrepr::Error> {
        let (gas_per_byte, rem) = FromBytes::from_bytes(bytes)?;

        Ok((StorageCosts { gas_per_byte }, rem))
    }
}

/// Support for host function gas cost tables.
use casper_types::{bytesrepr::U32_SERIALIZED_LENGTH, Gas};

/// Representation of argument's cost.
pub type Cost = u32;

const COST_SERIALIZED_LENGTH: usize = U32_SERIALIZED_LENGTH;

/// An identifier that represents an unused argument.
const NOT_USED: Cost = 0;

/// An arbitrary default fixed cost for host functions that were not researched yet.
const DEFAULT_FIXED_COST: Cost = 200;

const DEFAULT_ADD_COST: u32 = 5_800;
const DEFAULT_ADD_ASSOCIATED_KEY_COST: u32 = 9_000;

const DEFAULT_CALL_CONTRACT_COST: u32 = 4_500;
const DEFAULT_CALL_CONTRACT_ARGS_SIZE_WEIGHT: u32 = 420;

const DEFAULT_CREATE_PURSE_COST: u32 = 2_500_000_000;
const DEFAULT_GET_BALANCE_COST: u32 = 3_800;
const DEFAULT_GET_BLOCKTIME_COST: u32 = 330;
const DEFAULT_GET_CALLER_COST: u32 = 380;
const DEFAULT_GET_KEY_COST: u32 = 2_000;
const DEFAULT_GET_KEY_NAME_SIZE_WEIGHT: u32 = 440;
const DEFAULT_GET_MAIN_PURSE_COST: u32 = 1_300;
const DEFAULT_GET_PHASE_COST: u32 = 710;
const DEFAULT_GET_SYSTEM_CONTRACT_COST: u32 = 1_100;
const DEFAULT_HAS_KEY_COST: u32 = 1_500;
const DEFAULT_HAS_KEY_NAME_SIZE_WEIGHT: u32 = 840;
const DEFAULT_IS_VALID_UREF_COST: u32 = 760;
const DEFAULT_LOAD_NAMED_KEYS_COST: u32 = 42_000;
const DEFAULT_NEW_UREF_COST: u32 = 17_000;
const DEFAULT_NEW_UREF_VALUE_SIZE_WEIGHT: u32 = 590;

const DEFAULT_PRINT_COST: u32 = 20_000;
const DEFAULT_PRINT_TEXT_SIZE_WEIGHT: u32 = 4_600;

const DEFAULT_PUT_KEY_COST: u32 = 38_000;
const DEFAULT_PUT_KEY_NAME_SIZE_WEIGHT: u32 = 1_100;

const DEFAULT_READ_HOST_BUFFER_COST: u32 = 3_500;
const DEFAULT_READ_HOST_BUFFER_DEST_SIZE_WEIGHT: u32 = 310;

const DEFAULT_READ_VALUE_COST: u32 = 6_000;
const DEFAULT_DICTIONARY_GET_COST: u32 = 5_500;
const DEFAULT_DICTIONARY_GET_KEY_SIZE_WEIGHT: u32 = 590;

const DEFAULT_REMOVE_ASSOCIATED_KEY_COST: u32 = 4_200;

const DEFAULT_REMOVE_KEY_COST: u32 = 61_000;
const DEFAULT_REMOVE_KEY_NAME_SIZE_WEIGHT: u32 = 3_200;

const DEFAULT_RET_COST: u32 = 23_000;
const DEFAULT_RET_VALUE_SIZE_WEIGHT: u32 = 420_000;

const DEFAULT_REVERT_COST: u32 = 500;
const DEFAULT_SET_ACTION_THRESHOLD_COST: u32 = 74_000;
const DEFAULT_TRANSFER_FROM_PURSE_TO_ACCOUNT_COST: u32 = 2_500_000_000;
const DEFAULT_TRANSFER_FROM_PURSE_TO_PURSE_COST: u32 = 82_000;
const DEFAULT_TRANSFER_TO_ACCOUNT_COST: u32 = 2_500_000_000;
const DEFAULT_UPDATE_ASSOCIATED_KEY_COST: u32 = 4_200;

const DEFAULT_WRITE_COST: u32 = 14_000;
const DEFAULT_WRITE_VALUE_SIZE_WEIGHT: u32 = 980;

const DEFAULT_DICTIONARY_PUT_COST: u32 = 9_500;
const DEFAULT_DICTIONARY_PUT_KEY_BYTES_SIZE_WEIGHT: u32 = 1_800;
const DEFAULT_DICTIONARY_PUT_VALUE_SIZE_WEIGHT: u32 = 520;

/// Representation of a host function cost.
///
/// The total gas cost is equal to `cost` + sum of each argument weight multiplied by the byte size
/// of the data.
#[derive(Copy, Clone, PartialEq, Eq, Deserialize, Serialize, Debug, DataSize)]
#[serde(deny_unknown_fields)]
pub struct HostFunction<T> {
    /// How much the user is charged for calling the host function.
    cost: Cost,
    /// Weights of the function arguments.
    arguments: T,
}

impl<T> Default for HostFunction<T>
where
    T: Default,
{
    fn default() -> Self {
        HostFunction::new(DEFAULT_FIXED_COST, Default::default())
    }
}

impl<T> HostFunction<T> {
    /// Creates a new instance of `HostFunction` with a fixed call cost and argument weights.
    pub const fn new(cost: Cost, arguments: T) -> Self {
        Self { cost, arguments }
    }

    /// Returns the base gas fee for calling the host function.
    pub fn cost(&self) -> Cost {
        self.cost
    }
}

impl<T> HostFunction<T>
where
    T: Default,
{
    /// Creates a new fixed host function cost with argument weights of zero.
    pub fn fixed(cost: Cost) -> Self {
        Self {
            cost,
            ..Default::default()
        }
    }
}

impl<T> HostFunction<T>
where
    T: AsRef<[Cost]>,
{
    /// Returns a slice containing the argument weights.
    pub fn arguments(&self) -> &[Cost] {
        self.arguments.as_ref()
    }

    /// Calculate gas cost for a host function
    pub fn calculate_gas_cost(&self, weights: T) -> Gas {
        let mut gas = Gas::new(self.cost.into());
        for (argument, weight) in self.arguments.as_ref().iter().zip(weights.as_ref()) {
            let lhs = Gas::new((*argument).into());
            let rhs = Gas::new((*weight).into());
            gas += lhs * rhs;
        }
        gas
    }
}

impl<T> ToBytes for HostFunction<T>
where
    T: AsRef<[Cost]>,
{
    fn to_bytes(&self) -> Result<Vec<u8>, bytesrepr::Error> {
        let mut ret = bytesrepr::unchecked_allocate_buffer(self);
        ret.append(&mut self.cost.to_bytes()?);
        for value in self.arguments.as_ref().iter() {
            ret.append(&mut value.to_bytes()?);
        }
        Ok(ret)
    }

    fn serialized_length(&self) -> usize {
        self.cost.serialized_length() + (COST_SERIALIZED_LENGTH * self.arguments.as_ref().len())
    }
}

impl<T> FromBytes for HostFunction<T>
where
    T: Default + AsMut<[Cost]>,
{
    fn from_bytes(bytes: &[u8]) -> Result<(Self, &[u8]), bytesrepr::Error> {
        let (cost, mut bytes) = FromBytes::from_bytes(bytes)?;
        let mut arguments = T::default();
        let arguments_mut = arguments.as_mut();
        for ith_argument in arguments_mut {
            let (cost, rem) = FromBytes::from_bytes(bytes)?;
            *ith_argument = cost;
            bytes = rem;
        }
        Ok((Self { cost, arguments }, bytes))
    }
}

/// Definition of a host function cost table.
#[derive(Copy, Clone, PartialEq, Eq, Serialize, Deserialize, Debug, DataSize)]
#[serde(deny_unknown_fields)]
pub struct HostFunctionCosts {
    /// Cost of calling the `read_value` host function.
    pub read_value: HostFunction<[Cost; 3]>,
    /// Cost of calling the `dictionary_get` host function.
    #[serde(alias = "read_value_local")]
    pub dictionary_get: HostFunction<[Cost; 3]>,
    /// Cost of calling the `write` host function.
    pub write: HostFunction<[Cost; 4]>,
    /// Cost of calling the `dictionary_put` host function.
    #[serde(alias = "write_local")]
    pub dictionary_put: HostFunction<[Cost; 4]>,
    /// Cost of calling the `add` host function.
    pub add: HostFunction<[Cost; 4]>,
    /// Cost of calling the `new_uref` host function.
    pub new_uref: HostFunction<[Cost; 3]>,
    /// Cost of calling the `load_named_keys` host function.
    pub load_named_keys: HostFunction<[Cost; 2]>,
    /// Cost of calling the `ret` host function.
    pub ret: HostFunction<[Cost; 2]>,
    /// Cost of calling the `get_key` host function.
    pub get_key: HostFunction<[Cost; 5]>,
    /// Cost of calling the `has_key` host function.
    pub has_key: HostFunction<[Cost; 2]>,
    /// Cost of calling the `put_key` host function.
    pub put_key: HostFunction<[Cost; 4]>,
    /// Cost of calling the `remove_key` host function.
    pub remove_key: HostFunction<[Cost; 2]>,
    /// Cost of calling the `revert` host function.
    pub revert: HostFunction<[Cost; 1]>,
    /// Cost of calling the `is_valid_uref` host function.
    pub is_valid_uref: HostFunction<[Cost; 2]>,
    /// Cost of calling the `add_associated_key` host function.
    pub add_associated_key: HostFunction<[Cost; 3]>,
    /// Cost of calling the `remove_associated_key` host function.
    pub remove_associated_key: HostFunction<[Cost; 2]>,
    /// Cost of calling the `update_associated_key` host function.
    pub update_associated_key: HostFunction<[Cost; 3]>,
    /// Cost of calling the `set_action_threshold` host function.
    pub set_action_threshold: HostFunction<[Cost; 2]>,
    /// Cost of calling the `get_caller` host function.
    pub get_caller: HostFunction<[Cost; 1]>,
    /// Cost of calling the `get_blocktime` host function.
    pub get_blocktime: HostFunction<[Cost; 1]>,
    /// Cost of calling the `create_purse` host function.
    pub create_purse: HostFunction<[Cost; 2]>,
    /// Cost of calling the `transfer_to_account` host function.
    pub transfer_to_account: HostFunction<[Cost; 7]>,
    /// Cost of calling the `transfer_from_purse_to_account` host function.
    pub transfer_from_purse_to_account: HostFunction<[Cost; 9]>,
    /// Cost of calling the `transfer_from_purse_to_purse` host function.
    pub transfer_from_purse_to_purse: HostFunction<[Cost; 8]>,
    /// Cost of calling the `get_balance` host function.
    pub get_balance: HostFunction<[Cost; 3]>,
    /// Cost of calling the `get_phase` host function.
    pub get_phase: HostFunction<[Cost; 1]>,
    /// Cost of calling the `get_system_contract` host function.
    pub get_system_contract: HostFunction<[Cost; 3]>,
    /// Cost of calling the `get_main_purse` host function.
    pub get_main_purse: HostFunction<[Cost; 1]>,
    /// Cost of calling the `read_host_buffer` host function.
    pub read_host_buffer: HostFunction<[Cost; 3]>,
    /// Cost of calling the `create_contract_package_at_hash` host function.
    pub create_contract_package_at_hash: HostFunction<[Cost; 2]>,
    /// Cost of calling the `create_contract_user_group` host function.
    pub create_contract_user_group: HostFunction<[Cost; 8]>,
    /// Cost of calling the `add_contract_version` host function.
    pub add_contract_version: HostFunction<[Cost; 10]>,
    /// Cost of calling the `disable_contract_version` host function.
    pub disable_contract_version: HostFunction<[Cost; 4]>,
    /// Cost of calling the `call_contract` host function.
    pub call_contract: HostFunction<[Cost; 7]>,
    /// Cost of calling the `call_versioned_contract` host function.
    pub call_versioned_contract: HostFunction<[Cost; 9]>,
    /// Cost of calling the `get_named_arg_size` host function.
    pub get_named_arg_size: HostFunction<[Cost; 3]>,
    /// Cost of calling the `get_named_arg` host function.
    pub get_named_arg: HostFunction<[Cost; 4]>,
    /// Cost of calling the `remove_contract_user_group` host function.
    pub remove_contract_user_group: HostFunction<[Cost; 4]>,
    /// Cost of calling the `provision_contract_user_group_uref` host function.
    pub provision_contract_user_group_uref: HostFunction<[Cost; 5]>,
    /// Cost of calling the `remove_contract_user_group_urefs` host function.
    pub remove_contract_user_group_urefs: HostFunction<[Cost; 6]>,
    /// Cost of calling the `print` host function.
    pub print: HostFunction<[Cost; 2]>,
    /// Cost of calling the `blake2b` host function.
    pub blake2b: HostFunction<[Cost; 4]>,
    /// Cost of calling the `next address` host function.
    pub random_bytes: HostFunction<[Cost; 2]>,
    /// Cost of calling the `enable_contract_version` host function.
    pub enable_contract_version: HostFunction<[Cost; 4]>,
}

impl Default for HostFunctionCosts {
    fn default() -> Self {
        Self {
            read_value: HostFunction::fixed(DEFAULT_READ_VALUE_COST),
            dictionary_get: HostFunction::new(
                DEFAULT_DICTIONARY_GET_COST,
                [NOT_USED, DEFAULT_DICTIONARY_GET_KEY_SIZE_WEIGHT, NOT_USED],
            ),
            write: HostFunction::new(
                DEFAULT_WRITE_COST,
                [
                    NOT_USED,
                    NOT_USED,
                    NOT_USED,
                    DEFAULT_WRITE_VALUE_SIZE_WEIGHT,
                ],
            ),
            dictionary_put: HostFunction::new(
                DEFAULT_DICTIONARY_PUT_COST,
                [
                    NOT_USED,
                    DEFAULT_DICTIONARY_PUT_KEY_BYTES_SIZE_WEIGHT,
                    NOT_USED,
                    DEFAULT_DICTIONARY_PUT_VALUE_SIZE_WEIGHT,
                ],
            ),
            add: HostFunction::fixed(DEFAULT_ADD_COST),
            new_uref: HostFunction::new(
                DEFAULT_NEW_UREF_COST,
                [NOT_USED, NOT_USED, DEFAULT_NEW_UREF_VALUE_SIZE_WEIGHT],
            ),
            load_named_keys: HostFunction::fixed(DEFAULT_LOAD_NAMED_KEYS_COST),
            ret: HostFunction::new(DEFAULT_RET_COST, [NOT_USED, DEFAULT_RET_VALUE_SIZE_WEIGHT]),
            get_key: HostFunction::new(
                DEFAULT_GET_KEY_COST,
                [
                    NOT_USED,
                    DEFAULT_GET_KEY_NAME_SIZE_WEIGHT,
                    NOT_USED,
                    NOT_USED,
                    NOT_USED,
                ],
            ),
            has_key: HostFunction::new(
                DEFAULT_HAS_KEY_COST,
                [NOT_USED, DEFAULT_HAS_KEY_NAME_SIZE_WEIGHT],
            ),
            put_key: HostFunction::new(
                DEFAULT_PUT_KEY_COST,
                [
                    NOT_USED,
                    DEFAULT_PUT_KEY_NAME_SIZE_WEIGHT,
                    NOT_USED,
                    NOT_USED,
                ],
            ),
            remove_key: HostFunction::new(
                DEFAULT_REMOVE_KEY_COST,
                [NOT_USED, DEFAULT_REMOVE_KEY_NAME_SIZE_WEIGHT],
            ),
            revert: HostFunction::fixed(DEFAULT_REVERT_COST),
            is_valid_uref: HostFunction::fixed(DEFAULT_IS_VALID_UREF_COST),
            add_associated_key: HostFunction::fixed(DEFAULT_ADD_ASSOCIATED_KEY_COST),
            remove_associated_key: HostFunction::fixed(DEFAULT_REMOVE_ASSOCIATED_KEY_COST),
            update_associated_key: HostFunction::fixed(DEFAULT_UPDATE_ASSOCIATED_KEY_COST),
            set_action_threshold: HostFunction::fixed(DEFAULT_SET_ACTION_THRESHOLD_COST),
            get_caller: HostFunction::fixed(DEFAULT_GET_CALLER_COST),
            get_blocktime: HostFunction::fixed(DEFAULT_GET_BLOCKTIME_COST),
            create_purse: HostFunction::fixed(DEFAULT_CREATE_PURSE_COST),
            transfer_to_account: HostFunction::fixed(DEFAULT_TRANSFER_TO_ACCOUNT_COST),
            transfer_from_purse_to_account: HostFunction::fixed(
                DEFAULT_TRANSFER_FROM_PURSE_TO_ACCOUNT_COST,
            ),
            transfer_from_purse_to_purse: HostFunction::fixed(
                DEFAULT_TRANSFER_FROM_PURSE_TO_PURSE_COST,
            ),
            get_balance: HostFunction::fixed(DEFAULT_GET_BALANCE_COST),
            get_phase: HostFunction::fixed(DEFAULT_GET_PHASE_COST),
            get_system_contract: HostFunction::fixed(DEFAULT_GET_SYSTEM_CONTRACT_COST),
            get_main_purse: HostFunction::fixed(DEFAULT_GET_MAIN_PURSE_COST),
            read_host_buffer: HostFunction::new(
                DEFAULT_READ_HOST_BUFFER_COST,
                [
                    NOT_USED,
                    DEFAULT_READ_HOST_BUFFER_DEST_SIZE_WEIGHT,
                    NOT_USED,
                ],
            ),
            create_contract_package_at_hash: HostFunction::default(),
            create_contract_user_group: HostFunction::default(),
            add_contract_version: HostFunction::default(),
            disable_contract_version: HostFunction::default(),
            call_contract: HostFunction::new(
                DEFAULT_CALL_CONTRACT_COST,
                [
                    NOT_USED,
                    NOT_USED,
                    NOT_USED,
                    NOT_USED,
                    NOT_USED,
                    DEFAULT_CALL_CONTRACT_ARGS_SIZE_WEIGHT,
                    NOT_USED,
                ],
            ),
            call_versioned_contract: HostFunction::new(
                DEFAULT_CALL_CONTRACT_COST,
                [
                    NOT_USED,
                    NOT_USED,
                    NOT_USED,
                    NOT_USED,
                    NOT_USED,
                    NOT_USED,
                    NOT_USED,
                    DEFAULT_CALL_CONTRACT_ARGS_SIZE_WEIGHT,
                    NOT_USED,
                ],
            ),
            get_named_arg_size: HostFunction::default(),
            get_named_arg: HostFunction::default(),
            remove_contract_user_group: HostFunction::default(),
            provision_contract_user_group_uref: HostFunction::default(),
            remove_contract_user_group_urefs: HostFunction::default(),
            print: HostFunction::new(
                DEFAULT_PRINT_COST,
                [NOT_USED, DEFAULT_PRINT_TEXT_SIZE_WEIGHT],
            ),
            blake2b: HostFunction::default(),
            random_bytes: HostFunction::default(),
            enable_contract_version: HostFunction::default(),
        }
    }
}

impl ToBytes for HostFunctionCosts {
    fn to_bytes(&self) -> Result<Vec<u8>, bytesrepr::Error> {
        let mut ret = bytesrepr::unchecked_allocate_buffer(self);
        ret.append(&mut self.read_value.to_bytes()?);
        ret.append(&mut self.dictionary_get.to_bytes()?);
        ret.append(&mut self.write.to_bytes()?);
        ret.append(&mut self.dictionary_put.to_bytes()?);
        ret.append(&mut self.add.to_bytes()?);
        ret.append(&mut self.new_uref.to_bytes()?);
        ret.append(&mut self.load_named_keys.to_bytes()?);
        ret.append(&mut self.ret.to_bytes()?);
        ret.append(&mut self.get_key.to_bytes()?);
        ret.append(&mut self.has_key.to_bytes()?);
        ret.append(&mut self.put_key.to_bytes()?);
        ret.append(&mut self.remove_key.to_bytes()?);
        ret.append(&mut self.revert.to_bytes()?);
        ret.append(&mut self.is_valid_uref.to_bytes()?);
        ret.append(&mut self.add_associated_key.to_bytes()?);
        ret.append(&mut self.remove_associated_key.to_bytes()?);
        ret.append(&mut self.update_associated_key.to_bytes()?);
        ret.append(&mut self.set_action_threshold.to_bytes()?);
        ret.append(&mut self.get_caller.to_bytes()?);
        ret.append(&mut self.get_blocktime.to_bytes()?);
        ret.append(&mut self.create_purse.to_bytes()?);
        ret.append(&mut self.transfer_to_account.to_bytes()?);
        ret.append(&mut self.transfer_from_purse_to_account.to_bytes()?);
        ret.append(&mut self.transfer_from_purse_to_purse.to_bytes()?);
        ret.append(&mut self.get_balance.to_bytes()?);
        ret.append(&mut self.get_phase.to_bytes()?);
        ret.append(&mut self.get_system_contract.to_bytes()?);
        ret.append(&mut self.get_main_purse.to_bytes()?);
        ret.append(&mut self.read_host_buffer.to_bytes()?);
        ret.append(&mut self.create_contract_package_at_hash.to_bytes()?);
        ret.append(&mut self.create_contract_user_group.to_bytes()?);
        ret.append(&mut self.add_contract_version.to_bytes()?);
        ret.append(&mut self.disable_contract_version.to_bytes()?);
        ret.append(&mut self.call_contract.to_bytes()?);
        ret.append(&mut self.call_versioned_contract.to_bytes()?);
        ret.append(&mut self.get_named_arg_size.to_bytes()?);
        ret.append(&mut self.get_named_arg.to_bytes()?);
        ret.append(&mut self.remove_contract_user_group.to_bytes()?);
        ret.append(&mut self.provision_contract_user_group_uref.to_bytes()?);
        ret.append(&mut self.remove_contract_user_group_urefs.to_bytes()?);
        ret.append(&mut self.print.to_bytes()?);
        ret.append(&mut self.blake2b.to_bytes()?);
        ret.append(&mut self.random_bytes.to_bytes()?);
        ret.append(&mut self.enable_contract_version.to_bytes()?);
        Ok(ret)
    }

    fn serialized_length(&self) -> usize {
        self.read_value.serialized_length()
            + self.dictionary_get.serialized_length()
            + self.write.serialized_length()
            + self.dictionary_put.serialized_length()
            + self.add.serialized_length()
            + self.new_uref.serialized_length()
            + self.load_named_keys.serialized_length()
            + self.ret.serialized_length()
            + self.get_key.serialized_length()
            + self.has_key.serialized_length()
            + self.put_key.serialized_length()
            + self.remove_key.serialized_length()
            + self.revert.serialized_length()
            + self.is_valid_uref.serialized_length()
            + self.add_associated_key.serialized_length()
            + self.remove_associated_key.serialized_length()
            + self.update_associated_key.serialized_length()
            + self.set_action_threshold.serialized_length()
            + self.get_caller.serialized_length()
            + self.get_blocktime.serialized_length()
            + self.create_purse.serialized_length()
            + self.transfer_to_account.serialized_length()
            + self.transfer_from_purse_to_account.serialized_length()
            + self.transfer_from_purse_to_purse.serialized_length()
            + self.get_balance.serialized_length()
            + self.get_phase.serialized_length()
            + self.get_system_contract.serialized_length()
            + self.get_main_purse.serialized_length()
            + self.read_host_buffer.serialized_length()
            + self.create_contract_package_at_hash.serialized_length()
            + self.create_contract_user_group.serialized_length()
            + self.add_contract_version.serialized_length()
            + self.disable_contract_version.serialized_length()
            + self.call_contract.serialized_length()
            + self.call_versioned_contract.serialized_length()
            + self.get_named_arg_size.serialized_length()
            + self.get_named_arg.serialized_length()
            + self.remove_contract_user_group.serialized_length()
            + self.provision_contract_user_group_uref.serialized_length()
            + self.remove_contract_user_group_urefs.serialized_length()
            + self.print.serialized_length()
            + self.blake2b.serialized_length()
            + self.random_bytes.serialized_length()
            + self.enable_contract_version.serialized_length()
    }
}

impl FromBytes for HostFunctionCosts {
    fn from_bytes(bytes: &[u8]) -> Result<(Self, &[u8]), bytesrepr::Error> {
        let (read_value, rem) = FromBytes::from_bytes(bytes)?;
        let (dictionary_get, rem) = FromBytes::from_bytes(rem)?;
        let (write, rem) = FromBytes::from_bytes(rem)?;
        let (dictionary_put, rem) = FromBytes::from_bytes(rem)?;
        let (add, rem) = FromBytes::from_bytes(rem)?;
        let (new_uref, rem) = FromBytes::from_bytes(rem)?;
        let (load_named_keys, rem) = FromBytes::from_bytes(rem)?;
        let (ret, rem) = FromBytes::from_bytes(rem)?;
        let (get_key, rem) = FromBytes::from_bytes(rem)?;
        let (has_key, rem) = FromBytes::from_bytes(rem)?;
        let (put_key, rem) = FromBytes::from_bytes(rem)?;
        let (remove_key, rem) = FromBytes::from_bytes(rem)?;
        let (revert, rem) = FromBytes::from_bytes(rem)?;
        let (is_valid_uref, rem) = FromBytes::from_bytes(rem)?;
        let (add_associated_key, rem) = FromBytes::from_bytes(rem)?;
        let (remove_associated_key, rem) = FromBytes::from_bytes(rem)?;
        let (update_associated_key, rem) = FromBytes::from_bytes(rem)?;
        let (set_action_threshold, rem) = FromBytes::from_bytes(rem)?;
        let (get_caller, rem) = FromBytes::from_bytes(rem)?;
        let (get_blocktime, rem) = FromBytes::from_bytes(rem)?;
        let (create_purse, rem) = FromBytes::from_bytes(rem)?;
        let (transfer_to_account, rem) = FromBytes::from_bytes(rem)?;
        let (transfer_from_purse_to_account, rem) = FromBytes::from_bytes(rem)?;
        let (transfer_from_purse_to_purse, rem) = FromBytes::from_bytes(rem)?;
        let (get_balance, rem) = FromBytes::from_bytes(rem)?;
        let (get_phase, rem) = FromBytes::from_bytes(rem)?;
        let (get_system_contract, rem) = FromBytes::from_bytes(rem)?;
        let (get_main_purse, rem) = FromBytes::from_bytes(rem)?;
        let (read_host_buffer, rem) = FromBytes::from_bytes(rem)?;
        let (create_contract_package_at_hash, rem) = FromBytes::from_bytes(rem)?;
        let (create_contract_user_group, rem) = FromBytes::from_bytes(rem)?;
        let (add_contract_version, rem) = FromBytes::from_bytes(rem)?;
        let (disable_contract_version, rem) = FromBytes::from_bytes(rem)?;
        let (call_contract, rem) = FromBytes::from_bytes(rem)?;
        let (call_versioned_contract, rem) = FromBytes::from_bytes(rem)?;
        let (get_named_arg_size, rem) = FromBytes::from_bytes(rem)?;
        let (get_named_arg, rem) = FromBytes::from_bytes(rem)?;
        let (remove_contract_user_group, rem) = FromBytes::from_bytes(rem)?;
        let (provision_contract_user_group_uref, rem) = FromBytes::from_bytes(rem)?;
        let (remove_contract_user_group_urefs, rem) = FromBytes::from_bytes(rem)?;
        let (print, rem) = FromBytes::from_bytes(rem)?;
        let (blake2b, rem) = FromBytes::from_bytes(rem)?;
        let (random_bytes, rem) = FromBytes::from_bytes(rem)?;
        let (enable_contract_version, rem) = FromBytes::from_bytes(rem)?;
        Ok((
            HostFunctionCosts {
                read_value,
                dictionary_get,
                write,
                dictionary_put,
                add,
                new_uref,
                load_named_keys,
                ret,
                get_key,
                has_key,
                put_key,
                remove_key,
                revert,
                is_valid_uref,
                add_associated_key,
                remove_associated_key,
                update_associated_key,
                set_action_threshold,
                get_caller,
                get_blocktime,
                create_purse,
                transfer_to_account,
                transfer_from_purse_to_account,
                transfer_from_purse_to_purse,
                get_balance,
                get_phase,
                get_system_contract,
                get_main_purse,
                read_host_buffer,
                create_contract_package_at_hash,
                create_contract_user_group,
                add_contract_version,
                disable_contract_version,
                call_contract,
                call_versioned_contract,
                get_named_arg_size,
                get_named_arg,
                remove_contract_user_group,
                provision_contract_user_group_uref,
                remove_contract_user_group_urefs,
                print,
                blake2b,
                random_bytes,
                enable_contract_version,
            },
            rem,
        ))
    }
}
