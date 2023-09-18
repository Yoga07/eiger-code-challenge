pub mod chainspec;
pub mod crypto;
pub mod message;
pub mod ser_deser;

use datasize::DataSize;
use serde::{Deserialize, Serialize};

use std::fmt;
use std::fmt::{Display, Formatter};

#[derive(Clone, Copy, DataSize, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct Nonce(u64);

impl Nonce {
    pub fn new(num: u64) -> Self {
        Self(num)
    }
}

impl Display for Nonce {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{:016X}", self.0)
    }
}
