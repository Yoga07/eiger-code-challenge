pub mod crypto;
pub mod message;
pub mod protocol_version;
use datasize::DataSize;

use serde::{Deserialize, Serialize};

use std::fmt;
use std::fmt::{Display, Formatter};

#[derive(Clone, Copy, DataSize, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub(crate) struct Nonce(u64);

impl Display for Nonce {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{:016X}", self.0)
    }
}
