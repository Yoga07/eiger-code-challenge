use crate::casper_types::chainspec::Error as ChainspecError;
use crate::CommsError;
use bincode::ErrorKind;
use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Error from the Communications module {0:?}")]
    Comms(CommsError),
    #[error("Serialization error from Bincode {0:?}")]
    Bincode(ErrorKind),
    #[error("Chainspec Error {0:?}")]
    Chainspec(ChainspecError),
}

impl From<CommsError> for Error {
    fn from(value: CommsError) -> Self {
        Error::Comms(value)
    }
}

impl From<ChainspecError> for Error {
    fn from(value: ChainspecError) -> Self {
        Error::Chainspec(value)
    }
}

impl From<Box<ErrorKind>> for Error {
    fn from(value: Box<ErrorKind>) -> Self {
        Error::Bincode(*value)
    }
}
