use crate::casper_types::chainspec::Error as ChainspecError;
use crate::CommsError;
use bincode::ErrorKind;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    Generic(String),
    Comms(CommsError),
    Bincode(ErrorKind),
    HandShake(String),
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
