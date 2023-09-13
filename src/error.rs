use crate::CommsError;
use bincode::ErrorKind;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    Generic(String),
    Comms(CommsError),
    Bincode(ErrorKind),
    HandShake(String),
}

impl From<CommsError> for Error {
    fn from(value: CommsError) -> Self {
        Error::Comms(value)
    }
}

impl From<Box<ErrorKind>> for Error {
    fn from(value: Box<ErrorKind>) -> Self {
        Error::Bincode(*value)
    }
}
