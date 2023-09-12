use crate::CommsError;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    Generic(String),
    CommsError(CommsError),
}

impl From<CommsError> for Error {
    fn from(value: CommsError) -> Self {
        Error::CommsError(value)
    }
}
