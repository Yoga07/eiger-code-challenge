use casper_types::SemVer;

/// A newtype wrapping a [`SemVer`] which represents a Casper Platform protocol version.
#[derive(Copy, Clone, Debug, Default, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct ProtocolVersion(SemVer);
