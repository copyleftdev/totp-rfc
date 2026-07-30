use core::fmt;

/// An error in an HOTP or TOTP system parameter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Error {
    /// The shared secret is shorter than RFC 4226 permits.
    SecretTooShort {
        /// Length supplied by the caller, in bytes.
        actual: usize,
        /// Minimum accepted length, in bytes.
        minimum: usize,
    },
    /// The requested decimal code width is outside the RFC-defined range.
    InvalidDigits {
        /// Width supplied by the caller.
        actual: u8,
    },
    /// A zero-second TOTP period was requested.
    ZeroPeriod,
    /// The supplied Unix timestamp precedes the configured TOTP epoch.
    TimestampBeforeEpoch {
        /// Timestamp supplied by the caller.
        timestamp: u64,
        /// Configured initial timestamp (`T0`).
        epoch: u64,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SecretTooShort { actual, minimum } => write!(
                f,
                "shared secret is {actual} bytes; RFC 4226 requires at least {minimum}"
            ),
            Self::InvalidDigits { actual } => {
                write!(f, "invalid OTP width {actual}; expected 6, 7, or 8 digits")
            }
            Self::ZeroPeriod => f.write_str("TOTP period must be non-zero"),
            Self::TimestampBeforeEpoch { timestamp, epoch } => write!(
                f,
                "Unix timestamp {timestamp} precedes the configured TOTP epoch {epoch}"
            ),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

/// A syntax error in a user-supplied OTP code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum CodeError {
    /// The code does not have the configured number of bytes.
    InvalidLength {
        /// Actual byte length of the supplied value.
        actual: usize,
        /// Required byte length.
        expected: u8,
    },
    /// The code contains a byte outside ASCII `0` through `9`.
    NonDecimal {
        /// Zero-based byte position of the first invalid byte.
        index: usize,
    },
}

impl fmt::Display for CodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength { actual, expected } => {
                write!(f, "OTP is {actual} bytes; expected exactly {expected}")
            }
            Self::NonDecimal { index } => {
                write!(f, "OTP contains a non-decimal byte at index {index}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for CodeError {}
