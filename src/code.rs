use core::fmt;

use subtle::{Choice, ConstantTimeEq};

use crate::{CodeError, Error};

/// The number of decimal digits in an HOTP or TOTP code.
///
/// RFC 4226 requires implementations to support at least six digits and
/// defines six-, seven-, and eight-digit output.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Digits(u8);

impl Digits {
    /// A six-digit code, the RFC 4226 minimum and HOTP default.
    pub const SIX: Self = Self(6);
    /// A seven-digit code.
    pub const SEVEN: Self = Self(7);
    /// An eight-digit code, used by the RFC 6238 test vectors.
    pub const EIGHT: Self = Self(8);

    /// Validates an OTP width.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidDigits`] unless `value` is 6, 7, or 8.
    pub const fn new(value: u8) -> Result<Self, Error> {
        if value >= 6 && value <= 8 {
            Ok(Self(value))
        } else {
            Err(Error::InvalidDigits { actual: value })
        }
    }

    /// Returns the decimal width.
    #[must_use]
    pub const fn get(self) -> u8 {
        self.0
    }

    pub(crate) const fn modulus(self) -> u32 {
        match self.0 {
            6 => 1_000_000,
            7 => 10_000_000,
            8 => 100_000_000,
            _ => unreachable!(),
        }
    }
}

impl TryFrom<u8> for Digits {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<Digits> for u8 {
    fn from(value: Digits) -> Self {
        value.get()
    }
}

/// A generated or parsed decimal one-time password.
///
/// Formatting always preserves leading zeroes to the configured width.
#[derive(Clone, Copy, Debug)]
pub struct Code {
    value: u32,
    digits: Digits,
}

impl Code {
    pub(crate) const fn generated(value: u32, digits: Digits) -> Self {
        Self { value, digits }
    }

    /// Parses exactly the configured number of ASCII decimal digits.
    ///
    /// Whitespace, signs, non-ASCII numerals, and missing leading zeroes are
    /// rejected rather than normalized.
    ///
    /// # Errors
    ///
    /// Returns [`CodeError::InvalidLength`] for a different byte length or
    /// [`CodeError::NonDecimal`] for any non-ASCII-decimal byte.
    pub fn parse(input: &str, digits: Digits) -> Result<Self, CodeError> {
        let bytes = input.as_bytes();
        if bytes.len() != usize::from(digits.get()) {
            return Err(CodeError::InvalidLength {
                actual: bytes.len(),
                expected: digits.get(),
            });
        }

        let mut value = 0_u32;
        for (index, byte) in bytes.iter().copied().enumerate() {
            if !byte.is_ascii_digit() {
                return Err(CodeError::NonDecimal { index });
            }
            value = value * 10 + u32::from(byte - b'0');
        }

        Ok(Self { value, digits })
    }

    /// Returns the numeric value. Use [`Display`](fmt::Display) to retain
    /// leading zeroes.
    #[must_use]
    pub const fn value(self) -> u32 {
        self.value
    }

    /// Returns the configured decimal width.
    #[must_use]
    pub const fn digits(self) -> Digits {
        self.digits
    }

    pub(crate) fn ct_eq_choice(self, other: Self) -> Choice {
        let values_equal = self.value.to_be_bytes().ct_eq(&other.value.to_be_bytes());
        let widths_equal = self.digits.get().ct_eq(&other.digits.get());
        values_equal & widths_equal
    }

    pub(crate) fn ct_eq(self, other: Self) -> bool {
        bool::from(self.ct_eq_choice(other))
    }
}

impl PartialEq for Code {
    fn eq(&self, other: &Self) -> bool {
        (*self).ct_eq(*other)
    }
}

impl Eq for Code {}

impl fmt::Display for Code {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:0width$}",
            self.value,
            width = usize::from(self.digits.get())
        )
    }
}
