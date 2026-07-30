use hmac::{Hmac, KeyInit, Mac};
use sha2::{Sha256, Sha512};
use subtle::{Choice, ConditionallySelectable};

use crate::hotp::{dynamic_truncate, generate_with_sha1};
use crate::{Code, CodeError, Digits, Error, Secret};

/// HMAC algorithms permitted by RFC 6238.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum Algorithm {
    /// HMAC-SHA-1, the interoperable RFC default.
    #[default]
    Sha1,
    /// HMAC-SHA-256.
    Sha256,
    /// HMAC-SHA-512.
    Sha512,
}

impl Algorithm {
    /// Returns the RFC-recommended key length for this algorithm, in bytes.
    ///
    /// Longer or shorter keys remain valid as long as they satisfy RFC
    /// 4226's mandatory 128-bit minimum.
    #[must_use]
    pub const fn recommended_key_len(self) -> usize {
        match self {
            Self::Sha1 => 20,
            Self::Sha256 => 32,
            Self::Sha512 => 64,
        }
    }
}

/// A bounded TOTP validation window.
///
/// The window is expressed in time steps, not seconds. RFC 6238 recommends
/// allowing at most one past step for ordinary network delay. Clock-drift
/// resynchronization policy may deliberately use another bounded value.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ValidationWindow {
    past: u16,
    future: u16,
}

impl ValidationWindow {
    /// Validate only the current time step.
    pub const CURRENT: Self = Self::new(0, 0);
    /// RFC 6238's recommended maximum ordinary transmission-delay window.
    pub const RFC_RECOMMENDED: Self = Self::new(1, 0);

    /// Creates a window allowing the given number of past and future steps.
    #[must_use]
    pub const fn new(past: u16, future: u16) -> Self {
        Self { past, future }
    }

    /// Returns the number of accepted past steps.
    #[must_use]
    pub const fn past(self) -> u16 {
        self.past
    }

    /// Returns the number of accepted future steps.
    #[must_use]
    pub const fn future(self) -> u16 {
        self.future
    }
}

impl Default for ValidationWindow {
    fn default() -> Self {
        Self::RFC_RECOMMENDED
    }
}

/// RFC 6238 TOTP system parameters.
///
/// Parameters are immutable so a prover and verifier can share an exact
/// configuration without partial mutation.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Totp {
    algorithm: Algorithm,
    digits: Digits,
    period: u64,
    epoch: u64,
}

struct MatchAccumulator {
    found: Choice,
    counter: u64,
    drift: i32,
}

impl MatchAccumulator {
    fn new() -> Self {
        Self {
            found: Choice::from(0),
            counter: 0,
            drift: 0,
        }
    }
}

impl Totp {
    /// The RFC 6238 default period in seconds.
    pub const DEFAULT_PERIOD: u64 = 30;

    /// Creates and validates TOTP system parameters.
    ///
    /// `period` is `X` and `epoch` is `T0` in RFC 6238 terminology.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ZeroPeriod`] when `period` is zero.
    pub const fn new(
        algorithm: Algorithm,
        digits: Digits,
        period: u64,
        epoch: u64,
    ) -> Result<Self, Error> {
        if period == 0 {
            return Err(Error::ZeroPeriod);
        }
        Ok(Self {
            algorithm,
            digits,
            period,
            epoch,
        })
    }

    /// Returns the selected HMAC algorithm.
    #[must_use]
    pub const fn algorithm(self) -> Algorithm {
        self.algorithm
    }

    /// Returns the configured code width.
    #[must_use]
    pub const fn digits(self) -> Digits {
        self.digits
    }

    /// Returns time-step size `X`, in seconds.
    #[must_use]
    pub const fn period(self) -> u64 {
        self.period
    }

    /// Returns initial Unix time `T0`, in seconds.
    #[must_use]
    pub const fn epoch(self) -> u64 {
        self.epoch
    }

    /// Calculates `T = floor((timestamp - T0) / X)`.
    ///
    /// The 64-bit result remains valid beyond the year 2038 as required by
    /// RFC 6238.
    ///
    /// # Errors
    ///
    /// Returns [`Error::TimestampBeforeEpoch`] when `timestamp` precedes
    /// configured `T0`.
    pub const fn counter_at(self, timestamp: u64) -> Result<u64, Error> {
        if timestamp < self.epoch {
            return Err(Error::TimestampBeforeEpoch {
                timestamp,
                epoch: self.epoch,
            });
        }
        Ok((timestamp - self.epoch) / self.period)
    }

    /// Returns seconds remaining in the step containing `timestamp`.
    ///
    /// The result is in `1..=period`; a value equal to `period` means a new
    /// time step has just begun.
    ///
    /// # Errors
    ///
    /// Returns [`Error::TimestampBeforeEpoch`] when `timestamp` precedes
    /// configured `T0`.
    pub const fn seconds_remaining(self, timestamp: u64) -> Result<u64, Error> {
        if timestamp < self.epoch {
            return Err(Error::TimestampBeforeEpoch {
                timestamp,
                epoch: self.epoch,
            });
        }
        Ok(self.period - ((timestamp - self.epoch) % self.period))
    }

    /// Generates a TOTP for a Unix timestamp in seconds.
    ///
    /// # Errors
    ///
    /// Returns [`Error::TimestampBeforeEpoch`] when `timestamp` precedes
    /// configured `T0`.
    pub fn generate(&self, secret: &Secret<'_>, timestamp: u64) -> Result<Code, Error> {
        let counter = self.counter_at(timestamp)?;
        Ok(self.generate_for_counter(secret, counter))
    }

    /// Verifies a code only in the step containing `timestamp`.
    ///
    /// Comparison of well-formed codes is performed in constant time.
    ///
    /// # Errors
    ///
    /// Returns [`VerifyError::Code`] for invalid code syntax or
    /// [`VerifyError::Parameters`] when `timestamp` precedes configured `T0`.
    pub fn verify(
        &self,
        secret: &Secret<'_>,
        timestamp: u64,
        candidate: &str,
    ) -> Result<bool, VerifyError> {
        let candidate = Code::parse(candidate, self.digits)?;
        let counter = self.counter_at(timestamp)?;
        Ok(self.generate_for_counter(secret, counter).ct_eq(candidate))
    }

    /// Searches a bounded window around the step containing `timestamp`.
    ///
    /// The current step is preferred, followed by past steps nearest-first
    /// and future steps nearest-first. Every representable counter in the
    /// configured window is evaluated even after a match, and the first match
    /// is recorded with masked selection rather than position-dependent
    /// control flow.
    ///
    /// RFC 6238 requires the caller to record successful use and reject a
    /// replay of the same time-step code. The returned counter and drift are
    /// suitable for that persistent state.
    ///
    /// # Errors
    ///
    /// Returns [`VerifyError::Code`] for invalid code syntax or
    /// [`VerifyError::Parameters`] when `timestamp` precedes configured `T0`.
    pub fn verify_window(
        &self,
        secret: &Secret<'_>,
        timestamp: u64,
        window: ValidationWindow,
        candidate: &str,
    ) -> Result<Option<TotpMatch>, VerifyError> {
        let candidate = Code::parse(candidate, self.digits)?;
        let counter = self.counter_at(timestamp)?;
        let mut matched = MatchAccumulator::new();

        self.consider_match(secret, counter, 0, candidate, &mut matched);

        for distance in 1..=window.past {
            let Some(current) = counter.checked_sub(u64::from(distance)) else {
                continue;
            };
            self.consider_match(
                secret,
                current,
                -i32::from(distance),
                candidate,
                &mut matched,
            );
        }

        for distance in 1..=window.future {
            let Some(current) = counter.checked_add(u64::from(distance)) else {
                continue;
            };
            self.consider_match(
                secret,
                current,
                i32::from(distance),
                candidate,
                &mut matched,
            );
        }

        Ok(if bool::from(matched.found) {
            Some(TotpMatch {
                counter: matched.counter,
                drift: matched.drift,
            })
        } else {
            None
        })
    }

    fn consider_match(
        &self,
        secret: &Secret<'_>,
        counter: u64,
        drift: i32,
        candidate: Code,
        matched: &mut MatchAccumulator,
    ) {
        let equal = self
            .generate_for_counter(secret, counter)
            .ct_eq_choice(candidate);
        let select = equal & !matched.found;
        matched.counter = u64::conditional_select(&matched.counter, &counter, select);
        matched.drift = i32::conditional_select(&matched.drift, &drift, select);
        matched.found |= equal;
    }

    fn generate_for_counter(&self, secret: &Secret<'_>, counter: u64) -> Code {
        let message = counter.to_be_bytes();
        match self.algorithm {
            Algorithm::Sha1 => generate_with_sha1(secret, counter, self.digits),
            Algorithm::Sha256 => {
                let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes())
                    .expect("HMAC accepts keys of any length");
                mac.update(&message);
                dynamic_truncate(mac.finalize().into_bytes().as_slice(), self.digits)
            }
            Algorithm::Sha512 => {
                let mut mac = Hmac::<Sha512>::new_from_slice(secret.as_bytes())
                    .expect("HMAC accepts keys of any length");
                mac.update(&message);
                dynamic_truncate(mac.finalize().into_bytes().as_slice(), self.digits)
            }
        }
    }
}

impl Default for Totp {
    fn default() -> Self {
        Self {
            algorithm: Algorithm::Sha1,
            digits: Digits::SIX,
            period: Self::DEFAULT_PERIOD,
            epoch: 0,
        }
    }
}

/// An error while verifying a TOTP.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum VerifyError {
    /// The candidate code is not strict ASCII decimal syntax.
    Code(CodeError),
    /// The timestamp is invalid for the configured TOTP parameters.
    Parameters(Error),
}

impl core::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Code(error) => write!(f, "invalid OTP code: {error}"),
            Self::Parameters(error) => write!(f, "invalid TOTP input: {error}"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for VerifyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Code(error) => Some(error),
            Self::Parameters(error) => Some(error),
        }
    }
}

impl From<CodeError> for VerifyError {
    fn from(value: CodeError) -> Self {
        Self::Code(value)
    }
}

impl From<Error> for VerifyError {
    fn from(value: Error) -> Self {
        Self::Parameters(value)
    }
}

/// A successful TOTP validation-window match.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct TotpMatch {
    counter: u64,
    drift: i32,
}

impl TotpMatch {
    /// Returns the matched 64-bit time-step counter.
    #[must_use]
    pub const fn counter(self) -> u64 {
        self.counter
    }

    /// Returns prover drift in steps relative to the verifier timestamp.
    ///
    /// Negative values are in the past and positive values in the future.
    #[must_use]
    pub const fn drift(self) -> i32 {
        self.drift
    }
}
