use hmac::{Hmac, KeyInit, Mac};
use sha1::Sha1;

use crate::{Code, CodeError, Digits, Secret};

/// RFC 4226 HOTP parameters.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Hotp {
    digits: Digits,
}

impl Hotp {
    /// Creates an HOTP configuration.
    #[must_use]
    pub const fn new(digits: Digits) -> Self {
        Self { digits }
    }

    /// Returns the configured code width.
    #[must_use]
    pub const fn digits(self) -> Digits {
        self.digits
    }

    /// Generates `HOTP(K, C)` as specified by RFC 4226.
    #[must_use]
    pub fn generate(&self, secret: &Secret<'_>, counter: u64) -> Code {
        generate_with_sha1(secret, counter, self.digits)
    }

    /// Verifies a code at exactly one counter value.
    ///
    /// Comparison of well-formed codes is performed in constant time.
    ///
    /// # Errors
    ///
    /// Returns a [`CodeError`] when `candidate` is not exactly the configured
    /// number of ASCII decimal digits.
    pub fn verify(
        &self,
        secret: &Secret<'_>,
        counter: u64,
        candidate: &str,
    ) -> Result<bool, CodeError> {
        let candidate = Code::parse(candidate, self.digits)?;
        Ok(self.generate(secret, counter).ct_eq(candidate))
    }

    /// Searches the current counter and `look_ahead` following counters.
    ///
    /// Every representable counter in the window is evaluated even after a
    /// match. This avoids leaking the match position through the number of
    /// HMAC evaluations. The first matching counter is returned if a rare
    /// decimal-code collision occurs.
    ///
    /// The caller must atomically persist [`HotpMatch::next_counter`] after
    /// success to prevent replay. A `None` next counter means the 64-bit
    /// counter is exhausted and the credential must be reprovisioned.
    ///
    /// # Errors
    ///
    /// Returns a [`CodeError`] when `candidate` is not exactly the configured
    /// number of ASCII decimal digits.
    pub fn verify_window(
        &self,
        secret: &Secret<'_>,
        counter: u64,
        look_ahead: u16,
        candidate: &str,
    ) -> Result<Option<HotpMatch>, CodeError> {
        let candidate = Code::parse(candidate, self.digits)?;
        let mut matched = None;

        for offset in 0..=u64::from(look_ahead) {
            let Some(current) = counter.checked_add(offset) else {
                continue;
            };
            let equal = self.generate(secret, current).ct_eq(candidate);
            if equal && matched.is_none() {
                matched = Some(HotpMatch {
                    counter: current,
                    next_counter: current.checked_add(1),
                });
            }
        }

        Ok(matched)
    }
}

impl Default for Hotp {
    fn default() -> Self {
        Self::new(Digits::SIX)
    }
}

/// A successful HOTP look-ahead-window match.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct HotpMatch {
    counter: u64,
    next_counter: Option<u64>,
}

impl HotpMatch {
    /// Returns the counter that generated the accepted code.
    #[must_use]
    pub const fn counter(self) -> u64 {
        self.counter
    }

    /// Returns the counter the validator must persist before accepting
    /// another code.
    #[must_use]
    pub const fn next_counter(self) -> Option<u64> {
        self.next_counter
    }
}

pub(crate) fn generate_with_sha1(secret: &Secret<'_>, counter: u64, digits: Digits) -> Code {
    let mut mac =
        Hmac::<Sha1>::new_from_slice(secret.as_bytes()).expect("HMAC accepts keys of any length");
    mac.update(&counter.to_be_bytes());
    let output = mac.finalize().into_bytes();
    dynamic_truncate(output.as_slice(), digits)
}

pub(crate) fn dynamic_truncate(output: &[u8], digits: Digits) -> Code {
    // Every RFC-supported digest is at least 20 bytes, while the low nibble
    // limits the greatest accessed index to 18.
    let offset = usize::from(output[output.len() - 1] & 0x0f);
    let binary = u32::from_be_bytes([
        output[offset],
        output[offset + 1],
        output[offset + 2],
        output[offset + 3],
    ]) & 0x7fff_ffff;
    Code::generated(binary % digits.modulus(), digits)
}
