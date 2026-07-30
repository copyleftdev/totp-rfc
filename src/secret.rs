use crate::Error;

/// Minimum shared-secret length required by RFC 4226, in bytes (128 bits).
pub const MIN_SECRET_BYTES: usize = 16;

/// A validated, borrowed shared secret.
///
/// The wrapper deliberately does not implement [`Debug`] or expose the secret
/// bytes. It borrows rather than owns key material, so the caller retains
/// control over storage, encryption, locking, and zeroization.
pub struct Secret<'a> {
    bytes: &'a [u8],
}

impl<'a> Secret<'a> {
    /// Validates and borrows a binary shared secret.
    ///
    /// RFC 4226 requires at least 128 bits and recommends 160 bits. RFC 6238
    /// further recommends a key as long as the selected HMAC output.
    ///
    /// # Errors
    ///
    /// Returns [`Error::SecretTooShort`] when `bytes` contains fewer than
    /// [`MIN_SECRET_BYTES`] bytes.
    pub fn new(bytes: &'a [u8]) -> Result<Self, Error> {
        if bytes.len() < MIN_SECRET_BYTES {
            return Err(Error::SecretTooShort {
                actual: bytes.len(),
                minimum: MIN_SECRET_BYTES,
            });
        }
        Ok(Self { bytes })
    }

    pub(crate) const fn as_bytes(&self) -> &[u8] {
        self.bytes
    }

    /// Returns the secret length in bytes without exposing its contents.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Returns `false`; a validated secret is never empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        false
    }
}

impl<'a> TryFrom<&'a [u8]> for Secret<'a> {
    type Error = Error;

    fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}
